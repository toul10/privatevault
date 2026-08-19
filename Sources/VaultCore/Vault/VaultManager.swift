import Foundation
import CryptoKit

/// Orchestrates the vault lifecycle (SECURITY_ARCHITECTURE.md §7): create, unlock (password / Touch ID), lock,
/// change password, key rotation, Secret Key regeneration, Recovery Kit, backup export/restore, delete.
/// Owns the `VaultStore` and the current `VaultSession`. Never stores the Master Password.
public actor VaultManager {
    public nonisolated let vaultURL: URL
    public nonisolated let deviceKeys: DeviceKeyStore
    /// KDF parameters for new vaults and the upgrade target for old ones (tests inject `.testing`).
    public var kdfPolicy: KDFParameters
    private var store: VaultStore?
    public private(set) var session: VaultSession?

    public init(vaultURL: URL, deviceKeys: DeviceKeyStore, kdfPolicy: KDFParameters = .current) {
        self.vaultURL = vaultURL; self.deviceKeys = deviceKeys; self.kdfPolicy = kdfPolicy
    }

    public nonisolated var vaultExists: Bool { VaultStore.exists(at: vaultURL) }
    public func setKDFPolicy(_ p: KDFParameters) { kdfPolicy = p }
    public var isUnlocked: Bool { session != nil }

    // MARK: - Create
    public struct CreationResult: Sendable {
        public let session: VaultSession
        public let secretKey: SecretKey
        /// False when the Keychain was unavailable: the user will need the Recovery Kit at every unlock.
        public let secretKeyStoredOnDevice: Bool
    }

    public func createVault(password: String) async throws -> CreationResult {
        guard !vaultExists else { throw VaultError.vaultAlreadyExists }
        try MasterPasswordPolicy.validate(password)
        let pw = try PasswordNormalization.normalize(password)
        defer { pw.wipe() }
        let header = VaultHeader.new(kdf: kdfPolicy)
        let sk = SecretKey.generate()
        let vmk = KeyHierarchy.generateVMK()
        let kek = try KeyHierarchy.deriveKEK(password: pw, secretKey: sk, header: header)
        let wrapped = try KeyHierarchy.wrapVMK(vmk, kek: kek, header: header)
        let keys = try VaultKeys(vaultID: header.vaultID, vmk: vmk)
        let mac = VaultState.mac(key: keys.vaultStateKey, vaultID: header.vaultID, generation: header.generation, entries: [])
        let stored = StoredHeader(canonical: header.canonicalBytes, wrappedVMK: wrapped,
                                  headerSHA256: VaultHeader.sha256(canonical: header.canonicalBytes, wrappedVMK: wrapped),
                                  skID: sk.identifier(vaultID: header.vaultID), stateMAC: mac)
        let newStore = try VaultStore.create(at: vaultURL, header: stored)
        var storedOnDevice = true
        do { try deviceKeys.storeSecretKey(sk, vaultID: header.vaultID, generation: header.generation, headerSHA256: stored.headerSHA256) }
        catch { storedOnDevice = false; SecureLog.error(.keychain, "secret key could not be stored on device", error: error) }
        let s = try await VaultSession(store: newStore, keys: keys, header: header, stored: stored, pinnedGeneration: nil)
        store = newStore; session = s
        SecureLog.notice(.vault, "vault created")
        return CreationResult(session: s, secretKey: sk, secretKeyStoredOnDevice: storedOnDevice)
    }

    // MARK: - Unlock
    private func openStore() throws -> VaultStore {
        if let store { return store }
        let s = try VaultStore.open(at: vaultURL)
        store = s
        return s
    }

    /// Password unlock. Pass `recoveryKit` when the Secret Key is not on this device (`secretKeyRequired`).
    public func unlock(password: String, recoveryKit: String? = nil) async throws -> VaultSession {
        if let session { return session }
        let store = try openStore()
        let stored = try await store.readHeader()
        var header = try stored.header()
        var pinned: UInt32? = nil
        let sk: SecretKey
        var storeSK = false
        if let kit = recoveryKit {
            sk = try RecoveryKit.decode(kit); storeSK = true
        } else {
            switch try loadDeviceSecretKey(vaultID: header.vaultID) {
            case .available(let k, let record): sk = k; pinned = record.generation
            case .absent, .unusable: throw VaultError.secretKeyRequired
            }
        }
        guard sk.identifier(vaultID: header.vaultID) == stored.skID else {
            throw VaultError.recoveryKitInvalid("this Recovery Kit does not belong to this vault")
        }
        let pw = try PasswordNormalization.normalize(password)
        defer { pw.wipe() }
        let kek = try KeyHierarchy.deriveKEK(password: pw, secretKey: sk, header: header)
        let vmk = try KeyHierarchy.unwrapVMK(stored.wrappedVMK, kek: kek, header: header)
        let keys = try VaultKeys(vaultID: header.vaultID, vmk: vmk)
        var current = stored
        if !header.kdf.isAtLeast(kdfPolicy) {
            (header, current) = try await rewrapHeader(store: store, password: pw, secretKey: sk, keys: keys, header: header,
                                                         stateEntries: nil, stateMAC: stored.stateMAC)
            SecureLog.notice(.crypto, "KDF parameters upgraded")
        }
        if storeSK {
            do { try deviceKeys.storeSecretKey(sk, vaultID: header.vaultID, generation: header.generation, headerSHA256: current.headerSHA256) }
            catch { SecureLog.error(.keychain, "secret key could not be stored on device", error: error) }
        }
        let s = try await VaultSession(store: store, keys: keys, header: header, stored: current, pinnedGeneration: pinned)
        try? deviceKeys.updatePinnedState(vaultID: header.vaultID, generation: header.generation, headerSHA256: current.headerSHA256)
        session = s
        return s
    }

    /// Touch ID unlock (Secure-Enclave-enforced). Falls back to `biometryUnavailable`/`biometryInvalidated`/`userCancelled`.
    public func unlockWithBiometrics(reason: String = "Unlock PrivateVault") async throws -> VaultSession {
        if let session { return session }
        let store = try openStore()
        let stored = try await store.readHeader()
        let header = try stored.header()
        let vmk = try deviceKeys.loadBiometricVMK(vaultID: header.vaultID, expectedGeneration: header.generation, reason: reason)
        let keys = try VaultKeys(vaultID: header.vaultID, vmk: vmk)
        let pinned = deviceKeys.pinnedGeneration(vaultID: header.vaultID)
        let s: VaultSession
        do { s = try await VaultSession(store: store, keys: keys, header: header, stored: stored, pinnedGeneration: pinned) }
        catch VaultError.authenticationFailed { throw VaultError.biometryInvalidated } // stale blob: records do not open
        session = s
        SecureLog.notice(.auth, "biometric unlock")
        return s
    }

    public func lock() async {
        if let session { await session.lock() }
        session = nil
        if let store { await store.close() }
        store = nil
    }

    // MARK: - Secret Key helpers
    private func obtainSecretKey(vaultID: UUID, recoveryKit: String?) throws -> SecretKey {
        if let kit = recoveryKit { return try RecoveryKit.decode(kit) }
        switch try loadDeviceSecretKey(vaultID: vaultID) {
        case .available(let k, _): return k
        case .absent, .unusable: throw VaultError.secretKeyRequired
        }
    }
    /// Keychain problems are not fatal: the user can always supply the Recovery Kit.
    private func loadDeviceSecretKey(vaultID: UUID) throws -> DeviceKeyStore.SecretKeyLoad {
        do { return try deviceKeys.loadSecretKey(vaultID: vaultID) }
        catch VaultError.userCancelled { throw VaultError.userCancelled }
        catch { SecureLog.error(.keychain, "secret key load failed", error: error); return .absent }
    }
    private func verifyPassword(_ password: String, secretKey: SecretKey, header: VaultHeader, stored: StoredHeader) throws -> (SecureBytes, SecureBytes) {
        let pw = try PasswordNormalization.normalize(password)
        let kek = try KeyHierarchy.deriveKEK(password: pw, secretKey: secretKey, header: header)
        let vmk = try KeyHierarchy.unwrapVMK(stored.wrappedVMK, kek: kek, header: header)
        return (pw, vmk)
    }

    /// Writes a new header (new salt, policy KDF params, generation+1) wrapping the SAME VMK. Returns new header/stored.
    private func rewrapHeader(store: VaultStore, password: SecureBytes, secretKey: SecretKey, keys: VaultKeys, header: VaultHeader,
                              stateEntries: [(id: UUID, revision: UInt64)]?, stateMAC: Data) async throws -> (VaultHeader, StoredHeader) {
        var newHeader = header
        newHeader.salt = SecureRandom.bytes(Argon2id.saltLength)
        newHeader.kdf = kdfPolicy
        newHeader.generation &+= 1
        let kek = try KeyHierarchy.deriveKEK(password: password, secretKey: secretKey, header: newHeader)
        let wrapped = try KeyHierarchy.wrapVMK(keys.vmk, kek: kek, header: newHeader)
        _ = try KeyHierarchy.unwrapVMK(wrapped, kek: kek, header: newHeader) // self-check before commit
        let mac: Data
        if let entries = stateEntries {
            mac = VaultState.mac(key: keys.vaultStateKey, vaultID: header.vaultID, generation: newHeader.generation, entries: entries)
        } else {
            // entries unknown yet (unlock path): recompute from the store
            let recs = try await store.allRecords()
            mac = VaultState.mac(key: keys.vaultStateKey, vaultID: header.vaultID, generation: newHeader.generation, entries: recs.map { (id: $0.id, revision: $0.revision) })
            // if the old MAC did not verify, the session will still warn (we verify old state before rewriting)
            let oldOK = VaultState.verify(stateMAC, key: keys.vaultStateKey, vaultID: header.vaultID, generation: header.generation, entries: recs.map { (id: $0.id, revision: $0.revision) })
            if !oldOK { SecureLog.notice(.vault, "state MAC mismatch before header rewrite") }
        }
        let stored = StoredHeader(canonical: newHeader.canonicalBytes, wrappedVMK: wrapped,
                                  headerSHA256: VaultHeader.sha256(canonical: newHeader.canonicalBytes, wrappedVMK: wrapped),
                                  skID: secretKey.identifier(vaultID: header.vaultID), stateMAC: mac)
        try await store.writeHeader(stored)
        try? deviceKeys.rewrapBiometric(vmk: keys.vmk, vaultID: header.vaultID, generation: newHeader.generation)
        try? deviceKeys.updatePinnedState(vaultID: header.vaultID, generation: newHeader.generation, headerSHA256: stored.headerSHA256)
        return (newHeader, stored)
    }

    // MARK: - Change password / rotation
    /// Default: re-wrap only (records untouched). `rotateKeys`: new VMK + re-encrypt everything (§7.4).
    public func changePassword(current: String, new: String, rotateKeys: Bool = false, recoveryKit: String? = nil) async throws {
        guard let session, let store else { throw VaultError.vaultLocked }
        let header = await session.currentHeader, stored = await session.storedHeader
        let sk = try obtainSecretKey(vaultID: header.vaultID, recoveryKit: recoveryKit)
        let (oldPW, _) = try verifyPassword(current, secretKey: sk, header: header, stored: stored)
        oldPW.wipe()
        try MasterPasswordPolicy.validate(new)
        let newPW = try PasswordNormalization.normalize(new)
        defer { newPW.wipe() }
        if rotateKeys {
            try await rotate(session: session, store: store, password: newPW, secretKey: sk, header: header)
        } else {
            let keys = try await session.currentKeys()
            let entries = try await session.stateEntries()
            let (h, s) = try await rewrapHeader(store: store, password: newPW, secretKey: sk, keys: keys, header: header, stateEntries: entries, stateMAC: stored.stateMAC)
            await session.adopt(keys: nil, header: h, stored: s)
        }
        SecureLog.notice(.vault, "master password changed", .bool(rotateKeys))
    }

    private func rotate(session: VaultSession, store: VaultStore, password: SecureBytes, secretKey: SecretKey, header: VaultHeader) async throws {
        var newHeader = header
        newHeader.salt = SecureRandom.bytes(Argon2id.saltLength)
        newHeader.kdf = kdfPolicy
        newHeader.generation &+= 1
        let newVMK = KeyHierarchy.generateVMK()
        let newKeys = try VaultKeys(vaultID: header.vaultID, vmk: newVMK)
        let (records, mac, _) = try await session.reencryptAll(under: newKeys, generation: newHeader.generation)
        let kek = try KeyHierarchy.deriveKEK(password: password, secretKey: secretKey, header: newHeader)
        let wrapped = try KeyHierarchy.wrapVMK(newVMK, kek: kek, header: newHeader)
        _ = try KeyHierarchy.unwrapVMK(wrapped, kek: kek, header: newHeader)
        let stored = StoredHeader(canonical: newHeader.canonicalBytes, wrappedVMK: wrapped,
                                  headerSHA256: VaultHeader.sha256(canonical: newHeader.canonicalBytes, wrappedVMK: wrapped),
                                  skID: secretKey.identifier(vaultID: header.vaultID), stateMAC: mac)
        try await store.replaceAll(records: records, header: stored)
        await session.adopt(keys: newKeys, header: newHeader, stored: stored)
        try await session.reloadFromStore()
        try? deviceKeys.rewrapBiometric(vmk: newVMK, vaultID: header.vaultID, generation: newHeader.generation)
        try? deviceKeys.updatePinnedState(vaultID: header.vaultID, generation: newHeader.generation, headerSHA256: stored.headerSHA256)
        SecureLog.notice(.vault, "vault keys rotated", .count(records.count))
    }

    /// New Secret Key + full rotation. Old Recovery Kits and old backups stop working for NEW data.
    public func regenerateSecretKey(password: String, recoveryKit: String? = nil) async throws -> SecretKey {
        guard let session, let store else { throw VaultError.vaultLocked }
        let header = await session.currentHeader, stored = await session.storedHeader
        let oldSK = try obtainSecretKey(vaultID: header.vaultID, recoveryKit: recoveryKit)
        let (pw, _) = try verifyPassword(password, secretKey: oldSK, header: header, stored: stored)
        defer { pw.wipe() }
        let newSK = SecretKey.generate()
        try await rotate(session: session, store: store, password: pw, secretKey: newSK, header: header)
        let newStored = await session.storedHeader, newHeader = await session.currentHeader
        try deviceKeys.storeSecretKey(newSK, vaultID: header.vaultID, generation: newHeader.generation, headerSHA256: newStored.headerSHA256)
        SecureLog.notice(.vault, "secret key regenerated")
        return newSK
    }

    /// Re-display the Recovery Kit (requires the Master Password).
    public func recoveryKit(password: String) async throws -> String {
        guard let session else { throw VaultError.vaultLocked }
        let header = await session.currentHeader, stored = await session.storedHeader
        let sk = try obtainSecretKey(vaultID: header.vaultID, recoveryKit: nil)
        let (pw, vmk) = try verifyPassword(password, secretKey: sk, header: header, stored: stored)
        pw.wipe(); vmk.wipe()
        return RecoveryKit.encode(sk)
    }

    // MARK: - Touch ID
    public func isBiometricUnlockEnabled() async -> Bool {
        guard let vaultID = await currentVaultID() else { return false }
        return deviceKeys.isBiometricEnabled(vaultID: vaultID)
    }
    public func enableBiometricUnlock() async throws {
        guard let session else { throw VaultError.vaultLocked }
        let keys = try await session.currentKeys()
        let header = await session.currentHeader
        try deviceKeys.enableBiometric(vmk: keys.vmk, vaultID: header.vaultID, generation: header.generation)
    }
    public func disableBiometricUnlock(password: String) async throws {
        guard let session else { throw VaultError.vaultLocked }
        let header = await session.currentHeader, stored = await session.storedHeader
        let sk = try obtainSecretKey(vaultID: header.vaultID, recoveryKit: nil)
        let (pw, vmk) = try verifyPassword(password, secretKey: sk, header: header, stored: stored)
        pw.wipe(); vmk.wipe()
        try deviceKeys.disableBiometric(vaultID: header.vaultID)
    }
    private func currentVaultID() async -> UUID? {
        if let session { return await session.currentHeader.vaultID }
        guard let store = try? openStore(), let stored = try? await store.readHeader(), let h = try? stored.header() else { return nil }
        return h.vaultID
    }
    public func secretKeyAvailableOnDevice() async -> Bool {
        guard let id = await currentVaultID() else { return false }
        if case .available = (try? deviceKeys.loadSecretKey(vaultID: id)) ?? .absent { return true }
        return false
    }

    // MARK: - Backup
    public func exportBackup(password: String) async throws -> Data {
        guard let session else { throw VaultError.vaultLocked }
        let header = await session.currentHeader, stored = await session.storedHeader
        let sk = try obtainSecretKey(vaultID: header.vaultID, recoveryKit: nil)
        let (pw, vmk) = try verifyPassword(password, secretKey: sk, header: header, stored: stored)
        pw.wipe(); vmk.wipe()
        let keys = try await session.currentKeys()
        let records = try await session.exportRecords()
        SecureLog.notice(.backup, "backup exported", .count(records.count))
        return try BackupCodec.export(stored: stored, records: records, keys: keys)
    }

    /// Replaces the current vault (if any) with the backup after verifying MP + SK + manifest + every record.
    public func restoreBackup(_ data: Data, password: String, recoveryKit: String? = nil) async throws -> VaultSession {
        let parsed = try BackupCodec.parse(data)
        let sk = try obtainSecretKey(vaultID: parsed.header.vaultID, recoveryKit: recoveryKit)
        guard sk.identifier(vaultID: parsed.header.vaultID) == parsed.stored.skID else {
            throw VaultError.recoveryKitInvalid("this Recovery Kit does not belong to the vault in the backup")
        }
        let pw = try PasswordNormalization.normalize(password)
        defer { pw.wipe() }
        let kek = try KeyHierarchy.deriveKEK(password: pw, secretKey: sk, header: parsed.header)
        let vmk = try KeyHierarchy.unwrapVMK(parsed.stored.wrappedVMK, kek: kek, header: parsed.header)
        let keys = try VaultKeys(vaultID: parsed.header.vaultID, vmk: vmk)
        let mac = try BackupCodec.verify(parsed, keys: keys)
        var stored = parsed.stored; stored.stateMAC = mac
        // device records of a DIFFERENT existing vault become orphans: remove them
        if let existing = await currentVaultID(), existing != parsed.header.vaultID {
            try? deviceKeys.disableBiometric(vaultID: existing)
            try? deviceKeys.deleteSecretKey(vaultID: existing)
        }
        // write to a temporary file next to the vault, then swap atomically
        await lock()
        let tmpURL = vaultURL.deletingLastPathComponent().appendingPathComponent("vault.restore.tmp")
        try? FileManager.default.removeItem(at: tmpURL)
        let tmpStore = try VaultStore.create(at: tmpURL, header: stored)
        try await tmpStore.replaceAll(records: parsed.records, header: stored)
        try await tmpStore.integrityCheck()
        await tmpStore.close()
        if FileManager.default.fileExists(atPath: vaultURL.path) {
            _ = try FileManager.default.replaceItemAt(vaultURL, withItemAt: tmpURL, backupItemName: nil, options: [])
        } else {
            try FileManager.default.moveItem(at: tmpURL, to: vaultURL)
        }
        // device records: the VMK may differ from whatever an old bio blob wrapped
        try? deviceKeys.disableBiometric(vaultID: parsed.header.vaultID)
        if recoveryKit != nil {
            try? deviceKeys.storeSecretKey(sk, vaultID: parsed.header.vaultID, generation: parsed.header.generation, headerSHA256: stored.headerSHA256)
        } else {
            try? deviceKeys.updatePinnedState(vaultID: parsed.header.vaultID, generation: parsed.header.generation, headerSHA256: stored.headerSHA256)
        }
        let newStore = try VaultStore.open(at: vaultURL)
        let s = try await VaultSession(store: newStore, keys: keys, header: parsed.header, stored: stored, pinnedGeneration: nil)
        store = newStore; session = s
        SecureLog.notice(.backup, "backup restored", .count(parsed.records.count))
        return s
    }

    // MARK: - Delete
    public func deleteVault(password: String) async throws {
        guard let session else { throw VaultError.vaultLocked }
        let header = await session.currentHeader, stored = await session.storedHeader
        let sk = try obtainSecretKey(vaultID: header.vaultID, recoveryKit: nil)
        let (pw, vmk) = try verifyPassword(password, secretKey: sk, header: header, stored: stored)
        pw.wipe(); vmk.wipe()
        await lock()
        try FileManager.default.removeItem(at: vaultURL)
        try? deviceKeys.disableBiometric(vaultID: header.vaultID)
        try? deviceKeys.deleteSecretKey(vaultID: header.vaultID)
        SecureLog.notice(.vault, "vault deleted")
    }
}
