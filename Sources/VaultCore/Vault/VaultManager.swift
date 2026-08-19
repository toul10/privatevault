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
    /// Consecutive failed password attempts (in-process throttle against someone at the keyboard).
    private var failedAttempts = 0

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
        do { try deviceKeys.storeSecretKey(sk, vaultID: header.vaultID, generation: header.generation, headerSHA256: stored.headerSHA256, stateMAC: mac) }
        catch { storedOnDevice = false; SecureLog.error(.keychain, "secret key could not be stored on device", error: error) }
        let s = try await VaultSession(store: newStore, keys: keys, header: header, stored: stored, warnings: [])
        await installStateMirror(s)
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
    /// Reads and structurally validates the header; distinguishes corruption from wrong credentials (UX only).
    private func readHeader(_ store: VaultStore) async throws -> (VaultHeader, StoredHeader) {
        let stored = try await store.readHeader()
        let header = try stored.header()   // bounds validated before any KDF work
        guard VaultHeader.sha256(canonical: stored.canonical, wrappedVMK: stored.wrappedVMK) == stored.headerSHA256 else {
            throw VaultError.corrupted("header checksum")
        }
        return (header, stored)
    }
    /// Rollback checks against the state pinned on this device (before any header rewrite).
    private func rollbackWarnings(header: VaultHeader, stored: StoredHeader) -> [IntegrityWarning] {
        guard let pinned = deviceKeys.pinnedState(vaultID: header.vaultID) else { return [] }
        if header.generation < pinned.generation { return [.generationRollback] }
        if header.generation == pinned.generation, let mac = pinned.stateMAC, mac != stored.stateMAC { return [.fileRollback] }
        return []
    }
    private func throttleIfNeeded() async {
        guard failedAttempts >= 3 else { return }
        let seconds = min(30.0, pow(2.0, Double(failedAttempts - 3)))
        try? await Task.sleep(for: .seconds(seconds))
    }

    /// Password unlock. Pass `recoveryKit` when the Secret Key is not on this device (`secretKeyRequired`).
    public func unlock(password: String, recoveryKit: String? = nil) async throws -> VaultSession {
        if let session { return session }
        let store = try openStore()
        var (header, stored) = try await readHeader(store)
        let warnings = rollbackWarnings(header: header, stored: stored)
        let sk: SecretKey
        var storeSK = false
        if let kit = recoveryKit {
            sk = try RecoveryKit.decode(kit); storeSK = true
            guard sk.identifier(vaultID: header.vaultID) == stored.skID else {
                throw VaultError.recoveryKitInvalid("this Recovery Kit does not belong to this vault")
            }
        } else {
            sk = try deviceSecretKey(vaultID: header.vaultID, expectedID: stored.skID)
        }
        await throttleIfNeeded()
        let pw = try PasswordNormalization.normalize(password)
        defer { pw.wipe() }
        let kek = try KeyHierarchy.deriveKEK(password: pw, secretKey: sk, header: header)
        let vmk: SecureBytes
        do { vmk = try KeyHierarchy.unwrapVMK(stored.wrappedVMK, kek: kek, header: header) }
        catch { failedAttempts += 1; throw error }
        failedAttempts = 0
        let keys = try VaultKeys(vaultID: header.vaultID, vmk: vmk)
        var extraWarnings: [IntegrityWarning] = warnings
        if !header.kdf.isAtLeast(kdfPolicy) {
            // Verify the stored state MAC BEFORE rewriting the header (the rewrite recomputes it for the new
            // generation); a mismatch must still surface as a warning after the upgrade.
            let recs = try await store.allRecords()
            if !VaultState.verify(stored.stateMAC, key: keys.vaultStateKey, vaultID: header.vaultID, generation: header.generation,
                                  entries: recs.map { (id: $0.id, revision: $0.revision) }) { extraWarnings.append(.recordStateMismatch) }
            (header, stored) = try await rewrapHeader(store: store, password: pw, secretKey: sk, keys: keys, header: header, stateEntries: nil)
            SecureLog.notice(.crypto, "KDF parameters upgraded")
        }
        if storeSK {
            do { try deviceKeys.storeSecretKey(sk, vaultID: header.vaultID, generation: header.generation, headerSHA256: stored.headerSHA256, stateMAC: stored.stateMAC) }
            catch { SecureLog.error(.keychain, "secret key could not be stored on device", error: error) }
        }
        let s = try await VaultSession(store: store, keys: keys, header: header, stored: stored, warnings: extraWarnings)
        await installStateMirror(s)
        try? deviceKeys.updatePinnedState(vaultID: header.vaultID, generation: header.generation, headerSHA256: stored.headerSHA256, stateMAC: stored.stateMAC)
        session = s
        return s
    }

    /// Touch ID unlock (Secure-Enclave-enforced). The bio blob is bound to the exact header checksum, and the
    /// header is additionally compared with the one pinned on this device.
    public func unlockWithBiometrics(reason: String = "Unlock PrivateVault") async throws -> VaultSession {
        if let session { return session }
        let store = try openStore()
        let (header, stored) = try await readHeader(store)
        if let pinned = deviceKeys.pinnedState(vaultID: header.vaultID), pinned.headerSHA256 != stored.headerSHA256 {
            // The header changed behind this device's back (or a rollback): refuse the convenience path.
            throw VaultError.biometryInvalidated
        }
        let warnings = rollbackWarnings(header: header, stored: stored)
        let vmk = try deviceKeys.loadBiometricVMK(vaultID: header.vaultID, headerSHA256: stored.headerSHA256, reason: reason)
        let keys = try VaultKeys(vaultID: header.vaultID, vmk: vmk)
        let s = try await VaultSession(store: store, keys: keys, header: header, stored: stored, warnings: warnings)
        await installStateMirror(s)
        try? deviceKeys.updatePinnedState(vaultID: header.vaultID, generation: header.generation, headerSHA256: stored.headerSHA256, stateMAC: stored.stateMAC)
        session = s
        SecureLog.notice(.auth, "biometric unlock")
        return s
    }

    /// Mirrors every committed state MAC into the device record (whole-file rollback detection).
    private func installStateMirror(_ s: VaultSession) async {
        let vaultID = s.vaultID
        let deviceKeys = self.deviceKeys
        await s.setStateChangedHandler { [deviceKeys] mac in
            guard let pinned = deviceKeys.pinnedState(vaultID: vaultID) else { return }
            try? deviceKeys.updatePinnedState(vaultID: vaultID, generation: pinned.generation, headerSHA256: pinned.headerSHA256, stateMAC: mac)
        }
    }

    public func lock() async {
        if let session { await session.lock() }
        session = nil
        if let store { await store.close() }
        store = nil
    }

    // MARK: - Secret Key helpers
    /// Secret Key from this device: the main record, or the pending one left by an interrupted regeneration.
    private func deviceSecretKey(vaultID: UUID, expectedID: Data) throws -> SecretKey {
        switch try loadDeviceSecretKey(vaultID: vaultID, pending: false) {
        case .available(let k, _) where k.identifier(vaultID: vaultID) == expectedID: return k
        default: break
        }
        if case .available(let k, _) = try loadDeviceSecretKey(vaultID: vaultID, pending: true), k.identifier(vaultID: vaultID) == expectedID {
            try? deviceKeys.promotePendingSecretKey(vaultID: vaultID)
            SecureLog.notice(.keychain, "pending secret key promoted after interrupted regeneration")
            return k
        }
        throw VaultError.secretKeyRequired
    }
    private func obtainSecretKey(vaultID: UUID, expectedID: Data, recoveryKit: String?) throws -> SecretKey {
        if let kit = recoveryKit {
            let sk = try RecoveryKit.decode(kit)
            guard sk.identifier(vaultID: vaultID) == expectedID else { throw VaultError.recoveryKitInvalid("this Recovery Kit does not belong to this vault") }
            return sk
        }
        return try deviceSecretKey(vaultID: vaultID, expectedID: expectedID)
    }
    /// Keychain problems are not fatal: the user can always supply the Recovery Kit.
    private func loadDeviceSecretKey(vaultID: UUID, pending: Bool) throws -> DeviceKeyStore.SecretKeyLoad {
        do { return try deviceKeys.loadSecretKey(vaultID: vaultID, pending: pending) }
        catch VaultError.userCancelled { throw VaultError.userCancelled }
        catch { SecureLog.error(.keychain, "secret key load failed", error: error); return .absent }
    }
    private func verifyPassword(_ password: String, secretKey: SecretKey, header: VaultHeader, stored: StoredHeader) async throws -> (SecureBytes, SecureBytes) {
        await throttleIfNeeded()
        let pw = try PasswordNormalization.normalize(password)
        let kek = try KeyHierarchy.deriveKEK(password: pw, secretKey: secretKey, header: header)
        do {
            let vmk = try KeyHierarchy.unwrapVMK(stored.wrappedVMK, kek: kek, header: header)
            failedAttempts = 0
            return (pw, vmk)
        } catch { failedAttempts += 1; pw.wipe(); throw error }
    }

    /// Writes a new header (new salt, upgraded KDF params, generation+1) wrapping the SAME VMK. Returns new header/stored.
    private func rewrapHeader(store: VaultStore, password: SecureBytes, secretKey: SecretKey, keys: VaultKeys, header: VaultHeader,
                              stateEntries: [(id: UUID, revision: UInt64)]?) async throws -> (VaultHeader, StoredHeader) {
        var newHeader = header
        newHeader.salt = SecureRandom.bytes(Argon2id.saltLength)
        newHeader.kdf = header.kdf.upgraded(to: kdfPolicy)   // never lowers a dimension
        newHeader.generation &+= 1
        let kek = try KeyHierarchy.deriveKEK(password: password, secretKey: secretKey, header: newHeader)
        let wrapped = try KeyHierarchy.wrapVMK(keys.vmk, kek: kek, header: newHeader)
        _ = try KeyHierarchy.unwrapVMK(wrapped, kek: kek, header: newHeader) // self-check before commit
        let entries: [(id: UUID, revision: UInt64)]
        if let stateEntries { entries = stateEntries } else { entries = try await store.allRecords().map { (id: $0.id, revision: $0.revision) } }
        let mac = VaultState.mac(key: keys.vaultStateKey, vaultID: header.vaultID, generation: newHeader.generation, entries: entries)
        let stored = StoredHeader(canonical: newHeader.canonicalBytes, wrappedVMK: wrapped,
                                  headerSHA256: VaultHeader.sha256(canonical: newHeader.canonicalBytes, wrappedVMK: wrapped),
                                  skID: secretKey.identifier(vaultID: header.vaultID), stateMAC: mac)
        try await store.writeHeader(stored)
        deviceKeys.rewrapBiometric(vmk: keys.vmk, vaultID: header.vaultID, headerSHA256: stored.headerSHA256)
        try? deviceKeys.updatePinnedState(vaultID: header.vaultID, generation: newHeader.generation, headerSHA256: stored.headerSHA256, stateMAC: mac)
        return (newHeader, stored)
    }

    // MARK: - Change password / rotation
    /// Default: re-wrap only (records untouched). `rotateKeys`: new VMK + re-encrypt everything (§7.4).
    public func changePassword(current: String, new: String, rotateKeys: Bool = false, recoveryKit: String? = nil) async throws {
        guard let session, let store else { throw VaultError.vaultLocked }
        let header = await session.currentHeader, stored = await session.storedHeader
        let sk = try obtainSecretKey(vaultID: header.vaultID, expectedID: stored.skID, recoveryKit: recoveryKit)
        let (oldPW, oldVMK) = try await verifyPassword(current, secretKey: sk, header: header, stored: stored)
        oldPW.wipe(); oldVMK.wipe()
        try MasterPasswordPolicy.validate(new)
        let newPW = try PasswordNormalization.normalize(new)
        defer { newPW.wipe() }
        if rotateKeys {
            try await rotate(session: session, store: store, password: newPW, secretKey: sk, header: header)
        } else {
            let keys = try await session.currentKeys()
            let entries = try await session.stateEntries()
            let (h, s) = try await rewrapHeader(store: store, password: newPW, secretKey: sk, keys: keys, header: header, stateEntries: entries)
            await session.adopt(keys: nil, header: h, stored: s)
        }
        SecureLog.notice(.vault, "master password changed", .bool(rotateKeys))
    }

    private func rotate(session: VaultSession, store: VaultStore, password: SecureBytes, secretKey: SecretKey, header: VaultHeader) async throws {
        var newHeader = header
        newHeader.salt = SecureRandom.bytes(Argon2id.saltLength)
        newHeader.kdf = header.kdf.upgraded(to: kdfPolicy)
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
        try await store.replaceAll(records: records, header: stored)   // COMMIT; VACUUM inside is best-effort
        await session.adopt(keys: newKeys, header: newHeader, stored: stored)
        try await session.reloadFromStore()
        deviceKeys.rewrapBiometric(vmk: newVMK, vaultID: header.vaultID, headerSHA256: stored.headerSHA256)
        try? deviceKeys.updatePinnedState(vaultID: header.vaultID, generation: newHeader.generation, headerSHA256: stored.headerSHA256, stateMAC: mac)
        SecureLog.notice(.vault, "vault keys rotated", .count(records.count))
    }

    public struct RegenerationResult: Sendable {
        public let secretKey: SecretKey
        /// False ⇒ the Keychain refused the new key: the displayed Recovery Kit is the ONLY copy.
        public let secretKeyStoredOnDevice: Bool
    }
    /// New Secret Key + full rotation. Crash-safe: the new key is written to the device store (as "pending")
    /// BEFORE the vault is rewritten, promoted afterwards; unlock also accepts a pending key. Old Recovery Kits
    /// and old backups stop working for NEW data.
    public func regenerateSecretKey(password: String, recoveryKit: String? = nil) async throws -> RegenerationResult {
        guard let session, let store else { throw VaultError.vaultLocked }
        let header = await session.currentHeader, stored = await session.storedHeader
        let oldSK = try obtainSecretKey(vaultID: header.vaultID, expectedID: stored.skID, recoveryKit: recoveryKit)
        let (pw, vmk) = try await verifyPassword(password, secretKey: oldSK, header: header, stored: stored)
        vmk.wipe()
        defer { pw.wipe() }
        let newSK = SecretKey.generate()
        var storedOnDevice = true
        do { try deviceKeys.storeSecretKey(newSK, vaultID: header.vaultID, generation: header.generation, headerSHA256: stored.headerSHA256, stateMAC: stored.stateMAC, pending: true) }
        catch { storedOnDevice = false; SecureLog.error(.keychain, "pending secret key could not be stored", error: error) }
        do {
            try await rotate(session: session, store: store, password: pw, secretKey: newSK, header: header)
        } catch {
            try? deviceKeys.deletePendingSecretKey(vaultID: header.vaultID)
            throw error
        }
        let newStored = await session.storedHeader, newHeader = await session.currentHeader
        if storedOnDevice {
            do {
                try deviceKeys.promotePendingSecretKey(vaultID: header.vaultID)
                try deviceKeys.updatePinnedState(vaultID: header.vaultID, generation: newHeader.generation, headerSHA256: newStored.headerSHA256, stateMAC: newStored.stateMAC)
            } catch { storedOnDevice = false; SecureLog.error(.keychain, "secret key promotion failed", error: error) }
        }
        SecureLog.notice(.vault, "secret key regenerated", .bool(storedOnDevice))
        return RegenerationResult(secretKey: newSK, secretKeyStoredOnDevice: storedOnDevice)
    }

    /// Re-display the Recovery Kit (requires the Master Password).
    public func recoveryKit(password: String) async throws -> String {
        guard let session else { throw VaultError.vaultLocked }
        let header = await session.currentHeader, stored = await session.storedHeader
        let sk = try obtainSecretKey(vaultID: header.vaultID, expectedID: stored.skID, recoveryKit: nil)
        let (pw, vmk) = try await verifyPassword(password, secretKey: sk, header: header, stored: stored)
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
        let header = await session.currentHeader, stored = await session.storedHeader
        try deviceKeys.enableBiometric(vmk: keys.vmk, vaultID: header.vaultID, headerSHA256: stored.headerSHA256)
    }
    public func disableBiometricUnlock(password: String) async throws {
        guard let session else { throw VaultError.vaultLocked }
        let header = await session.currentHeader, stored = await session.storedHeader
        let sk = try obtainSecretKey(vaultID: header.vaultID, expectedID: stored.skID, recoveryKit: nil)
        let (pw, vmk) = try await verifyPassword(password, secretKey: sk, header: header, stored: stored)
        pw.wipe(); vmk.wipe()
        try deviceKeys.disableBiometric(vaultID: header.vaultID)
    }
    private func currentVaultID() async -> UUID? {
        if let session { return await session.currentHeader.vaultID }
        guard let store = try? openStore(), let stored = try? await store.readHeader(), let h = try? stored.header() else { return nil }
        return h.vaultID
    }
    public func secretKeyAvailableOnDevice() async -> Bool {
        guard let store = try? openStore(), let stored = try? await store.readHeader(), let h = try? stored.header() else { return false }
        return (try? deviceSecretKey(vaultID: h.vaultID, expectedID: stored.skID)) != nil
    }

    // MARK: - Backup
    public func exportBackup(password: String) async throws -> Data {
        guard let session else { throw VaultError.vaultLocked }
        let header = await session.currentHeader, stored = await session.storedHeader
        let sk = try obtainSecretKey(vaultID: header.vaultID, expectedID: stored.skID, recoveryKit: nil)
        let (pw, vmk) = try await verifyPassword(password, secretKey: sk, header: header, stored: stored)
        pw.wipe(); vmk.wipe()
        let keys = try await session.currentKeys()
        let records = try await session.exportRecords()
        SecureLog.notice(.backup, "backup exported", .count(records.count))
        return try BackupCodec.export(stored: stored, records: records, keys: keys)
    }

    /// Structural inspection of a backup file (no credentials needed): creation time and record count.
    public nonisolated func inspectBackup(_ data: Data) throws -> (createdAt: Date, recordCount: Int, vaultID: UUID) {
        let p = try BackupCodec.parse(data)
        return (p.createdAt, p.records.count, p.header.vaultID)
    }

    /// Replaces the current vault (if any) with the backup after verifying MP + SK + manifest + every record.
    public func restoreBackup(_ data: Data, password: String, recoveryKit: String? = nil) async throws -> VaultSession {
        let parsed = try BackupCodec.parse(data)
        let sk: SecretKey
        if let kit = recoveryKit {
            sk = try RecoveryKit.decode(kit)
            guard sk.identifier(vaultID: parsed.header.vaultID) == parsed.stored.skID else {
                throw VaultError.recoveryKitInvalid("this Recovery Kit does not belong to the vault in the backup")
            }
        } else {
            sk = try deviceSecretKey(vaultID: parsed.header.vaultID, expectedID: parsed.stored.skID)
        }
        await throttleIfNeeded()
        let pw = try PasswordNormalization.normalize(password)
        defer { pw.wipe() }
        let kek = try KeyHierarchy.deriveKEK(password: pw, secretKey: sk, header: parsed.header)
        let vmk: SecureBytes
        do { vmk = try KeyHierarchy.unwrapVMK(parsed.stored.wrappedVMK, kek: kek, header: parsed.header) }
        catch { failedAttempts += 1; throw error }
        failedAttempts = 0
        let keys = try VaultKeys(vaultID: parsed.header.vaultID, vmk: vmk)
        let mac = try BackupCodec.verify(parsed, keys: keys)
        var stored = parsed.stored; stored.stateMAC = mac
        let previousVaultID = await currentVaultID()
        // write to a temporary file next to the vault, then swap atomically (nothing touched until verified)
        await lock()
        let dir = vaultURL.deletingLastPathComponent()
        let tmpURL = dir.appendingPathComponent("vault.restore.tmp")
        try? FileManager.default.removeItem(at: tmpURL)
        VaultStore.removeSideFiles(for: tmpURL)
        do {
            let tmpStore = try VaultStore.create(at: tmpURL, header: stored)
            try await tmpStore.replaceAll(records: parsed.records, header: stored)
            try await tmpStore.integrityCheck()
            await tmpStore.close()
            VaultStore.removeSideFiles(for: vaultURL)   // a stale -journal would be replayed onto the new file
            if FileManager.default.fileExists(atPath: vaultURL.path) {
                _ = try FileManager.default.replaceItemAt(vaultURL, withItemAt: tmpURL, backupItemName: nil, options: [])
            } else {
                try FileManager.default.moveItem(at: tmpURL, to: vaultURL)
            }
        } catch {
            try? FileManager.default.removeItem(at: tmpURL)
            VaultStore.removeSideFiles(for: tmpURL)
            throw error
        }
        // ---- point of no return passed: now update device records ----
        if let previous = previousVaultID, previous != parsed.header.vaultID {
            try? deviceKeys.disableBiometric(vaultID: previous)
            try? deviceKeys.deleteSecretKey(vaultID: previous)
        }
        try? deviceKeys.disableBiometric(vaultID: parsed.header.vaultID)   // the VMK may differ from an old bio blob
        if recoveryKit != nil {
            try? deviceKeys.storeSecretKey(sk, vaultID: parsed.header.vaultID, generation: parsed.header.generation, headerSHA256: stored.headerSHA256, stateMAC: mac)
        } else {
            try? deviceKeys.updatePinnedState(vaultID: parsed.header.vaultID, generation: parsed.header.generation, headerSHA256: stored.headerSHA256, stateMAC: mac)
        }
        let newStore = try VaultStore.open(at: vaultURL)
        let s = try await VaultSession(store: newStore, keys: keys, header: parsed.header, stored: stored, warnings: [])
        await installStateMirror(s)
        store = newStore; session = s
        SecureLog.notice(.backup, "backup restored", .count(parsed.records.count))
        return s
    }

    // MARK: - Delete
    public func deleteVault(password: String) async throws {
        guard let session else { throw VaultError.vaultLocked }
        let header = await session.currentHeader, stored = await session.storedHeader
        let sk = try obtainSecretKey(vaultID: header.vaultID, expectedID: stored.skID, recoveryKit: nil)
        let (pw, vmk) = try await verifyPassword(password, secretKey: sk, header: header, stored: stored)
        pw.wipe(); vmk.wipe()
        await lock()
        try FileManager.default.removeItem(at: vaultURL)
        VaultStore.removeSideFiles(for: vaultURL)
        try? deviceKeys.disableBiometric(vaultID: header.vaultID)
        try? deviceKeys.deleteSecretKey(vaultID: header.vaultID)
        SecureLog.notice(.vault, "vault deleted")
    }
}
