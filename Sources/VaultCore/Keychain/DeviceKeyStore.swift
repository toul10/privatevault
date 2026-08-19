import Foundation

/// Device-bound key material (SECURITY_ARCHITECTURE.md §8): the Secure-Enclave-wrapped Secret Key, the Touch ID
/// wrapped VMK, and the pinned vault state (generation, header checksum, last state MAC) used for rollback detection.
public final class DeviceKeyStore: Sendable {
    public struct SecretKeyRecord: Codable, Sendable, Equatable {
        public enum Mode: String, Codable, Sendable { case secureEnclave, raw }
        public var version: Int
        public var mode: Mode
        public var seKey: SEKeyHandle?
        public var blob: HPKEWrappedBlob?
        public var raw: Data?                 // only when no Secure Enclave exists (documented degradation)
        public var generation: UInt32         // last seen header generation
        public var headerSHA256: Data         // last seen header checksum
        public var stateMAC: Data?            // last seen record-state MAC (whole-file rollback detection)
    }
    public struct PinnedState: Sendable, Equatable {
        public var generation: UInt32
        public var headerSHA256: Data
        public var stateMAC: Data?
    }
    public struct BiometricRecord: Codable, Sendable, Equatable {
        public var version: Int
        public var seKey: SEKeyHandle
        public var blob: HPKEWrappedBlob
        public var headerSHA256: Data         // the header this blob is bound to (AAD)
    }

    public let store: SecretStore
    public let enclave: SecureEnclaveService
    public init(store: SecretStore, enclave: SecureEnclaveService) { self.store = store; self.enclave = enclave }

    static func skAccount(_ vaultID: UUID) -> String { "sk:\(vaultID.uuidString)" }
    static func pendingAccount(_ vaultID: UUID) -> String { "sk-pending:\(vaultID.uuidString)" }
    static func bioAccount(_ vaultID: UUID) -> String { "bio:\(vaultID.uuidString)" }

    // MARK: Secret Key
    /// True when the Secret Key at rest is Secure-Enclave-wrapped (false ⇒ raw in the Keychain, login-password protected).
    public var secretKeyIsHardwareBound: Bool { enclave.isAvailable }

    public func storeSecretKey(_ sk: SecretKey, vaultID: UUID, generation: UInt32, headerSHA256: Data, stateMAC: Data?, pending: Bool = false) throws {
        let record: SecretKeyRecord
        if enclave.isAvailable {
            let key = try enclave.createKey(biometric: false)
            let blob = try enclave.seal(sk.bytes, to: key, info: HPKEWrap.info(.hpkeSecretKey, vaultID: vaultID), aad: Self.skAAD(vaultID))
            record = SecretKeyRecord(version: 2, mode: .secureEnclave, seKey: key, blob: blob, raw: nil, generation: generation, headerSHA256: headerSHA256, stateMAC: stateMAC)
        } else {
            record = SecretKeyRecord(version: 2, mode: .raw, seKey: nil, blob: nil, raw: sk.bytes.copyData(), generation: generation, headerSHA256: headerSHA256, stateMAC: stateMAC)
        }
        try store.write(pending ? Self.pendingAccount(vaultID) : Self.skAccount(vaultID), data: try JSONEncoder().encode(record))
        SecureLog.log(.keychain, "secret key stored", .bool(record.mode == .secureEnclave), .bool(pending))
    }

    public enum SecretKeyLoad: Sendable {
        case absent
        case available(SecretKey, SecretKeyRecord)
        /// A record exists but cannot be opened on this Mac (new machine, SEP reset, migrated keychain).
        case unusable
    }
    public func loadSecretKey(vaultID: UUID, pending: Bool = false) throws -> SecretKeyLoad {
        let account = pending ? Self.pendingAccount(vaultID) : Self.skAccount(vaultID)
        guard let data = try store.read(account) else { return .absent }
        guard let record = try? JSONDecoder().decode(SecretKeyRecord.self, from: data) else { return .unusable }
        switch record.mode {
        case .raw:
            guard var raw = record.raw else { return .unusable }
            defer { raw.wipe() }
            guard let sk = try? SecretKey(bytes: SecureBytes(copying: raw)) else { return .unusable }
            return .available(sk, record)
        case .secureEnclave:
            guard let key = record.seKey, let blob = record.blob else { return .unusable }
            do {
                let bytes = try enclave.open(blob, with: key, info: HPKEWrap.info(.hpkeSecretKey, vaultID: vaultID), aad: Self.skAAD(vaultID), reason: "Unlock your PrivateVault Secret Key")
                return .available(try SecretKey(bytes: bytes), record)
            } catch VaultError.userCancelled {
                throw VaultError.userCancelled
            } catch {
                SecureLog.error(.keychain, "secret key unusable on this device", error: error)
                return .unusable
            }
        }
    }
    /// Moves the pending record (written before a Secret-Key regeneration) into place.
    public func promotePendingSecretKey(vaultID: UUID) throws {
        guard let data = try store.read(Self.pendingAccount(vaultID)) else { return }
        try store.write(Self.skAccount(vaultID), data: data)
        try store.delete(Self.pendingAccount(vaultID))
    }
    public func deletePendingSecretKey(vaultID: UUID) throws { try store.delete(Self.pendingAccount(vaultID)) }

    public func pinnedState(vaultID: UUID) -> PinnedState? {
        guard let data = try? store.read(Self.skAccount(vaultID)), let r = try? JSONDecoder().decode(SecretKeyRecord.self, from: data) else { return nil }
        return PinnedState(generation: r.generation, headerSHA256: r.headerSHA256, stateMAC: r.stateMAC)
    }
    public func updatePinnedState(vaultID: UUID, generation: UInt32, headerSHA256: Data, stateMAC: Data?) throws {
        guard let data = try store.read(Self.skAccount(vaultID)), var record = try? JSONDecoder().decode(SecretKeyRecord.self, from: data) else { return }
        record.generation = generation; record.headerSHA256 = headerSHA256; record.stateMAC = stateMAC
        try store.write(Self.skAccount(vaultID), data: try JSONEncoder().encode(record))
    }
    public func deleteSecretKey(vaultID: UUID) throws {
        try store.delete(Self.skAccount(vaultID))
        try? store.delete(Self.pendingAccount(vaultID))
    }

    static func skAAD(_ vaultID: UUID) -> Data { Data([0x01]) + vaultID.rawBytes }

    // MARK: Touch ID
    /// The bio blob is bound to the exact header it was created under (checksum covers canonical bytes + wrapped VMK).
    static func bioAAD(_ vaultID: UUID, headerSHA256: Data) -> Data {
        var w = ByteWriter(); w.u8(0x02); w.raw(vaultID.rawBytes); w.raw(headerSHA256); return w.data
    }
    public func isBiometricEnabled(vaultID: UUID) -> Bool { (try? store.read(Self.bioAccount(vaultID))) != nil }

    /// Creates a FRESH biometric Secure-Enclave key and wraps the VMK to it. Used for enabling and for every re-wrap
    /// (never re-wrap to a public key read back from the store: it could have been substituted).
    public func enableBiometric(vmk: SecureBytes, vaultID: UUID, headerSHA256: Data) throws {
        guard enclave.isAvailable else { throw VaultError.secureEnclaveUnavailable }
        let key = try enclave.createKey(biometric: true)
        let blob = try enclave.seal(vmk, to: key, info: HPKEWrap.info(.hpkeBiometric, vaultID: vaultID), aad: Self.bioAAD(vaultID, headerSHA256: headerSHA256))
        let record = BiometricRecord(version: 2, seKey: key, blob: blob, headerSHA256: headerSHA256)
        try store.write(Self.bioAccount(vaultID), data: try JSONEncoder().encode(record))
        SecureLog.log(.auth, "biometric unlock enabled")
    }
    /// After a header change: re-enrol under a fresh key if Touch ID is enabled; if that is impossible, disable it
    /// (the user can re-enable) rather than leaving a stale blob.
    public func rewrapBiometric(vmk: SecureBytes, vaultID: UUID, headerSHA256: Data) {
        guard isBiometricEnabled(vaultID: vaultID) else { return }
        do { try enableBiometric(vmk: vmk, vaultID: vaultID, headerSHA256: headerSHA256) }
        catch {
            SecureLog.error(.auth, "biometric re-wrap failed; disabling", error: error)
            try? disableBiometric(vaultID: vaultID)
        }
    }
    /// Prompts Touch ID (SEP-enforced) and returns the VMK. Throws `userCancelled`, `biometryUnavailable`,
    /// `biometryInvalidated` (fingerprints changed / stale blob / header changed) or `secureEnclaveUnavailable`.
    public func loadBiometricVMK(vaultID: UUID, headerSHA256: Data, reason: String) throws -> SecureBytes {
        guard let data = try store.read(Self.bioAccount(vaultID)), let record = try? JSONDecoder().decode(BiometricRecord.self, from: data) else {
            throw VaultError.biometryUnavailable
        }
        guard record.headerSHA256 == headerSHA256 else { throw VaultError.biometryInvalidated }
        do {
            return try enclave.open(record.blob, with: record.seKey, info: HPKEWrap.info(.hpkeBiometric, vaultID: vaultID), aad: Self.bioAAD(vaultID, headerSHA256: headerSHA256), reason: reason)
        } catch VaultError.userCancelled { throw VaultError.userCancelled
        } catch VaultError.biometryUnavailable { throw VaultError.biometryUnavailable
        } catch VaultError.secureEnclaveUnavailable { throw VaultError.secureEnclaveUnavailable
        } catch { throw VaultError.biometryInvalidated }
    }
    public func disableBiometric(vaultID: UUID) throws {
        try store.delete(Self.bioAccount(vaultID))
        SecureLog.log(.auth, "biometric unlock disabled")
    }
}
