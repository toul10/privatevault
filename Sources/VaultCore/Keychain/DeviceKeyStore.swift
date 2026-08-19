import Foundation

/// Device-bound key material (SECURITY_ARCHITECTURE.md §8): the Secure-Enclave-wrapped Secret Key, the Touch ID
/// wrapped VMK, and the pinned vault generation. Built on a `SecretStore` and a `SecureEnclaveService`.
public final class DeviceKeyStore: Sendable {
    public struct SecretKeyRecord: Codable, Sendable, Equatable {
        public enum Mode: String, Codable, Sendable { case secureEnclave, raw }
        public var version: Int
        public var mode: Mode
        public var seKey: SEKeyHandle?
        public var blob: HPKEWrappedBlob?
        public var raw: Data?                 // only when no Secure Enclave exists (documented degradation)
        public var generation: UInt32         // last seen header generation (whole-file rollback detection)
        public var headerSHA256: Data
    }
    public struct BiometricRecord: Codable, Sendable, Equatable {
        public var version: Int
        public var seKey: SEKeyHandle
        public var blob: HPKEWrappedBlob
        public var generation: UInt32
    }

    public let store: SecretStore
    public let enclave: SecureEnclaveService
    public init(store: SecretStore, enclave: SecureEnclaveService) { self.store = store; self.enclave = enclave }

    static func skAccount(_ vaultID: UUID) -> String { "sk:\(vaultID.uuidString)" }
    static func bioAccount(_ vaultID: UUID) -> String { "bio:\(vaultID.uuidString)" }

    // MARK: Secret Key
    public var secretKeyIsHardwareBound: Bool { enclave.isAvailable }

    public func storeSecretKey(_ sk: SecretKey, vaultID: UUID, generation: UInt32, headerSHA256: Data) throws {
        let record: SecretKeyRecord
        if enclave.isAvailable {
            let key = try enclave.createKey(biometric: false)
            let blob = try enclave.seal(sk.bytes, to: key, info: HPKEWrap.info(.hpkeSecretKey, vaultID: vaultID), aad: Self.skAAD(vaultID))
            record = SecretKeyRecord(version: 1, mode: .secureEnclave, seKey: key, blob: blob, raw: nil, generation: generation, headerSHA256: headerSHA256)
        } else {
            record = SecretKeyRecord(version: 1, mode: .raw, seKey: nil, blob: nil, raw: sk.bytes.copyData(), generation: generation, headerSHA256: headerSHA256)
        }
        try store.write(Self.skAccount(vaultID), data: try JSONEncoder().encode(record))
        SecureLog.log(.keychain, "secret key stored", .category(record.mode.rawValue))
    }

    public enum SecretKeyLoad: Sendable {
        case absent
        case available(SecretKey, SecretKeyRecord)
        /// A record exists but cannot be opened on this Mac (new machine, SEP reset, migrated keychain).
        case unusable
    }
    public func loadSecretKey(vaultID: UUID) throws -> SecretKeyLoad {
        guard let data = try store.read(Self.skAccount(vaultID)) else { return .absent }
        guard let record = try? JSONDecoder().decode(SecretKeyRecord.self, from: data) else { return .unusable }
        switch record.mode {
        case .raw:
            guard let raw = record.raw, let sk = try? SecretKey(bytes: SecureBytes(copying: raw)) else { return .unusable }
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
    public func updatePinnedState(vaultID: UUID, generation: UInt32, headerSHA256: Data) throws {
        guard let data = try store.read(Self.skAccount(vaultID)), var record = try? JSONDecoder().decode(SecretKeyRecord.self, from: data) else { return }
        record.generation = generation; record.headerSHA256 = headerSHA256
        try store.write(Self.skAccount(vaultID), data: try JSONEncoder().encode(record))
    }
    public func deleteSecretKey(vaultID: UUID) throws { try store.delete(Self.skAccount(vaultID)) }
    /// The last header generation this device saw (no Secure Enclave access needed).
    public func pinnedGeneration(vaultID: UUID) -> UInt32? {
        guard let data = try? store.read(Self.skAccount(vaultID)), let record = try? JSONDecoder().decode(SecretKeyRecord.self, from: data) else { return nil }
        return record.generation
    }

    static func skAAD(_ vaultID: UUID) -> Data { Data([0x01]) + vaultID.rawBytes }

    // MARK: Touch ID
    static func bioAAD(_ vaultID: UUID, generation: UInt32) -> Data {
        var w = ByteWriter(); w.u8(0x02); w.raw(vaultID.rawBytes); w.u32be(generation); return w.data
    }
    public func isBiometricEnabled(vaultID: UUID) -> Bool { (try? store.read(Self.bioAccount(vaultID))) != nil }

    public func enableBiometric(vmk: SecureBytes, vaultID: UUID, generation: UInt32) throws {
        guard enclave.isAvailable else { throw VaultError.secureEnclaveUnavailable }
        let key = try enclave.createKey(biometric: true)
        let blob = try enclave.seal(vmk, to: key, info: HPKEWrap.info(.hpkeBiometric, vaultID: vaultID), aad: Self.bioAAD(vaultID, generation: generation))
        let record = BiometricRecord(version: 1, seKey: key, blob: blob, generation: generation)
        try store.write(Self.bioAccount(vaultID), data: try JSONEncoder().encode(record))
        SecureLog.log(.auth, "biometric unlock enabled")
    }
    /// Re-wrap under the existing biometric key after a header generation change (public-key op, no prompt).
    public func rewrapBiometric(vmk: SecureBytes, vaultID: UUID, generation: UInt32) throws {
        guard let data = try store.read(Self.bioAccount(vaultID)), let record = try? JSONDecoder().decode(BiometricRecord.self, from: data) else { return }
        let blob = try enclave.seal(vmk, to: record.seKey, info: HPKEWrap.info(.hpkeBiometric, vaultID: vaultID), aad: Self.bioAAD(vaultID, generation: generation))
        let updated = BiometricRecord(version: 1, seKey: record.seKey, blob: blob, generation: generation)
        try store.write(Self.bioAccount(vaultID), data: try JSONEncoder().encode(updated))
    }
    /// Prompts Touch ID (SEP-enforced) and returns the VMK. Throws `userCancelled`, `biometryUnavailable`,
    /// `biometryInvalidated` (fingerprints changed / stale blob) or `secureEnclaveUnavailable`.
    public func loadBiometricVMK(vaultID: UUID, expectedGeneration: UInt32, reason: String) throws -> SecureBytes {
        guard let data = try store.read(Self.bioAccount(vaultID)), let record = try? JSONDecoder().decode(BiometricRecord.self, from: data) else {
            throw VaultError.biometryUnavailable
        }
        guard record.generation == expectedGeneration else { throw VaultError.biometryInvalidated }
        do {
            return try enclave.open(record.blob, with: record.seKey, info: HPKEWrap.info(.hpkeBiometric, vaultID: vaultID), aad: Self.bioAAD(vaultID, generation: expectedGeneration), reason: reason)
        } catch VaultError.userCancelled { throw VaultError.userCancelled
        } catch VaultError.biometryUnavailable { throw VaultError.biometryUnavailable
        } catch { throw VaultError.biometryInvalidated }
    }
    public func disableBiometric(vaultID: UUID) throws {
        try store.delete(Self.bioAccount(vaultID))
        SecureLog.log(.auth, "biometric unlock disabled")
    }
}
