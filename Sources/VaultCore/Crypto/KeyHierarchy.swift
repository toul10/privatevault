import Foundation
import CryptoKit

/// The Secret Key (256 bit, random, independent of the password). See SECURITY_ARCHITECTURE.md §2.4.
public struct SecretKey: Sendable {
    public static let byteCount = 32
    public let bytes: SecureBytes
    public init(bytes: SecureBytes) throws {
        guard bytes.count == Self.byteCount else { throw VaultError.invalidInput("secret key length") }
        self.bytes = bytes
    }
    public static func generate() -> SecretKey { try! SecretKey(bytes: SecureRandom.secureBytes(byteCount)) }
    /// Non-secret 4-byte identifier printed on the Recovery Kit and stored in the header.
    public func identifier(vaultID: UUID) -> Data {
        let k = KeyDerivation.hkdf(ikm: bytes, vaultID: vaultID, label: .skID)
        return k.withUnsafeBytes { Data($0.prefix(4)) }
    }
}

/// All keys that exist only while the vault is unlocked, derived from the VMK with domain separation.
public final class VaultKeys: @unchecked Sendable {
    public let vaultID: UUID
    public let vmk: SecureBytes
    public let recordRootKey: SymmetricKey
    public let tier2Key: SymmetricKey
    public let vaultStateKey: SymmetricKey
    public let backupManifestKey: SymmetricKey

    public init(vaultID: UUID, vmk: SecureBytes) throws {
        guard vmk.count == 32 else { throw VaultError.invalidInput("vmk length") }
        self.vaultID = vaultID
        self.vmk = vmk
        recordRootKey = KeyDerivation.hkdf(ikm: vmk, vaultID: vaultID, label: .recordEncryption)
        tier2Key = KeyDerivation.hkdf(ikm: vmk, vaultID: vaultID, label: .tier2)
        vaultStateKey = KeyDerivation.hkdf(ikm: vmk, vaultID: vaultID, label: .vaultState)
        backupManifestKey = KeyDerivation.hkdf(ikm: vmk, vaultID: vaultID, label: .backupManifest)
    }
    /// Per-record key (§4.2).
    public func recordKey(for recordID: UUID) -> SymmetricKey {
        KeyDerivation.hkdf(ikm: recordRootKey, vaultID: vaultID, label: .recordPrefix, suffix: recordID.rawBytes)
    }
    /// Wipe the VMK bytes (SymmetricKeys are wiped by CryptoKit when released).
    public func wipe() { vmk.wipe() }
}

/// The MP + SK → KEK → VMK construction (SECURITY_ARCHITECTURE.md §2, §3.2).
public enum KeyHierarchy {
    public static let commitmentPrefixLength = 32
    public static let wrappedVMKLength = 12 + 64 + 16

    /// KEK = HKDF(MPK ‖ SKK). `password` is already normalised bytes. Runs Argon2id (slow, memory-hard).
    public static func deriveKEK(password: SecureBytes, secretKey: SecretKey, header: VaultHeader) throws -> SymmetricKey {
        let mpk = try Argon2id.derive(password: password, salt: header.salt, params: header.kdf)
        defer { mpk.wipe() }
        let skk = KeyDerivation.hkdf(ikm: secretKey.bytes, vaultID: header.vaultID, label: .secretKey)
        let ikm = SecureBytes(count: 64)
        defer { ikm.wipe() }
        ikm.withUnsafeMutableBytes { dst in
            mpk.withUnsafeBytes { dst.copyMemory(from: $0) }
            skk.withUnsafeBytes { src in
                UnsafeMutableRawBufferPointer(rebasing: dst[32..<64]).copyMemory(from: src)
            }
        }
        return KeyDerivation.hkdf(ikm: ikm, vaultID: header.vaultID, label: .kek)
    }

    /// wrapped = nonce ‖ AES-256-GCM(KEK, 0x00×32 ‖ VMK, aad = canonical header) ‖ tag
    public static func wrapVMK(_ vmk: SecureBytes, kek: SymmetricKey, header: VaultHeader) throws -> Data {
        guard vmk.count == 32 else { throw VaultError.invalidInput("vmk length") }
        let plaintext = SecureBytes(count: 64)
        defer { plaintext.wipe() }
        plaintext.withUnsafeMutableBytes { dst in
            vmk.withUnsafeBytes { src in UnsafeMutableRawBufferPointer(rebasing: dst[32..<64]).copyMemory(from: src) }
        }
        let box = try plaintext.withUnsafeBytes { pt in
            try AES.GCM.seal(pt, using: kek, nonce: AES.GCM.Nonce(), authenticating: header.canonicalBytes)
        }
        guard let combined = box.combined, combined.count == wrappedVMKLength else { throw VaultError.corrupted("wrap") }
        return combined
    }

    /// Inverse of `wrapVMK`. Any failure (wrong KEK, tampered header or ciphertext, bad commitment) is the
    /// single uniform `authenticationFailed`.
    public static func unwrapVMK(_ wrapped: Data, kek: SymmetricKey, header: VaultHeader) throws -> SecureBytes {
        guard wrapped.count == wrappedVMKLength else { throw VaultError.authenticationFailed }
        let box: AES.GCM.SealedBox
        do { box = try AES.GCM.SealedBox(combined: wrapped) } catch { throw VaultError.authenticationFailed }
        var opened: Data
        do { opened = try AES.GCM.open(box, using: kek, authenticating: header.canonicalBytes) }
        catch { throw VaultError.authenticationFailed }
        defer { opened.wipe() }
        guard opened.count == 64, opened.prefix(32).allSatisfy({ $0 == 0 }) else { throw VaultError.authenticationFailed }
        return SecureBytes(copying: opened.suffix(32))
    }

    public static func generateVMK() -> SecureBytes { SecureRandom.secureBytes(32) }
}
