import Foundation
import CryptoKit

/// HPKE (RFC 9180) base-mode wrapping to a P-256 recipient — used for Secure-Enclave-bound blobs
/// (SECURITY_ARCHITECTURE.md §8). One `HPKE.Sender` per seal (single-use context).
public struct HPKEWrappedBlob: Equatable, Sendable, Codable {
    public static let currentVersion: UInt8 = 1
    public var version: UInt8
    public var encapsulatedKey: Data   // 65 bytes (uncompressed P-256 point)
    public var ciphertext: Data
    public init(version: UInt8 = HPKEWrappedBlob.currentVersion, encapsulatedKey: Data, ciphertext: Data) {
        self.version = version; self.encapsulatedKey = encapsulatedKey; self.ciphertext = ciphertext
    }
}

public enum HPKEWrap {
    public static let ciphersuite = HPKE.Ciphersuite.P256_SHA256_AES_GCM_256
    public static let commitmentPrefix = Data(count: 32)

    public static func info(_ label: KDFLabel, vaultID: UUID) -> Data { label.bytes + vaultID.rawBytes }

    /// Seal `plaintext` (prefixed with 32 zero bytes for key commitment) to `recipient`.
    public static func seal(_ plaintext: SecureBytes, recipient: P256.KeyAgreement.PublicKey, info: Data, aad: Data) throws -> HPKEWrappedBlob {
        var sender = try HPKE.Sender(recipientKey: recipient, ciphersuite: ciphersuite, info: info)
        let ct = try plaintext.withUnsafeBytes { pt in
            try sender.seal(commitmentPrefix + Data(pt), authenticating: aad)
        }
        return HPKEWrappedBlob(encapsulatedKey: Data(sender.encapsulatedKey), ciphertext: Data(ct))
    }

    /// Open with any HPKE-capable private key (software P-256 in tests, Secure Enclave key in the app).
    public static func open<K: HPKEDiffieHellmanPrivateKey>(_ blob: HPKEWrappedBlob, privateKey: K, info: Data, aad: Data) throws -> SecureBytes
    where K.PublicKey == P256.KeyAgreement.PublicKey {
        guard blob.version == HPKEWrappedBlob.currentVersion, blob.encapsulatedKey.count == 65 else { throw VaultError.authenticationFailed }
        let opened: Data
        do {
            var recipient = try HPKE.Recipient(privateKey: privateKey, ciphersuite: ciphersuite, info: info, encapsulatedKey: blob.encapsulatedKey)
            opened = try recipient.open(blob.ciphertext, authenticating: aad)
        } catch { throw VaultError.authenticationFailed }
        guard opened.count > 32, opened.prefix(32) == commitmentPrefix else { throw VaultError.authenticationFailed }
        return SecureBytes(copying: opened.suffix(from: 32))
    }
}
