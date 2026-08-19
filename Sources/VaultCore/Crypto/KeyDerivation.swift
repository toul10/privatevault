import Foundation
import CryptoKit

/// All HKDF labels in one place. Labels are versioned and never reused with different semantics.
public enum KDFLabel: String, Sendable {
    case secretKey        = "privatevault/v1/secret-key"
    case skID             = "privatevault/v1/sk-id"
    case kek              = "privatevault/v1/kek/a256gcm"
    case recordEncryption = "privatevault/v1/record-encryption"
    case recordPrefix     = "privatevault/v1/record/"        // + recordID raw bytes
    case tier2            = "privatevault/v1/tier2"
    case vaultState       = "privatevault/v1/vault-state"
    case backupManifest   = "privatevault/v1/backup-manifest"
    // reserved for future use (declared so they are never accidentally reused for something else)
    case metadata         = "privatevault/v1/metadata"
    case searchIndex      = "privatevault/v1/search-index"
    case syncAuth         = "privatevault/v1/sync-auth"
    // HPKE info strings
    case hpkeSecretKey    = "privatevault/v1/hpke/se-wrap-sk"  // + vaultID
    case hpkeBiometric    = "privatevault/v1/hpke/bio-wrap-vmk" // + vaultID

    public var bytes: Data { Data(rawValue.utf8) }
}

public enum KeyDerivation {
    /// HKDF-SHA256 with the vault ID as salt. Output 32 bytes.
    public static func hkdf(ikm: SecureBytes, vaultID: UUID, label: KDFLabel, suffix: Data = Data()) -> SymmetricKey {
        ikm.withUnsafeBytes { raw in
            HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: raw),
                                   salt: vaultID.rawBytes,
                                   info: label.bytes + suffix,
                                   outputByteCount: 32)
        }
    }
    public static func hkdf(ikm: SymmetricKey, vaultID: UUID, label: KDFLabel, suffix: Data = Data()) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: ikm, salt: vaultID.rawBytes, info: label.bytes + suffix, outputByteCount: 32)
    }
}
