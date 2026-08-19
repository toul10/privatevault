import Foundation

/// All errors surfaced by VaultCore. Associated values are never secret.
public enum VaultError: Error, Equatable, Sendable {
    /// Wrong master password, wrong secret key, or tampered/corrupted header or ciphertext.
    /// Deliberately a single uniform case: the caller cannot distinguish the reasons.
    case authenticationFailed
    /// The header/backup failed structural validation before any cryptography ran.
    case invalidHeader(String)
    /// Data was written by a newer, unsupported format version.
    case unsupportedFormat(UInt8)
    /// Stored data is structurally corrupted (wrong lengths, bad JSON, failed integrity check).
    case corrupted(String)
    /// The Argon2 implementation reported an error (code is the argon2 error code).
    case kdfFailed(Int32)
    /// Keychain operation failed with the given OSStatus.
    case keychain(Int32)
    case keychainUnavailable
    case secureEnclaveUnavailable
    case secureEnclaveFailed(String)
    case biometryUnavailable
    case biometryInvalidated
    case userCancelled
    case storage(String)
    case backupInvalid(String)
    case recoveryKitInvalid(String)
    case vaultLocked
    case vaultAlreadyExists
    case vaultNotFound
    case invalidInput(String)
}
