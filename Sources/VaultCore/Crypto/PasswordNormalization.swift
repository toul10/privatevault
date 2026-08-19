import Foundation

/// Master-password normalisation (SECURITY_ARCHITECTURE.md §2.2): Unicode NFC, UTF-8, no trimming.
public enum PasswordNormalization {
    /// Identifier stored in the header so the rule can evolve without locking users out.
    public static let currentID: UInt8 = 1 // 1 = NFC
    public static let maxBytes = 1024

    public static func normalize(_ password: String, normalizationID: UInt8 = currentID) throws -> SecureBytes {
        guard normalizationID == 1 else { throw VaultError.invalidHeader("unknown password normalization") }
        guard !password.isEmpty else { throw VaultError.invalidInput("empty password") }
        let nfc = password.precomposedStringWithCanonicalMapping
        guard nfc.utf8.count <= maxBytes else { throw VaultError.invalidInput("password too long") }
        return SecureBytes(utf8: nfc)
    }
    public static func hasLeadingOrTrailingWhitespace(_ password: String) -> Bool {
        password != password.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
