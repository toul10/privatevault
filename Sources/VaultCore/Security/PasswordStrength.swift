import Foundation

/// Local, offline password strength estimate (no network, no dictionaries beyond a tiny built-in blocklist).
/// Used for the generator display and the master-password policy. It is an estimate, not a guarantee.
public struct PasswordStrength: Sendable, Equatable {
    public enum Rating: String, Sendable { case veryWeak, weak, fair, strong, veryStrong }
    public let entropyBits: Double
    public let rating: Rating
    public let warnings: [String]

    static let commonPasswords: Set<String> = ["password", "123456", "12345678", "qwerty", "letmein", "iloveyou", "admin", "welcome",
        "monkey", "dragon", "master", "sunshine", "princess", "football", "baseball", "passw0rd", "password1", "123456789", "abc123", "111111"]

    public static func estimate(_ password: String) -> PasswordStrength {
        let chars = Array(password)
        guard !chars.isEmpty else { return PasswordStrength(entropyBits: 0, rating: .veryWeak, warnings: ["Empty"]) }
        var pool = 0
        if chars.contains(where: { $0.isLowercase }) { pool += 26 }
        if chars.contains(where: { $0.isUppercase }) { pool += 26 }
        if chars.contains(where: { $0.isNumber }) { pool += 10 }
        if chars.contains(where: { !$0.isLetter && !$0.isNumber && !$0.isWhitespace }) { pool += 33 }
        if chars.contains(where: { $0.isWhitespace }) { pool += 1 }
        if chars.contains(where: { !$0.isASCII }) { pool += 100 }
        var bits = Double(chars.count) * log2(Double(max(pool, 2)))
        var warnings: [String] = []
        let lower = password.lowercased()
        let perChar = log2(Double(max(pool, 2)))
        if commonPasswords.contains(lower) { bits = min(bits, 8); warnings.append("This is one of the most common passwords") }
        else if let common = commonPasswords.first(where: { $0.count >= 6 && lower.contains($0) }) {
            bits -= Double(common.count) * perChar - 10; warnings.append("Contains a very common password")
        }
        // pure repetition of a short pattern ("abcabcabc") is worth little more than the pattern
        if let unit = repeatedUnit(chars), unit.count < chars.count {
            let reps = chars.count / unit.count
            bits = min(bits, Double(unit.count) * perChar + log2(Double(reps)) + 2)
            warnings.append("Repeated pattern")
        }
        // repeated characters / sequences reduce effective entropy
        let unique = Set(chars).count
        if unique <= max(2, chars.count / 4) { bits *= 0.5; warnings.append("Too many repeated characters") }
        if isSequential(chars) { bits *= 0.6; warnings.append("Sequential characters are easy to guess") }
        if chars.count < 12 { warnings.append("Use at least 12 characters") }
        let rating: Rating
        switch bits {
        case ..<28: rating = .veryWeak
        case ..<40: rating = .weak
        case ..<60: rating = .fair
        case ..<90: rating = .strong
        default: rating = .veryStrong
        }
        return PasswordStrength(entropyBits: bits, rating: rating, warnings: warnings)
    }
    private static func repeatedUnit(_ chars: [Character]) -> [Character]? {
        guard chars.count >= 4 else { return nil }
        for len in 1...(chars.count / 2) where chars.count % len == 0 {
            let unit = Array(chars[0..<len])
            if stride(from: 0, to: chars.count, by: len).allSatisfy({ Array(chars[$0..<$0+len]) == unit }) { return unit }
        }
        return nil
    }
    private static func isSequential(_ chars: [Character]) -> Bool {
        guard chars.count >= 4 else { return false }
        let scalars = chars.compactMap { $0.unicodeScalars.first?.value }
        guard scalars.count == chars.count else { return false }
        var run = 1, best = 1
        for i in 1..<scalars.count {
            if scalars[i] == scalars[i-1] + 1 || scalars[i] == scalars[i-1] - 1 { run += 1; best = max(best, run) } else { run = 1 }
        }
        return best >= 4
    }
}

/// Master-password policy for NEW vaults (SECURITY_ARCHITECTURE.md §2.2).
public enum MasterPasswordPolicy {
    public static let minimumLength = 12
    public static let minimumEntropyBits = 50.0
    public static func validate(_ password: String) throws {
        guard password.count >= minimumLength else { throw VaultError.invalidInput("Master Password must be at least \(minimumLength) characters") }
        let s = PasswordStrength.estimate(password)
        guard s.entropyBits >= minimumEntropyBits else { throw VaultError.invalidInput("Master Password is too weak (estimated \(Int(s.entropyBits)) bits, need \(Int(minimumEntropyBits)))") }
    }
}
