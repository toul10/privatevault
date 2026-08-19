import Foundation
import CryptoKit

/// Human-transcribable encoding of the Secret Key (SECURITY_ARCHITECTURE.md §2.4):
/// `PV1-` + 11 groups of 5 Crockford-Base32 characters = 52 data chars (260 bits, top 4 bits zero) + 3 check chars (15 bits).
public enum RecoveryKit {
    public static let prefix = "PV1-"
    static let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    static let dataChars = 52
    static let checkChars = 3
    static let checkDomain = Data("privatevault-sk-v1".utf8)

    public static func encode(_ sk: SecretKey) -> String {
        let bytes = sk.bytes.copyData()
        defer { /* bytes is a Data copy; cannot wipe reliably */ }
        // 256 bits → 52 symbols of 5 bits (260 bits): left-pad with 4 zero bits.
        var bits: [UInt8] = [0, 0, 0, 0]
        for b in bytes { for i in (0..<8).reversed() { bits.append((b >> UInt8(i)) & 1) } }
        var symbols: [Character] = []
        for i in stride(from: 0, to: bits.count, by: 5) {
            var v = 0
            for j in 0..<5 { v = v << 1 | Int(bits[i + j]) }
            symbols.append(alphabet[v])
        }
        let check = checksum(bytes)
        symbols.append(contentsOf: check)
        // group 5
        var groups: [String] = []
        for i in stride(from: 0, to: symbols.count, by: 5) { groups.append(String(symbols[i..<min(i + 5, symbols.count)])) }
        return prefix + groups.joined(separator: "-")
    }

    /// Parses user input (case-insensitive, tolerant of spaces/hyphens/I/L/O). Verifies checksum locally.
    public static func decode(_ input: String) throws -> SecretKey {
        var s = input.uppercased().replacingOccurrences(of: " ", with: "").replacingOccurrences(of: "-", with: "")
        s = String(s.map { c -> Character in
            switch c { case "I", "L": return "1"; case "O": return "0"; default: return c }
        })
        if s.hasPrefix("PV1") { s.removeFirst(3) }
        guard s.count == dataChars + checkChars else { throw VaultError.recoveryKitInvalid("wrong length") }
        var values: [Int] = []
        for c in s {
            guard let idx = alphabet.firstIndex(of: c) else { throw VaultError.recoveryKitInvalid("invalid character") }
            values.append(idx)
        }
        let dataValues = values.prefix(dataChars)
        var bits: [UInt8] = []
        for v in dataValues { for i in (0..<5).reversed() { bits.append(UInt8((v >> i) & 1)) } }
        guard bits.prefix(4).allSatisfy({ $0 == 0 }) else { throw VaultError.recoveryKitInvalid("invalid character") }
        var bytes = Data(capacity: 32)
        for i in stride(from: 4, to: bits.count, by: 8) {
            var b: UInt8 = 0
            for j in 0..<8 { b = b << 1 | bits[i + j] }
            bytes.append(b)
        }
        let expected = checksum(bytes)
        let given = Array(s.suffix(checkChars))
        guard expected == given else { throw VaultError.recoveryKitInvalid("checksum mismatch") }
        return try SecretKey(bytes: SecureBytes(copying: bytes))
    }

    /// 15 bits of SHA-256(domain ‖ sk) as 3 symbols.
    static func checksum(_ sk: Data) -> [Character] {
        let h = Data(SHA256.hash(data: checkDomain + sk))
        let v = Int(h[0]) << 7 | Int(h[1]) >> 1 // 15 bits
        return [alphabet[(v >> 10) & 31], alphabet[(v >> 5) & 31], alphabet[v & 31]]
    }
}
