import Foundation

/// CSPRNG password generator with rejection sampling (no modulo bias). Nothing leaves the process.
public struct PasswordGenerator: Sendable {
    public struct Options: Sendable, Equatable {
        public var length: Int
        public var uppercase: Bool
        public var lowercase: Bool
        public var digits: Bool
        public var symbols: Bool
        public var excludeAmbiguous: Bool
        public init(length: Int = 20, uppercase: Bool = true, lowercase: Bool = true, digits: Bool = true, symbols: Bool = true, excludeAmbiguous: Bool = false) {
            self.length = length; self.uppercase = uppercase; self.lowercase = lowercase; self.digits = digits; self.symbols = symbols; self.excludeAmbiguous = excludeAmbiguous
        }
    }
    public static let minLength = 8
    public static let maxLength = 128
    static let upper = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    static let lower = Array("abcdefghijklmnopqrstuvwxyz")
    static let digitChars = Array("0123456789")
    static let symbolChars = Array("!@#$%^&*()-_=+[]{};:,.<>?/~")
    static let ambiguous: Set<Character> = ["0", "O", "o", "1", "l", "I", "|", "`", "'", "\""]

    public static func classes(for o: Options) -> [[Character]] {
        var c: [[Character]] = []
        if o.uppercase { c.append(upper) }
        if o.lowercase { c.append(lower) }
        if o.digits { c.append(digitChars) }
        if o.symbols { c.append(symbolChars) }
        if o.excludeAmbiguous { c = c.map { $0.filter { !ambiguous.contains($0) } } }
        return c.filter { !$0.isEmpty }
    }

    /// Generates a password containing at least one character of every selected class.
    public static func generate(_ o: Options) throws -> String {
        let length = max(minLength, min(maxLength, o.length))
        let classes = classes(for: o)
        guard !classes.isEmpty else { throw VaultError.invalidInput("select at least one character class") }
        let pool = classes.flatMap { $0 }
        var out: [Character] = []
        // one from each class, then fill, then shuffle (Fisher–Yates with CSPRNG)
        for c in classes { out.append(c[Int(SecureRandom.uniform(UInt32(c.count)))]) }
        while out.count < length { out.append(pool[Int(SecureRandom.uniform(UInt32(pool.count)))]) }
        if out.count > 1 {
            for i in stride(from: out.count - 1, to: 0, by: -1) {
                let j = Int(SecureRandom.uniform(UInt32(i + 1)))
                out.swapAt(i, j)
            }
        }
        return String(out)
    }
    /// log2(pool^length) for the given options (upper bound on entropy of a generated password).
    public static func entropyBits(_ o: Options) -> Double {
        let pool = classes(for: o).reduce(0) { $0 + $1.count }
        guard pool > 1 else { return 0 }
        return Double(max(minLength, min(maxLength, o.length))) * log2(Double(pool))
    }
}
