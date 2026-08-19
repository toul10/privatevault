import Foundation
import Security

/// Cryptographically secure randomness from the operating system.
public enum SecureRandom {
    public static func bytes(_ count: Int) -> Data {
        precondition(count >= 0)
        var d = Data(count: count)
        if count == 0 { return d }
        let status = d.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        // SecRandomCopyBytes cannot realistically fail on macOS; if it does we must not continue with weak randomness.
        precondition(status == errSecSuccess, "OS CSPRNG unavailable")
        return d
    }
    public static func secureBytes(_ count: Int) -> SecureBytes {
        let s = SecureBytes(count: count)
        s.withUnsafeMutableBytes { buf in
            let st = SecRandomCopyBytes(kSecRandomDefault, count, buf.baseAddress!)
            precondition(st == errSecSuccess, "OS CSPRNG unavailable")
        }
        return s
    }
    public static func uuid() -> UUID { UUID() } // Foundation's UUID() uses the OS CSPRNG (uuid_generate_random).
    /// Uniform integer in 0..<upperBound using rejection sampling (no modulo bias).
    public static func uniform(_ upperBound: UInt32) -> UInt32 {
        precondition(upperBound > 0)
        var g = SystemRandomNumberGenerator() // CSPRNG on Apple platforms
        return UInt32.random(in: 0..<upperBound, using: &g)
    }
}
