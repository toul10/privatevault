import Testing
import Foundation
@testable import VaultCore

@Suite("Recovery Kit encoding, SecureBytes, password normalisation")
struct RecoveryKitAndSecureBytesTests {
    @Test func recovery_kit_roundtrip_format() throws {
        for _ in 0..<50 {
            let sk = SecretKey.generate()
            let s = RecoveryKit.encode(sk)
            #expect(s.hasPrefix("PV1-"))
            let groups = s.dropFirst(4).split(separator: "-")
            #expect(groups.count == 11); #expect(groups.allSatisfy { $0.count == 5 })
            #expect(try RecoveryKit.decode(s).bytes.constantTimeEquals(sk.bytes))
        }
    }
    @Test func recovery_kit_is_tolerant_to_case_spaces_and_lookalikes() throws {
        let sk = SecretKey.generate()
        let s = RecoveryKit.encode(sk)
        let sloppy = s.lowercased().replacingOccurrences(of: "-", with: " ").replacingOccurrences(of: "1", with: "l").replacingOccurrences(of: "0", with: "o")
        #expect(try RecoveryKit.decode(sloppy).bytes.constantTimeEquals(sk.bytes))
        #expect(try RecoveryKit.decode(String(s.dropFirst(4))).bytes.constantTimeEquals(sk.bytes)) // prefix optional
    }
    @Test func recovery_kit_rejects_typos_locally() throws {
        let s = RecoveryKit.encode(SecretKey.generate())
        var chars = Array(s)
        // mutate one data character to a different valid symbol
        let idx = 6
        chars[idx] = chars[idx] == "A" ? "B" : "A"
        #expect(throws: VaultError.recoveryKitInvalid("checksum mismatch")) { _ = try RecoveryKit.decode(String(chars)) }
        #expect(throws: VaultError.self) { _ = try RecoveryKit.decode(String(s.dropLast())) }
        #expect(throws: VaultError.self) { _ = try RecoveryKit.decode(s + "A") }
        #expect(throws: VaultError.self) { _ = try RecoveryKit.decode(s.replacingOccurrences(of: "PV1-", with: "PV1-U")) } // 'U' not in alphabet
        #expect(throws: VaultError.self) { _ = try RecoveryKit.decode("") }
    }
    @Test func recovery_kit_known_answer() throws {
        // SK = 0x00*32 → all-zero data symbols; checksum = first 15 bits of SHA256("privatevault-sk-v1" ‖ 0^32)
        let zero = try SecretKey(bytes: SecureBytes(copying: Data(count: 32)))
        let s = RecoveryKit.encode(zero)
        #expect(s.hasPrefix("PV1-00000-00000-00000-00000-00000-00000-00000-00000-00000-00000-00"))
        #expect(try RecoveryKit.decode(s).bytes.constantTimeEquals(zero.bytes))
    }
    @Test func secure_bytes_redaction_and_wipe() {
        let s = SecureBytes(copying: Data("supersecret".utf8))
        #expect(!"\(s)".contains("supersecret"))
        #expect(!String(reflecting: s).contains("supersecret"))
        #expect(Mirror(reflecting: s).children.isEmpty)
        s.wipe()
        #expect(s.copyData() == Data(count: 11))
    }
    @Test func secure_bytes_constant_time_equals() {
        let a = SecureBytes(copying: rep(1, 32)), b = SecureBytes(copying: rep(1, 32)), c = SecureBytes(copying: rep(2, 32))
        #expect(a.constantTimeEquals(b)); #expect(!a.constantTimeEquals(c)); #expect(!a.constantTimeEquals(SecureBytes(copying: rep(1, 31))))
    }
    @Test func password_normalisation_rules() throws {
        #expect(throws: VaultError.self) { _ = try PasswordNormalization.normalize("") }
        #expect(throws: VaultError.self) { _ = try PasswordNormalization.normalize(String(repeating: "a", count: 1025)) }
        #expect(try PasswordNormalization.normalize(" x ").copyData() == Data(" x ".utf8)) // no trimming
        #expect(PasswordNormalization.hasLeadingOrTrailingWhitespace(" x"))
        #expect(!PasswordNormalization.hasLeadingOrTrailingWhitespace("x y"))
        // compatibility characters are NOT folded (NFC, not NFKC): ligature "ﬁ" stays distinct from "fi"
        #expect(try PasswordNormalization.normalize("\u{FB01}").copyData() != Data("fi".utf8))
    }
}
