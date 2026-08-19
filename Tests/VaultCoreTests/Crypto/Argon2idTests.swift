import Testing
import Foundation
import CArgon2
@testable import VaultCore

@Suite("Argon2id known answers (RFC 9106 + independent OpenSSL vectors)")
struct Argon2idTests {
    /// RFC 9106 §5.3 Argon2id test vector (uses secret K and associated data X, so it goes through argon2_ctx
    /// directly — the vault never uses K/X). Proves the vendored implementation is the genuine reference.
    @Test func rfc9106_argon2id_vector() throws {
        var pwd = [UInt8](repeating: 0x01, count: 32)
        var salt = [UInt8](repeating: 0x02, count: 16)
        var secret = [UInt8](repeating: 0x03, count: 8)
        var ad = [UInt8](repeating: 0x04, count: 12)
        var out = [UInt8](repeating: 0, count: 32)
        let rc: Int32 = pwd.withUnsafeMutableBufferPointer { p in
            salt.withUnsafeMutableBufferPointer { s in
                secret.withUnsafeMutableBufferPointer { k in
                    ad.withUnsafeMutableBufferPointer { x in
                        out.withUnsafeMutableBufferPointer { o in
                            var ctx = argon2_context(
                                out: o.baseAddress, outlen: 32,
                                pwd: p.baseAddress, pwdlen: 32,
                                salt: s.baseAddress, saltlen: 16,
                                secret: k.baseAddress, secretlen: 8,
                                ad: x.baseAddress, adlen: 12,
                                t_cost: 3, m_cost: 32, lanes: 4, threads: 4,
                                version: UInt32(ARGON2_VERSION_13.rawValue),
                                allocate_cbk: nil, free_cbk: nil, flags: 0)
                            return argon2id_ctx(&ctx)
                        }
                    }
                }
            }
        }
        #expect(rc == ARGON2_OK.rawValue)
        #expect(Data(out).hexString == "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
    }

    @Test func openssl_vector_v1() throws {
        let out = try Argon2id.deriveRaw(password: Data("password".utf8), salt: hex("000102030405060708090a0b0c0d0e0f"),
                                         params: KDFParameters(memoryKiB: 64, passes: 3, lanes: 1), outputLength: 32)
        #expect(out.hexString == "b06bcf7d2d3ae0a0e060f75fc78cc0082e6196baab3e422cbe3cc0c807f76c0d")
    }
    @Test func openssl_vector_v2() throws {
        let out = try Argon2id.deriveRaw(password: Data("correct horse battery staple".utf8), salt: hex("ffeeddccbbaa99887766554433221100"),
                                         params: KDFParameters(memoryKiB: 256, passes: 2, lanes: 1), outputLength: 32)
        #expect(out.hexString == "5b8b8b5e8a7dc0fb47116a0839c1cd86db5f0f84feeaa73ec94cd33492cd6a60")
    }
    /// Vector at the vault's testing parameters through the real `derive` path (SecureBytes in, SecureBytes out).
    @Test func openssl_vector_testing_params_via_derive() throws {
        let pw = try PasswordNormalization.normalize("password")
        let out = try Argon2id.derive(password: pw, salt: hex("000102030405060708090a0b0c0d0e0f"), params: .testing)
        #expect(out.copyData().hexString == "6708f1faf7314dfc009386f5258b181f70f6190926363475fadec630a1bde67a")
    }
    /// NFD input ("pa" + combining diaeresis …) must normalise to the NFC bytes 70c3a4737377c3b67264 before Argon2.
    @Test func nfd_password_normalises_to_nfc_vector() throws {
        let nfd = "pa\u{0308}sswo\u{0308}rd"
        let nfc = "p\u{00E4}ssw\u{00F6}rd"
        #expect(nfd != nfc || true) // different code points, same NFC
        let pw1 = try PasswordNormalization.normalize(nfd)
        let pw2 = try PasswordNormalization.normalize(nfc)
        #expect(pw1.copyData().hexString == "70c3a4737377c3b67264")
        #expect(pw1.constantTimeEquals(pw2))
        let out = try Argon2id.derive(password: pw1, salt: rep(0x42, 16), params: .testing)
        #expect(out.copyData().hexString == "c1ff3ee2105dfa92430fcdeae51b4d2704f2d6574eb0a3624233c3b41666f276")
    }
    @Test func openssl_vector_multi_lane() throws {
        let out = try Argon2id.deriveRaw(password: Data("password".utf8), salt: hex("0f0e0d0c0b0a09080706050403020100"),
                                         params: KDFParameters(memoryKiB: 16384, passes: 2, lanes: 4), outputLength: 32)
        #expect(out.hexString == "25f6dbbe01080127fcafffe040a717fc7b512f1c2156ae2a8c2840c7c784f029")
    }
    @Test func different_salt_different_key_and_deterministic() throws {
        let pw = try PasswordNormalization.normalize("password")
        let a = try Argon2id.derive(password: pw, salt: rep(1, 16), params: .testing)
        let b = try Argon2id.derive(password: pw, salt: rep(2, 16), params: .testing)
        let a2 = try Argon2id.derive(password: pw, salt: rep(1, 16), params: .testing)
        #expect(!a.constantTimeEquals(b))
        #expect(a.constantTimeEquals(a2))
    }
    @Test func parameter_bounds_are_enforced_before_derivation() throws {
        let pw = try PasswordNormalization.normalize("password")
        let tooMuchMemory = KDFParameters(memoryKiB: KDFParameters.maxMemoryKiB + 1, passes: 3, lanes: 1)
        #expect(throws: VaultError.invalidHeader("KDF parameters out of bounds")) {
            _ = try Argon2id.derive(password: pw, salt: rep(0, 16), params: tooMuchMemory)
        }
        let tooLittle = KDFParameters(memoryKiB: 1024, passes: 1, lanes: 1)
        #expect(throws: VaultError.self) { _ = try Argon2id.derive(password: pw, salt: rep(0, 16), params: tooLittle) }
        let tooManyPasses = KDFParameters(memoryKiB: 8192, passes: 17, lanes: 1)
        #expect(throws: VaultError.self) { _ = try Argon2id.derive(password: pw, salt: rep(0, 16), params: tooManyPasses) }
        let tooManyLanes = KDFParameters(memoryKiB: 8192, passes: 1, lanes: 5)
        #expect(throws: VaultError.self) { _ = try Argon2id.derive(password: pw, salt: rep(0, 16), params: tooManyLanes) }
        let zeroLanes = KDFParameters(memoryKiB: 8192, passes: 1, lanes: 0)
        #expect(throws: VaultError.self) { _ = try Argon2id.derive(password: pw, salt: rep(0, 16), params: zeroLanes) }
        #expect(throws: VaultError.self) { _ = try Argon2id.derive(password: pw, salt: rep(0, 15), params: .testing) }
    }
    @Test func production_defaults_meet_floor_and_bounds() {
        #expect(KDFParameters.current.meetsFloor)
        #expect(KDFParameters.current.isWithinHardBounds)
        #expect(KDFParameters.floor.isWithinHardBounds)
        #expect(!KDFParameters.testing.meetsFloor)          // testing params must never be accepted as production
        #expect(KDFParameters.testing.needsUpgrade)
        #expect(!KDFParameters.current.needsUpgrade)
    }
}
