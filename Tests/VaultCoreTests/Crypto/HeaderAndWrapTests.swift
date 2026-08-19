import Testing
import Foundation
import CryptoKit
@testable import VaultCore

@Suite("Vault header canonical encoding, VMK wrap/unwrap, unlock semantics")
struct HeaderAndWrapTests {
    @Test func canonical_header_golden_bytes() throws {
        let h = VaultHeader.fixture
        let expected = "50564c54" /*PVLT*/ + "01" + "0123456789abcdef0123456789abcdef" + "01" /*argon2id*/
            + "00002000" /*m=8192*/ + "00000001" /*t*/ + "01" /*p*/ + "10" /*salt len*/ + "000102030405060708090a0b0c0d0e0f"
            + "01" /*NFC*/ + "01" /*AES-GCM*/ + "00000001" /*generation*/ + "000000006553f100" /*1700000000*/
        #expect(h.canonicalBytes.hexString == expected)
        #expect(try VaultHeader.parse(canonical: h.canonicalBytes) == h)
    }
    @Test func parse_rejects_untrusted_input_before_kdf() {
        let h = VaultHeader.fixture
        var bad = h; bad.format = 2
        #expect(throws: VaultError.unsupportedFormat(2)) { _ = try VaultHeader.parse(canonical: bad.canonicalBytes) }
        var huge = h; huge.kdf = KDFParameters(memoryKiB: 8 * 1024 * 1024, passes: 3, lanes: 1) // 8 GiB
        #expect(throws: VaultError.invalidHeader("KDF parameters out of bounds")) { _ = try VaultHeader.parse(canonical: huge.canonicalBytes) }
        var hang = h; hang.kdf = KDFParameters(memoryKiB: 65536, passes: 1_000_000, lanes: 1)
        #expect(throws: VaultError.self) { _ = try VaultHeader.parse(canonical: hang.canonicalBytes) }
        var kdf = h; kdf.kdfID = 7
        #expect(throws: VaultError.self) { _ = try VaultHeader.parse(canonical: kdf.canonicalBytes) }
        var norm = h; norm.passwordNormalization = 2
        #expect(throws: VaultError.self) { _ = try VaultHeader.parse(canonical: norm.canonicalBytes) }
        var salt = h; salt.salt = rep(0, 8)
        #expect(throws: VaultError.self) { _ = try VaultHeader.parse(canonical: salt.canonicalBytes) }
        #expect(throws: VaultError.self) { _ = try VaultHeader.parse(canonical: h.canonicalBytes.dropLast()) }
        #expect(throws: VaultError.self) { _ = try VaultHeader.parse(canonical: h.canonicalBytes + [0]) }
        #expect(throws: VaultError.self) { _ = try VaultHeader.parse(canonical: Data("XXXX".utf8) + h.canonicalBytes.dropFirst(4)) }
        #expect(throws: VaultError.self) { _ = try VaultHeader.parse(canonical: Data()) }
    }

    @Test func wrap_unwrap_roundtrip_and_commitment() throws {
        let header = VaultHeader.fixture
        let pw = try PasswordNormalization.normalize("correct horse battery staple")
        let kek = try KeyHierarchy.deriveKEK(password: pw, secretKey: .test(), header: header)
        let vmk = KeyHierarchy.generateVMK()
        let wrapped = try KeyHierarchy.wrapVMK(vmk, kek: kek, header: header)
        #expect(wrapped.count == 92)
        let unwrapped = try KeyHierarchy.unwrapVMK(wrapped, kek: kek, header: header)
        #expect(unwrapped.constantTimeEquals(vmk))
        // two wraps of the same VMK differ (fresh nonce)
        #expect(try KeyHierarchy.wrapVMK(vmk, kek: kek, header: header) != wrapped)
    }
    @Test func wrong_password_wrong_secret_key_and_tampering_all_fail_uniformly() throws {
        let header = VaultHeader.fixture
        let pw = try PasswordNormalization.normalize("correct horse battery staple")
        let kek = try KeyHierarchy.deriveKEK(password: pw, secretKey: .test(0x11), header: header)
        let vmk = KeyHierarchy.generateVMK()
        let wrapped = try KeyHierarchy.wrapVMK(vmk, kek: kek, header: header)

        let wrongPW = try KeyHierarchy.deriveKEK(password: PasswordNormalization.normalize("correct horse battery staple "), secretKey: .test(0x11), header: header)
        #expect(throws: VaultError.authenticationFailed) { _ = try KeyHierarchy.unwrapVMK(wrapped, kek: wrongPW, header: header) }
        let wrongSK = try KeyHierarchy.deriveKEK(password: pw, secretKey: .test(0x12), header: header)
        #expect(throws: VaultError.authenticationFailed) { _ = try KeyHierarchy.unwrapVMK(wrapped, kek: wrongSK, header: header) }
        // header tampering: KDF downgrade, salt, vault id, generation
        var downgraded = header; downgraded.kdf = KDFParameters(memoryKiB: 8192, passes: 1, lanes: 1); downgraded.salt = header.salt
        #expect(downgraded == header) // fixture already uses the smallest params; build a genuinely different header instead
        downgraded.kdf = KDFParameters(memoryKiB: 16384, passes: 1, lanes: 1)
        var salt = header; salt.salt = rep(9, 16)
        var vid = header; vid.vaultID = UUID()
        var gen = header; gen.generation = 2
        for h in [downgraded, salt, vid, gen] {
            #expect(throws: VaultError.authenticationFailed) { _ = try KeyHierarchy.unwrapVMK(wrapped, kek: kek, header: h) }
        }
        // ciphertext tampering
        for i in [0, 12, 50, 91] {
            var t = wrapped; t[i] ^= 1
            #expect(throws: VaultError.authenticationFailed) { _ = try KeyHierarchy.unwrapVMK(t, kek: kek, header: header) }
        }
        #expect(throws: VaultError.authenticationFailed) { _ = try KeyHierarchy.unwrapVMK(wrapped.dropLast(), kek: kek, header: header) }
    }
    @Test func header_sha256_changes_with_any_field() throws {
        let h = VaultHeader.fixture
        let w = Data(repeating: 1, count: 92)
        let a = VaultHeader.sha256(canonical: h.canonicalBytes, wrappedVMK: w)
        var g = h; g.generation = 2
        #expect(VaultHeader.sha256(canonical: g.canonicalBytes, wrappedVMK: w) != a)
        #expect(VaultHeader.sha256(canonical: h.canonicalBytes, wrappedVMK: Data(repeating: 2, count: 92)) != a)
        #expect(a.count == 32)
    }
    @Test func new_header_has_current_params_and_random_salt() {
        let a = VaultHeader.new(), b = VaultHeader.new()
        #expect(a.kdf == .current); #expect(a.generation == 1)
        #expect(a.salt != b.salt); #expect(a.vaultID != b.vaultID); #expect(a.salt.count == 16)
    }
}
