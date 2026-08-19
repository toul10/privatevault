import Testing
import Foundation
import CryptoKit
@testable import VaultCore

@Suite("HKDF (RFC 5869) and key hierarchy golden vectors")
struct HKDFAndKeyHierarchyTests {
    private func hkdf(ikm: Data, salt: Data, info: Data, len: Int) -> Data {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm), salt: salt, info: info, outputByteCount: len)
            .withUnsafeBytes { Data($0) }
    }
    @Test func rfc5869_A1() {
        let okm = hkdf(ikm: rep(0x0b, 22), salt: hex("000102030405060708090a0b0c"), info: hex("f0f1f2f3f4f5f6f7f8f9"), len: 42)
        #expect(okm.hexString == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    }
    @Test func rfc5869_A2() {
        let ikm = Data((0x00...0x4f).map { UInt8($0) }), salt = Data((0x60...0xaf).map { UInt8($0) }), info = Data((0xb0...0xff).map { UInt8($0) })
        let okm = hkdf(ikm: ikm, salt: salt, info: info, len: 82)
        #expect(okm.hexString == "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87")
    }
    @Test func rfc5869_A3() {
        let okm = hkdf(ikm: rep(0x0b, 22), salt: Data(), info: Data(), len: 42)
        #expect(okm.hexString == "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
    }

    /// Whole MP+SK→KEK chain, cross-checked with OpenSSL (argon2id + two HKDF steps).
    @Test func kek_golden_chain() throws {
        let header = VaultHeader.fixture
        let pw = try PasswordNormalization.normalize("correct horse battery staple")
        let kek = try KeyHierarchy.deriveKEK(password: pw, secretKey: .test(0x11), header: header)
        #expect(kek.withUnsafeBytes { Data($0) }.hexString == "a0b376a8d50b72dbbdf327210c2251fe4a62c2b1b9cbb8b736b11590c79c7c6e")
    }
    @Test func secret_key_identifier_golden() {
        let id = SecretKey.test(0x11).identifier(vaultID: testVaultID)
        #expect(id.hexString == "d5db03db")
    }
    @Test func subkeys_golden_and_distinct() throws {
        let keys = try VaultKeys(vaultID: testVaultID, vmk: SecureBytes(copying: rep(0x22, 32)))
        func h(_ k: SymmetricKey) -> String { k.withUnsafeBytes { Data($0) }.hexString }
        #expect(h(keys.recordRootKey) == "73352287b210d4c55849bf1916aaee2bdc36a16332ca5b40795a952ce0ec24dc")
        #expect(h(keys.tier2Key) == "96789d97812754cb4fdce29d28c73bc9279c2976e6fdf0a7e01b16df85fdcd94")
        #expect(h(keys.vaultStateKey) == "00c1cae584bca7aa209e07b3f7568ecd00df3d1a2e0159ca221264b2f07d17c9")
        #expect(h(keys.backupManifestKey) == "4ef643f1be68cd3ac453e2c5bf687f8f93f27c9d6a7147701c7d5c7972853635")
        #expect(h(keys.recordKey(for: testRecordID)) == "c4abbbdb9d40d0893e84063371b5ad57e7474d5e1a78b43518ecb45a98b447f3")
        let all = [keys.recordRootKey, keys.tier2Key, keys.vaultStateKey, keys.backupManifestKey, keys.recordKey(for: testRecordID)].map(h)
        #expect(Set(all).count == all.count)
        // per-record keys differ per record
        #expect(h(keys.recordKey(for: testRecordID)) != h(keys.recordKey(for: testVaultID)))
        // different vault id ⇒ different subkeys even with the same VMK
        let other = try VaultKeys(vaultID: testRecordID, vmk: SecureBytes(copying: rep(0x22, 32)))
        #expect(h(other.recordRootKey) != h(keys.recordRootKey))
    }
    @Test func kek_depends_on_both_password_and_secret_key() throws {
        let header = VaultHeader.fixture
        let pw = try PasswordNormalization.normalize("correct horse battery staple")
        let pw2 = try PasswordNormalization.normalize("correct horse battery staplE")
        let k1 = try KeyHierarchy.deriveKEK(password: pw, secretKey: .test(0x11), header: header)
        let k2 = try KeyHierarchy.deriveKEK(password: pw2, secretKey: .test(0x11), header: header)
        let k3 = try KeyHierarchy.deriveKEK(password: pw, secretKey: .test(0x12), header: header)
        #expect(k1 != k2); #expect(k1 != k3); #expect(k2 != k3)
    }
}
