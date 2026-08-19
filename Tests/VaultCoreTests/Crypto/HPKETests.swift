import Testing
import Foundation
import CryptoKit
@testable import VaultCore

@Suite("HPKE (RFC 9180 A.3) and Secure-Enclave-style wrapping")
struct HPKETests {
    /// RFC 9180 Appendix A.3.1: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, base mode — recipient side.
    @Test func rfc9180_A3_recipient_decrypts_and_exports() throws {
        let skR = try P256.KeyAgreement.PrivateKey(rawRepresentation: hex("f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2"))
        #expect(skR.publicKey.x963Representation.hexString == "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0")
        let suite = HPKE.Ciphersuite(kem: .P256_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_128)
        let info = hex("4f6465206f6e2061204772656369616e2055726e")
        let enc = hex("04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4")
        var r = try HPKE.Recipient(privateKey: skR, ciphersuite: suite, info: info, encapsulatedKey: enc)
        let pt0 = try r.open(hex("5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434"), authenticating: hex("436f756e742d30"))
        #expect(pt0.hexString == "4265617574792069732074727574682c20747275746820626561757479")
        let pt1 = try r.open(hex("fa6f037b47fc21826b610172ca9637e82d6e5801eb31cbd3748271affd4ecb06646e0329cbdf3c3cd655b28e82"), authenticating: hex("436f756e742d31"))
        #expect(pt1.hexString == "4265617574792069732074727574682c20747275746820626561757479")
        let exported = try r.exportSecret(context: Data(), outputByteCount: 32)
        #expect(exported.withUnsafeBytes { Data($0) }.hexString == "5e9bc3d236e1911d95e65b576a8a86d478fb827e8bdfe77b741b289890490d4d")
    }

    @Test func wrap_roundtrip_with_software_key() throws {
        let recipient = P256.KeyAgreement.PrivateKey()
        let secret = SecureBytes(copying: rep(0x33, 32))
        let info = HPKEWrap.info(.hpkeSecretKey, vaultID: testVaultID)
        let aad = Data([0x01]) + testVaultID.rawBytes
        let blob = try HPKEWrap.seal(secret, recipient: recipient.publicKey, info: info, aad: aad)
        #expect(blob.encapsulatedKey.count == 65)
        #expect(blob.ciphertext.count == 32 + 32 + 16) // commitment prefix + secret + tag
        let opened = try HPKEWrap.open(blob, privateKey: recipient, info: info, aad: aad)
        #expect(opened.constantTimeEquals(secret))
    }
    @Test func wrap_fails_with_wrong_key_info_aad_or_tampering() throws {
        let recipient = P256.KeyAgreement.PrivateKey()
        let secret = SecureBytes(copying: rep(0x33, 32))
        let info = HPKEWrap.info(.hpkeSecretKey, vaultID: testVaultID)
        let aad = Data([0x01]) + testVaultID.rawBytes
        let blob = try HPKEWrap.seal(secret, recipient: recipient.publicKey, info: info, aad: aad)
        #expect(throws: VaultError.authenticationFailed) { _ = try HPKEWrap.open(blob, privateKey: P256.KeyAgreement.PrivateKey(), info: info, aad: aad) }
        #expect(throws: VaultError.authenticationFailed) { _ = try HPKEWrap.open(blob, privateKey: recipient, info: HPKEWrap.info(.hpkeBiometric, vaultID: testVaultID), aad: aad) }
        #expect(throws: VaultError.authenticationFailed) { _ = try HPKEWrap.open(blob, privateKey: recipient, info: info, aad: Data([0x02]) + testVaultID.rawBytes) }
        var t = blob; t.ciphertext[t.ciphertext.startIndex + 5] ^= 1
        #expect(throws: VaultError.authenticationFailed) { _ = try HPKEWrap.open(t, privateKey: recipient, info: info, aad: aad) }
        var e = blob; e.encapsulatedKey[e.encapsulatedKey.startIndex + 10] ^= 1
        #expect(throws: VaultError.authenticationFailed) { _ = try HPKEWrap.open(e, privateKey: recipient, info: info, aad: aad) }
        var v = blob; v.version = 9
        #expect(throws: VaultError.authenticationFailed) { _ = try HPKEWrap.open(v, privateKey: recipient, info: info, aad: aad) }
    }
    @Test func each_wrap_uses_fresh_ephemeral_key() throws {
        let recipient = P256.KeyAgreement.PrivateKey()
        let secret = SecureBytes(copying: rep(0x33, 32))
        let info = HPKEWrap.info(.hpkeSecretKey, vaultID: testVaultID)
        let a = try HPKEWrap.seal(secret, recipient: recipient.publicKey, info: info, aad: Data())
        let b = try HPKEWrap.seal(secret, recipient: recipient.publicKey, info: info, aad: Data())
        #expect(a.encapsulatedKey != b.encapsulatedKey); #expect(a.ciphertext != b.ciphertext)
    }
}
