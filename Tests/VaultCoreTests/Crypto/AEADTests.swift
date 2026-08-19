import Testing
import Foundation
import CryptoKit
@testable import VaultCore

@Suite("AES-256-GCM (Wycheproof vectors) and record envelope")
struct AEADTests {
    struct V { let key, iv, aad, msg, ct, tag: String; let valid: Bool }
    static let vectors: [V] = [
        V(key: "92ace3e348cd821092cd921aa3546374299ab46209691bc28b8752d17f123c20", iv: "00112233445566778899aabb", aad: "00000000ffffffff", msg: "00010203040506070809", ct: "e27abdd2d2a53d2f136b", tag: "9a4a2579529301bcfb71c78d4060f52c", valid: true),
        V(key: "29d3a44f8723dc640239100c365423a312934ac80239212ac3df3421a2098123", iv: "00112233445566778899aabb", aad: "aabbccddeeff", msg: "", ct: "", tag: "2a7d77fa526b8250cb296078926b5020", valid: true),
        V(key: "80ba3192c803ce965ea371d5ff073cf0f43b6a2ab576b208426e11409c09b9b0", iv: "4da5bf8dfd5852c1ea12379d", aad: "", msg: "", ct: "", tag: "4771a7c404a472966cea8f73c8bfe17a", valid: true),
        V(key: "cc56b680552eb75008f5484b4cb803fa5063ebd6eab91f6ab6aef4916a766273", iv: "99e23ec48985bccdeeab60f1", aad: "", msg: "2a", ct: "06", tag: "633c1e9703ef744ffffb40edf9d14355", valid: true),
        V(key: "51e4bf2bad92b7aff1a4bc05550ba81df4b96fabf41c12c7b00e60e48db7e152", iv: "4f07afedfdc3b6c2361823d3", aad: "", msg: "be3308f72a2c6aed", ct: "cf332a12fdee800b", tag: "602e8d7c4799d62c140c9bb834876b09", valid: true),
        V(key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", iv: "505152535455565758595a5b", aad: "", msg: "202122232425262728292a2b2c2d2e2f", ct: "b2061457c0759fc1749f174ee1ccadfa", tag: "9de8fef6d8ab1bf1bf887232eab590dd", valid: false),
        V(key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", iv: "505152535455565758595a5b", aad: "", msg: "202122232425262728292a2b2c2d2e2f", ct: "b2061457c0759fc1749f174ee1ccadfa", tag: "9ee8fef6d8ab1bf1bf887232eab590dd", valid: false),
        V(key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", iv: "505152535455565758595a5b", aad: "", msg: "202122232425262728292a2b2c2d2e2f", ct: "b2061457c0759fc1749f174ee1ccadfa", tag: "1ce8fef6d8ab1bf1bf887232eab590dd", valid: false),
    ]
    @Test func wycheproof_aes256gcm() throws {
        for v in Self.vectors {
            let key = SymmetricKey(data: hex(v.key))
            let nonce = try AES.GCM.Nonce(data: hex(v.iv))
            if v.valid {
                let box = try AES.GCM.seal(hex(v.msg), using: key, nonce: nonce, authenticating: hex(v.aad))
                #expect(box.ciphertext.hexString == v.ct)
                #expect(box.tag.hexString == v.tag)
            }
            let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: hex(v.ct), tag: hex(v.tag))
            if v.valid {
                #expect(try AES.GCM.open(box, using: key, authenticating: hex(v.aad)).hexString == v.msg)
            } else {
                #expect(throws: (any Error).self) { try AES.GCM.open(box, using: key, authenticating: hex(v.aad)) }
            }
        }
    }

    // MARK: record envelope
    let key = SymmetricKey(size: .bits256)
    let aad = RecordCipher.recordAAD(vaultID: testVaultID, recordID: testRecordID, cryptoVersion: 1, revision: 7)

    @Test func record_aad_golden_layout() {
        // "record" ‖ vaultID ‖ recordID ‖ u32 cryptoVersion ‖ u64 revision
        #expect(aad.hexString == "7265636f7264" + "0123456789abcdef0123456789abcdef" + "fedcba9876543210fedcba9876543210" + "00000001" + "0000000000000007")
    }
    @Test func roundtrip_and_padding() throws {
        let payload = Data("{\"title\":\"Binance\"}".utf8)
        let blob = try RecordCipher.seal(payload: payload, key: key, aad: aad)
        #expect(try RecordCipher.open(blob: blob, key: key, aad: aad) == payload)
        // padded plaintext = 256 bytes ⇒ blob = 1 + 12 + 256 + 16
        #expect(blob.count == 1 + 12 + 256 + 16)
        let big = Data(repeating: 0x41, count: 5000)
        let blob2 = try RecordCipher.seal(payload: big, key: key, aad: aad)
        #expect(blob2.count == 1 + 12 + 8192 + 16)
        #expect(try RecordCipher.open(blob: blob2, key: key, aad: aad) == big)
        let empty = try RecordCipher.seal(payload: Data(), key: key, aad: aad)
        #expect(try RecordCipher.open(blob: empty, key: key, aad: aad) == Data())
        #expect(empty.count == 1 + 12 + 256 + 16)
    }
    @Test func identical_plaintext_gives_different_ciphertext_and_nonce() throws {
        var blobs = Set<Data>(), nonces = Set<Data>()
        for _ in 0..<200 {
            let b = try RecordCipher.seal(payload: Data("same".utf8), key: key, aad: aad)
            blobs.insert(b); nonces.insert(b.subdata(in: 1..<13))
        }
        #expect(blobs.count == 200); #expect(nonces.count == 200)
    }
    @Test func tampering_any_byte_fails_authentication() throws {
        let blob = try RecordCipher.seal(payload: Data("secret".utf8), key: key, aad: aad)
        for i in [0, 1, 5, 13, 40, blob.count - 17, blob.count - 1] {
            var t = blob; t[i] ^= 0x01
            #expect(throws: VaultError.authenticationFailed) { _ = try RecordCipher.open(blob: t, key: key, aad: aad) }
        }
        #expect(throws: VaultError.authenticationFailed) { _ = try RecordCipher.open(blob: blob.dropLast(), key: key, aad: aad) }
        #expect(throws: VaultError.authenticationFailed) { _ = try RecordCipher.open(blob: blob + [0], key: key, aad: aad) }
        #expect(throws: VaultError.authenticationFailed) { _ = try RecordCipher.open(blob: Data(), key: key, aad: aad) }
    }
    @Test func wrong_key_or_aad_fails() throws {
        let blob = try RecordCipher.seal(payload: Data("secret".utf8), key: key, aad: aad)
        #expect(throws: VaultError.authenticationFailed) { _ = try RecordCipher.open(blob: blob, key: SymmetricKey(size: .bits256), aad: aad) }
        let otherRecord = RecordCipher.recordAAD(vaultID: testVaultID, recordID: UUID(), cryptoVersion: 1, revision: 7)
        let otherVault = RecordCipher.recordAAD(vaultID: UUID(), recordID: testRecordID, cryptoVersion: 1, revision: 7)
        let otherRevision = RecordCipher.recordAAD(vaultID: testVaultID, recordID: testRecordID, cryptoVersion: 1, revision: 8)
        let otherVersion = RecordCipher.recordAAD(vaultID: testVaultID, recordID: testRecordID, cryptoVersion: 2, revision: 7)
        for a in [otherRecord, otherVault, otherRevision, otherVersion] {
            #expect(throws: VaultError.authenticationFailed) { _ = try RecordCipher.open(blob: blob, key: key, aad: a) }
        }
    }
    @Test func unpad_rejects_nonzero_padding_and_bad_length() {
        var p = RecordCipher.pad(Data("x".utf8)); p[p.count - 1] = 1
        #expect(throws: VaultError.self) { _ = try RecordCipher.unpad(p) }
        var q = RecordCipher.pad(Data("x".utf8)); q[3] = 0xff
        #expect(throws: VaultError.self) { _ = try RecordCipher.unpad(q) }
    }
    @Test func tier2_box_roundtrip_and_binding() throws {
        let t2 = RecordCipher.tier2AAD(vaultID: testVaultID, recordID: testRecordID, field: "seedPhrase")
        let box = try RecordCipher.sealTier2(plaintext: Data("abandon abandon FAKE".utf8), key: key, aad: t2)
        #expect(try RecordCipher.openTier2(box: box, key: key, aad: t2) == Data("abandon abandon FAKE".utf8))
        let otherField = RecordCipher.tier2AAD(vaultID: testVaultID, recordID: testRecordID, field: "privateKey")
        #expect(throws: VaultError.authenticationFailed) { _ = try RecordCipher.openTier2(box: box, key: key, aad: otherField) }
        var t = box; t[20] ^= 1
        #expect(throws: VaultError.authenticationFailed) { _ = try RecordCipher.openTier2(box: t, key: key, aad: t2) }
    }
}
