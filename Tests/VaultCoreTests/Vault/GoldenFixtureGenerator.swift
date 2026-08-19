import Testing
import Foundation
@testable import VaultCore

/// Opt-in generator for the frozen format fixture (PV_GEN_FIXTURE=1). Normally disabled.
@Suite("Golden fixture generator", .enabled(if: ProcessInfo.processInfo.environment["PV_GEN_FIXTURE"] == "1"))
struct GoldenFixtureGenerator {
    @Test func generate() async throws {
        let out = URL(fileURLWithPath: ProcessInfo.processInfo.environment["PV_GEN_FIXTURE_DIR"]!)
        let (m, store, _, _) = TestEnv.makeManager()
        // fixed, obviously fake credentials for the fixture
        let created = try await m.createVault(password: GoldenFixture.password)
        // we need a DETERMINISTIC secret key in the fixture: re-create the vault header with a known SK instead.
        _ = created; _ = store
        await m.lock()
        try FileManager.default.removeItem(at: m.vaultURL)
        // build manually with known SK
        let sk = try SecretKey(bytes: SecureBytes(copying: Data(repeating: 0x5A, count: 32)))
        let header = VaultHeader(vaultID: UUID(rawBytes: Data(repeating: 0xA1, count: 16))!, kdf: .testing, salt: Data(repeating: 0x11, count: 16), generation: 1, createdAt: 1_755_000_000)
        let pw = try PasswordNormalization.normalize(GoldenFixture.password)
        let vmk = SecureBytes(copying: Data(repeating: 0x33, count: 32))
        let kek = try KeyHierarchy.deriveKEK(password: pw, secretKey: sk, header: header)
        let wrapped = try KeyHierarchy.wrapVMK(vmk, kek: kek, header: header)
        let keys = try VaultKeys(vaultID: header.vaultID, vmk: vmk)
        let codec = RecordCodec(keys: keys)
        var records: [EncryptedRecord] = []
        for (i, item) in GoldenFixture.items().enumerated() { records.append(try codec.seal(item, revision: UInt64(i + 1))) }
        let mac = VaultState.mac(key: keys.vaultStateKey, vaultID: header.vaultID, generation: 1, entries: records.map { (id: $0.id, revision: $0.revision) })
        let stored = StoredHeader(canonical: header.canonicalBytes, wrappedVMK: wrapped, headerSHA256: VaultHeader.sha256(canonical: header.canonicalBytes, wrappedVMK: wrapped), skID: sk.identifier(vaultID: header.vaultID), stateMAC: mac)
        let s = try VaultStore.create(at: out.appendingPathComponent("golden-v1.sqlite"), header: stored)
        try await s.replaceAll(records: records, header: stored)
        try await s.integrityCheck(); await s.close()
        let backup = try BackupCodec.export(stored: stored, records: records, keys: keys, now: Date(timeIntervalSince1970: 1_755_000_100))
        try backup.write(to: out.appendingPathComponent("golden-v1.privatevault"))
        print("RECOVERY KIT: \(RecoveryKit.encode(sk))")
    }
}

enum GoldenFixture {
    static let password = "golden fixture password (FAKE) 2026"
    static func items() -> [VaultItem] {
        [
            VaultItem(id: UUID(rawBytes: Data(repeating: 0x01, count: 16))!, title: "Golden login", createdAt: Date(timeIntervalSince1970: 1_755_000_000), updatedAt: Date(timeIntervalSince1970: 1_755_000_000),
                      payload: .login(LoginPayload(website: "https://example.com", username: "golden@example.com", password: Secret("FAKE-golden-pass"), notes: Secret("n")))),
            VaultItem(id: UUID(rawBytes: Data(repeating: 0x02, count: 16))!, title: "Golden wallet", createdAt: Date(timeIntervalSince1970: 1_755_000_000), updatedAt: Date(timeIntervalSince1970: 1_755_000_000),
                      payload: .wallet(WalletPayload(name: "G", blockchain: .sui, publicAddress: "0xFAKE", seedPhrase: .plaintext(Secret("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong")), privateKey: .plaintext(Secret("FAKE-priv")), derivationPath: "m/44'/784'/0'/0'/0'"))),
        ]
    }
}
