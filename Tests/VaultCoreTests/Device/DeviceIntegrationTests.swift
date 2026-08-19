import Testing
import Foundation
@testable import VaultCore

/// Real Secure Enclave + real macOS Keychain. Opt-in: PV_DEVICE_TESTS=1 Scripts/run-tests.sh --filter Device
/// (never prompts for Touch ID: only the non-biometric Secure-Enclave key is exercised).
@Suite("Device integration (real Keychain + Secure Enclave)", .serialized, .enabled(if: ProcessInfo.processInfo.environment["PV_DEVICE_TESTS"] == "1"))
struct DeviceIntegrationTests {
    @Test func real_secure_enclave_wraps_and_unwraps() throws {
        let se = SystemSecureEnclave()
        #expect(se.isAvailable)
        let key = try se.createKey(biometric: false)
        #expect(key.publicKeyX963.count == 65)
        let secret = SecureBytes(copying: Data(repeating: 7, count: 32))
        let blob = try se.seal(secret, to: key, info: Data("i".utf8), aad: Data("a".utf8))
        let opened = try se.open(blob, with: key, info: Data("i".utf8), aad: Data("a".utf8), reason: "test")
        #expect(opened.constantTimeEquals(secret))
        #expect(throws: VaultError.authenticationFailed) { _ = try se.open(blob, with: key, info: Data("x".utf8), aad: Data("a".utf8), reason: "test") }
        // a different SE key cannot open it
        let other = try se.createKey(biometric: false)
        #expect(throws: VaultError.self) { _ = try se.open(blob, with: other, info: Data("i".utf8), aad: Data("a".utf8), reason: "test") }
    }

    @Test func real_keychain_store_roundtrip_and_secret_key_flow() async throws {
        let store = KeychainSecretStore(service: "com.kostastoulis.privatevault.tests")
        let account = "device-test-\(UUID().uuidString)"
        defer { try? store.delete(account) }
        #expect(try store.read(account) == nil)
        try store.write(account, data: Data([1, 2, 3]))
        #expect(try store.read(account) == Data([1, 2, 3]))
        try store.write(account, data: Data([9]))
        #expect(try store.read(account) == Data([9]))
        try store.delete(account)
        #expect(try store.read(account) == nil)

        // full manager flow on real device key store (non-biometric)
        let dir = TestEnv.tempDir()
        let deviceKeys = DeviceKeyStore(store: store, enclave: SystemSecureEnclave())
        let m = VaultManager(vaultURL: dir.appendingPathComponent("vault.sqlite"), deviceKeys: deviceKeys, kdfPolicy: .testing)
        let created = try await m.createVault(password: TestEnv.password)
        let vaultID = await created.session.currentHeader.vaultID
        defer { try? deviceKeys.deleteSecretKey(vaultID: vaultID) }
        #expect(created.secretKeyStoredOnDevice)
        #expect(deviceKeys.secretKeyIsHardwareBound)
        // the keychain item holds only an SE-wrapped blob
        let raw = try store.read("sk:\(vaultID.uuidString)")!
        #expect(raw.range(of: created.secretKey.bytes.copyData()) == nil)
        try await created.session.save(TestEnv.sampleItems()[0])
        await m.lock()
        let s = try await m.unlock(password: TestEnv.password)
        #expect(try await s.count() == 1)
        await m.lock()
    }
}
