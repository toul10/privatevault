import Foundation
import CryptoKit
@testable import VaultCore

/// Software stand-in for the Secure Enclave: P-256 keys held in memory, addressed by their public key.
/// `dataRepresentation` is an opaque token (NOT the private key) so tests can also simulate "blob useless on another Mac".
final class FakeSecureEnclave: SecureEnclaveService, @unchecked Sendable {
    private var keys: [Data: (P256.KeyAgreement.PrivateKey, biometric: Bool)] = [:]
    private let lock = NSLock()
    var available = true
    var biometryInvalidated = false       // simulate fingerprint change: biometric keys stop working
    var cancelNext = false                // simulate user cancelling the Touch ID sheet
    var biometryPromptCount = 0
    var forgetAllKeys = false             // simulate a different Mac / SEP reset

    var isAvailable: Bool { available }
    func createKey(biometric: Bool) throws -> SEKeyHandle {
        guard available else { throw VaultError.secureEnclaveUnavailable }
        let k = P256.KeyAgreement.PrivateKey()
        let token = SecureRandom.bytes(16)
        lock.lock(); keys[token] = (k, biometric); lock.unlock()
        return SEKeyHandle(dataRepresentation: token, publicKeyX963: k.publicKey.x963Representation)
    }
    func open(_ blob: HPKEWrappedBlob, with key: SEKeyHandle, info: Data, aad: Data, reason: String) throws -> SecureBytes {
        guard available else { throw VaultError.secureEnclaveUnavailable }
        lock.lock(); let entry = forgetAllKeys ? nil : keys[key.dataRepresentation]; lock.unlock()
        guard let (priv, biometric) = entry else { throw VaultError.secureEnclaveFailed("unknown key") }
        if biometric {
            biometryPromptCount += 1
            if cancelNext { cancelNext = false; throw VaultError.userCancelled }
            if biometryInvalidated { throw VaultError.secureEnclaveFailed("biometry changed") }
        }
        return try HPKEWrap.open(blob, privateKey: priv, info: info, aad: aad)
    }
}

enum TestEnv {
    static func tempDir() -> URL {
        let base = URL(fileURLWithPath: ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory())
        let dir = base.appendingPathComponent("pv-tests-\(UUID().uuidString)")
        try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        return dir
    }
    static func makeManager(dir: URL? = nil, store: InMemorySecretStore = InMemorySecretStore(), enclave: FakeSecureEnclave = FakeSecureEnclave())
        -> (VaultManager, InMemorySecretStore, FakeSecureEnclave, URL) {
        let d = dir ?? tempDir()
        let url = d.appendingPathComponent("Vault.noindex/vault.sqlite")
        let m = VaultManager(vaultURL: url, deviceKeys: DeviceKeyStore(store: store, enclave: enclave), kdfPolicy: .testing, allowWeakKDFForTesting: true)
        return (m, store, enclave, d)
    }
    static let password = "correct horse battery staple 2026"
    static let otherPassword = "Tr0ub4dor&3 is not the same thing"

    static func sampleItems() -> [VaultItem] {
        [
            VaultItem(title: "Binance", payload: .login(LoginPayload(website: "https://binance.com", username: "kostas@example.com",
                                                                      password: Secret("FAKE-login-pass-Q9z!"), notes: Secret("fake note")))),
            VaultItem(title: "OpenAI key", tags: ["work"], payload: .apiCredential(APICredentialPayload(service: "OpenAI", apiKey: Secret("sk-FAKEFAKE1234"),
                                                                      apiSecret: Secret("FAKE-secret-xyz"), environment: "prod"))),
            VaultItem(title: "Main wallet", favorite: true, payload: .wallet(WalletPayload(name: "Main", blockchain: .ethereum, publicAddress: "0xFAKE000000000000000000000000000000000001",
                                                                      seedPhrase: .plaintext(Secret("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")),
                                                                      privateKey: .plaintext(Secret("0xFAKEPRIVATEKEY00000000000000000000000000000000000000000000000001")),
                                                                      derivationPath: "m/44'/60'/0'/0/0"))),
            VaultItem(title: "Server notes", payload: .secureNote(SecureNotePayload(body: Secret("the door code is FAKE-4242")))),
            VaultItem(title: "GitHub recovery", payload: .recoveryCodes(RecoveryCodesPayload(service: "GitHub", codes: Secret(["FAKE-1111-2222", "FAKE-3333-4444"])))),
        ]
    }
    /// Sentinel plaintext strings that must never appear on disk or in logs.
    static let sentinels = ["Binance", "kostas@example.com", "FAKE-login-pass-Q9z!", "sk-FAKEFAKE1234", "FAKE-secret-xyz", "Main wallet",
                            "abandon abandon", "0xFAKEPRIVATEKEY", "the door code is FAKE-4242", "FAKE-1111-2222", "GitHub recovery", "Server notes", "0xFAKE0000"]

    static func fileContains(_ url: URL, anyOf needles: [String]) -> [String] {
        guard let data = try? Data(contentsOf: url) else { return [] }
        return needles.filter { data.range(of: Data($0.utf8)) != nil }
    }
    static func directoryContains(_ dir: URL, anyOf needles: [String]) -> [String] {
        var hits: [String] = []
        if let e = FileManager.default.enumerator(at: dir, includingPropertiesForKeys: nil) {
            for case let f as URL in e { hits += fileContains(f, anyOf: needles).map { "\(f.lastPathComponent): \($0)" } }
        }
        return hits
    }
}
