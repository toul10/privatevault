import Foundation
import Security

/// Small device-local store for Secure-Enclave-wrapped blobs and pinned vault state (SECURITY_ARCHITECTURE.md §8).
public protocol SecretStore: Sendable {
    /// Returns nil when no item exists. Throws `keychainUnavailable` when the store cannot be used at all.
    func read(_ account: String) throws -> Data?
    func write(_ account: String, data: Data) throws
    func delete(_ account: String) throws
}

/// macOS Keychain implementation. Tries the Data-Protection keychain first; an ad-hoc-signed build gets
/// `errSecMissingEntitlement` and falls back to the classic login keychain. Items are never synchronised.
public final class KeychainSecretStore: SecretStore, @unchecked Sendable {
    /// Keychain service of the production app (`SECURITY_ARCHITECTURE.md` §8.1, item 3).
    public static let productionService = "com.kostastoulis.privatevault"
    /// Service used by this process: see `serviceName(forBundleIdentifier:)`.
    public static let service = serviceName(forBundleIdentifier: Bundle.main.bundleIdentifier)

    /// A development build (bundle id `com.kostastoulis.privatevault.<suffix>`, e.g. `.dev`) gets its own Keychain
    /// service. Restoring a real backup keeps the vault UUID, so with a shared service a development build could
    /// overwrite or delete an installed app's `sk:`/`bio:` items; with its own service it never can. The production
    /// app, command-line tools and test runners use `productionService`.
    public static func serviceName(forBundleIdentifier bundleID: String?) -> String {
        if let bundleID, bundleID.hasPrefix(productionService + ".") { return bundleID }
        return productionService
    }

    private let service: String
    private let lock = NSLock()
    private var useDataProtection: Bool? // resolved on first use

    public init(service: String = KeychainSecretStore.service) { self.service = service }

    private func baseQuery(_ account: String, dataProtection: Bool) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: false,
        ]
        if dataProtection { q[kSecUseDataProtectionKeychain as String] = true }
        return q
    }

    /// Decide DP vs legacy once, by probing.
    private func resolveMode() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if let m = useDataProtection { return m }
        let probe = "com.kostastoulis.privatevault.probe"
        var q = baseQuery(probe, dataProtection: true)
        q[kSecValueData as String] = Data([1])
        q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        SecItemDelete(baseQuery(probe, dataProtection: true) as CFDictionary)
        let st = SecItemAdd(q as CFDictionary, nil)
        SecItemDelete(baseQuery(probe, dataProtection: true) as CFDictionary)
        let dp = (st == errSecSuccess)
        useDataProtection = dp
        SecureLog.log(.keychain, "keychain mode resolved", .bool(dp))
        return dp
    }

    public func read(_ account: String) throws -> Data? {
        let dp = resolveMode()
        var q = baseQuery(account, dataProtection: dp)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let st = SecItemCopyMatching(q as CFDictionary, &out)
        switch st {
        case errSecSuccess: return out as? Data
        case errSecItemNotFound: return nil
        case errSecNotAvailable, errSecNoSuchKeychain, errSecInteractionNotAllowed: throw VaultError.keychainUnavailable
        default: throw VaultError.keychain(st)
        }
    }

    public func write(_ account: String, data: Data) throws {
        let dp = resolveMode()
        let q = baseQuery(account, dataProtection: dp)
        let update: [String: Any] = [kSecValueData as String: data]
        var st = SecItemUpdate(q as CFDictionary, update as CFDictionary)
        if st == errSecItemNotFound {
            var add = q
            add[kSecValueData as String] = data
            if dp { add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly }
            st = SecItemAdd(add as CFDictionary, nil)
        }
        switch st {
        case errSecSuccess: return
        case errSecNotAvailable, errSecNoSuchKeychain, errSecInteractionNotAllowed, errSecMissingEntitlement: throw VaultError.keychainUnavailable
        default: throw VaultError.keychain(st)
        }
    }

    public func delete(_ account: String) throws {
        let dp = resolveMode()
        let st = SecItemDelete(baseQuery(account, dataProtection: dp) as CFDictionary)
        guard st == errSecSuccess || st == errSecItemNotFound else { throw VaultError.keychain(st) }
    }
}

/// In-memory store for tests and for the "Keychain unavailable" state (nothing is ever written to disk).
public final class InMemorySecretStore: SecretStore, @unchecked Sendable {
    private var items: [String: Data] = [:]
    private let lock = NSLock()
    public var unavailable = false
    /// Test hook: reads work, writes/deletes fail (simulates a Keychain that refuses new items).
    public var writesFail = false
    public init() {}
    public func read(_ account: String) throws -> Data? {
        lock.lock(); defer { lock.unlock() }
        if unavailable { throw VaultError.keychainUnavailable }
        return items[account]
    }
    public func write(_ account: String, data: Data) throws {
        lock.lock(); defer { lock.unlock() }
        if unavailable || writesFail { throw VaultError.keychainUnavailable }
        items[account] = data
    }
    public func delete(_ account: String) throws {
        lock.lock(); defer { lock.unlock() }
        if unavailable { throw VaultError.keychainUnavailable }
        items[account] = nil
    }
    public var allAccounts: [String] { lock.lock(); defer { lock.unlock() }; return Array(items.keys) }
    public func rawValue(_ account: String) -> Data? { lock.lock(); defer { lock.unlock() }; return items[account] }
}
