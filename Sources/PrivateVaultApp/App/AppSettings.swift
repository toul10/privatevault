import Foundation
import VaultCore

/// Non-sensitive preferences only (UserDefaults). Never store secrets, titles, ids or search text here.
@MainActor @Observable
final class AppSettings {
    private let defaults: UserDefaults
    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        autoLock = AutoLockPolicy.Timeout(rawValue: defaults.object(forKey: Keys.autoLock) as? Int ?? AutoLockPolicy.defaultTimeout.rawValue) ?? .fiveMinutes
        clipboardSeconds = defaults.object(forKey: Keys.clipboard) as? Int ?? Int(SecureClipboard.defaultTimeout)
        blockScreenCapture = defaults.object(forKey: Keys.blockCapture) as? Bool ?? true
        hasCompletedOnboarding = defaults.bool(forKey: Keys.onboarded)
        requireAuthForSecrets = defaults.object(forKey: Keys.authSecrets) as? Bool ?? true
    }
    enum Keys {
        static let autoLock = "autoLockSeconds", clipboard = "clipboardClearSeconds", blockCapture = "blockScreenCapture", onboarded = "hasCompletedOnboarding"
        static let authSecrets = "requireAuthForSecrets"
    }
    var autoLock: AutoLockPolicy.Timeout { didSet { defaults.set(autoLock.rawValue, forKey: Keys.autoLock) } }
    var clipboardSeconds: Int { didSet { defaults.set(clipboardSeconds, forKey: Keys.clipboard) } }
    var blockScreenCapture: Bool { didSet { defaults.set(blockScreenCapture, forKey: Keys.blockCapture) } }
    var hasCompletedOnboarding: Bool { didSet { defaults.set(hasCompletedOnboarding, forKey: Keys.onboarded) } }
    /// Touch ID (or login password) before revealing/copying passwords, API keys, notes, recovery codes.
    var requireAuthForSecrets: Bool { didSet { defaults.set(requireAuthForSecrets, forKey: Keys.authSecrets) } }
}
