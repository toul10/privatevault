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
    }
    enum Keys {
        static let autoLock = "autoLockSeconds", clipboard = "clipboardClearSeconds", blockCapture = "blockScreenCapture", onboarded = "hasCompletedOnboarding"
    }
    var autoLock: AutoLockPolicy.Timeout { didSet { defaults.set(autoLock.rawValue, forKey: Keys.autoLock) } }
    var clipboardSeconds: Int { didSet { defaults.set(clipboardSeconds, forKey: Keys.clipboard) } }
    var blockScreenCapture: Bool { didSet { defaults.set(blockScreenCapture, forKey: Keys.blockCapture) } }
    var hasCompletedOnboarding: Bool { didSet { defaults.set(hasCompletedOnboarding, forKey: Keys.onboarded) } }
}
