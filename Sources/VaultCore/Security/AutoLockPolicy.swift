import Foundation

/// Pure auto-lock decision logic (SECURITY_ARCHITECTURE.md §7.5). The app feeds it events; it says when to lock.
public struct AutoLockPolicy: Sendable, Equatable {
    public enum Timeout: Int, CaseIterable, Sendable, Codable, Identifiable {
        case oneMinute = 60, fiveMinutes = 300, fifteenMinutes = 900, thirtyMinutes = 1800, never = 0
        public var id: Int { rawValue }
        public var displayName: String {
            switch self {
            case .oneMinute: return "1 minute"
            case .fiveMinutes: return "5 minutes"
            case .fifteenMinutes: return "15 minutes"
            case .thirtyMinutes: return "30 minutes"
            case .never: return "Never (not recommended)"
            }
        }
        public var seconds: TimeInterval? { self == .never ? nil : TimeInterval(rawValue) }
    }
    public enum Event: Sendable, Equatable {
        case userActivity
        case systemWillSleep
        case screensDidSleep
        case screenLocked
        case sessionResignedActive
        case willPowerOff
        case appWillTerminate
        case explicitLock
    }
    public static let defaultTimeout = Timeout.fiveMinutes
    public var timeout: Timeout
    public var lockOnSleep = true
    public var lockOnScreenLock = true

    public init(timeout: Timeout = AutoLockPolicy.defaultTimeout) { self.timeout = timeout }

    /// Events that lock immediately regardless of the idle timer.
    public func locksImmediately(on event: Event) -> Bool {
        switch event {
        case .userActivity: return false
        case .systemWillSleep, .screensDidSleep: return lockOnSleep
        case .screenLocked, .sessionResignedActive: return lockOnScreenLock
        case .willPowerOff, .appWillTerminate, .explicitLock: return true
        }
    }
    /// True when `now - lastActivity` exceeds the idle timeout.
    public func shouldLockForIdle(lastActivity: Date, now: Date) -> Bool {
        guard let s = timeout.seconds else { return false }
        return now.timeIntervalSince(lastActivity) >= s
    }
}

/// Tracks activity and drives a lock callback. Thread-safe; used by the app with real notifications.
public final class AutoLockController: @unchecked Sendable {
    private let lock = NSLock()
    private var policy: AutoLockPolicy
    private let clock: Clock
    private var lastActivity: Date
    private var timer: ClockCancellable?
    private let onLock: @Sendable () -> Void
    public private(set) var isArmed = false

    public init(policy: AutoLockPolicy, clock: Clock, onLock: @escaping @Sendable () -> Void) {
        self.policy = policy; self.clock = clock; self.lastActivity = clock.now; self.onLock = onLock
    }
    public var currentPolicy: AutoLockPolicy { lock.lock(); defer { lock.unlock() }; return policy }
    public func update(policy: AutoLockPolicy) { lock.lock(); self.policy = policy; lock.unlock(); rearm() }
    /// Start watching (vault unlocked).
    public func arm() { lock.lock(); isArmed = true; lastActivity = clock.now; lock.unlock(); rearm() }
    /// Stop watching (vault locked).
    public func disarm() { lock.lock(); isArmed = false; timer?.cancel(); timer = nil; lock.unlock() }

    public func handle(_ event: AutoLockPolicy.Event) {
        lock.lock()
        guard isArmed else { lock.unlock(); return }
        if event == .userActivity { lastActivity = clock.now; lock.unlock(); return }
        let immediate = policy.locksImmediately(on: event)
        lock.unlock()
        if immediate { fire() }
    }
    /// Called periodically by the app (and by the internal timer) — also covers system-idle checks.
    public func tick(now: Date? = nil, systemIdleSeconds: TimeInterval? = nil) {
        lock.lock()
        guard isArmed else { lock.unlock(); return }
        let n = now ?? clock.now
        var idle = policy.shouldLockForIdle(lastActivity: lastActivity, now: n)
        if let sys = systemIdleSeconds, let s = policy.timeout.seconds, sys >= s { idle = true }
        lock.unlock()
        if idle { fire() }
    }
    private func rearm() {
        lock.lock()
        timer?.cancel(); timer = nil
        guard isArmed, let s = policy.timeout.seconds else { lock.unlock(); return }
        timer = clock.schedule(after: max(1, min(s, 15))) { [weak self] in self?.tick(); self?.rearm() }
        lock.unlock()
    }
    private func fire() {
        disarm()
        SecureLog.log(.lock, "auto-lock fired")
        onLock()
    }
}
