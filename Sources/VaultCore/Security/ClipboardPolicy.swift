import Foundation

/// Abstraction over NSPasteboard so the clearing policy is testable. SECURITY_ARCHITECTURE.md §10.
public protocol Pasteboard: AnyObject, Sendable {
    /// Writes a concealed, current-host-only string. Returns the pasteboard change count after the write.
    func writeConcealed(_ string: String) -> Int
    var changeCount: Int { get }
    func clear()
}

public protocol Clock: Sendable {
    var now: Date { get }
    func schedule(after seconds: TimeInterval, _ body: @escaping @Sendable () -> Void) -> ClockCancellable
}
public protocol ClockCancellable: Sendable { func cancel() }

/// Copies secrets with automatic clearing. Only clears if the pasteboard still holds OUR value (change count).
public final class SecureClipboard: @unchecked Sendable {
    public static let defaultTimeout: TimeInterval = 30
    private let pasteboard: Pasteboard
    private let clock: Clock
    private let lock = NSLock()
    private var ourChangeCount: Int?
    private var pending: ClockCancellable?
    public private(set) var clearAt: Date?
    public var timeout: TimeInterval

    public init(pasteboard: Pasteboard, clock: Clock, timeout: TimeInterval = SecureClipboard.defaultTimeout) {
        self.pasteboard = pasteboard; self.clock = clock; self.timeout = timeout
    }

    /// Explicit user action only. Returns the moment the clipboard will be cleared.
    @discardableResult
    public func copy(_ secret: String) -> Date {
        lock.lock(); defer { lock.unlock() }
        pending?.cancel()
        ourChangeCount = pasteboard.writeConcealed(secret)
        let at = clock.now.addingTimeInterval(timeout)
        clearAt = at
        pending = clock.schedule(after: timeout) { [weak self] in self?.clearIfStillOurs() }
        SecureLog.log(.clipboard, "secret copied; auto-clear scheduled", .int(Int(timeout)))
        return at
    }
    /// Clears the pasteboard only if nobody else has written to it since our copy.
    public func clearIfStillOurs() {
        lock.lock(); defer { lock.unlock() }
        guard let ours = ourChangeCount else { return }
        if pasteboard.changeCount == ours {
            pasteboard.clear()
            SecureLog.log(.clipboard, "clipboard cleared")
        }
        ourChangeCount = nil; clearAt = nil; pending?.cancel(); pending = nil
    }
    public var holdsOurSecret: Bool {
        lock.lock(); defer { lock.unlock() }
        guard let ours = ourChangeCount else { return false }
        return pasteboard.changeCount == ours
    }
}

// MARK: - Real clock
public final class SystemClock: Clock {
    public init() {}
    public var now: Date { Date() }
    public func schedule(after seconds: TimeInterval, _ body: @escaping @Sendable () -> Void) -> ClockCancellable {
        let item = DispatchWorkItem(block: body)
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + seconds, execute: item)
        return WorkItemCancellable(item)
    }
    private final class WorkItemCancellable: ClockCancellable, @unchecked Sendable {
        let item: DispatchWorkItem
        init(_ i: DispatchWorkItem) { item = i }
        func cancel() { item.cancel() }
    }
}
