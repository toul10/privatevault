import Foundation
import os

/// Secret-safe logging (SECURITY_ARCHITECTURE.md §10).
/// Only `StaticString` messages and a closed set of non-secret value types can be logged; there is no API that
/// accepts an arbitrary `String`, model or error payload, so secrets cannot be logged by accident.
public enum SecureLog {
    public enum Category: String, Sendable { case vault, crypto, keychain, auth, ui, backup, clipboard, lock, storage }
    public enum Level: Sendable { case debug, info, notice, error }

    /// Non-secret values that may accompany a message.
    public enum Value: Sendable, CustomStringConvertible {
        case int(Int), bool(Bool), code(Int32), count(Int), category(String)
        public var description: String {
            switch self {
            case .int(let v): return String(v)
            case .bool(let b): return b ? "true" : "false"
            case .code(let c): return "code=\(c)"
            case .count(let c): return "count=\(c)"
            case .category(let s): return s
            }
        }
    }

    /// Test hook: an in-memory sink that receives every rendered line (used to assert no secrets leak).
    public static let sink = LogSink()

    public static let subsystem = "com.kostastoulis.privatevault"
    nonisolated(unsafe) private static var loggers: [Category: Logger] = [:]
    private static let lock = NSLock()

    private static func logger(_ c: Category) -> Logger {
        lock.lock(); defer { lock.unlock() }
        if let l = loggers[c] { return l }
        let l = Logger(subsystem: subsystem, category: c.rawValue)
        loggers[c] = l
        return l
    }

    public static func log(_ category: Category, _ message: StaticString, _ values: Value...) { emit(.info, category, message, values) }
    public static func debug(_ category: Category, _ message: StaticString, _ values: Value...) { emit(.debug, category, message, values) }
    public static func notice(_ category: Category, _ message: StaticString, _ values: Value...) { emit(.notice, category, message, values) }
    public static func error(_ category: Category, _ message: StaticString, _ values: Value...) { emit(.error, category, message, values) }
    /// Log a VaultError by its case name only.
    public static func error(_ category: Category, _ message: StaticString, error: Error) {
        let name: String
        if let v = error as? VaultError { name = v.caseName } else { name = "other" }
        emit(.error, category, message, [.category(name)])
    }

    private static func emit(_ level: Level, _ category: Category, _ message: StaticString, _ values: [Value]) {
        let rendered = values.isEmpty ? "\(message)" : "\(message) " + values.map(\.description).joined(separator: " ")
        sink.append(rendered)
        let l = logger(category)
        switch level {
        case .debug: l.debug("\(rendered, privacy: .public)")
        case .info: l.info("\(rendered, privacy: .public)")
        case .notice: l.notice("\(rendered, privacy: .public)")
        case .error: l.error("\(rendered, privacy: .public)")
        }
    }
}

public final class LogSink: @unchecked Sendable {
    private var lines: [String] = []
    private let lock = NSLock()
    public func append(_ s: String) { lock.lock(); lines.append(s); if lines.count > 2000 { lines.removeFirst(1000) }; lock.unlock() }
    public func snapshot() -> [String] { lock.lock(); defer { lock.unlock() }; return lines }
    public func clear() { lock.lock(); lines.removeAll(); lock.unlock() }
}

extension VaultError {
    public var caseName: String {
        switch self {
        case .authenticationFailed: return "authenticationFailed"
        case .invalidHeader: return "invalidHeader"
        case .unsupportedFormat: return "unsupportedFormat"
        case .corrupted: return "corrupted"
        case .kdfFailed: return "kdfFailed"
        case .keychain: return "keychain"
        case .keychainUnavailable: return "keychainUnavailable"
        case .secureEnclaveUnavailable: return "secureEnclaveUnavailable"
        case .secureEnclaveFailed: return "secureEnclaveFailed"
        case .biometryUnavailable: return "biometryUnavailable"
        case .biometryInvalidated: return "biometryInvalidated"
        case .userCancelled: return "userCancelled"
        case .storage: return "storage"
        case .backupInvalid: return "backupInvalid"
        case .recoveryKitInvalid: return "recoveryKitInvalid"
        case .vaultLocked: return "vaultLocked"
        case .secretKeyRequired: return "secretKeyRequired"
        case .vaultAlreadyExists: return "vaultAlreadyExists"
        case .vaultNotFound: return "vaultNotFound"
        case .invalidInput: return "invalidInput"
        }
    }
}
