import Foundation
import SQLite3
import CSecureMemory

/// Thin wrapper over the system SQLite C API. Not thread-safe by itself: one instance is owned by one actor.
/// Configured per SECURITY_ARCHITECTURE.md §5.1.
final class SQLiteDatabase {
    private var db: OpaquePointer?
    let path: String

    static let transientDestructor = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    init(path rawPath: String, create: Bool) throws {
        // Resolve directory symlinks (/var → /private/var) ourselves: SQLITE_OPEN_NOFOLLOW rejects any symlink in
        // the path, and Foundation hides /private. The vault FILE itself must not be a symlink.
        let url = URL(fileURLWithPath: rawPath)
        let path = SQLiteDatabase.realPath(url.deletingLastPathComponent().path) + "/" + url.lastPathComponent
        self.path = path
        var flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW | SQLITE_OPEN_EXRESCODE
        if create { flags |= SQLITE_OPEN_CREATE }
        var handle: OpaquePointer?
        let rc = sqlite3_open_v2(path, &handle, flags, nil)
        guard rc == SQLITE_OK, let h = handle else {
            if let h = handle { sqlite3_close_v2(h) }
            throw VaultError.storage("open failed \(rc)")
        }
        db = h
        guard pv_sqlite_set_defensive(UnsafeMutableRawPointer(h)) == SQLITE_OK else { sqlite3_close_v2(h); throw VaultError.storage("defensive mode") }
        sqlite3_busy_timeout(h, 5000)
        try exec("PRAGMA secure_delete = ON")
        try exec("PRAGMA journal_mode = DELETE")
        try exec("PRAGMA foreign_keys = ON")
        try exec("PRAGMA trusted_schema = OFF")
        // restrict file permissions (best effort; directory is 0700)
        chmod(path, 0o600)
    }

    deinit { close() }

    static func realPath(_ dir: String) -> String {
        var buf = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
        guard let r = realpath(dir, &buf) else { return dir }
        return String(cString: r)
    }

    func close() {
        if let d = db { sqlite3_close_v2(d); db = nil }
    }

    func exec(_ sql: String) throws {
        guard let db else { throw VaultError.storage("closed") }
        var err: UnsafeMutablePointer<CChar>?
        let rc = sqlite3_exec(db, sql, nil, nil, &err)
        if rc != SQLITE_OK {
            let msg = err.map { String(cString: $0) } ?? ""
            sqlite3_free(err)
            throw VaultError.storage("exec \(rc): \(msg.prefix(80))")
        }
    }

    func integrityCheck() throws {
        let rows = try query("PRAGMA integrity_check", bind: { _ in }) { $0.text(0) }
        guard rows == ["ok"] else { throw VaultError.corrupted("integrity_check") }
    }

    func transaction<T>(_ body: () throws -> T) throws -> T {
        try exec("BEGIN IMMEDIATE")
        do {
            let r = try body()
            try exec("COMMIT")
            return r
        } catch {
            try? exec("ROLLBACK")
            throw error
        }
    }

    // MARK: statements
    final class Statement {
        let stmt: OpaquePointer
        init(_ s: OpaquePointer) { stmt = s }
        deinit { sqlite3_finalize(stmt) }
        func bind(_ idx: Int32, _ data: Data) {
            _ = data.withUnsafeBytes { sqlite3_bind_blob(stmt, idx, $0.baseAddress, Int32(data.count), SQLiteDatabase.transientDestructor) }
        }
        func bind(_ idx: Int32, _ text: String) { sqlite3_bind_text(stmt, idx, text, -1, SQLiteDatabase.transientDestructor) }
        func bind(_ idx: Int32, _ value: Int64) { sqlite3_bind_int64(stmt, idx, value) }
        func blob(_ col: Int32) -> Data {
            guard let p = sqlite3_column_blob(stmt, col) else { return Data() }
            return Data(bytes: p, count: Int(sqlite3_column_bytes(stmt, col)))
        }
        func int64(_ col: Int32) -> Int64 { sqlite3_column_int64(stmt, col) }
        func text(_ col: Int32) -> String { sqlite3_column_text(stmt, col).map { String(cString: $0) } ?? "" }
    }

    func prepare(_ sql: String) throws -> Statement {
        guard let db else { throw VaultError.storage("closed") }
        var s: OpaquePointer?
        let rc = sqlite3_prepare_v2(db, sql, -1, &s, nil)
        guard rc == SQLITE_OK, let st = s else { throw VaultError.storage("prepare \(rc)") }
        return Statement(st)
    }

    func run(_ sql: String, bind: (Statement) -> Void) throws {
        let st = try prepare(sql)
        bind(st)
        let rc = sqlite3_step(st.stmt)
        guard rc == SQLITE_DONE || rc == SQLITE_ROW else { throw VaultError.storage("step \(rc)") }
    }

    func query<T>(_ sql: String, bind: (Statement) -> Void, row: (Statement) throws -> T) throws -> [T] {
        let st = try prepare(sql)
        bind(st)
        var out: [T] = []
        while true {
            let rc = sqlite3_step(st.stmt)
            if rc == SQLITE_ROW { out.append(try row(st)) }
            else if rc == SQLITE_DONE { break }
            else { throw VaultError.storage("step \(rc)") }
        }
        return out
    }
}
