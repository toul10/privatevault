import Foundation

/// What the header row stores (SECURITY_ARCHITECTURE.md §3.3). All fields are non-secret.
public struct StoredHeader: Sendable, Equatable {
    public var canonical: Data
    public var wrappedVMK: Data
    public var headerSHA256: Data
    public var skID: Data
    public var stateMAC: Data
    public init(canonical: Data, wrappedVMK: Data, headerSHA256: Data, skID: Data, stateMAC: Data) {
        self.canonical = canonical; self.wrappedVMK = wrappedVMK; self.headerSHA256 = headerSHA256; self.skID = skID; self.stateMAC = stateMAC
    }
    public func header() throws -> VaultHeader { try VaultHeader.parse(canonical: canonical) }
}

/// Encrypted persistence: owns the SQLite connection, knows nothing about keys or plaintext.
/// Schema and migrations per SECURITY_ARCHITECTURE.md §5.2.
public actor VaultStore {
    public static let schemaVersion = 1
    public static let fileName = "vault.sqlite"
    private let db: SQLiteDatabase
    public nonisolated let url: URL

    // MARK: open / create
    public static func exists(at url: URL) -> Bool { FileManager.default.fileExists(atPath: url.path) }

    public static func create(at url: URL, header: StoredHeader) throws -> VaultStore {
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        guard !exists(at: url) else { throw VaultError.vaultAlreadyExists }
        // Resolve directory symlinks (e.g. /var → /private/var) but refuse a symlinked vault FILE (NOFOLLOW).
        let db = try SQLiteDatabase(path: url.path, create: true)
        try db.exec("PRAGMA auto_vacuum = FULL")
        try db.transaction {
            try db.exec("""
            CREATE TABLE meta(key TEXT PRIMARY KEY, value BLOB) WITHOUT ROWID;
            CREATE TABLE vault_header(id INTEGER PRIMARY KEY CHECK(id = 1), canonical BLOB NOT NULL, wrapped_vmk BLOB NOT NULL,
                                      header_sha256 BLOB NOT NULL, sk_id BLOB NOT NULL, state_mac BLOB NOT NULL);
            CREATE TABLE records(id BLOB PRIMARY KEY, crypto_version INTEGER NOT NULL, revision INTEGER NOT NULL, blob BLOB NOT NULL) WITHOUT ROWID;
            """)
            try db.run("INSERT INTO meta(key, value) VALUES('schema_version', ?)") { $0.bind(1, Data([UInt8(schemaVersion)])) }
            try Self.insertHeader(db, header)
        }
        return VaultStore(db: db, url: url)
    }

    public static func open(at url: URL) throws -> VaultStore {
        guard exists(at: url) else { throw VaultError.vaultNotFound }
        let db = try SQLiteDatabase(path: url.path, create: false)
        try db.integrityCheck()
        try migrateIfNeeded(db)
        return VaultStore(db: db, url: url)
    }

    private init(db: SQLiteDatabase, url: URL) { self.db = db; self.url = url }

    // MARK: migrations
    private static func migrateIfNeeded(_ db: SQLiteDatabase) throws {
        let rows = try db.query("SELECT value FROM meta WHERE key = 'schema_version'", bind: { _ in }) { $0.blob(0) }
        guard let raw = rows.first, raw.count == 1 else { throw VaultError.corrupted("schema_version") }
        let v = Int(raw[0])
        guard v >= 1 else { throw VaultError.corrupted("schema_version") }
        guard v <= Self.schemaVersion else { throw VaultError.unsupportedFormat(UInt8(truncatingIfNeeded: v)) }
        for m in SchemaMigrations.plan(from: v, to: Self.schemaVersion) {
            try db.transaction {
                try m.run(db)
                try db.run("UPDATE meta SET value = ? WHERE key = 'schema_version'") { $0.bind(1, Data([UInt8(m.version)])) }
            }
            SecureLog.notice(.storage, "schema migrated", .int(m.version))
        }
    }

    // MARK: header
    private static func insertHeader(_ db: SQLiteDatabase, _ h: StoredHeader) throws {
        try db.run("INSERT INTO vault_header(id, canonical, wrapped_vmk, header_sha256, sk_id, state_mac) VALUES(1, ?, ?, ?, ?, ?)") {
            $0.bind(1, h.canonical); $0.bind(2, h.wrappedVMK); $0.bind(3, h.headerSHA256); $0.bind(4, h.skID); $0.bind(5, h.stateMAC)
        }
    }
    public func readHeader() throws -> StoredHeader {
        let rows = try db.query("SELECT canonical, wrapped_vmk, header_sha256, sk_id, state_mac FROM vault_header WHERE id = 1", bind: { _ in }) {
            StoredHeader(canonical: $0.blob(0), wrappedVMK: $0.blob(1), headerSHA256: $0.blob(2), skID: $0.blob(3), stateMAC: $0.blob(4))
        }
        guard rows.count == 1 else { throw VaultError.corrupted("header row") }
        return rows[0]
    }
    private func updateHeader(_ h: StoredHeader) throws {
        try db.run("UPDATE vault_header SET canonical = ?, wrapped_vmk = ?, header_sha256 = ?, sk_id = ?, state_mac = ? WHERE id = 1") {
            $0.bind(1, h.canonical); $0.bind(2, h.wrappedVMK); $0.bind(3, h.headerSHA256); $0.bind(4, h.skID); $0.bind(5, h.stateMAC)
        }
    }
    /// Header rewrite (password change / KDF upgrade): single transaction, then VACUUM so the old row is gone.
    public func writeHeader(_ h: StoredHeader) throws {
        try db.transaction { try updateHeader(h) }
        try vacuum()
    }

    // MARK: records
    public func allRecords() throws -> [EncryptedRecord] {
        try db.query("SELECT id, crypto_version, revision, blob FROM records", bind: { _ in }) { st in
            guard let id = UUID(rawBytes: st.blob(0)) else { throw VaultError.corrupted("record id") }
            return EncryptedRecord(id: id, cryptoVersion: UInt32(truncatingIfNeeded: st.int64(1)), revision: UInt64(bitPattern: st.int64(2)), blob: st.blob(3))
        }
    }
    public func recordCount() throws -> Int {
        let r = try db.query("SELECT COUNT(*) FROM records", bind: { _ in }) { Int($0.int64(0)) }
        return r.first ?? 0
    }

    /// Applies a set of writes and the matching new state MAC atomically (SECURITY_ARCHITECTURE.md §5.3).
    public func commit(upserts: [EncryptedRecord], deletes: [UUID], stateMAC: Data) throws {
        try db.transaction {
            for r in upserts {
                try db.run("INSERT INTO records(id, crypto_version, revision, blob) VALUES(?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET crypto_version = excluded.crypto_version, revision = excluded.revision, blob = excluded.blob") {
                    $0.bind(1, r.id.rawBytes); $0.bind(2, Int64(r.cryptoVersion)); $0.bind(3, Int64(bitPattern: r.revision)); $0.bind(4, r.blob)
                }
            }
            for id in deletes {
                try db.run("DELETE FROM records WHERE id = ?") { $0.bind(1, id.rawBytes) }
            }
            try db.run("UPDATE vault_header SET state_mac = ? WHERE id = 1") { $0.bind(1, stateMAC) }
        }
    }

    /// Replaces every record and the header in one transaction (key rotation / restore), then VACUUM.
    public func replaceAll(records: [EncryptedRecord], header: StoredHeader) throws {
        try db.transaction {
            try db.exec("DELETE FROM records")
            for r in records {
                try db.run("INSERT INTO records(id, crypto_version, revision, blob) VALUES(?, ?, ?, ?)") {
                    $0.bind(1, r.id.rawBytes); $0.bind(2, Int64(r.cryptoVersion)); $0.bind(3, Int64(bitPattern: r.revision)); $0.bind(4, r.blob)
                }
            }
            try updateHeader(header)
        }
        try vacuum()
    }

    public func vacuum() throws { try db.exec("VACUUM") }
    public func integrityCheck() throws { try db.integrityCheck() }
    public func close() { db.close() }
}
