import Foundation

/// Ordered schema migrations. Each migration upgrades the database from `version - 1` to `version` inside one
/// transaction; the plan is the ordered list of migrations strictly above the current version.
/// (V1 ships schema_version 1; future versions append here. Record envelopes carry their own crypto_version.)
struct SchemaMigration: Sendable {
    let version: Int
    let run: @Sendable (SQLiteDatabase) throws -> Void
}

enum SchemaMigrations {
    /// Registered migrations, ascending by version. Version 1 is the baseline created by `VaultStore.create`.
    static let all: [SchemaMigration] = []

    static func plan(from current: Int, to target: Int, registry: [SchemaMigration] = all) -> [SchemaMigration] {
        registry.filter { $0.version > current && $0.version <= target }.sorted { $0.version < $1.version }
    }
    /// True when every step between `from` and `to` exists (no gaps).
    static func isComplete(from current: Int, to target: Int, registry: [SchemaMigration] = all) -> Bool {
        guard target > current else { return true }
        return plan(from: current, to: target, registry: registry).map(\.version) == Array((current + 1)...target)
    }
}
