import Testing
import Foundation
@testable import VaultCore

/// Format-stability safety net: a vault + backup frozen in the v1 format (FAKE credentials) must open forever.
/// If this test fails, a format change broke compatibility with existing vaults — add a migration, do not "fix" the fixture.
@Suite("Golden v1 fixture (format stability)", .serialized)
struct GoldenFixtureTests {
    static let fixtureSK = try! SecretKey(bytes: SecureBytes(copying: Data(repeating: 0x5A, count: 32)))
    static var kit: String { RecoveryKit.encode(fixtureSK) }
    static func fixtureURL(_ name: String) -> URL { Bundle.module.url(forResource: name, withExtension: nil, subdirectory: "Fixtures")! }

    @Test func golden_vault_still_unlocks() async throws {
        let (m, _, _, dir) = TestEnv.makeManager()
        try FileManager.default.createDirectory(at: m.vaultURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try FileManager.default.copyItem(at: Self.fixtureURL("golden-v1.sqlite"), to: m.vaultURL)
        let s = try await m.unlock(password: GoldenFixture.password, recoveryKit: Self.kit)
        let items = try await s.allItems()
        #expect(items.map(\.title) == ["Golden login", "Golden wallet"])
        guard case .login(let p) = items[0].payload else { Issue.record("login"); return }
        #expect(p.password.value == "FAKE-golden-pass")
        #expect(try await s.revealTier2(itemID: items[1].id, field: .seedPhrase) == "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong")
        #expect(try await s.revealTier2(itemID: items[1].id, field: .privateKey) == "FAKE-priv")
        #expect(await s.integrityWarnings.isEmpty)
        #expect(await s.currentHeader.kdf == .testing)
        _ = dir
    }
    @Test func golden_backup_still_restores() async throws {
        let (m, _, _, _) = TestEnv.makeManager()
        let data = try Data(contentsOf: Self.fixtureURL("golden-v1.privatevault"))
        let s = try await m.restoreBackup(data, password: GoldenFixture.password, recoveryKit: Self.kit)
        #expect(try await s.count() == 2)
        #expect(await s.integrityWarnings.isEmpty)
        await #expect(throws: VaultError.authenticationFailed) { _ = try await TestEnv.makeManager().0.restoreBackup(data, password: "wrong password 123456", recoveryKit: Self.kit) }
    }
    @Test func schema_migration_plan_is_ordered_and_gapless() {
        let reg = [SchemaMigration(version: 3) { _ in }, SchemaMigration(version: 2) { _ in }, SchemaMigration(version: 4) { _ in }]
        #expect(SchemaMigrations.plan(from: 1, to: 4, registry: reg).map(\.version) == [2, 3, 4])
        #expect(SchemaMigrations.plan(from: 2, to: 3, registry: reg).map(\.version) == [3])
        #expect(SchemaMigrations.plan(from: 4, to: 4, registry: reg).isEmpty)
        #expect(SchemaMigrations.isComplete(from: 1, to: 4, registry: reg))
        #expect(!SchemaMigrations.isComplete(from: 1, to: 5, registry: reg))
        #expect(SchemaMigrations.isComplete(from: 1, to: VaultStore.schemaVersion)) // shipping registry has no gaps
    }
}

@Suite("Schema/crypto version error paths", .serialized)
struct VersionPathTests {
    @Test func newer_schema_version_is_refused_and_corrupt_version_reported() async throws {
        let (m, _, _, _) = TestEnv.makeManager()
        _ = try await m.createVault(password: TestEnv.password)
        await m.lock()
        let db = try SQLiteDatabase(path: m.vaultURL.path, create: false)
        try db.run("UPDATE meta SET value = ? WHERE key = 'schema_version'") { $0.bind(1, Data([9])) }; db.close()
        await #expect(throws: VaultError.unsupportedFormat(9)) { _ = try await m.unlock(password: TestEnv.password) }
        let db2 = try SQLiteDatabase(path: m.vaultURL.path, create: false)
        try db2.run("UPDATE meta SET value = ? WHERE key = 'schema_version'") { $0.bind(1, Data([1, 2])) }; db2.close()
        await #expect(throws: VaultError.corrupted("schema_version")) { _ = try await m.unlock(password: TestEnv.password) }
        let db3 = try SQLiteDatabase(path: m.vaultURL.path, create: false)
        try db3.exec("DELETE FROM meta"); db3.close()
        await #expect(throws: VaultError.corrupted("schema_version")) { _ = try await m.unlock(password: TestEnv.password) }
    }
    @Test func unknown_record_crypto_version_aborts_unlock() async throws {
        let (m, _, _, _) = TestEnv.makeManager()
        let s = try await m.createVault(password: TestEnv.password).session
        try await s.save(TestEnv.sampleItems()[0])
        await m.lock()
        let db = try SQLiteDatabase(path: m.vaultURL.path, create: false)
        try db.exec("UPDATE records SET crypto_version = 2"); db.close()
        await #expect(throws: VaultError.unsupportedFormat(2)) { _ = try await m.unlock(password: TestEnv.password) }
    }
}
