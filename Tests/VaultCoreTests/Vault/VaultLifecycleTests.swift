import Testing
import Foundation
@testable import VaultCore

@Suite("Vault lifecycle: create, unlock, items, lock, tamper detection", .serialized)
struct VaultLifecycleTests {
    @Test func create_unlock_roundtrip_all_item_kinds() async throws {
        let (m, _, _, dir) = TestEnv.makeManager()
        let created = try await m.createVault(password: TestEnv.password)
        #expect(created.secretKeyStoredOnDevice)
        for item in TestEnv.sampleItems() { try await created.session.save(item) }
        #expect(try await created.session.count() == 5)
        await m.lock()
        #expect(await !m.isUnlocked)

        let s = try await m.unlock(password: TestEnv.password)
        let items = try await s.allItems()
        #expect(items.count == 5)
        #expect(items.map(\.title).sorted() == TestEnv.sampleItems().map(\.title).sorted())
        #expect(await s.integrityWarnings.isEmpty)
        // login payload intact
        let login = items.first { $0.title == "Binance" }!
        guard case .login(let p) = login.payload else { Issue.record("not login"); return }
        #expect(p.username == "kostas@example.com"); #expect(p.password.value == "FAKE-login-pass-Q9z!")
        // wallet tier-2 stays sealed in memory and reveals correctly
        let wallet = items.first { $0.title == "Main wallet" }!
        guard case .wallet(let w) = wallet.payload else { Issue.record("not wallet"); return }
        #expect(w.seedPhrase?.isSealed == true); #expect(w.privateKey?.isSealed == true)
        #expect(w.publicAddress.hasPrefix("0xFAKE"))
        #expect(try await s.revealTier2(itemID: wallet.id, field: .seedPhrase)?.hasPrefix("abandon abandon") == true)
        #expect(try await s.revealTier2(itemID: wallet.id, field: .privateKey)?.hasPrefix("0xFAKEPRIVATEKEY") == true)
        // no plaintext anywhere in the vault directory
        #expect(TestEnv.directoryContains(dir, anyOf: TestEnv.sentinels).isEmpty)
        // file permissions
        let attrs = try FileManager.default.attributesOfItem(atPath: m.vaultURL.path)
        #expect((attrs[.posixPermissions] as? Int) == 0o600)
    }

    @Test func wrong_password_wrong_kit_missing_kit() async throws {
        let (m, store, enclave, dir) = TestEnv.makeManager()
        let created = try await m.createVault(password: TestEnv.password)
        let kit = RecoveryKit.encode(created.secretKey)
        await m.lock()
        await #expect(throws: VaultError.authenticationFailed) { _ = try await m.unlock(password: TestEnv.otherPassword) }
        await #expect(throws: VaultError.authenticationFailed) { _ = try await m.unlock(password: TestEnv.password + " ") }
        // Secret Key gone from device ⇒ must present Recovery Kit
        let vaultID = try await m.unlock(password: TestEnv.password).currentHeader.vaultID
        await m.lock()
        try m.deviceKeys.deleteSecretKey(vaultID: vaultID)
        await #expect(throws: VaultError.secretKeyRequired) { _ = try await m.unlock(password: TestEnv.password) }
        // wrong kit (valid format, different key) is reported as such, before the KDF runs
        let otherKit = RecoveryKit.encode(SecretKey.generate())
        await #expect(throws: VaultError.recoveryKitInvalid("this Recovery Kit does not belong to this vault")) { _ = try await m.unlock(password: TestEnv.password, recoveryKit: otherKit) }
        // right kit + wrong password
        await #expect(throws: VaultError.authenticationFailed) { _ = try await m.unlock(password: TestEnv.otherPassword, recoveryKit: kit) }
        // right kit + right password ⇒ unlocked, and SK re-stored on device
        _ = try await m.unlock(password: TestEnv.password, recoveryKit: kit)
        await m.lock()
        _ = try await m.unlock(password: TestEnv.password)
        // simulate a new Mac: SE forgets all keys ⇒ stored SK unusable ⇒ secretKeyRequired
        await m.lock()
        enclave.forgetAllKeys = true
        await #expect(throws: VaultError.secretKeyRequired) { _ = try await m.unlock(password: TestEnv.password) }
        enclave.forgetAllKeys = false
        _ = store; _ = dir
    }

    @Test func secret_key_is_only_stored_secure_enclave_wrapped() async throws {
        let (m, store, _, _) = TestEnv.makeManager()
        let created = try await m.createVault(password: TestEnv.password)
        let skBytes = created.secretKey.bytes.copyData()
        for account in store.allAccounts {
            let raw = store.rawValue(account)!
            #expect(raw.range(of: skBytes) == nil)
            #expect(raw.range(of: Data(RecoveryKit.encode(created.secretKey).utf8)) == nil)
        }
        #expect(store.allAccounts.count == 1)
    }

    @Test func keychain_unavailable_means_recovery_kit_each_time_and_no_disk_fallback() async throws {
        let store = InMemorySecretStore(); store.unavailable = true
        let (m, _, _, dir) = TestEnv.makeManager(store: store)
        let created = try await m.createVault(password: TestEnv.password)
        #expect(!created.secretKeyStoredOnDevice)
        let kit = RecoveryKit.encode(created.secretKey)
        try await created.session.save(TestEnv.sampleItems()[0])
        await m.lock()
        await #expect(throws: VaultError.secretKeyRequired) { _ = try await m.unlock(password: TestEnv.password) }
        _ = try await m.unlock(password: TestEnv.password, recoveryKit: kit)
        // the SK must not have been written anywhere in the vault directory
        let skHex = created.secretKey.bytes.copyData().hexString
        #expect(TestEnv.directoryContains(dir, anyOf: [kit, skHex]).isEmpty)
        let files = (FileManager.default.enumerator(at: dir, includingPropertiesForKeys: nil)?.allObjects as? [URL]) ?? []
        for f in files { if let d = try? Data(contentsOf: f) { #expect(d.range(of: created.secretKey.bytes.copyData()) == nil) } }
    }

    @Test func no_secure_enclave_degrades_to_raw_keychain_storage_and_still_works() async throws {
        let enclave = FakeSecureEnclave(); enclave.available = false
        let (m, store, _, _) = TestEnv.makeManager(enclave: enclave)
        let created = try await m.createVault(password: TestEnv.password)
        #expect(created.secretKeyStoredOnDevice)
        #expect(!m.deviceKeys.secretKeyIsHardwareBound)
        await m.lock()
        _ = try await m.unlock(password: TestEnv.password)
        await #expect(throws: VaultError.secureEnclaveUnavailable) { try await m.enableBiometricUnlock() }
        _ = store
    }

    @Test func lock_drops_keys_and_blocks_access() async throws {
        let (m, _, _, _) = TestEnv.makeManager()
        let created = try await m.createVault(password: TestEnv.password)
        let s = created.session
        try await s.save(TestEnv.sampleItems()[0])
        let keys = try await s.currentKeys()
        await m.lock()
        #expect(await s.isLocked)
        #expect(keys.vmk.copyData() == Data(count: 32)) // wiped
        await #expect(throws: VaultError.vaultLocked) { _ = try await s.allItems() }
        await #expect(throws: VaultError.vaultLocked) { _ = try await s.save(TestEnv.sampleItems()[1]) }
        await #expect(throws: VaultError.vaultLocked) { _ = try await s.revealTier2(itemID: UUID(), field: .seedPhrase) }
        await #expect(throws: VaultError.vaultLocked) { _ = try await m.exportBackup(password: TestEnv.password) }
    }

    @Test func tampering_with_records_or_header_is_detected() async throws {
        let (m, _, _, _) = TestEnv.makeManager()
        let created = try await m.createVault(password: TestEnv.password)
        for item in TestEnv.sampleItems() { try await created.session.save(item) }
        await m.lock()
        let path = m.vaultURL.path
        // 1) flip a byte inside a record blob ⇒ unlock fails (authentication)
        let db = try SQLiteDatabase(path: path, create: false)
        let rows = try db.query("SELECT id, blob FROM records LIMIT 1", bind: { _ in }) { ($0.blob(0), $0.blob(1)) }
        var blob = rows[0].1; blob[blob.count / 2] ^= 0x01
        try db.run("UPDATE records SET blob = ? WHERE id = ?") { $0.bind(1, blob); $0.bind(2, rows[0].0) }
        db.close()
        await #expect(throws: VaultError.authenticationFailed) { _ = try await m.unlock(password: TestEnv.password) }
        // restore the blob, then 2) swap two records' blobs ⇒ fails (AAD binds record id)
        let db2 = try SQLiteDatabase(path: path, create: false)
        try db2.run("UPDATE records SET blob = ? WHERE id = ?") { $0.bind(1, rows[0].1); $0.bind(2, rows[0].0) }
        let two = try db2.query("SELECT id, blob FROM records LIMIT 2", bind: { _ in }) { ($0.blob(0), $0.blob(1)) }
        try db2.run("UPDATE records SET blob = ? WHERE id = ?") { $0.bind(1, two[1].1); $0.bind(2, two[0].0) }
        try db2.run("UPDATE records SET blob = ? WHERE id = ?") { $0.bind(1, two[0].1); $0.bind(2, two[1].0) }
        db2.close()
        await #expect(throws: VaultError.authenticationFailed) { _ = try await m.unlock(password: TestEnv.password) }
        let db3 = try SQLiteDatabase(path: path, create: false)
        try db3.run("UPDATE records SET blob = ? WHERE id = ?") { $0.bind(1, two[0].1); $0.bind(2, two[0].0) }
        try db3.run("UPDATE records SET blob = ? WHERE id = ?") { $0.bind(1, two[1].1); $0.bind(2, two[1].0) }
        // 3) delete a record row behind the app's back ⇒ unlock succeeds with an integrity warning
        try db3.run("DELETE FROM records WHERE id = ?") { $0.bind(1, two[1].0) }
        db3.close()
        let s = try await m.unlock(password: TestEnv.password)
        #expect(await s.integrityWarnings == [.recordStateMismatch])
        #expect(try await s.count() == 4)
        await m.lock()
        // 4) tamper with the header's KDF params (downgrade) ⇒ authentication fails
        let db4 = try SQLiteDatabase(path: path, create: false)
        let hdr = try db4.query("SELECT canonical FROM vault_header", bind: { _ in }) { $0.blob(0) }[0]
        var h = try VaultHeader.parse(canonical: hdr); h.kdf = KDFParameters(memoryKiB: 8192, passes: 2, lanes: 1)
        try db4.run("UPDATE vault_header SET canonical = ?") { $0.bind(1, h.canonicalBytes) }
        db4.close()
        await #expect(throws: VaultError.authenticationFailed) { _ = try await m.unlock(password: TestEnv.password) }
        // 5) absurd KDF params ⇒ rejected before any allocation (invalidHeader, not a crash or a hang)
        let db5 = try SQLiteDatabase(path: path, create: false)
        var huge = try VaultHeader.parse(canonical: hdr); huge.kdf = KDFParameters(memoryKiB: 4 * 1024 * 1024, passes: 3, lanes: 1)
        try db5.run("UPDATE vault_header SET canonical = ?") { $0.bind(1, huge.canonicalBytes) }
        db5.close()
        await #expect(throws: VaultError.invalidHeader("KDF parameters out of bounds")) { _ = try await m.unlock(password: TestEnv.password) }
        // 6) newer format version ⇒ unsupportedFormat
        let db6 = try SQLiteDatabase(path: path, create: false)
        var newer = try VaultHeader.parse(canonical: hdr); newer.format = 9
        try db6.run("UPDATE vault_header SET canonical = ?") { $0.bind(1, newer.canonicalBytes) }
        db6.close()
        await #expect(throws: VaultError.unsupportedFormat(9)) { _ = try await m.unlock(password: TestEnv.password) }
    }

    @Test func whole_file_rollback_is_detected_via_pinned_generation() async throws {
        let (m, _, _, _) = TestEnv.makeManager()
        let created = try await m.createVault(password: TestEnv.password)
        try await created.session.save(TestEnv.sampleItems()[0])
        await m.lock()
        let old = try Data(contentsOf: m.vaultURL)
        _ = try await m.unlock(password: TestEnv.password)
        try await m.changePassword(current: TestEnv.password, new: TestEnv.otherPassword) // generation 2
        await m.lock()
        try old.write(to: m.vaultURL) // attacker/restores an older copy
        let s = try await m.unlock(password: TestEnv.password) // old password works on the old copy…
        #expect(await s.integrityWarnings.contains(.generationRollback)) // …but the app notices
    }

    @Test func database_corruption_is_reported_not_crashing() async throws {
        let (m, _, _, _) = TestEnv.makeManager()
        _ = try await m.createVault(password: TestEnv.password)
        await m.lock()
        let url = m.vaultURL
        // truncated file
        let data = try Data(contentsOf: url)
        try data.prefix(data.count / 2).write(to: url)
        await #expect(throws: VaultError.self) { _ = try await m.unlock(password: TestEnv.password) }
        // random bytes
        try SecureRandom.bytes(4096).write(to: url)
        await #expect(throws: VaultError.self) { _ = try await m.unlock(password: TestEnv.password) }
        // empty file
        try Data().write(to: url)
        await #expect(throws: VaultError.self) { _ = try await m.unlock(password: TestEnv.password) }
        // valid db, missing header row
        try data.write(to: url)
        let db = try SQLiteDatabase(path: url.path, create: false)
        try db.exec("DELETE FROM vault_header"); db.close()
        await #expect(throws: VaultError.corrupted("header row")) { _ = try await m.unlock(password: TestEnv.password) }
    }

    @Test func secrets_never_appear_in_logs_or_serialisation() async throws {
        SecureLog.sink.clear()
        let (m, _, _, _) = TestEnv.makeManager()
        let created = try await m.createVault(password: TestEnv.password)
        for item in TestEnv.sampleItems() { try await created.session.save(item) }
        let wallet = try await created.session.allItems().first { $0.kind == .wallet }!
        _ = try await created.session.revealTier2(itemID: wallet.id, field: .seedPhrase)
        _ = try await m.exportBackup(password: TestEnv.password)
        try await m.changePassword(current: TestEnv.password, new: TestEnv.otherPassword)
        await m.lock()
        await #expect(throws: VaultError.authenticationFailed) { _ = try await m.unlock(password: TestEnv.password) }
        _ = try await m.unlock(password: TestEnv.otherPassword)
        let lines = SecureLog.sink.snapshot().joined(separator: "\n")
        for s in TestEnv.sentinels + [TestEnv.password, TestEnv.otherPassword, RecoveryKit.encode(created.secretKey)] {
            #expect(!lines.contains(s), "log leaked \(s.prefix(8))…")
        }
        // models refuse to serialise outside the vault codec
        #expect(throws: (any Error).self) { _ = try JSONEncoder().encode(TestEnv.sampleItems()[0]) }
        #expect(throws: (any Error).self) { _ = try JSONEncoder().encode(Secret("x")) }
        #expect(throws: (any Error).self) { _ = try JSONEncoder().encode(Tier2Value.plaintext(Secret("x"))) }
        // textual representations are redacted
        let item = TestEnv.sampleItems()[2]
        for text in ["\(item)", String(reflecting: item), "\(Secret("s3cret"))", String(reflecting: Tier2Value.plaintext(Secret("seed")))] {
            for s in ["s3cret", "seed", "Main", "abandon", "0xFAKE"] { #expect(!text.contains(s)) }
        }
    }

    @Test func search_favorites_recent_and_delete() async throws {
        let (m, _, _, _) = TestEnv.makeManager()
        let s = try await m.createVault(password: TestEnv.password).session
        for item in TestEnv.sampleItems() { try await s.save(item) }
        #expect(try await s.search("binance").count == 1)
        #expect(try await s.search("KOSTAS@").count == 1)          // username
        #expect(try await s.search("0xfake").count == 1)           // public address
        #expect(try await s.search("work").count == 1)             // tag
        #expect(try await s.search("FAKE-login-pass").isEmpty)    // passwords are not searchable
        #expect(try await s.search("abandon").isEmpty)             // seed phrases are not searchable
        #expect(try await s.search("").count == 5)
        let login = try await s.search("binance")[0]
        try await s.setFavorite(login.id, true)
        #expect(try await s.item(login.id)?.favorite == true)
        try await s.markUsed(login.id)
        #expect(try await s.item(login.id)?.lastUsedAt != nil)
        try await s.delete(login.id)
        #expect(try await s.count() == 4)
        #expect(try await s.item(login.id) == nil)
        // deleted ciphertext is gone from the file (secure_delete + vacuum on next header rewrite)
        await m.lock()
        let s2 = try await m.unlock(password: TestEnv.password)
        #expect(try await s2.count() == 4)
        #expect(await s2.integrityWarnings.isEmpty)
    }

    @Test func unicode_empty_and_very_long_values() async throws {
        let (m, _, _, _) = TestEnv.makeManager()
        let s = try await m.createVault(password: TestEnv.password).session
        let long = String(repeating: "Λ", count: 1_000_000) // ~2 MB UTF-8
        let items = [
            VaultItem(title: "Ελληνικά 🔐 日本語", tags: ["τάγκ"], payload: .login(LoginPayload(website: "https://παράδειγμα.gr", username: "χρήστης@παράδειγμα.gr", password: Secret("pässwörd✓"), notes: Secret("a\u{0308}")))),
            VaultItem(title: "", payload: .secureNote(SecureNotePayload(body: Secret("")))),
            VaultItem(title: "long", payload: .secureNote(SecureNotePayload(body: Secret(long)))),
            VaultItem(title: "wallet-empty", payload: .wallet(WalletPayload(name: "", seedPhrase: .plaintext(Secret("")), privateKey: nil))),
        ]
        for i in items { try await s.save(i) }
        await m.lock()
        let s2 = try await m.unlock(password: TestEnv.password)
        let back = try await s2.allItems()
        #expect(back.count == 4)
        #expect(try await s2.search("日本語").count == 1)
        #expect(try await s2.search("παραδειγμα").count == 1) // diacritic-insensitive
        guard case .secureNote(let n) = back.first(where: { $0.title == "long" })!.payload else { return }
        #expect(n.body.value == long)
        guard case .wallet(let w) = back.first(where: { $0.title == "wallet-empty" })!.payload else { return }
        #expect(w.seedPhrase == nil) // empty tier-2 input is stored as absent
    }

    @Test func large_vault_unlocks_within_budget() async throws {
        let (m, _, _, _) = TestEnv.makeManager()
        let s = try await m.createVault(password: TestEnv.password).session
        for i in 0..<2000 {
            try await s.save(VaultItem(title: "Item \(i)", payload: .login(LoginPayload(website: "https://site\(i).example", username: "u\(i)", password: Secret("p\(i)")))))
        }
        await m.lock()
        let start = Date()
        let s2 = try await m.unlock(password: TestEnv.password)
        let elapsed = Date().timeIntervalSince(start)
        #expect(try await s2.count() == 2000)
        #expect(try await s2.search("site1999").count == 1)
        #expect(elapsed < 10, "unlock of 2000 records took \(elapsed)s")
    }
}
