import Testing
import Foundation
@testable import VaultCore

@Suite("Folders: encrypted folder records, item membership, rename/delete/move, persistence", .serialized)
struct FolderTests {
    static let folderSentinels = ["FAKE-FOLDER-Cold-Wallets", "FAKE-FOLDER-Work-Keys", "FAKE-FOLDER-Renamed"]

    private func readRecordBlobs(_ url: URL) throws -> [Data: Data] {
        let db = try SQLiteDatabase(path: url.path, create: false)
        defer { db.close() }
        return Dictionary(uniqueKeysWithValues: try db.query("SELECT id, blob FROM records", bind: { _ in }) { ($0.blob(0), $0.blob(1)) })
    }

    @Test func create_move_rename_persist_across_lock_and_unlock() async throws {
        let (m, _, _, dir) = TestEnv.makeManager()
        let s = try await m.createVault(password: TestEnv.password).session
        let cold = try await s.createFolder(name: "  FAKE-FOLDER-Cold-Wallets  ")   // trimmed
        let work = try await s.createFolder(name: "FAKE-FOLDER-Work-Keys")
        #expect(cold.name == "FAKE-FOLDER-Cold-Wallets")
        #expect(try await s.allFolders().map(\.name) == ["FAKE-FOLDER-Cold-Wallets", "FAKE-FOLDER-Work-Keys"])
        // save items straight into a folder, and move some afterwards
        var samples = TestEnv.sampleItems()
        samples[2].folderID = cold.id                        // wallet
        for item in samples { try await s.save(item) }
        try await s.moveItems([samples[1].id, samples[4].id], toFolder: work.id)   // api key + recovery codes
        try await s.moveItems([samples[1].id], toFolder: work.id)                  // no-op, already there
        #expect(try await s.items(inFolder: cold.id).map(\.title) == ["Main wallet"])
        #expect(try await s.items(inFolder: work.id).map(\.title).sorted() == ["GitHub recovery", "OpenAI key"])
        #expect(try await s.items(inFolder: nil).count == 2)
        #expect(try await s.count() == 5)                     // folders are not items
        try await s.renameFolder(cold.id, to: "FAKE-FOLDER-Renamed")
        try await s.moveItems([samples[3].id], toFolder: nil)  // already unfiled: no-op
        await m.lock()

        let s2 = try await m.unlock(password: TestEnv.password)
        #expect(await s2.integrityWarnings.isEmpty)           // folders are covered by the state MAC like items
        let folders = try await s2.allFolders()
        #expect(folders.map(\.name) == ["FAKE-FOLDER-Renamed", "FAKE-FOLDER-Work-Keys"])
        #expect(folders[0].id == cold.id)
        #expect(abs(folders[0].createdAt.timeIntervalSince(cold.createdAt)) < 0.001)   // JSON timestamp round-trip
        #expect(folders[0].updatedAt > cold.updatedAt)
        #expect(try await s2.items(inFolder: cold.id).map(\.title) == ["Main wallet"])
        #expect(try await s2.items(inFolder: work.id).count == 2)
        let wallet = try await s2.item(samples[2].id)!
        #expect(try await s2.folder(of: wallet)?.name == "FAKE-FOLDER-Renamed")
        guard case .wallet(let w) = wallet.payload else { Issue.record("wallet"); return }
        #expect(w.seedPhrase?.isSealed == true)               // moving never opens tier-2 boxes
        // nothing about folders is visible on disk
        #expect(TestEnv.directoryContains(dir, anyOf: Self.folderSentinels + ["folder", "\"doc\""]).isEmpty)
        // search finds items by their folder name
        #expect(try await s2.search("work-keys").map(\.title).sorted() == ["GitHub recovery", "OpenAI key"])
    }

    @Test func folder_name_rules_and_uniqueness() async throws {
        let (m, _, _, _) = TestEnv.makeManager()
        let s = try await m.createVault(password: TestEnv.password).session
        let a = try await s.createFolder(name: "Wallets")
        await #expect(throws: VaultError.invalidInput("The folder needs a name.")) { _ = try await s.createFolder(name: "   ") }
        await #expect(throws: VaultError.invalidInput("Folder names are limited to 64 characters.")) { _ = try await s.createFolder(name: String(repeating: "x", count: 65)) }
        await #expect(throws: VaultError.invalidInput("Folder names cannot contain line breaks.")) { _ = try await s.createFolder(name: "a\nb") }
        await #expect(throws: VaultError.invalidInput("A folder named “wallets” already exists.")) { _ = try await s.createFolder(name: "wallets") }
        await #expect(throws: VaultError.invalidInput("A folder named “WÁLLETS” already exists.")) { _ = try await s.createFolder(name: "WÁLLETS") }
        let b = try await s.createFolder(name: "Keys")
        await #expect(throws: VaultError.invalidInput("A folder named “wallets” already exists.")) { try await s.renameFolder(b.id, to: "wallets") }
        try await s.renameFolder(a.id, to: "WALLETS")           // case change of its own name is allowed
        #expect(try await s.folder(a.id)?.name == "WALLETS")
        let before = try await s.folder(a.id)!.updatedAt
        try await s.renameFolder(a.id, to: " WALLETS ")         // same name after trimming: no write
        #expect(try await s.folder(a.id)!.updatedAt == before)
        await #expect(throws: VaultError.invalidInput("This folder no longer exists.")) { try await s.renameFolder(UUID(), to: "x") }
        await #expect(throws: VaultError.invalidInput("This folder no longer exists.")) { try await s.moveItems([], toFolder: UUID()) }
        #expect(try await s.allFolders().count == 2)
    }

    @Test func deleting_a_folder_keeps_its_items_unfiled_or_moved() async throws {
        let (m, _, _, _) = TestEnv.makeManager()
        let s = try await m.createVault(password: TestEnv.password).session
        let a = try await s.createFolder(name: "A"), b = try await s.createFolder(name: "B")
        let items = TestEnv.sampleItems()
        for item in items { try await s.save(item) }
        try await s.moveItems(items.prefix(3).map(\.id), toFolder: a.id)
        try await s.moveItems([items[3].id], toFolder: b.id)
        try await s.deleteFolder(a.id)                          // → unfiled
        #expect(try await s.folder(a.id) == nil)
        #expect(try await s.items(inFolder: nil).count == 4)
        for id in items.prefix(3).map(\.id) { #expect(try await s.item(id)?.folderID == nil) }
        await #expect(throws: VaultError.invalidInput("This folder no longer exists.")) { try await s.moveItems([items[0].id], toFolder: a.id) }   // gone: refuses
        let c = try await s.createFolder(name: "C")
        try await s.deleteFolder(b.id, movingItemsTo: c.id)     // → moved
        #expect(try await s.item(items[3].id)?.folderID == c.id)
        await #expect(throws: VaultError.invalidInput("The destination folder no longer exists.")) { try await s.deleteFolder(c.id, movingItemsTo: UUID()) }
        await #expect(throws: VaultError.invalidInput("The destination folder no longer exists.")) { try await s.deleteFolder(c.id, movingItemsTo: c.id) }
        try await s.deleteFolder(UUID())                        // unknown: no-op
        #expect(try await s.count() == 5)
        await m.lock()
        let s2 = try await m.unlock(password: TestEnv.password)
        #expect(await s2.integrityWarnings.isEmpty)
        #expect(try await s2.allFolders().map(\.name) == ["C"])
        #expect(try await s2.items(inFolder: c.id).map(\.title) == ["Server notes"])
    }

    @Test func dangling_or_unreadable_folder_references_degrade_to_unfiled() async throws {
        let (m, _, _, _) = TestEnv.makeManager()
        let s = try await m.createVault(password: TestEnv.password).session
        // an item saved with an unknown folder id is stored as unfiled
        var item = TestEnv.sampleItems()[0]; item.folderID = UUID()
        let stored = try await s.save(item)
        #expect(stored.folderID == nil)
        // an item id that is a folder id is refused
        let f = try await s.createFolder(name: "F")
        await #expect(throws: VaultError.invalidInput("This id belongs to a folder.")) { try await s.save(VaultItem(id: f.id, title: "x", payload: .secureNote(SecureNotePayload()))) }
        try await s.moveItems([item.id], toFolder: f.id)
        await m.lock()
        // the folder record is tampered on disk ⇒ quarantined, vault still opens, item shows as unfiled
        let db = try SQLiteDatabase(path: m.vaultURL.path, create: false)
        var blob = try db.query("SELECT blob FROM records WHERE id = ?", bind: { $0.bind(1, f.id.rawBytes) }) { $0.blob(0) }[0]
        blob[blob.count / 2] ^= 0x55
        try db.run("UPDATE records SET blob = ? WHERE id = ?") { $0.bind(1, blob); $0.bind(2, f.id.rawBytes) }
        db.close()
        let s2 = try await m.unlock(password: TestEnv.password)
        #expect(await s2.integrityWarnings == [.unreadableRecords])
        #expect(try await s2.allFolders().isEmpty)
        let reloaded = try await s2.item(item.id)!
        #expect(reloaded.folderID == f.id)                      // the reference is kept…
        #expect(try await s2.folder(of: reloaded) == nil)       // …but resolves to "no folder"
        #expect(try await s2.items(inFolder: nil).map(\.id) == [item.id])
        try await s2.purgeUnreadableRecords()
        #expect(await s2.integrityWarnings.isEmpty)
    }

    @Test func folder_records_look_like_item_records_on_disk() async throws {
        let (m, _, _, dir) = TestEnv.makeManager()
        let s = try await m.createVault(password: TestEnv.password).session
        for item in TestEnv.sampleItems() { try await s.save(item) }
        _ = try await s.createFolder(name: "FAKE-FOLDER-Cold-Wallets")
        _ = try await s.createFolder(name: "FAKE-FOLDER-Work-Keys")
        let blobs = try readRecordBlobs(m.vaultURL)
        #expect(blobs.count == 7)
        #expect(Set(blobs.values.map(\.count)).count == 1)      // every record (5 items + 2 folders) in the same 4 KiB bucket
        #expect(TestEnv.directoryContains(dir, anyOf: Self.folderSentinels).isEmpty)
        // schema unchanged: no folder table/column anywhere
        let db = try SQLiteDatabase(path: m.vaultURL.path, create: false)
        let sql = try db.query("SELECT sql FROM sqlite_master", bind: { _ in }) { $0.text(0) }.joined(separator: "\n")
        db.close()
        #expect(!sql.lowercased().contains("folder"))
    }

    @Test func folders_survive_key_rotation_backup_and_restore() async throws {
        let (m, _, _, _) = TestEnv.makeManager()
        let created = try await m.createVault(password: TestEnv.password)
        let s = created.session
        let f = try await s.createFolder(name: "FAKE-FOLDER-Cold-Wallets")
        let items = TestEnv.sampleItems()
        for item in items { try await s.save(item) }
        try await s.moveItems([items[2].id], toFolder: f.id)
        let before = try readRecordBlobs(m.vaultURL)
        try await m.changePassword(current: TestEnv.password, new: TestEnv.otherPassword, rotateKeys: true)
        let after = try readRecordBlobs(m.vaultURL)
        #expect(Set(before.keys) == Set(after.keys))
        #expect(after[f.id.rawBytes] != before[f.id.rawBytes])   // folder record re-encrypted too
        #expect(try await s.allFolders().map(\.name) == ["FAKE-FOLDER-Cold-Wallets"])
        #expect(try await s.items(inFolder: f.id).map(\.title) == ["Main wallet"])
        let backup = try await m.exportBackup(password: TestEnv.otherPassword)
        #expect(try m.inspectBackup(backup).recordCount == 6)
        #expect(backup.range(of: Data("FAKE-FOLDER".utf8)) == nil)
        let (m2, _, _, _) = TestEnv.makeManager()
        let r = try await m2.restoreBackup(backup, password: TestEnv.otherPassword, recoveryKit: RecoveryKit.encode(created.secretKey))
        #expect(await r.integrityWarnings.isEmpty)
        #expect(try await r.allFolders().map(\.id) == [f.id])
        #expect(try await r.items(inFolder: f.id).map(\.title) == ["Main wallet"])
        #expect(try await r.revealTier2(itemID: items[2].id, field: .seedPhrase)?.hasPrefix("abandon") == true)
    }

    @Test func codec_rejects_unknown_document_tags_and_id_mismatch() async throws {
        let (m, _, _, _) = TestEnv.makeManager()
        let s = try await m.createVault(password: TestEnv.password).session
        let keys = try await s.currentKeys()
        let codec = RecordCodec(keys: keys)
        let recordID = SecureRandom.uuid()
        func sealJSON(_ json: String) throws -> EncryptedRecord {
            let aad = RecordCipher.recordAAD(vaultID: keys.vaultID, recordID: recordID, cryptoVersion: 1, revision: 1)
            return EncryptedRecord(id: recordID, cryptoVersion: 1, revision: 1, blob: try RecordCipher.seal(payload: Data(json.utf8), key: keys.recordKey(for: recordID), aad: aad))
        }
        let ts = "1755000000"
        let unknownTag = try sealJSON(#"{"doc":"weird","id":"\#(recordID.uuidString)","name":"x","createdAt":\#(ts),"updatedAt":\#(ts)}"#)
        #expect(throws: VaultError.corrupted("record json")) { _ = try codec.openDocument(unknownTag) }
        let otherID = SecureRandom.uuid()
        let mismatch = try sealJSON(#"{"doc":"folder","id":"\#(otherID.uuidString)","name":"x","createdAt":\#(ts),"updatedAt":\#(ts)}"#)
        #expect(throws: VaultError.authenticationFailed) { _ = try codec.openDocument(mismatch) }
        let good = try sealJSON(#"{"doc":"folder","id":"\#(recordID.uuidString)","name":"x","createdAt":\#(ts),"updatedAt":\#(ts)}"#)
        guard case .folder(let f) = try codec.openDocument(good) else { Issue.record("folder"); return }
        #expect(f.name == "x" && f.id == recordID)
        #expect(throws: VaultError.corrupted("expected item record")) { _ = try codec.open(good) }
        // a folder blob under someone else's record id fails authentication (AAD binding)
        let sealedFolder = try codec.seal(f, revision: 3)
        let moved = EncryptedRecord(id: otherID, cryptoVersion: 1, revision: 3, blob: sealedFolder.blob)
        #expect(throws: VaultError.authenticationFailed) { _ = try codec.openDocument(moved) }
        // models never print their contents
        #expect(String(describing: f) == "VaultFolder(<redacted>)" && String(reflecting: f) == "VaultFolder(<redacted>)")
        #expect(Mirror(reflecting: f).children.isEmpty)
        // folder JSON cannot be produced outside the record codec
        #expect(throws: (any Error).self) { _ = try JSONEncoder().encode(f) }
    }
}
