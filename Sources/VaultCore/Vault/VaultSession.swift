import Foundation
import CryptoKit

/// The unlocked vault: keys in memory, decrypted items cache (tier-2 fields stay sealed), writes through the store.
/// Created only by `VaultManager`. After `lock()` every call throws `vaultLocked`.
public actor VaultSession {
    public let vaultID: UUID
    public nonisolated let store: VaultStore
    private(set) var keys: VaultKeys?
    private(set) var codec: RecordCodec?
    private(set) var header: VaultHeader
    private(set) var stored: StoredHeader
    private var items: [UUID: VaultItem] = [:]
    private var folders: [UUID: VaultFolder] = [:]
    private var revisions: [UUID: UInt64] = [:]
    /// Records whose ciphertext did not authenticate at unlock (tampered/corrupted). Kept in the store, hidden from the UI.
    public private(set) var unreadableRecordIDs: [UUID] = []
    public private(set) var integrityWarnings: [IntegrityWarning] = []
    public let unlockedAt: Date
    /// Called after every committed change with the new state MAC (the manager mirrors it to the device store).
    var onStateChanged: (@Sendable (Data) -> Void)?

    init(store: VaultStore, keys: VaultKeys, header: VaultHeader, stored: StoredHeader, warnings: [IntegrityWarning]) async throws {
        self.store = store; self.keys = keys; self.codec = RecordCodec(keys: keys)
        self.header = header; self.stored = stored; self.vaultID = header.vaultID
        self.unlockedAt = Date()
        self.integrityWarnings = warnings
        try await loadAndVerify()
    }

    private func loadAndVerify() async throws {
        guard let keys, let codec else { throw VaultError.vaultLocked }
        let records = try await store.allRecords()
        var loaded: [UUID: VaultItem] = [:], loadedFolders: [UUID: VaultFolder] = [:], revs: [UUID: UInt64] = [:], bad: [UUID] = []
        for r in records {
            revs[r.id] = r.revision
            do {
                switch try codec.openDocument(r) {
                case .item(let item): loaded[item.id] = item
                case .folder(let folder): loadedFolders[folder.id] = folder
                }
            } catch { bad.append(r.id) }   // tampered / corrupted / unknown version: quarantine, do not brick the vault
        }
        // Every record failing means the VMK is wrong for this data (stale blob) or the whole file was tampered —
        // not a partial-recovery situation.
        if !records.isEmpty && bad.count == records.count { throw VaultError.corrupted("all records unreadable") }
        items = loaded; folders = loadedFolders; revisions = revs; unreadableRecordIDs = bad
        if !bad.isEmpty { addIntegrityWarning(.unreadableRecords); SecureLog.error(.vault, "unreadable records at unlock", .count(bad.count)) }
        if !VaultState.verify(stored.stateMAC, key: keys.vaultStateKey, vaultID: vaultID, generation: header.generation, entries: entries()) {
            addIntegrityWarning(.recordStateMismatch)
        }
        if !integrityWarnings.isEmpty { SecureLog.notice(.vault, "integrity warning on unlock", .count(integrityWarnings.count)) }
        SecureLog.log(.vault, "vault unlocked", .count(items.count))
    }

    func addIntegrityWarning(_ w: IntegrityWarning) { if !integrityWarnings.contains(w) { integrityWarnings.append(w) } }
    func setStateChangedHandler(_ h: @escaping @Sendable (Data) -> Void) { onStateChanged = h }
    private func entries() -> [(id: UUID, revision: UInt64)] { revisions.map { (id: $0.key, revision: $0.value) } }
    private func requireKeys() throws -> (VaultKeys, RecordCodec) {
        guard let keys, let codec else { throw VaultError.vaultLocked }
        return (keys, codec)
    }
    private func currentStateMAC(_ keys: VaultKeys) -> Data {
        VaultState.mac(key: keys.vaultStateKey, vaultID: vaultID, generation: header.generation, entries: entries())
    }

    // MARK: read
    public var isLocked: Bool { keys == nil }
    public var currentHeader: VaultHeader { header }
    public var storedHeader: StoredHeader { stored }
    public func allItems() throws -> [VaultItem] {
        _ = try requireKeys()
        return items.values.sorted { a, b in
            a.title.localizedCaseInsensitiveCompare(b.title) == .orderedAscending || (a.title == b.title && a.id.uuidString < b.id.uuidString)
        }
    }
    public func item(_ id: UUID) throws -> VaultItem? { _ = try requireKeys(); return items[id] }
    /// Number of items (folders are not counted).
    public func count() throws -> Int { _ = try requireKeys(); return items.count }

    // MARK: folders
    public func allFolders() throws -> [VaultFolder] {
        _ = try requireKeys()
        return folders.values.sorted { a, b in
            let c = a.name.localizedCaseInsensitiveCompare(b.name)
            return c == .orderedAscending || (c == .orderedSame && a.id.uuidString < b.id.uuidString)
        }
    }
    public func folder(_ id: UUID) throws -> VaultFolder? { _ = try requireKeys(); return folders[id] }
    /// The folder an item is in, or nil when unfiled or when its folder record no longer exists.
    public func folder(of item: VaultItem) throws -> VaultFolder? {
        _ = try requireKeys()
        guard let fid = item.folderID else { return nil }
        return folders[fid]
    }
    public func items(inFolder id: UUID?) throws -> [VaultItem] {
        try allItems().filter { try folder(of: $0)?.id == id }
    }
    /// Creates a folder. Names are trimmed, bounded and unique (case-insensitive).
    @discardableResult
    public func createFolder(name rawName: String) async throws -> VaultFolder {
        _ = try requireKeys()
        let name = try VaultFolder.normalizedName(rawName)
        try ensureUniqueFolderName(name, excluding: nil)
        let folder = VaultFolder(name: name)
        try await commit(items: [], folders: [folder], deletes: [])
        SecureLog.log(.vault, "folder created")
        return folder
    }
    public func renameFolder(_ id: UUID, to rawName: String) async throws {
        _ = try requireKeys()
        guard var folder = folders[id] else { throw VaultError.invalidInput("This folder no longer exists.") }
        let name = try VaultFolder.normalizedName(rawName)
        try ensureUniqueFolderName(name, excluding: id)
        guard folder.name != name else { return }
        folder.name = name; folder.updatedAt = Date()
        try await commit(items: [], folders: [folder], deletes: [])
        SecureLog.log(.vault, "folder renamed")
    }
    /// Deletes a folder. Its items are kept: they move to `destination` (nil = no folder) in the same transaction.
    public func deleteFolder(_ id: UUID, movingItemsTo destination: UUID? = nil) async throws {
        _ = try requireKeys()
        guard folders[id] != nil else { return }
        if let destination { guard destination != id, folders[destination] != nil else { throw VaultError.invalidInput("The destination folder no longer exists.") } }
        var moved: [VaultItem] = []
        for var item in items.values where item.folderID == id { item.folderID = destination; moved.append(item) }
        try await commit(items: moved, folders: [], deletes: [id])
        SecureLog.log(.vault, "folder deleted", .count(moved.count))
    }
    /// Moves items into a folder (nil = no folder). Unknown item ids are ignored; an unknown folder is an error.
    public func moveItems(_ ids: [UUID], toFolder destination: UUID?) async throws {
        _ = try requireKeys()
        if let destination { guard folders[destination] != nil else { throw VaultError.invalidInput("This folder no longer exists.") } }
        var changed: [VaultItem] = []
        for id in Set(ids) {
            guard var item = items[id], item.folderID != destination else { continue }
            item.folderID = destination; changed.append(item)
        }
        guard !changed.isEmpty else { return }
        try await commit(items: changed, folders: [], deletes: [])
        SecureLog.log(.vault, "items moved", .count(changed.count))
    }
    private func ensureUniqueFolderName(_ name: String, excluding: UUID?) throws {
        if folders.values.contains(where: { $0.id != excluding && VaultFolder.sameName($0.name, name) }) {
            throw VaultError.invalidInput("A folder named “\(name)” already exists.")
        }
    }
    /// One transaction: seal every given item/folder at its next revision, apply deletes, write the new state MAC.
    private func commit(items changedItems: [VaultItem], folders changedFolders: [VaultFolder], deletes: [UUID]) async throws {
        let (keys, codec) = try requireKeys()
        var newRevs = revisions
        var upserts: [EncryptedRecord] = []
        var storedItems: [VaultItem] = []
        for item in changedItems {
            let rev = (newRevs[item.id] ?? 0) + 1
            let record = try codec.seal(item, revision: rev)
            storedItems.append(try codec.open(record))   // in-memory copy keeps tier-2 sealed
            upserts.append(record); newRevs[item.id] = rev
        }
        for folder in changedFolders {
            let rev = (newRevs[folder.id] ?? 0) + 1
            upserts.append(try codec.seal(folder, revision: rev)); newRevs[folder.id] = rev
        }
        for id in deletes { newRevs[id] = nil }
        let mac = VaultState.mac(key: keys.vaultStateKey, vaultID: vaultID, generation: header.generation, entries: newRevs.map { (id: $0.key, revision: $0.value) })
        try await store.commit(upserts: upserts, deletes: deletes, stateMAC: mac)
        for item in storedItems { items[item.id] = item }
        for folder in changedFolders { folders[folder.id] = folder }
        for id in deletes { items[id] = nil; folders[id] = nil }
        revisions = newRevs; self.stored.stateMAC = mac
        onStateChanged?(mac)
    }

    /// Local, in-memory search over decrypted non-tier-2 fields.
    public func search(_ query: String) throws -> [VaultItem] {
        let all = try allItems()
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !q.isEmpty else { return all }
        return all.filter { item in
            var hay: [String] = [item.title] + item.tags
            if let fid = item.folderID, let f = folders[fid] { hay.append(f.name) }
            switch item.payload {
            case .login(let p): hay += [p.website, p.username]
            case .apiCredential(let p): hay += [p.service, p.environment]
            case .wallet(let p): hay += [p.name, p.blockchain.displayName, p.publicAddress]
            case .secureNote: break
            case .recoveryCodes(let p): hay += [p.service]
            }
            return hay.contains { $0.range(of: q, options: [.caseInsensitive, .diacriticInsensitive]) != nil }
        }
    }

    // MARK: write
    /// Insert or update. Bumps the record revision, seals tier-2 plaintext, writes record + state MAC atomically.
    @discardableResult
    public func save(_ input: VaultItem, touchUpdatedAt: Bool = true) async throws -> VaultItem {
        let (keys, codec) = try requireKeys()
        var item = input
        if touchUpdatedAt { item.updatedAt = Date() }
        if let fid = item.folderID, folders[fid] == nil { item.folderID = nil }   // never persist a dangling folder reference
        guard folders[item.id] == nil else { throw VaultError.invalidInput("This id belongs to a folder.") }
        let revision = (revisions[item.id] ?? 0) + 1
        let record = try codec.seal(item, revision: revision)
        // the in-memory copy keeps tier-2 sealed (never plaintext)
        let stored = try codec.open(record)
        var newRevs = revisions; newRevs[item.id] = revision
        let mac = VaultState.mac(key: keys.vaultStateKey, vaultID: vaultID, generation: header.generation, entries: newRevs.map { (id: $0.key, revision: $0.value) })
        try await store.commit(upserts: [record], deletes: [], stateMAC: mac)
        items[item.id] = stored; revisions = newRevs; self.stored.stateMAC = mac
        onStateChanged?(mac)
        SecureLog.log(.vault, "item saved")
        return stored
    }
    public func delete(_ id: UUID) async throws {
        let (keys, _) = try requireKeys()
        guard items[id] != nil else { return }
        var newRevs = revisions; newRevs[id] = nil
        let mac = VaultState.mac(key: keys.vaultStateKey, vaultID: vaultID, generation: header.generation, entries: newRevs.map { (id: $0.key, revision: $0.value) })
        try await store.commit(upserts: [], deletes: [id], stateMAC: mac)
        items[id] = nil; revisions = newRevs; self.stored.stateMAC = mac
        onStateChanged?(mac)
        SecureLog.log(.vault, "item deleted")
    }
    /// Permanently removes the records that could not be decrypted at unlock (user-confirmed).
    public func purgeUnreadableRecords() async throws {
        let (keys, _) = try requireKeys()
        guard !unreadableRecordIDs.isEmpty else { return }
        var newRevs = revisions
        for id in unreadableRecordIDs { newRevs[id] = nil }
        let mac = VaultState.mac(key: keys.vaultStateKey, vaultID: vaultID, generation: header.generation, entries: newRevs.map { (id: $0.key, revision: $0.value) })
        try await store.commit(upserts: [], deletes: unreadableRecordIDs, stateMAC: mac)
        revisions = newRevs; self.stored.stateMAC = mac; unreadableRecordIDs = []
        integrityWarnings.removeAll { $0 == .unreadableRecords }
        onStateChanged?(mac)
        SecureLog.notice(.vault, "unreadable records purged")
    }
    public func setFavorite(_ id: UUID, _ favorite: Bool) async throws {
        guard var item = items[id] else { return }
        item.favorite = favorite
        try await save(item, touchUpdatedAt: false)
    }
    public func markUsed(_ id: UUID) async throws {
        guard var item = items[id] else { return }
        item.lastUsedAt = Date()
        try await save(item, touchUpdatedAt: false)
    }

    // MARK: tier-2
    /// Opens a seed phrase / private key for display. Caller must drop the String promptly.
    public func revealTier2(itemID: UUID, field: RecordCodec.Tier2Field) throws -> String? {
        let (_, codec) = try requireKeys()
        guard let item = items[itemID], case .wallet(let w) = item.payload else { return nil }
        let v = field == .seedPhrase ? w.seedPhrase : w.privateKey
        guard let v else { return nil }
        SecureLog.notice(.vault, "tier-2 field revealed")
        return try codec.openTier2(v, itemID: itemID, field: field)
    }

    // MARK: lifecycle / manager support
    func exportRecords() async throws -> [EncryptedRecord] {
        _ = try requireKeys()
        let bad = Set(unreadableRecordIDs)
        return try await store.allRecords().filter { !bad.contains($0.id) }
    }
    func stateEntries() throws -> [(id: UUID, revision: UInt64)] { _ = try requireKeys(); return entries() }
    func currentKeys() throws -> VaultKeys { try requireKeys().0 }
    func currentCodec() throws -> RecordCodec { try requireKeys().1 }
    func replaceHeader(_ newHeader: VaultHeader, stored newStored: StoredHeader) { header = newHeader; stored = newStored }
    /// Re-encrypt everything under new keys (rotation). Returns the new records; caller persists them with the header.
    func reencryptAll(under newKeys: VaultKeys, generation: UInt32) throws -> (records: [EncryptedRecord], stateMAC: Data, revisions: [UUID: UInt64]) {
        let (_, oldCodec) = try requireKeys()
        if !unreadableRecordIDs.isEmpty { SecureLog.notice(.vault, "rotation drops unreadable records", .count(unreadableRecordIDs.count)) }
        let newCodec = RecordCodec(keys: newKeys)
        var out: [EncryptedRecord] = []; var newRevs: [UUID: UInt64] = [:]
        for (id, item) in items {
            let resealed = try oldCodec.reseal(item, into: newCodec)
            let rev = (revisions[id] ?? 0) + 1
            out.append(try newCodec.seal(resealed, revision: rev)); newRevs[id] = rev
        }
        for (id, folder) in folders {
            let rev = (revisions[id] ?? 0) + 1
            out.append(try newCodec.seal(folder, revision: rev)); newRevs[id] = rev
        }
        let mac = VaultState.mac(key: newKeys.vaultStateKey, vaultID: vaultID, generation: generation, entries: newRevs.map { (id: $0.key, revision: $0.value) })
        return (out, mac, newRevs)
    }
    /// Switch to new keys/header after the store has been rewritten (rotation / KDF upgrade / password change).
    func adopt(keys newKeys: VaultKeys?, header newHeader: VaultHeader, stored newStored: StoredHeader) {
        if let newKeys { keys?.wipe(); keys = newKeys; codec = RecordCodec(keys: newKeys) }
        header = newHeader; stored = newStored
    }
    func reloadFromStore() async throws {
        guard let codec else { throw VaultError.vaultLocked }
        let records = try await store.allRecords()
        var loaded: [UUID: VaultItem] = [:], loadedFolders: [UUID: VaultFolder] = [:], revs: [UUID: UInt64] = [:]
        for r in records {
            switch try codec.openDocument(r) {
            case .item(let item): loaded[item.id] = item
            case .folder(let folder): loadedFolders[folder.id] = folder
            }
            revs[r.id] = r.revision
        }
        items = loaded; folders = loadedFolders; revisions = revs; unreadableRecordIDs = []
        integrityWarnings.removeAll { $0 == .unreadableRecords }
    }

    /// Drops every key and all decrypted data. Idempotent.
    public func lock() {
        keys?.wipe()
        keys = nil; codec = nil
        items.removeAll(); folders.removeAll(); revisions.removeAll()
        SecureLog.log(.vault, "vault locked")
    }
}
