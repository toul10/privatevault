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
    private var revisions: [UUID: UInt64] = [:]
    public private(set) var integrityWarnings: [IntegrityWarning] = []
    public let unlockedAt: Date

    init(store: VaultStore, keys: VaultKeys, header: VaultHeader, stored: StoredHeader, pinnedGeneration: UInt32?) async throws {
        self.store = store; self.keys = keys; self.codec = RecordCodec(keys: keys)
        self.header = header; self.stored = stored; self.vaultID = header.vaultID
        self.unlockedAt = Date()
        try await loadAndVerify(pinnedGeneration: pinnedGeneration)
    }

    private func loadAndVerify(pinnedGeneration: UInt32?) async throws {
        guard let keys, let codec else { throw VaultError.vaultLocked }
        let records = try await store.allRecords()
        var loaded: [UUID: VaultItem] = [:], revs: [UUID: UInt64] = [:]
        for r in records {
            let item = try codec.open(r)   // any tampering ⇒ authenticationFailed (unlock fails)
            loaded[item.id] = item; revs[r.id] = r.revision
        }
        items = loaded; revisions = revs
        var warnings: [IntegrityWarning] = []
        if !VaultState.verify(stored.stateMAC, key: keys.vaultStateKey, vaultID: vaultID, generation: header.generation, entries: entries()) {
            warnings.append(.recordStateMismatch)
        }
        if let pinned = pinnedGeneration, header.generation < pinned { warnings.append(.generationRollback) }
        integrityWarnings = warnings
        if !warnings.isEmpty { SecureLog.notice(.vault, "integrity warning on unlock", .count(warnings.count)) }
        SecureLog.log(.vault, "vault unlocked", .count(items.count))
    }

    func addIntegrityWarning(_ w: IntegrityWarning) { if !integrityWarnings.contains(w) { integrityWarnings.append(w) } }
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
    public func count() throws -> Int { _ = try requireKeys(); return items.count }

    /// Local, in-memory search over decrypted non-tier-2 fields.
    public func search(_ query: String) throws -> [VaultItem] {
        let all = try allItems()
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !q.isEmpty else { return all }
        return all.filter { item in
            var hay: [String] = [item.title] + item.tags
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
        let revision = (revisions[item.id] ?? 0) + 1
        let record = try codec.seal(item, revision: revision)
        // the in-memory copy keeps tier-2 sealed (never plaintext)
        let stored = try codec.open(record)
        var newRevs = revisions; newRevs[item.id] = revision
        let mac = VaultState.mac(key: keys.vaultStateKey, vaultID: vaultID, generation: header.generation, entries: newRevs.map { (id: $0.key, revision: $0.value) })
        try await store.commit(upserts: [record], deletes: [], stateMAC: mac)
        items[item.id] = stored; revisions = newRevs; self.stored.stateMAC = mac
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
        SecureLog.log(.vault, "item deleted")
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
    func exportRecords() async throws -> [EncryptedRecord] { _ = try requireKeys(); return try await store.allRecords() }
    func stateEntries() throws -> [(id: UUID, revision: UInt64)] { _ = try requireKeys(); return entries() }
    func currentKeys() throws -> VaultKeys { try requireKeys().0 }
    func currentCodec() throws -> RecordCodec { try requireKeys().1 }
    func replaceHeader(_ newHeader: VaultHeader, stored newStored: StoredHeader) { header = newHeader; stored = newStored }
    /// Re-encrypt everything under new keys (rotation). Returns the new records; caller persists them with the header.
    func reencryptAll(under newKeys: VaultKeys, generation: UInt32) throws -> (records: [EncryptedRecord], stateMAC: Data, revisions: [UUID: UInt64]) {
        let (_, oldCodec) = try requireKeys()
        let newCodec = RecordCodec(keys: newKeys)
        var out: [EncryptedRecord] = []; var newRevs: [UUID: UInt64] = [:]
        for (id, item) in items {
            let resealed = try oldCodec.reseal(item, into: newCodec)
            let rev = (revisions[id] ?? 0) + 1
            out.append(try newCodec.seal(resealed, revision: rev)); newRevs[id] = rev
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
        var loaded: [UUID: VaultItem] = [:], revs: [UUID: UInt64] = [:]
        for r in records { let item = try codec.open(r); loaded[item.id] = item; revs[r.id] = r.revision }
        items = loaded; revisions = revs
    }

    /// Drops every key and all decrypted data. Idempotent.
    public func lock() {
        keys?.wipe()
        keys = nil; codec = nil
        items.removeAll(); revisions.removeAll()
        SecureLog.log(.vault, "vault locked")
    }
}
