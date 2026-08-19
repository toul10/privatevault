import Foundation
import CryptoKit

/// Turns `VaultItem` ⇄ `EncryptedRecord` using the vault keys (SECURITY_ARCHITECTURE.md §4).
/// The only place that creates JSON encoders/decoders for secret-bearing models.
public struct RecordCodec: Sendable {
    public let keys: VaultKeys
    public init(keys: VaultKeys) { self.keys = keys }

    static func makeEncoder() -> JSONEncoder {
        let e = JSONEncoder()
        e.userInfo[.vaultBlobCodec] = true
        e.dateEncodingStrategy = .secondsSince1970
        e.outputFormatting = [.sortedKeys]
        return e
    }
    static func makeDecoder() -> JSONDecoder {
        let d = JSONDecoder()
        d.userInfo[.vaultBlobCodec] = true
        d.dateDecodingStrategy = .secondsSince1970
        return d
    }

    /// Encrypts an item at the given revision. Any tier-2 `.plaintext` value is sealed into an inner box first.
    public func seal(_ item: VaultItem, revision: UInt64) throws -> EncryptedRecord {
        let prepared = try sealTier2(in: item)
        let json = try Self.makeEncoder().encode(prepared)
        let aad = RecordCipher.recordAAD(vaultID: keys.vaultID, recordID: item.id, cryptoVersion: RecordCipher.currentCryptoVersion, revision: revision)
        let blob = try RecordCipher.seal(payload: json, key: keys.recordKey(for: item.id), aad: aad)
        return EncryptedRecord(id: item.id, cryptoVersion: RecordCipher.currentCryptoVersion, revision: revision, blob: blob)
    }

    /// Decrypts the outer envelope. Tier-2 fields stay sealed. The decoded item's id must match the record id.
    public func open(_ record: EncryptedRecord) throws -> VaultItem {
        guard record.cryptoVersion == RecordCipher.currentCryptoVersion else { throw VaultError.unsupportedFormat(UInt8(truncatingIfNeeded: record.cryptoVersion)) }
        let aad = RecordCipher.recordAAD(vaultID: keys.vaultID, recordID: record.id, cryptoVersion: record.cryptoVersion, revision: record.revision)
        let json = try RecordCipher.open(blob: record.blob, key: keys.recordKey(for: record.id), aad: aad)
        let item: VaultItem
        do { item = try Self.makeDecoder().decode(VaultItem.self, from: json) } catch { throw VaultError.corrupted("record json") }
        guard item.id == record.id else { throw VaultError.authenticationFailed }
        return item
    }

    // MARK: tier-2
    public enum Tier2Field: String, Sendable { case seedPhrase, privateKey }

    func sealTier2(in item: VaultItem) throws -> VaultItem {
        guard case .wallet(var w) = item.payload else { return item }
        w.seedPhrase = try sealIfNeeded(w.seedPhrase, item: item, field: .seedPhrase)
        w.privateKey = try sealIfNeeded(w.privateKey, item: item, field: .privateKey)
        var copy = item; copy.payload = .wallet(w)
        return copy
    }
    private func sealIfNeeded(_ v: Tier2Value?, item: VaultItem, field: Tier2Field) throws -> Tier2Value? {
        guard let v else { return nil }
        switch v {
        case .sealed: return v
        case .plaintext(let s):
            if s.value.isEmpty { return nil }
            let aad = RecordCipher.tier2AAD(vaultID: keys.vaultID, recordID: item.id, field: field.rawValue)
            return .sealed(try RecordCipher.sealTier2(plaintext: Data(s.value.utf8), key: keys.tier2Key, aad: aad))
        }
    }
    /// Opens one tier-2 box for display. The caller is responsible for dropping the result promptly.
    public func openTier2(_ value: Tier2Value, itemID: UUID, field: Tier2Field) throws -> String {
        switch value {
        case .plaintext(let s): return s.value
        case .sealed(let box):
            let aad = RecordCipher.tier2AAD(vaultID: keys.vaultID, recordID: itemID, field: field.rawValue)
            let pt = try RecordCipher.openTier2(box: box, key: keys.tier2Key, aad: aad)
            guard let s = String(data: pt, encoding: .utf8) else { throw VaultError.corrupted("tier2 utf8") }
            return s
        }
    }
    /// Re-seals all tier-2 boxes of an item under a different codec (used by key rotation).
    public func reseal(_ item: VaultItem, into other: RecordCodec) throws -> VaultItem {
        guard case .wallet(var w) = item.payload else { return item }
        if let s = w.seedPhrase { w.seedPhrase = .plaintext(Secret(try openTier2(s, itemID: item.id, field: .seedPhrase))) }
        if let p = w.privateKey { w.privateKey = .plaintext(Secret(try openTier2(p, itemID: item.id, field: .privateKey))) }
        var copy = item; copy.payload = .wallet(w)
        return try other.sealTier2(in: copy)
    }
}
