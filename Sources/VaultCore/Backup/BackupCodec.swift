import Foundation
import CryptoKit

/// Encrypted backup container (`.privatevault`, SECURITY_ARCHITECTURE.md §9). Contains only ciphertext and
/// non-secret parameters; restoring requires the Master Password AND the Secret Key.
public enum BackupCodec {
    public static let format = "privatevault-backup"
    public static let version: UInt8 = 1
    public static let fileExtension = "privatevault"
    public static let maxFileBytes = 512 * 1024 * 1024
    public static let maxRecords = 1_000_000

    public struct Document: Codable, Sendable, Equatable {
        public struct Header: Codable, Sendable, Equatable { public var canonical, wrappedVMK, headerSHA256, skID: Data }
        public struct Record: Codable, Sendable, Equatable { public var id: Data; public var cryptoVersion: UInt32; public var revision: UInt64; public var blob: Data }
        public struct Manifest: Codable, Sendable, Equatable { public var nonce, ciphertext: Data }
        public var format: String
        public var version: UInt8
        public var createdAt: Int64
        public var header: Header
        public var records: [Record]
        public var manifest: Manifest
    }

    // MARK: export
    public static func export(stored: StoredHeader, records: [EncryptedRecord], keys: VaultKeys, now: Date = Date()) throws -> Data {
        let header = try stored.header()
        guard header.vaultID == keys.vaultID else { throw VaultError.invalidInput("keys do not match header") }
        let createdAt = Int64(now.timeIntervalSince1970)
        let sorted = records.sorted { $0.id.rawBytes.lexicographicallyPrecedes($1.id.rawBytes) }
        let manifestPlain = manifestBytes(headerSHA256: stored.headerSHA256, records: sorted)
        let aad = manifestAAD(vaultID: header.vaultID, createdAt: createdAt)
        let box = try AES.GCM.seal(manifestPlain, using: keys.backupManifestKey, nonce: AES.GCM.Nonce(), authenticating: aad)
        let doc = Document(format: format, version: version, createdAt: createdAt,
                           header: .init(canonical: stored.canonical, wrappedVMK: stored.wrappedVMK, headerSHA256: stored.headerSHA256, skID: stored.skID),
                           records: sorted.map { .init(id: $0.id.rawBytes, cryptoVersion: $0.cryptoVersion, revision: $0.revision, blob: $0.blob) },
                           manifest: .init(nonce: Data(box.nonce), ciphertext: box.ciphertext + box.tag))
        let enc = JSONEncoder(); enc.outputFormatting = [.sortedKeys]
        return try enc.encode(doc)
    }

    static func manifestBytes(headerSHA256: Data, records: [EncryptedRecord]) -> Data {
        var w = ByteWriter()
        w.u8(version); w.raw(headerSHA256); w.u32be(UInt32(records.count))
        for r in records { w.raw(r.id.rawBytes); w.u32be(r.cryptoVersion); w.u64be(r.revision); w.raw(Data(SHA256.hash(data: r.blob))) }
        return w.data
    }
    static func manifestAAD(vaultID: UUID, createdAt: Int64) -> Data {
        var w = ByteWriter(); w.ascii("backup"); w.u8(version); w.raw(vaultID.rawBytes); w.i64be(createdAt); return w.data
    }

    // MARK: import (two phases: parse → verify with keys)
    public struct Parsed: Sendable {
        public let header: VaultHeader
        public let stored: StoredHeader
        public let records: [EncryptedRecord]
        public let createdAtUnix: Int64
        public let document: Document
        public var createdAt: Date { Date(timeIntervalSince1970: TimeInterval(createdAtUnix)) }
    }
    /// Sane bounds for the (untrusted) creation timestamp: 2020-01-01 … 2200-01-01.
    static let minCreatedAt: Int64 = 1_577_836_800
    static let maxCreatedAt: Int64 = 7_258_118_400

    /// Structural validation of untrusted input. No cryptography, no allocation beyond the file itself.
    public static func parse(_ data: Data) throws -> Parsed {
        guard data.count <= maxFileBytes else { throw VaultError.backupInvalid("file too large") }
        let doc: Document
        do { doc = try JSONDecoder().decode(Document.self, from: data) } catch { throw VaultError.backupInvalid("not a PrivateVault backup") }
        guard doc.format == format else { throw VaultError.backupInvalid("not a PrivateVault backup") }
        guard doc.version != 0 else { throw VaultError.backupInvalid("version") }
        guard doc.version <= version else { throw VaultError.unsupportedFormat(doc.version) }
        guard doc.records.count <= maxRecords else { throw VaultError.backupInvalid("too many records") }
        guard doc.createdAt >= minCreatedAt, doc.createdAt <= maxCreatedAt else { throw VaultError.backupInvalid("creation time") }
        let header: VaultHeader
        do { header = try VaultHeader.parse(canonical: doc.header.canonical) } catch let e as VaultError {
            if case .unsupportedFormat = e { throw e }
            throw VaultError.backupInvalid("header")
        }
        guard doc.header.wrappedVMK.count == KeyHierarchy.wrappedVMKLength, doc.header.headerSHA256.count == 32, doc.header.skID.count == 4 else {
            throw VaultError.backupInvalid("header fields")
        }
        guard doc.manifest.nonce.count == 12, doc.manifest.ciphertext.count >= 16 + 1 + 32 + 4 else { throw VaultError.backupInvalid("manifest") }
        var records: [EncryptedRecord] = []
        var seen = Set<UUID>()
        for r in doc.records {
            guard let id = UUID(rawBytes: r.id), r.blob.count >= RecordCipher.minBlobLength, r.cryptoVersion == RecordCipher.currentCryptoVersion else {
                throw VaultError.backupInvalid("record")
            }
            guard seen.insert(id).inserted else { throw VaultError.backupInvalid("duplicate record") }
            records.append(EncryptedRecord(id: id, cryptoVersion: r.cryptoVersion, revision: r.revision, blob: r.blob))
        }
        let stored = StoredHeader(canonical: doc.header.canonical, wrappedVMK: doc.header.wrappedVMK, headerSHA256: doc.header.headerSHA256, skID: doc.header.skID, stateMAC: Data())
        return Parsed(header: header, stored: stored, records: records, createdAtUnix: doc.createdAt, document: doc)
    }

    /// Verifies the manifest and every record's authentication tag with the vault keys derived from MP + SK.
    /// Returns the state MAC to store so the restored vault passes its own integrity check.
    public static func verify(_ parsed: Parsed, keys: VaultKeys) throws -> Data {
        guard keys.vaultID == parsed.header.vaultID else { throw VaultError.authenticationFailed }
        let aad = manifestAAD(vaultID: parsed.header.vaultID, createdAt: parsed.createdAtUnix)
        let plain: Data
        do {
            let box = try AES.GCM.SealedBox(combined: parsed.document.manifest.nonce + parsed.document.manifest.ciphertext)
            plain = try AES.GCM.open(box, using: keys.backupManifestKey, authenticating: aad)
        } catch { throw VaultError.backupInvalid("manifest authentication failed") }
        let sorted = parsed.records.sorted { $0.id.rawBytes.lexicographicallyPrecedes($1.id.rawBytes) }
        let expected = manifestBytes(headerSHA256: parsed.stored.headerSHA256, records: sorted)
        guard expected.count == plain.count, SecureBytes(copying: expected).constantTimeEquals(plain) else {
            throw VaultError.backupInvalid("manifest mismatch (records or header altered)")
        }
        // header checksum must match the canonical+wrapped bytes (cheap corruption check)
        guard VaultHeader.sha256(canonical: parsed.stored.canonical, wrappedVMK: parsed.stored.wrappedVMK) == parsed.stored.headerSHA256 else {
            throw VaultError.backupInvalid("header checksum")
        }
        let codec = RecordCodec(keys: keys)
        for r in sorted { _ = try codec.open(r) } // authenticates every record (plaintext discarded)
        return VaultState.mac(key: keys.vaultStateKey, vaultID: parsed.header.vaultID, generation: parsed.header.generation,
                              entries: sorted.map { (id: $0.id, revision: $0.revision) })
    }
}
