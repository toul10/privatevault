import Foundation
import CryptoKit

/// The non-secret vault header (SECURITY_ARCHITECTURE.md §3). Its canonical byte encoding is the AAD of the
/// wrapped VMK and the preimage of `headerSHA256`. Every field here is public information.
public struct VaultHeader: Equatable, Sendable {
    public static let magic: StaticString = "PVLT"
    public static let currentFormat: UInt8 = 1
    public static let kdfArgon2id13: UInt8 = 1
    public static let wrapAESGCM256: UInt8 = 1

    public var format: UInt8
    public var vaultID: UUID
    public var kdfID: UInt8
    public var kdf: KDFParameters
    public var salt: Data
    public var passwordNormalization: UInt8
    public var wrapAlgorithm: UInt8
    public var generation: UInt32
    public var createdAt: Int64

    public init(format: UInt8 = VaultHeader.currentFormat, vaultID: UUID, kdfID: UInt8 = VaultHeader.kdfArgon2id13,
                kdf: KDFParameters, salt: Data, passwordNormalization: UInt8 = PasswordNormalization.currentID,
                wrapAlgorithm: UInt8 = VaultHeader.wrapAESGCM256, generation: UInt32, createdAt: Int64) {
        self.format = format; self.vaultID = vaultID; self.kdfID = kdfID; self.kdf = kdf; self.salt = salt
        self.passwordNormalization = passwordNormalization; self.wrapAlgorithm = wrapAlgorithm
        self.generation = generation; self.createdAt = createdAt
    }

    /// Fresh header for a new vault.
    public static func new(vaultID: UUID = SecureRandom.uuid(), kdf: KDFParameters = .current, now: Date = Date()) -> VaultHeader {
        VaultHeader(vaultID: vaultID, kdf: kdf, salt: SecureRandom.bytes(Argon2id.saltLength),
                    generation: 1, createdAt: Int64(now.timeIntervalSince1970))
    }

    /// Exactly the bytes of §3.1.
    public var canonicalBytes: Data {
        var w = ByteWriter()
        w.ascii(Self.magic)
        w.u8(format)
        w.raw(vaultID.rawBytes)
        w.u8(kdfID)
        w.u32be(kdf.memoryKiB)
        w.u32be(kdf.passes)
        w.u8(kdf.lanes)
        w.u8(UInt8(salt.count))
        w.raw(salt)
        w.u8(passwordNormalization)
        w.u8(wrapAlgorithm)
        w.u32be(generation)
        w.i64be(createdAt)
        return w.data
    }

    /// Parses and VALIDATES untrusted canonical bytes. Rejects unknown formats/algorithms and out-of-bounds KDF
    /// parameters before any memory is allocated for key derivation.
    public static func parse(canonical: Data) throws -> VaultHeader {
        guard canonical.count <= 256 else { throw VaultError.invalidHeader("header too large") }
        var r = ByteReader(canonical)
        do {
            try r.expectASCII(magic)
        } catch { throw VaultError.invalidHeader("bad magic") }
        let format = try r.u8()
        guard format != 0 else { throw VaultError.invalidHeader("format 0") }
        guard format <= currentFormat else { throw VaultError.unsupportedFormat(format) }
        guard let vaultID = UUID(rawBytes: try r.rawData(16)) else { throw VaultError.invalidHeader("vault id") }
        let kdfID = try r.u8()
        guard kdfID == kdfArgon2id13 else { throw VaultError.invalidHeader("unknown KDF") }
        let m = try r.u32be(); let t = try r.u32be(); let p = try r.u8()
        let kdf = KDFParameters(memoryKiB: m, passes: t, lanes: p)
        try kdf.validateHardBounds()
        let saltLen = Int(try r.u8())
        guard saltLen == Argon2id.saltLength else { throw VaultError.invalidHeader("salt length") }
        let salt = try r.rawData(saltLen)
        let norm = try r.u8()
        guard norm == PasswordNormalization.currentID else { throw VaultError.invalidHeader("unknown password normalization") }
        let wrap = try r.u8()
        guard wrap == wrapAESGCM256 else { throw VaultError.invalidHeader("unknown wrap algorithm") }
        let gen = try r.u32be()
        guard gen >= 1 else { throw VaultError.invalidHeader("generation") }
        let created = try r.i64be()
        guard r.isAtEnd else { throw VaultError.invalidHeader("trailing bytes") }
        return VaultHeader(format: format, vaultID: vaultID, kdfID: kdfID, kdf: kdf, salt: salt,
                           passwordNormalization: norm, wrapAlgorithm: wrap, generation: gen, createdAt: created)
    }

    /// Unkeyed integrity checksum (UX only, see §3.3).
    public static func sha256(canonical: Data, wrappedVMK: Data) -> Data {
        Data(SHA256.hash(data: canonical + wrappedVMK))
    }
}
