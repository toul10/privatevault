import Foundation
import CryptoKit

/// Record envelope (SECURITY_ARCHITECTURE.md §4.2–4.3) and tier-2 inner box (§4.4).
public enum RecordCipher {
    public static let currentCryptoVersion: UInt32 = 1
    public static let minBlobLength = 1 + 12 + 16 + 4 // version + nonce + tag + length prefix (empty payload)

    // MARK: AAD
    public static func recordAAD(vaultID: UUID, recordID: UUID, cryptoVersion: UInt32, revision: UInt64) -> Data {
        var w = ByteWriter()
        w.ascii("record"); w.raw(vaultID.rawBytes); w.raw(recordID.rawBytes); w.u32be(cryptoVersion); w.u64be(revision)
        return w.data
    }
    public static func tier2AAD(vaultID: UUID, recordID: UUID, field: String) -> Data {
        var w = ByteWriter()
        w.ascii("tier2"); w.raw(vaultID.rawBytes); w.raw(recordID.rawBytes); w.raw(Data(field.utf8))
        return w.data
    }

    // MARK: Padding
    /// [u32be length][payload][zeros] padded to 256 B steps up to 4 KiB, then 4 KiB steps.
    public static func pad(_ payload: Data) -> Data {
        let raw = 4 + payload.count
        let step = raw <= 4096 ? 256 : 4096
        let padded = ((raw + step - 1) / step) * step
        var w = ByteWriter()
        w.u32be(UInt32(payload.count)); w.raw(payload)
        var out = w.data
        out.append(Data(count: padded - raw))
        return out
    }
    public static func unpad(_ padded: Data) throws -> Data {
        var r = ByteReader(padded)
        let n = Int(try r.u32be())
        guard n <= r.remaining else { throw VaultError.corrupted("pad length") }
        let payload = try r.rawData(n)
        // remaining bytes must be zero
        guard (try r.raw(r.remaining)).allSatisfy({ $0 == 0 }) else { throw VaultError.corrupted("pad bytes") }
        return payload
    }

    // MARK: Envelope
    public static func seal(payload: Data, key: SymmetricKey, aad: Data) throws -> Data {
        let box = try AES.GCM.seal(pad(payload), using: key, nonce: AES.GCM.Nonce(), authenticating: aad)
        guard let combined = box.combined else { throw VaultError.corrupted("seal") }
        return Data([UInt8(currentCryptoVersion)]) + combined
    }
    /// Opens a version-1 blob. Tampering of any byte ⇒ `authenticationFailed`.
    public static func open(blob: Data, key: SymmetricKey, aad: Data) throws -> Data {
        guard blob.count >= minBlobLength, blob.first == UInt8(currentCryptoVersion) else { throw VaultError.authenticationFailed }
        let box: AES.GCM.SealedBox
        do { box = try AES.GCM.SealedBox(combined: blob.dropFirst()) } catch { throw VaultError.authenticationFailed }
        let padded: Data
        do { padded = try AES.GCM.open(box, using: key, authenticating: aad) } catch { throw VaultError.authenticationFailed }
        return try unpad(padded)
    }

    // MARK: Tier-2 inner box (no padding: the outer envelope is padded)
    public static func sealTier2(plaintext: Data, key: SymmetricKey, aad: Data) throws -> Data {
        let box = try AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce(), authenticating: aad)
        guard let combined = box.combined else { throw VaultError.corrupted("seal") }
        return Data([0x01]) + combined
    }
    public static func openTier2(box blob: Data, key: SymmetricKey, aad: Data) throws -> Data {
        guard blob.count >= 1 + 12 + 16, blob.first == 0x01 else { throw VaultError.authenticationFailed }
        do {
            let box = try AES.GCM.SealedBox(combined: blob.dropFirst())
            return try AES.GCM.open(box, using: key, authenticating: aad)
        } catch { throw VaultError.authenticationFailed }
    }
}
