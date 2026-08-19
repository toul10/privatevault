import Foundation
import CryptoKit

/// Authenticated vault state (SECURITY_ARCHITECTURE.md §5.3): detects deleted / rolled-back records by anyone
/// who cannot unlock the vault.
public enum VaultState {
    public static func mac(key: SymmetricKey, vaultID: UUID, generation: UInt32, entries: [(id: UUID, revision: UInt64)]) -> Data {
        var w = ByteWriter()
        w.ascii("state"); w.raw(vaultID.rawBytes); w.u32be(generation); w.u32be(UInt32(entries.count))
        for e in entries.sorted(by: { $0.id.rawBytes.lexicographicallyPrecedes($1.id.rawBytes) }) {
            w.raw(e.id.rawBytes); w.u64be(e.revision)
        }
        return Data(HMAC<SHA256>.authenticationCode(for: w.data, using: key))
    }
    public static func verify(_ mac: Data, key: SymmetricKey, vaultID: UUID, generation: UInt32, entries: [(id: UUID, revision: UInt64)]) -> Bool {
        let expected = Self.mac(key: key, vaultID: vaultID, generation: generation, entries: entries)
        guard expected.count == mac.count else { return false }
        return SecureBytes(copying: expected).constantTimeEquals(mac)
    }
}

public enum IntegrityWarning: String, Sendable, Equatable {
    /// Records were deleted, replaced with older versions or otherwise modified outside PrivateVault.
    case recordStateMismatch
    /// The vault file's header generation is lower than the one this Mac last saw (whole-file rollback / old copy).
    case generationRollback
}
