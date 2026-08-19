import Foundation
import CArgon2

/// Argon2id parameters. Stored (non-secret) in the vault header; validated as untrusted input on read.
public struct KDFParameters: Equatable, Sendable, Codable {
    public var memoryKiB: UInt32
    public var passes: UInt32
    public var lanes: UInt8

    public init(memoryKiB: UInt32, passes: UInt32, lanes: UInt8) {
        self.memoryKiB = memoryKiB; self.passes = passes; self.lanes = lanes
    }

    // ---- policy ----------------------------------------------------------------------------
    /// Hard bounds for anything read from disk. Anything outside is rejected BEFORE allocation/derivation.
    public static let minMemoryKiB: UInt32 = 8 * 1024          // 8 MiB
    public static let maxMemoryKiB: UInt32 = 1024 * 1024       // 1 GiB
    public static let minPasses: UInt32 = 1
    public static let maxPasses: UInt32 = 16
    public static let maxLanes: UInt8 = 4
    /// Floor for vaults created or upgraded by this app (never write weaker parameters).
    public static let floor = KDFParameters(memoryKiB: 64 * 1024, passes: 3, lanes: 1)
    /// Production defaults for new vaults. Chosen by Scripts/benchmark-kdf.sh on the owner's Mac
    /// (target 0.5–1.0 s in a release build). See SECURITY_ARCHITECTURE.md §2.3.
    public static let current = KDFParameters(memoryKiB: 256 * 1024, passes: 6, lanes: 4)
    /// Small parameters for unit tests only (never used for real vaults; tests assert that).
    public static let testing = KDFParameters(memoryKiB: 8 * 1024, passes: 1, lanes: 1)

    public var isWithinHardBounds: Bool {
        memoryKiB >= Self.minMemoryKiB && memoryKiB <= Self.maxMemoryKiB &&
        passes >= Self.minPasses && passes <= Self.maxPasses &&
        lanes >= 1 && lanes <= Self.maxLanes &&
        memoryKiB >= 8 * UInt32(lanes) // Argon2 requirement: m >= 8*p
    }
    public func validateHardBounds() throws {
        guard isWithinHardBounds else { throw VaultError.invalidHeader("KDF parameters out of bounds") }
    }
    /// True when `self` is at least as strong as `other` in both memory and passes.
    public func isAtLeast(_ other: KDFParameters) -> Bool {
        memoryKiB >= other.memoryKiB && passes >= other.passes
    }
    public var meetsFloor: Bool { isAtLeast(Self.floor) }
    /// True when a vault with these parameters should be upgraded on the next password unlock.
    public var needsUpgrade: Bool { !isAtLeast(Self.current) }
}

/// Thin, safe wrapper around the vendored PHC reference Argon2id.
public enum Argon2id {
    public static let saltLength = 16
    public static let outputLength = 32

    /// Derives `outputLength` bytes. `password` bytes are read but not modified. The output is a SecureBytes.
    public static func derive(password: SecureBytes, salt: Data, params: KDFParameters) throws -> SecureBytes {
        try params.validateHardBounds()
        guard salt.count == saltLength else { throw VaultError.invalidHeader("salt length") }
        guard password.count > 0 else { throw VaultError.invalidInput("empty password") }
        let out = SecureBytes(count: outputLength)
        let rc: Int32 = password.withUnsafeBytes { pw in
            salt.withUnsafeBytes { sb in
                out.withUnsafeMutableBytes { ob in
                    argon2id_hash_raw(params.passes, params.memoryKiB, UInt32(params.lanes),
                                      pw.baseAddress, pw.count,
                                      sb.baseAddress, sb.count,
                                      ob.baseAddress, ob.count)
                }
            }
        }
        guard rc == ARGON2_OK.rawValue else { throw VaultError.kdfFailed(rc) }
        return out
    }

    /// Same as `derive` but for test vectors / benchmarks with arbitrary lengths (never used by the vault).
    public static func deriveRaw(password: Data, salt: Data, params: KDFParameters, outputLength: Int) throws -> Data {
        try params.validateHardBoundsForRaw()
        var out = Data(count: outputLength)
        let rc: Int32 = password.withUnsafeBytes { pw in
            salt.withUnsafeBytes { sb in
                out.withUnsafeMutableBytes { ob in
                    argon2id_hash_raw(params.passes, params.memoryKiB, UInt32(params.lanes),
                                      pw.baseAddress, pw.count, sb.baseAddress, sb.count, ob.baseAddress, ob.count)
                }
            }
        }
        guard rc == ARGON2_OK.rawValue else { throw VaultError.kdfFailed(rc) }
        return out
    }
}

private extension KDFParameters {
    /// Raw/test derivations may use RFC test-vector parameters (e.g. m=32 KiB, p=4) that are below the
    /// vault's hard minimum memory; still cap the maximum to protect the machine.
    func validateHardBoundsForRaw() throws {
        guard memoryKiB <= Self.maxMemoryKiB, passes <= Self.maxPasses, lanes >= 1, lanes <= Self.maxLanes,
              memoryKiB >= 8 * UInt32(lanes) else { throw VaultError.invalidHeader("KDF parameters out of bounds") }
    }
}
