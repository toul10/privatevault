import Foundation
import CSecureMemory

/// A fixed-size byte buffer for key material and passwords.
/// - pinned with mlock (best effort, small buffers only) so it is less likely to be swapped,
/// - wiped with memset_s on deinit (cannot be optimised away),
/// - never printed: description is redacted.
/// Swift cannot guarantee that no copy of the bytes exists elsewhere (e.g. if a caller copies them into a
/// `Data`); this type minimises, not eliminates, plaintext residue. See SECURITY_ARCHITECTURE.md §10.
public final class SecureBytes: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let count: Int
    private let buffer: UnsafeMutableRawBufferPointer
    private let locked: Bool

    public init(count: Int) {
        precondition(count >= 0)
        self.count = count
        buffer = UnsafeMutableRawBufferPointer.allocate(byteCount: max(count, 1), alignment: 16)
        buffer.initializeMemory(as: UInt8.self, repeating: 0)
        locked = count > 0 && pv_mlock(buffer.baseAddress, count)
    }
    public convenience init(copying data: Data) {
        self.init(count: data.count)
        withUnsafeMutableBytes { $0.copyBytes(from: data) }
    }
    public convenience init(copying bytes: [UInt8]) {
        self.init(count: bytes.count)
        withUnsafeMutableBytes { buf in bytes.withUnsafeBytes { buf.copyMemory(from: $0) } }
    }
    /// Copy of a Swift string's UTF-8 (caller is responsible for the String itself).
    public convenience init(utf8 string: String) {
        var s = string
        let n = s.utf8.count
        self.init(count: n)
        s.withUTF8 { src in withUnsafeMutableBytes { $0.copyMemory(from: UnsafeRawBufferPointer(src)) } }
    }
    deinit {
        pv_memzero(buffer.baseAddress, buffer.count)
        if locked { _ = pv_munlock(buffer.baseAddress, count) }
        buffer.deallocate()
    }
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try body(UnsafeRawBufferPointer(start: buffer.baseAddress, count: count))
    }
    public func withUnsafeMutableBytes<R>(_ body: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R {
        try body(UnsafeMutableRawBufferPointer(start: buffer.baseAddress, count: count))
    }
    /// Constant-time equality.
    public func constantTimeEquals(_ other: SecureBytes) -> Bool {
        guard count == other.count else { return false }
        return withUnsafeBytes { a in other.withUnsafeBytes { b in pv_ct_equal(a.baseAddress, b.baseAddress, count) } }
    }
    public func constantTimeEquals(_ other: Data) -> Bool {
        guard count == other.count else { return false }
        return withUnsafeBytes { a in other.withUnsafeBytes { b in pv_ct_equal(a.baseAddress, b.baseAddress, count) } }
    }
    /// Explicitly wipe now (e.g. on lock) — the object becomes all-zero.
    public func wipe() { pv_memzero(buffer.baseAddress, buffer.count) }
    /// Copy out as Data. Use sparingly (the Data is NOT wiped automatically).
    public func copyData() -> Data { withUnsafeBytes { Data($0) } }
    public var description: String { "SecureBytes(<redacted \(count) bytes>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: []) }
}

public extension Data {
    /// Best-effort in-place zeroisation of a Data buffer we own (copy-on-write: only effective for unique buffers).
    mutating func wipe() {
        let n = count
        guard n > 0 else { return }
        withUnsafeMutableBytes { pv_memzero($0.baseAddress, n) }
    }
}
