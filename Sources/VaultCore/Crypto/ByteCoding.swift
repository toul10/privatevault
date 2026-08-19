import Foundation

/// Minimal, deterministic binary encoding helpers. Used for every canonical encoding (AAD, headers,
/// manifests) so that the byte layout is explicit and stable — never JSON.
public struct ByteWriter: Sendable {
    public private(set) var bytes: [UInt8] = []
    public init() {}
    public mutating func u8(_ v: UInt8) { bytes.append(v) }
    public mutating func u32be(_ v: UInt32) {
        bytes.append(UInt8(truncatingIfNeeded: v >> 24)); bytes.append(UInt8(truncatingIfNeeded: v >> 16))
        bytes.append(UInt8(truncatingIfNeeded: v >> 8)); bytes.append(UInt8(truncatingIfNeeded: v))
    }
    public mutating func u64be(_ v: UInt64) { u32be(UInt32(truncatingIfNeeded: v >> 32)); u32be(UInt32(truncatingIfNeeded: v)) }
    public mutating func i64be(_ v: Int64) { u64be(UInt64(bitPattern: v)) }
    public mutating func raw(_ d: [UInt8]) { bytes.append(contentsOf: d) }
    public mutating func raw(_ d: Data) { bytes.append(contentsOf: d) }
    public mutating func ascii(_ s: StaticString) { s.withUTF8Buffer { bytes.append(contentsOf: $0) } }
    public var data: Data { Data(bytes) }
}

public struct ByteReader {
    private let bytes: [UInt8]
    public private(set) var offset = 0
    public init(_ d: Data) { bytes = [UInt8](d) }
    public init(_ b: [UInt8]) { bytes = b }
    public var remaining: Int { bytes.count - offset }
    public var isAtEnd: Bool { remaining == 0 }
    public mutating func u8() throws -> UInt8 { try need(1); defer { offset += 1 }; return bytes[offset] }
    public mutating func u32be() throws -> UInt32 {
        try need(4); defer { offset += 4 }
        return UInt32(bytes[offset]) << 24 | UInt32(bytes[offset+1]) << 16 | UInt32(bytes[offset+2]) << 8 | UInt32(bytes[offset+3])
    }
    public mutating func u64be() throws -> UInt64 { let hi = try u32be(); let lo = try u32be(); return UInt64(hi) << 32 | UInt64(lo) }
    public mutating func i64be() throws -> Int64 { Int64(bitPattern: try u64be()) }
    public mutating func raw(_ n: Int) throws -> [UInt8] { try need(n); defer { offset += n }; return Array(bytes[offset..<offset+n]) }
    public mutating func rawData(_ n: Int) throws -> Data { Data(try raw(n)) }
    public mutating func expectASCII(_ s: StaticString) throws {
        let expected = s.withUTF8Buffer { Array($0) }
        let got = try raw(expected.count)
        guard got == expected else { throw VaultError.corrupted("bad magic") }
    }
    private func need(_ n: Int) throws { guard remaining >= n else { throw VaultError.corrupted("truncated data") } }
}

public extension Data {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
    init?(hexString: String) {
        let s = hexString.replacingOccurrences(of: " ", with: "")
        guard s.count % 2 == 0 else { return nil }
        var out = Data(capacity: s.count / 2)
        var idx = s.startIndex
        while idx < s.endIndex {
            let next = s.index(idx, offsetBy: 2)
            guard let b = UInt8(s[idx..<next], radix: 16) else { return nil }
            out.append(b); idx = next
        }
        self = out
    }
}

public extension UUID {
    /// The 16 raw bytes of the UUID (big-endian as laid out by `uuid`).
    var rawBytes: Data { withUnsafeBytes(of: uuid) { Data($0) } }
    init?(rawBytes d: Data) {
        guard d.count == 16 else { return nil }
        var u = uuid_t(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
        withUnsafeMutableBytes(of: &u) { $0.copyBytes(from: d) }
        self = UUID(uuid: u)
    }
}
