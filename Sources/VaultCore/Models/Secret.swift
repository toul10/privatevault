import Foundation

public extension CodingUserInfoKey {
    /// Present (== true) only on the encoder/decoder created by `RecordCodec`. Any other (de)serialisation of
    /// secret-bearing models fails loudly. SECURITY_ARCHITECTURE.md §6.
    static let vaultBlobCodec = CodingUserInfoKey(rawValue: "com.kostastoulis.privatevault.vaultBlobCodec")!
}

enum CodecGuard {
    static func check(_ userInfo: [CodingUserInfoKey: Any]) throws {
        guard userInfo[.vaultBlobCodec] as? Bool == true else {
            throw VaultError.invalidInput("secret-bearing model serialised outside the vault codec")
        }
    }
}

/// A sensitive value. Redacted in every textual representation; only serialisable by the vault codec.
public struct Secret<Value: Codable & Sendable & Equatable>: Codable, Sendable, Equatable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var value: Value
    public init(_ value: Value) { self.value = value }

    public init(from decoder: Decoder) throws {
        try CodecGuard.check(decoder.userInfo)
        value = try decoder.singleValueContainer().decode(Value.self)
    }
    public func encode(to encoder: Encoder) throws {
        try CodecGuard.check(encoder.userInfo)
        var c = encoder.singleValueContainer()
        try c.encode(value)
    }
    public var description: String { "<redacted>" }
    public var debugDescription: String { "<redacted>" }
    public var customMirror: Mirror { Mirror(self, children: []) }
}

extension Secret where Value == String {
    public var isEmpty: Bool { value.isEmpty }
    public static var empty: Secret<String> { Secret("") }
}

/// Highest-sensitivity field (seed phrase / private key): stored as an inner ciphertext box while the vault is
/// unlocked and opened only on explicit Reveal. `.plaintext` exists only transiently (user just typed it, or a
/// reveal in progress) and can never be serialised outside the vault codec.
public enum Tier2Value: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    case sealed(Data)
    case plaintext(Secret<String>)

    public var isSealed: Bool { if case .sealed = self { return true } else { return false } }
    public var description: String { "<tier2 redacted>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: []) }
}

extension Tier2Value: Codable {
    enum Keys: String, CodingKey { case sealed, plaintext }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Keys.self)
        if let d = try c.decodeIfPresent(Data.self, forKey: .sealed) { self = .sealed(d); return }
        try CodecGuard.check(decoder.userInfo)
        self = .plaintext(try c.decode(Secret<String>.self, forKey: .plaintext))
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: Keys.self)
        switch self {
        case .sealed(let d): try c.encode(d, forKey: .sealed)
        case .plaintext(let s):
            try CodecGuard.check(encoder.userInfo)
            try c.encode(s, forKey: .plaintext)
        }
    }
}

/// Pure decision logic for editing a tier-2 field (seed phrase / private key) in the UI; unit-tested.
public enum Tier2Edit {
    /// - existing: the stored (sealed) value, if any
    /// - keep: the user left the stored value untouched
    /// - remove: the user explicitly removed it
    /// - input: new plaintext typed by the user
    public static func resolve(existing: Tier2Value?, keep: Bool, remove: Bool, input: String) -> Tier2Value? {
        if remove { return nil }
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        if let existing, keep || trimmed.isEmpty { return existing }
        return trimmed.isEmpty ? nil : .plaintext(Secret(trimmed))
    }
}
