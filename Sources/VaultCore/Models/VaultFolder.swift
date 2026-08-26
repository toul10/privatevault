import Foundation

/// A user-defined folder for organising items (SECURITY_ARCHITECTURE.md §6.1). Stored as its own encrypted
/// record — the name, timestamps and even the fact that folders exist are inside ciphertext, and folder records
/// pad to the same 4 KiB bucket as items, so they are indistinguishable from items on disk.
/// Flat (no nesting) in Version 1. Items reference a folder by `VaultItem.folderID`.
public struct VaultFolder: Sendable, Equatable, Identifiable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public static let maxNameLength = 64
    public var id: UUID
    public var name: String
    public var createdAt: Date
    public var updatedAt: Date

    public init(id: UUID = SecureRandom.uuid(), name: String, createdAt: Date = Date(), updatedAt: Date = Date()) {
        self.id = id; self.name = name; self.createdAt = createdAt; self.updatedAt = updatedAt
    }
    public var description: String { "VaultFolder(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: []) }

    /// Trims whitespace and enforces a non-empty, bounded name. Throws `invalidInput` with a user-facing message.
    public static func normalizedName(_ raw: String) throws -> String {
        let name = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else { throw VaultError.invalidInput("The folder needs a name.") }
        guard name.count <= maxNameLength else { throw VaultError.invalidInput("Folder names are limited to \(maxNameLength) characters.") }
        guard !name.contains(where: \.isNewline) else { throw VaultError.invalidInput("Folder names cannot contain line breaks.") }
        return name
    }
    /// Case- and diacritic-insensitive comparison used for the uniqueness rule.
    public static func sameName(_ a: String, _ b: String) -> Bool {
        a.compare(b, options: [.caseInsensitive, .diacriticInsensitive]) == .orderedSame
    }
}

extension VaultFolder: Codable {
    /// Discriminator value written as `"doc": "folder"` at the top of the JSON document (items carry no `doc` key).
    public static let documentTag = "folder"
    enum Keys: String, CodingKey { case doc, id, name, createdAt, updatedAt }
    public init(from decoder: Decoder) throws {
        try CodecGuard.check(decoder.userInfo)
        let c = try decoder.container(keyedBy: Keys.self)
        guard try c.decode(String.self, forKey: .doc) == Self.documentTag else { throw VaultError.corrupted("folder doc tag") }
        id = try c.decode(UUID.self, forKey: .id)
        name = try c.decode(String.self, forKey: .name)
        createdAt = try c.decode(Date.self, forKey: .createdAt)
        updatedAt = try c.decode(Date.self, forKey: .updatedAt)
    }
    public func encode(to encoder: Encoder) throws {
        try CodecGuard.check(encoder.userInfo)
        var c = encoder.container(keyedBy: Keys.self)
        try c.encode(Self.documentTag, forKey: .doc); try c.encode(id, forKey: .id); try c.encode(name, forKey: .name)
        try c.encode(createdAt, forKey: .createdAt); try c.encode(updatedAt, forKey: .updatedAt)
    }
}

/// What one encrypted record contains once opened: an item or a folder.
public enum VaultDocument: Sendable, Equatable, Identifiable {
    case item(VaultItem)
    case folder(VaultFolder)
    public var id: UUID {
        switch self { case .item(let i): return i.id; case .folder(let f): return f.id }
    }
}
