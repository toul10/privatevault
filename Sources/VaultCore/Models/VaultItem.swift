import Foundation

public enum ItemKind: String, Codable, Sendable, CaseIterable, Identifiable {
    case login, apiCredential, wallet, secureNote, recoveryCodes
    public var id: String { rawValue }
    public var displayName: String {
        switch self {
        case .login: return "Login"
        case .apiCredential: return "API Credential"
        case .wallet: return "Wallet"
        case .secureNote: return "Secure Note"
        case .recoveryCodes: return "Recovery Codes"
        }
    }
    public var pluralName: String {
        switch self {
        case .login: return "Logins"
        case .apiCredential: return "API Keys"
        case .wallet: return "Wallets"
        case .secureNote: return "Secure Notes"
        case .recoveryCodes: return "Recovery Codes"
        }
    }
    public var symbolName: String {
        switch self {
        case .login: return "person.badge.key"
        case .apiCredential: return "key.horizontal"
        case .wallet: return "wallet.bifold"
        case .secureNote: return "note.text"
        case .recoveryCodes: return "lifepreserver"
        }
    }
}

public enum Blockchain: String, Codable, Sendable, CaseIterable, Identifiable {
    case sui, ethereum, bitcoin, solana, other
    public var id: String { rawValue }
    public var displayName: String {
        switch self {
        case .sui: return "Sui"
        case .ethereum: return "Ethereum / EVM"
        case .bitcoin: return "Bitcoin"
        case .solana: return "Solana"
        case .other: return "Other"
        }
    }
}

public struct LoginPayload: Codable, Sendable, Equatable {
    public var website: String
    public var username: String
    public var password: Secret<String>
    public var notes: Secret<String>
    public init(website: String = "", username: String = "", password: Secret<String> = .empty, notes: Secret<String> = .empty) {
        self.website = website; self.username = username; self.password = password; self.notes = notes
    }
}
public struct APICredentialPayload: Codable, Sendable, Equatable {
    public var service: String
    public var apiKey: Secret<String>
    public var apiSecret: Secret<String>
    public var environment: String
    public var notes: Secret<String>
    public init(service: String = "", apiKey: Secret<String> = .empty, apiSecret: Secret<String> = .empty, environment: String = "", notes: Secret<String> = .empty) {
        self.service = service; self.apiKey = apiKey; self.apiSecret = apiSecret; self.environment = environment; self.notes = notes
    }
}
public struct WalletPayload: Codable, Sendable, Equatable {
    public var name: String
    public var blockchain: Blockchain
    public var publicAddress: String
    public var seedPhrase: Tier2Value?
    public var privateKey: Tier2Value?
    public var derivationPath: String
    public var notes: Secret<String>
    public init(name: String = "", blockchain: Blockchain = .other, publicAddress: String = "", seedPhrase: Tier2Value? = nil,
                privateKey: Tier2Value? = nil, derivationPath: String = "", notes: Secret<String> = .empty) {
        self.name = name; self.blockchain = blockchain; self.publicAddress = publicAddress; self.seedPhrase = seedPhrase
        self.privateKey = privateKey; self.derivationPath = derivationPath; self.notes = notes
    }
}
public struct SecureNotePayload: Codable, Sendable, Equatable {
    public var body: Secret<String>
    public init(body: Secret<String> = .empty) { self.body = body }
}
public struct RecoveryCodesPayload: Codable, Sendable, Equatable {
    public var service: String
    public var codes: Secret<[String]>
    public var notes: Secret<String>
    public init(service: String = "", codes: Secret<[String]> = Secret([]), notes: Secret<String> = .empty) {
        self.service = service; self.codes = codes; self.notes = notes
    }
}

public enum ItemPayload: Sendable, Equatable {
    case login(LoginPayload)
    case apiCredential(APICredentialPayload)
    case wallet(WalletPayload)
    case secureNote(SecureNotePayload)
    case recoveryCodes(RecoveryCodesPayload)

    public var kind: ItemKind {
        switch self {
        case .login: return .login
        case .apiCredential: return .apiCredential
        case .wallet: return .wallet
        case .secureNote: return .secureNote
        case .recoveryCodes: return .recoveryCodes
        }
    }
}

extension ItemPayload: Codable {
    enum Keys: String, CodingKey { case type, login, apiCredential, wallet, secureNote, recoveryCodes }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Keys.self)
        let kind = try c.decode(ItemKind.self, forKey: .type)
        switch kind {
        case .login: self = .login(try c.decode(LoginPayload.self, forKey: .login))
        case .apiCredential: self = .apiCredential(try c.decode(APICredentialPayload.self, forKey: .apiCredential))
        case .wallet: self = .wallet(try c.decode(WalletPayload.self, forKey: .wallet))
        case .secureNote: self = .secureNote(try c.decode(SecureNotePayload.self, forKey: .secureNote))
        case .recoveryCodes: self = .recoveryCodes(try c.decode(RecoveryCodesPayload.self, forKey: .recoveryCodes))
        }
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: Keys.self)
        try c.encode(kind, forKey: .type)
        switch self {
        case .login(let p): try c.encode(p, forKey: .login)
        case .apiCredential(let p): try c.encode(p, forKey: .apiCredential)
        case .wallet(let p): try c.encode(p, forKey: .wallet)
        case .secureNote(let p): try c.encode(p, forKey: .secureNote)
        case .recoveryCodes(let p): try c.encode(p, forKey: .recoveryCodes)
        }
    }
}

/// One vault entry. The whole struct — including title, tags and timestamps — lives inside the record ciphertext.
/// It can only be serialised by `RecordCodec`; textual representations are redacted.
public struct VaultItem: Sendable, Equatable, Identifiable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var id: UUID
    public var title: String
    public var favorite: Bool
    public var tags: [String]
    public var createdAt: Date
    public var updatedAt: Date
    public var lastUsedAt: Date?
    public var payload: ItemPayload

    public var kind: ItemKind { payload.kind }

    public init(id: UUID = SecureRandom.uuid(), title: String, favorite: Bool = false, tags: [String] = [],
                createdAt: Date = Date(), updatedAt: Date = Date(), lastUsedAt: Date? = nil, payload: ItemPayload) {
        self.id = id; self.title = title; self.favorite = favorite; self.tags = tags
        self.createdAt = createdAt; self.updatedAt = updatedAt; self.lastUsedAt = lastUsedAt; self.payload = payload
    }
    public var description: String { "VaultItem(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: []) }
}

extension VaultItem: Codable {
    enum Keys: String, CodingKey { case id, title, favorite, tags, createdAt, updatedAt, lastUsedAt, payload }
    public init(from decoder: Decoder) throws {
        try CodecGuard.check(decoder.userInfo)
        let c = try decoder.container(keyedBy: Keys.self)
        id = try c.decode(UUID.self, forKey: .id)
        title = try c.decode(String.self, forKey: .title)
        favorite = try c.decode(Bool.self, forKey: .favorite)
        tags = try c.decode([String].self, forKey: .tags)
        createdAt = try c.decode(Date.self, forKey: .createdAt)
        updatedAt = try c.decode(Date.self, forKey: .updatedAt)
        lastUsedAt = try c.decodeIfPresent(Date.self, forKey: .lastUsedAt)
        payload = try c.decode(ItemPayload.self, forKey: .payload)
    }
    public func encode(to encoder: Encoder) throws {
        try CodecGuard.check(encoder.userInfo)
        var c = encoder.container(keyedBy: Keys.self)
        try c.encode(id, forKey: .id); try c.encode(title, forKey: .title); try c.encode(favorite, forKey: .favorite)
        try c.encode(tags, forKey: .tags); try c.encode(createdAt, forKey: .createdAt); try c.encode(updatedAt, forKey: .updatedAt)
        try c.encodeIfPresent(lastUsedAt, forKey: .lastUsedAt); try c.encode(payload, forKey: .payload)
    }
}

/// The opaque unit of storage, backup and (future) sync: ciphertext plus non-secret addressing data.
public struct EncryptedRecord: Sendable, Equatable, Identifiable {
    public var id: UUID
    public var cryptoVersion: UInt32
    public var revision: UInt64
    public var blob: Data
    public init(id: UUID, cryptoVersion: UInt32, revision: UInt64, blob: Data) {
        self.id = id; self.cryptoVersion = cryptoVersion; self.revision = revision; self.blob = blob
    }
}
