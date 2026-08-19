import Foundation
import CryptoKit
import LocalAuthentication
import Security

/// Opaque handle to a Secure-Enclave-resident P-256 key: the SEP-wrapped representation plus its public key.
public struct SEKeyHandle: Codable, Sendable, Equatable {
    public var dataRepresentation: Data   // only usable by this Mac's Secure Enclave
    public var publicKeyX963: Data
    public init(dataRepresentation: Data, publicKeyX963: Data) { self.dataRepresentation = dataRepresentation; self.publicKeyX963 = publicKeyX963 }
}

/// Abstraction over the Secure Enclave so VaultCore logic is testable without hardware.
public protocol SecureEnclaveService: Sendable {
    var isAvailable: Bool { get }
    /// Creates a new key. `biometric == true` ⇒ access control `[.privateKeyUsage, .biometryCurrentSet]`, else `[.privateKeyUsage]`.
    func createKey(biometric: Bool) throws -> SEKeyHandle
    /// Public-key operation (no Secure Enclave access, no prompt).
    func seal(_ plaintext: SecureBytes, to key: SEKeyHandle, info: Data, aad: Data) throws -> HPKEWrappedBlob
    /// Private-key operation inside the Secure Enclave. For biometric keys the SEP demands Touch ID first.
    func open(_ blob: HPKEWrappedBlob, with key: SEKeyHandle, info: Data, aad: Data, reason: String) throws -> SecureBytes
}

public extension SecureEnclaveService {
    func seal(_ plaintext: SecureBytes, to key: SEKeyHandle, info: Data, aad: Data) throws -> HPKEWrappedBlob {
        let pub = try P256.KeyAgreement.PublicKey(x963Representation: key.publicKeyX963)
        return try HPKEWrap.seal(plaintext, recipient: pub, info: info, aad: aad)
    }
}

/// The real thing: CryptoKit `SecureEnclave.P256.KeyAgreement` + LocalAuthentication.
public final class SystemSecureEnclave: SecureEnclaveService {
    public init() {}
    public var isAvailable: Bool { SecureEnclave.isAvailable }

    public func createKey(biometric: Bool) throws -> SEKeyHandle {
        guard isAvailable else { throw VaultError.secureEnclaveUnavailable }
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        if biometric {
            let ctx = LAContext()
            var err: NSError?
            guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err) else { throw VaultError.biometryUnavailable }
            flags.insert(.biometryCurrentSet)
        }
        var cfErr: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &cfErr) else {
            throw VaultError.secureEnclaveFailed("access control")
        }
        do {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: ac, authenticationContext: nil)
            return SEKeyHandle(dataRepresentation: key.dataRepresentation, publicKeyX963: key.publicKey.x963Representation)
        } catch {
            throw VaultError.secureEnclaveFailed("key creation")
        }
    }

    public func open(_ blob: HPKEWrappedBlob, with key: SEKeyHandle, info: Data, aad: Data, reason: String) throws -> SecureBytes {
        guard isAvailable else { throw VaultError.secureEnclaveUnavailable }
        let ctx = LAContext()
        ctx.localizedReason = reason
        ctx.localizedFallbackTitle = ""            // no "Use Password…" button: the Master Password field is the fallback
        ctx.touchIDAuthenticationAllowableReuseDuration = 0
        let priv: SecureEnclave.P256.KeyAgreement.PrivateKey
        do { priv = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: key.dataRepresentation, authenticationContext: ctx) }
        catch { throw VaultError.secureEnclaveFailed("key load") }
        do {
            return try HPKEWrap.open(blob, privateKey: priv, info: info, aad: aad)
        } catch let e as VaultError {
            throw e
        } catch {
            let ns = error as NSError
            if ns.domain == LAError.errorDomain {
                switch LAError.Code(rawValue: ns.code) {
                case .userCancel, .appCancel, .systemCancel: throw VaultError.userCancelled
                case .biometryNotAvailable, .biometryNotEnrolled, .biometryLockout: throw VaultError.biometryUnavailable
                default: break
                }
            }
            // Any other Secure-Enclave failure (key unusable after fingerprint change, SEP error) — the caller
            // decides between "invalidated" (bio path) and "unusable on this device" (secret key path).
            throw VaultError.secureEnclaveFailed("open")
        }
    }
}
