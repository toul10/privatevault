import Foundation
import LocalAuthentication
import VaultCore

/// System authentication gate (Touch ID or login password) for revealing tier-2 secrets. This is a UI/policy
/// gate (SECURITY_ARCHITECTURE.md §8.3): the Secure Enclave gate for *unlocking* lives in VaultCore.
protocol Authenticator: Sendable {
    func authenticate(reason: String) async throws
    var biometryAvailable: Bool { get }
}

final class SystemAuthenticator: Authenticator {
    var biometryAvailable: Bool {
        LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }
    func authenticate(reason: String) async throws {
        let ctx = LAContext()
        ctx.localizedCancelTitle = "Cancel"
        ctx.touchIDAuthenticationAllowableReuseDuration = 0
        do {
            let ok = try await ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
            guard ok else { throw VaultError.userCancelled }
        } catch let e as LAError {
            switch e.code {
            case .userCancel, .appCancel, .systemCancel: throw VaultError.userCancelled
            default: throw VaultError.biometryUnavailable
            }
        } catch let e as VaultError { throw e }
        catch { throw VaultError.biometryUnavailable }
    }
}
