import SwiftUI
import VaultCore

struct LockView: View {
    @Environment(AppModel.self) private var model
    @State private var password = ""
    @State private var recoveryKit = ""
    @State private var needsKit = false
    @State private var busy = false
    @State private var error: String?
    @FocusState private var focused: Bool

    var body: some View {
        VStack(spacing: 18) {
            Spacer()
            Image(systemName: "lock.fill").font(.system(size: 40)).foregroundStyle(.tint)
            Text("PrivateVault is locked").font(.title2.weight(.semibold))
            VStack(spacing: 10) {
                SecureField("Master Password", text: $password)
                    .textFieldStyle(.roundedBorder).frame(width: 320).focused($focused)
                    .onSubmit { Task { await unlock() } }
                if needsKit || !model.secretKeyOnDevice {
                    VStack(alignment: .leading, spacing: 4) {
                        PlainSecretTextField(placeholder: "Recovery Kit (PV1-…)", text: $recoveryKit, monospaced: true).frame(width: 320)
                        Text("Your Secret Key is not available on this Mac. Enter your Recovery Kit once; it will be stored again protected by the Secure Enclave.")
                            .font(.caption).foregroundStyle(.secondary).frame(width: 320)
                    }
                }
                HStack {
                    Button(busy ? "Unlocking…" : "Unlock") { Task { await unlock() } }
                        .buttonStyle(.borderedProminent).disabled(busy || password.isEmpty).keyboardShortcut(.defaultAction)
                    if model.biometricEnabled && model.biometricAvailable {
                        Button { Task { await unlockBiometric() } } label: { Label("Touch ID", systemImage: "touchid") }.disabled(busy)
                    }
                }
            }
            ErrorBanner(message: error).frame(width: 320)
            Spacer()
            Text("Offline · encrypted on this Mac · no accounts · Settings: ⌘,").font(.caption).foregroundStyle(.tertiary).padding(.bottom, 12)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onAppear { focused = true; Task { await model.refreshPhase() } }
    }

    private func unlock() async {
        busy = true; error = nil
        do {
            try await model.unlock(password: password, recoveryKit: (needsKit || !model.secretKeyOnDevice) && !recoveryKit.isEmpty ? recoveryKit : nil)
            password = ""; recoveryKit = ""
        } catch VaultError.secretKeyRequired {
            needsKit = true; error = VaultError.secretKeyRequired.userMessage
        } catch { self.error = describe(error) }
        busy = false
    }
    private func unlockBiometric() async {
        busy = true; error = nil
        do { try await model.unlockWithBiometrics() }
        catch VaultError.userCancelled { }
        catch { self.error = describe(error) }
        busy = false
    }
}
