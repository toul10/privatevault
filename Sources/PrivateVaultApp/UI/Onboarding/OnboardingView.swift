import SwiftUI
import AppKit
import UniformTypeIdentifiers
import VaultCore

struct OnboardingView: View {
    @Environment(AppModel.self) private var model
    enum Step { case welcome, password, kit(String, storedOnDevice: Bool), restore }
    @State private var step: Step = .welcome
    @State private var password = ""
    @State private var confirm = ""
    @State private var busy = false
    @State private var error: String?
    @State private var kitCheck = ""
    @State private var kitConfirmed = false
    @State private var restorePassword = ""
    @State private var restoreKit = ""
    @State private var restoreData: Data?
    @State private var restoreName = ""

    var body: some View {
        VStack(spacing: 0) {
            Spacer(minLength: 0)
            Group {
                switch step {
                case .welcome: welcome
                case .password: createPassword
                case .kit(let kit, let stored): showKit(kit, storedOnDevice: stored)
                case .restore: restore
                }
            }
            .frame(maxWidth: 560)
            .padding(32)
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var welcome: some View {
        VStack(alignment: .leading, spacing: 18) {
            Image(systemName: "lock.shield.fill").font(.system(size: 44)).foregroundStyle(.tint)
            Text("Welcome to PrivateVault").font(.largeTitle.weight(.semibold))
            Text("A private, offline vault for your passwords, API keys, wallet seed phrases and recovery codes. Everything is encrypted on this Mac with your Master Password and a Secret Key that never leaves your control. No cloud, no accounts, no network.")
                .foregroundStyle(.secondary)
            HStack {
                Button("Create a new vault") { step = .password }.buttonStyle(.borderedProminent).controlSize(.large)
                Button("Restore from an encrypted backup") { step = .restore }.controlSize(.large)
            }
        }
    }

    private var createPassword: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Choose your Master Password").font(.title.weight(.semibold))
            Text("This password is never stored anywhere. If you forget it, nobody — not even the author of this app — can recover your vault. Use a long passphrase you can remember (at least 12 characters).")
                .foregroundStyle(.secondary)
            MasterPasswordField(title: "Master Password", text: $password, showStrength: true)
            MasterPasswordField(title: "Confirm Master Password", text: $confirm)
            ErrorBanner(message: error)
            HStack {
                Button("Back") { step = .welcome }
                Spacer()
                Button(busy ? "Creating…" : "Create vault") { Task { await create() } }
                    .buttonStyle(.borderedProminent).disabled(busy || password.isEmpty || password != confirm)
                    .keyboardShortcut(.defaultAction)
            }
            if !confirm.isEmpty && confirm != password { Text("Passwords do not match").font(.caption).foregroundStyle(.red) }
        }
    }

    private func create() async {
        busy = true; error = nil
        do {
            let created = try await model.createVault(password: password)
            password = ""; confirm = ""
            step = .kit(created.recoveryKit, storedOnDevice: created.secretKeyStoredOnDevice)
        } catch { self.error = describe(error) }
        busy = false
    }

    private func showKit(_ kit: String, storedOnDevice: Bool) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Your Recovery Kit").font(.title.weight(.semibold))
            Text("This is your Secret Key. Together with your Master Password it is the only way to open your vault on another Mac or from a backup. It is stored on this Mac protected by the Secure Enclave, but you MUST keep a copy on paper.")
                .foregroundStyle(.secondary)
            if !storedOnDevice {
                Label("The Keychain was unavailable: the Secret Key could not be stored on this Mac. You will need to type this kit every time you unlock.", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
            }
            RecoveryKitView(kit: kit)
            HStack {
                Button("Save as text file…") { saveKit(kit) }
                Spacer()
            }
            Divider()
            Text("To continue, type the LAST group of the kit (the 5 characters after the final dash) to confirm you wrote it down:").font(.callout)
            HStack {
                TextField("Last group", text: $kitCheck).textFieldStyle(.roundedBorder).frame(width: 120)
                    .autocorrectionDisabled()
                    .onChange(of: kitCheck) { _, v in kitConfirmed = v.uppercased().trimmingCharacters(in: .whitespaces) == String(kit.suffix(5)) }
                if kitConfirmed { Image(systemName: "checkmark.circle.fill").foregroundStyle(.green) }
                Spacer()
                Button("I saved my Recovery Kit — open vault") { Task { await model.refreshPhase() } }
                    .buttonStyle(.borderedProminent).disabled(!kitConfirmed)
            }
        }
    }

    private func saveKit(_ kit: String) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "PrivateVault Recovery Kit.txt"
        panel.allowedContentTypes = [.plainText]
        panel.message = "WARNING: this file is as sensitive as your vault. Store it offline (USB stick in a safe), never in cloud storage."
        if panel.runModal() == .OK, let url = panel.url {
            let text = "PrivateVault Recovery Kit\n\nSecret Key:\n\(kit)\n\nKeep this together with your memory of the Master Password. Both are required to open your vault on another Mac or from a backup. There is no other way to recover the vault.\n"
            try? text.write(to: url, atomically: true, encoding: .utf8)
        }
    }

    private var restore: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Restore from an encrypted backup").font(.title.weight(.semibold))
            Text("You need the .privatevault backup file, the Master Password used when it was made, and the Recovery Kit of that vault.")
                .foregroundStyle(.secondary)
            HStack {
                Button("Choose backup file…") { chooseBackup() }
                Text(restoreName.isEmpty ? "No file selected" : restoreName).foregroundStyle(.secondary)
            }
            MasterPasswordField(title: "Master Password", text: $restorePassword)
            TextField("Recovery Kit (PV1-…)", text: $restoreKit).textFieldStyle(.roundedBorder).font(.system(.body, design: .monospaced)).autocorrectionDisabled()
            ErrorBanner(message: error)
            HStack {
                Button("Back") { step = .welcome }
                Spacer()
                Button(busy ? "Restoring…" : "Restore") { Task { await doRestore() } }
                    .buttonStyle(.borderedProminent).disabled(busy || restoreData == nil || restorePassword.isEmpty || restoreKit.isEmpty)
            }
        }
    }
    private func chooseBackup() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [UTType(filenameExtension: BackupCodec.fileExtension) ?? .data, .data]
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let url = panel.url {
            restoreData = try? Data(contentsOf: url); restoreName = url.lastPathComponent
        }
    }
    private func doRestore() async {
        guard let data = restoreData else { return }
        busy = true; error = nil
        do { try await model.restoreBackup(data, password: restorePassword, recoveryKit: restoreKit); restorePassword = ""; restoreKit = "" }
        catch { self.error = describe(error) }
        busy = false
    }
}
