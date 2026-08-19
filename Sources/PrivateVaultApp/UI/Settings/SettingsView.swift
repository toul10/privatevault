import SwiftUI
import AppKit
import UniformTypeIdentifiers
import VaultCore

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        TabView {
            GeneralSettings().tabItem { Label("General", systemImage: "gear") }
            SecuritySettings().tabItem { Label("Security", systemImage: "lock.shield") }
            BackupSettings().tabItem { Label("Backup", systemImage: "externaldrive") }
            AboutSettings().tabItem { Label("About", systemImage: "info.circle") }
        }
        .frame(width: 560, height: 460)
    }
}

struct GeneralSettings: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        @Bindable var settings = model.settings
        Form {
            Section("Auto-lock") {
                Picker("Lock after inactivity", selection: $settings.autoLock) {
                    ForEach(AutoLockPolicy.Timeout.allCases) { Text($0.displayName).tag($0) }
                }
                if settings.autoLock == .never {
                    Label("Not recommended: the vault stays open until you lock it, sleep the Mac or lock the screen.", systemImage: "exclamationmark.triangle").foregroundStyle(.orange).font(.callout)
                }
                Text("The vault always locks when the Mac sleeps, the screen locks, you switch user, or the app quits.").font(.caption).foregroundStyle(.secondary)
            }
            Section("Clipboard") {
                Stepper("Clear copied secrets after \(settings.clipboardSeconds) s", value: $settings.clipboardSeconds, in: 10...120, step: 5)
                Text("Copies are marked 'concealed' and 'current host only' (no Universal Clipboard). Clipboard managers that ignore this convention can still capture them.").font(.caption).foregroundStyle(.secondary)
            }
            Section("Screen") {
                Toggle("Block screen capture and screen sharing of PrivateVault windows while unlocked", isOn: $settings.blockScreenCapture)
            }
        }
        .formStyle(.grouped)
        .onChange(of: settings.autoLock) { _, _ in model.settingsChanged() }
        .onChange(of: settings.clipboardSeconds) { _, _ in model.settingsChanged() }
        .onChange(of: settings.blockScreenCapture) { _, _ in model.settingsChanged() }
    }
}

struct SecuritySettings: View {
    @Environment(AppModel.self) private var model
    @State private var sheet: Sheet?
    enum Sheet: Identifiable { case changePassword, disableTouchID, showKit, regenerateKit, deleteVault; var id: Int { hashValue } }
    @State private var error: String?

    var body: some View {
        Form {
            Section("Touch ID") {
                if model.phase != .unlocked {
                    Text("Unlock the vault to change security settings.").foregroundStyle(.secondary)
                } else if !model.biometricAvailable {
                    Text("Touch ID / Secure Enclave is not available on this Mac.").foregroundStyle(.secondary)
                } else {
                    Toggle("Unlock with Touch ID", isOn: Binding(get: { model.biometricEnabled }, set: { on in
                        if on { Task { do { try await model.enableBiometricUnlock() } catch { self.error = describe(error) } } }
                        else { sheet = .disableTouchID }
                    }))
                    Text("Touch ID releases the vault key from the Secure Enclave. Your Master Password is never stored. Adding or removing a fingerprint disables Touch ID unlock until you re-enable it.").font(.caption).foregroundStyle(.secondary)
                }
            }
            Section("Master Password & keys") {
                Button("Change Master Password…") { sheet = .changePassword }
                Button("Show Recovery Kit…") { sheet = .showKit }
                Button("Regenerate Secret Key (new Recovery Kit)…") { sheet = .regenerateKit }
                if !model.secretKeyOnDevice {
                    Label("Your Secret Key is not stored on this Mac. You will be asked for the Recovery Kit when unlocking.", systemImage: "key").foregroundStyle(.orange).font(.callout)
                }
            }
            .disabled(model.phase != .unlocked)
            Section("Danger zone") {
                Button("Delete this vault…", role: .destructive) { sheet = .deleteVault }
            }
            .disabled(model.phase != .unlocked)
            ErrorBanner(message: error)
        }
        .formStyle(.grouped)
        .sheet(item: $sheet) { s in
            switch s {
            case .changePassword: ChangePasswordSheet().environment(model)
            case .disableTouchID: PasswordPromptSheet(title: "Disable Touch ID unlock", action: "Disable") { pw in try await model.disableBiometricUnlock(password: pw) }.environment(model)
            case .showKit: ShowKitSheet(mode: .show).environment(model)
            case .regenerateKit: ShowKitSheet(mode: .regenerate).environment(model)
            case .deleteVault: PasswordPromptSheet(title: "Delete this vault permanently", action: "Delete vault", destructive: true,
                                                   message: "All items will be erased from this Mac. Make sure you have an encrypted backup you can restore. This cannot be undone.") { pw in try await model.deleteVault(password: pw) }.environment(model)
            }
        }
    }
}

/// Generic "enter your Master Password to confirm" sheet.
/// Closes the sheet (and clears its state via view teardown) the moment the vault is no longer unlocked.
struct DismissWhenLocked: ViewModifier {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    func body(content: Content) -> some View {
        content.onChange(of: model.phase) { _, p in if p != .unlocked { dismiss() } }
    }
}
extension View { func dismissWhenLocked() -> some View { modifier(DismissWhenLocked()) } }

struct PasswordPromptSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let title: String
    let action: String
    var destructive = false
    var message: String? = nil
    let perform: (String) async throws -> Void
    @State private var password = ""
    @State private var busy = false
    @State private var error: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(title).font(.title3.weight(.semibold))
            if let message { Text(message).foregroundStyle(.secondary) }
            SecureField("Master Password", text: $password).textFieldStyle(.roundedBorder).onSubmit { Task { await run() } }
            ErrorBanner(message: error)
            HStack { Spacer(); Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(action) { Task { await run() } }.buttonStyle(.borderedProminent).tint(destructive ? .red : .accentColor).disabled(busy || password.isEmpty) }
        }.padding(20).frame(width: 420).dismissWhenLocked()
    }
    private func run() async {
        busy = true; error = nil
        do { try await perform(password); password = ""; dismiss() } catch { self.error = describe(error) }
        busy = false
    }
}

struct ChangePasswordSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var current = ""
    @State private var new = ""
    @State private var confirm = ""
    @State private var rotate = false
    @State private var busy = false
    @State private var error: String?
    @State private var done = false
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Change Master Password").font(.title3.weight(.semibold))
            SecureField("Current Master Password", text: $current).textFieldStyle(.roundedBorder)
            MasterPasswordField(title: "New Master Password", text: $new, showStrength: true)
            MasterPasswordField(title: "Confirm new Master Password", text: $confirm)
            Toggle("Also rotate all vault encryption keys (re-encrypts every item)", isOn: $rotate)
            Text(rotate ? "Use this if your old password or Recovery Kit may have been exposed. Old backups made before today will only open with the OLD password + Recovery Kit."
                        : "Quick change: only the key wrapping is redone; your items are not re-encrypted. The Recovery Kit stays the same.")
                .font(.caption).foregroundStyle(.secondary)
            ErrorBanner(message: error)
            HStack { Spacer(); Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(busy ? "Working…" : "Change password") { Task { await run() } }.buttonStyle(.borderedProminent)
                    .disabled(busy || current.isEmpty || new.isEmpty || new != confirm) }
        }.padding(20).frame(width: 460).dismissWhenLocked()
    }
    private func run() async {
        busy = true; error = nil
        do { try await model.changePassword(current: current, new: new, rotateKeys: rotate); current = ""; new = ""; confirm = ""; dismiss() }
        catch { self.error = describe(error) }
        busy = false
    }
}

struct ShowKitSheet: View {
    enum Mode { case show, regenerate }
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let mode: Mode
    @State private var password = ""
    @State private var kit: String?
    @State private var busy = false
    @State private var error: String?
    @State private var hideAt: Date?
    @State private var now = Date()
    static let visibleSeconds: TimeInterval = 90
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text(mode == .show ? "Recovery Kit" : "Regenerate Secret Key").font(.title3.weight(.semibold))
                Spacer()
                if let hideAt, kit != nil { Text("hides in \(max(0, Int(hideAt.timeIntervalSince(now).rounded(.up)))) s").font(.caption).foregroundStyle(.secondary) }
            }
            if let kit {
                RecoveryKitView(kit: kit)
                if mode == .regenerate { Text("Your OLD Recovery Kit no longer works. Old backups stay readable only with the old kit + old password; make a new backup now.").font(.callout).foregroundStyle(.orange) }
                HStack { Spacer(); Button("Done") { self.kit = nil; dismiss() }.buttonStyle(.borderedProminent) }
            } else {
                Text(mode == .show ? "Enter your Master Password to display the Recovery Kit." : "This creates a NEW Secret Key and re-encrypts the whole vault. Enter your Master Password to continue.")
                    .foregroundStyle(.secondary)
                SecureField("Master Password", text: $password).textFieldStyle(.roundedBorder).onSubmit { Task { await run() } }
                ErrorBanner(message: error)
                HStack { Spacer(); Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                    Button(busy ? "Working…" : (mode == .show ? "Show" : "Regenerate")) { Task { await run() } }.buttonStyle(.borderedProminent).disabled(busy || password.isEmpty) }
            }
        }.padding(20).frame(width: 520)
        .dismissWhenLocked()
        .task(id: hideAt) {
            guard hideAt != nil else { return }
            while let at = hideAt, !Task.isCancelled {
                if Date() >= at { kit = nil; hideAt = nil; dismiss(); break }
                try? await Task.sleep(for: .seconds(1)); now = Date()
            }
        }
    }
    private func run() async {
        busy = true; error = nil
        do {
            kit = mode == .show ? try await model.recoveryKit(password: password) : try await model.regenerateSecretKey(password: password)
            password = ""
            hideAt = Date().addingTimeInterval(Self.visibleSeconds); now = Date()
        } catch { self.error = describe(error) }
        busy = false
    }
}

struct BackupSettings: View {
    @Environment(AppModel.self) private var model
    @State private var sheet: Sheet?
    enum Sheet: Identifiable { case export, restore; var id: Int { hashValue } }
    var body: some View {
        Form {
            Section("Encrypted backup") {
                Text("A backup is a single .privatevault file containing your vault exactly as it is stored on disk: encrypted. Restoring it anywhere requires your Master Password AND your Recovery Kit. Keep backups on an external disk or USB stick.")
                    .font(.callout).foregroundStyle(.secondary)
                Button("Export encrypted backup…") { sheet = .export }
                Button("Restore encrypted backup… (replaces this vault)") { sheet = .restore }
            }
            .disabled(model.phase != .unlocked)
            if model.phase != .unlocked { Text("Unlock the vault to export or restore.").foregroundStyle(.secondary) }
        }
        .formStyle(.grouped)
        .sheet(item: $sheet) { s in
            switch s {
            case .export: PasswordPromptSheet(title: "Export encrypted backup", action: "Export") { pw in
                    let data = try await model.exportBackup(password: pw)
                    await MainActor.run {
                        let panel = NSSavePanel()
                        panel.nameFieldStringValue = "PrivateVault \(Date().formatted(.iso8601.year().month().day())).\(BackupCodec.fileExtension)"
                        panel.allowedContentTypes = [UTType(filenameExtension: BackupCodec.fileExtension) ?? .data]
                        if panel.runModal() == .OK, let url = panel.url { try? data.write(to: url, options: [.atomic]) }
                    }
                }.environment(model)
            case .restore: RestoreSheet().environment(model)
            }
        }
    }
}

struct RestoreSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var kit = ""
    @State private var data: Data?
    @State private var name = ""
    @State private var busy = false
    @State private var error: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Restore encrypted backup").font(.title3.weight(.semibold))
            Text("The current vault on this Mac will be REPLACED by the backup. Items added since the backup was made will be lost.").foregroundStyle(.orange)
            HStack { Button("Choose backup file…") { choose() }; Text(name.isEmpty ? "No file selected" : name).foregroundStyle(.secondary) }
            SecureField("Master Password of the backup", text: $password).textFieldStyle(.roundedBorder)
            PlainSecretTextField(placeholder: "Recovery Kit (only if the backup is from a different vault / Secret Key)", text: $kit, monospaced: true)
            ErrorBanner(message: error)
            HStack { Spacer(); Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(busy ? "Restoring…" : "Replace vault with backup") { Task { await run() } }.buttonStyle(.borderedProminent).tint(.red).disabled(busy || data == nil || password.isEmpty) }
        }.padding(20).frame(width: 520).dismissWhenLocked()
    }
    private func choose() {
        let panel = NSOpenPanel(); panel.allowedContentTypes = [UTType(filenameExtension: BackupCodec.fileExtension) ?? .data, .data]
        if panel.runModal() == .OK, let url = panel.url { data = try? Data(contentsOf: url); name = url.lastPathComponent }
    }
    private func run() async {
        guard let data else { return }
        busy = true; error = nil
        do { try await model.restoreBackup(data, password: password, recoveryKit: kit.isEmpty ? nil : kit); password = ""; kit = ""; dismiss() }
        catch { self.error = describe(error) }
        busy = false
    }
}

struct AboutSettings: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("PrivateVault").font(.title2.weight(.semibold))
            Text("Local-only, zero-knowledge secrets manager for macOS. Version 1.0.")
            Text("Cryptography: Argon2id (PHC reference), HKDF-SHA256, AES-256-GCM, HPKE + Secure Enclave (Apple CryptoKit). No network access, no telemetry, no accounts.").font(.callout).foregroundStyle(.secondary)
            Text("Documentation: SECURITY_ARCHITECTURE.md, THREAT_MODEL.md, RECOVERY.md in the project folder.").font(.callout).foregroundStyle(.secondary)
            Spacer()
        }.padding(20).frame(maxWidth: .infinity, alignment: .leading)
    }
}
