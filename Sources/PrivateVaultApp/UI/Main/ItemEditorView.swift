import SwiftUI
import VaultCore

/// Add / edit sheet for every item kind. Secret fields use secure entry; tier-2 fields are replaced, not shown.
struct ItemEditorView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let existing: VaultItem?
    let kind: ItemKind
    let onSaved: (VaultItem) -> Void

    @State private var title = ""
    @State private var tags = ""
    @State private var favorite = false
    // login
    @State private var website = ""
    @State private var username = ""
    @State private var password = ""
    @State private var notes = ""
    // api
    @State private var service = ""
    @State private var apiKey = ""
    @State private var apiSecret = ""
    @State private var environment = ""
    // wallet
    @State private var walletName = ""
    @State private var chain: Blockchain = .ethereum
    @State private var address = ""
    @State private var derivation = ""
    @State private var seedInput = ""
    @State private var privInput = ""
    @State private var keepSeed = true
    @State private var keepPriv = true
    @State private var existingSeed: Tier2Value?
    @State private var existingPriv: Tier2Value?
    // note
    @State private var body_ = ""
    // recovery
    @State private var codes = ""
    @State private var error: String?
    @State private var busy = false
    @State private var showGenerator = false

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(existing == nil ? "New \(kind.displayName)" : "Edit \(kind.displayName)").font(.title2.weight(.semibold))
                Spacer()
            }.padding()
            Form {
                Section {
                    TextField("Title", text: $title)
                    TextField("Tags (comma separated)", text: $tags)
                    Toggle("Favorite", isOn: $favorite)
                }
                switch kind {
                case .login: loginFields
                case .apiCredential: apiFields
                case .wallet: walletFields
                case .secureNote: Section("Note") { PlainSecretTextEditor(text: $body_, monospaced: false).frame(minHeight: 160) }
                case .recoveryCodes: recoveryFields
                }
            }
            .formStyle(.grouped)
            Divider()
            HStack {
                ErrorBanner(message: error)
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(busy ? "Saving…" : "Save") { Task { await save() } }.buttonStyle(.borderedProminent).disabled(busy).keyboardShortcut(.defaultAction)
            }.padding()
        }
        .frame(minWidth: 560, minHeight: 520)
        .onAppear(perform: load)
        .sheet(isPresented: $showGenerator) {
            PasswordGeneratorView { generated in password = generated }.environment(model)
        }
    }

    @ViewBuilder private var loginFields: some View {
        Section("Login") {
            TextField("Website", text: $website).autocorrectionDisabled()
            TextField("Username / email", text: $username).autocorrectionDisabled()
            HStack {
                SecureField("Password", text: $password)
                Button { showGenerator = true } label: { Image(systemName: "dice") }.help("Generate")
            }
            if !password.isEmpty {
                let s = PasswordStrength.estimate(password)
                Text("Strength: \(s.rating.rawValue) · ~\(Int(s.entropyBits)) bits").font(.caption).foregroundStyle(.secondary)
            }
        }
        Section("Notes") { PlainSecretTextEditor(text: $notes, monospaced: false).frame(minHeight: 80) }
    }
    @ViewBuilder private var apiFields: some View {
        Section("API Credential") {
            TextField("Service", text: $service)
            TextField("Environment (e.g. prod, test)", text: $environment)
            SecureField("API key", text: $apiKey)
            SecureField("API secret (optional)", text: $apiSecret)
        }
        Section("Notes") { PlainSecretTextEditor(text: $notes, monospaced: false).frame(minHeight: 80) }
    }
    @ViewBuilder private var walletFields: some View {
        Section("Wallet") {
            TextField("Wallet name", text: $walletName)
            Picker("Blockchain", selection: $chain) { ForEach(Blockchain.allCases) { Text($0.displayName).tag($0) } }
            TextField("Public address", text: $address).autocorrectionDisabled().font(.system(.body, design: .monospaced))
            TextField("Derivation path (optional)", text: $derivation).autocorrectionDisabled().font(.system(.body, design: .monospaced))
        }
        Section {
            tier2Editor(label: "Seed phrase / mnemonic", existing: existingSeed, keep: $keepSeed, text: $seedInput)
            tier2Editor(label: "Private key", existing: existingPriv, keep: $keepPriv, text: $privInput)
        } header: { Label("Highest sensitivity", systemImage: "exclamationmark.shield") } footer: {
            Text("Stored encrypted twice (record + inner box). PrivateVault never validates, derives or uses these values — it only stores them.").font(.caption).foregroundStyle(.secondary)
        }
        Section("Notes") { PlainSecretTextEditor(text: $notes, monospaced: false).frame(minHeight: 60) }
    }
    @ViewBuilder private func tier2Editor(label: String, existing: Tier2Value?, keep: Binding<Bool>, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label).font(.body.weight(.medium))
            if existing != nil && keep.wrappedValue {
                HStack {
                    Text("•••••••• (stored, encrypted)").foregroundStyle(.secondary).font(.system(.body, design: .monospaced))
                    Spacer()
                    Button("Replace") { keep.wrappedValue = false }
                    Button("Remove", role: .destructive) { keep.wrappedValue = false; text.wrappedValue = "" }
                }
            } else {
                PlainSecretTextEditor(text: text).frame(minHeight: 64)
                if existing != nil { Button("Keep existing value") { keep.wrappedValue = true; text.wrappedValue = "" } }
            }
        }
    }
    @ViewBuilder private var recoveryFields: some View {
        Section("Recovery Codes") {
            TextField("Service", text: $service)
            Text("One code per line").font(.caption).foregroundStyle(.secondary)
            PlainSecretTextEditor(text: $codes).frame(minHeight: 140)
        }
        Section("Notes") { PlainSecretTextEditor(text: $notes, monospaced: false).frame(minHeight: 60) }
    }

    private func load() {
        guard let e = existing else { return }
        title = e.title; tags = e.tags.joined(separator: ", "); favorite = e.favorite
        switch e.payload {
        case .login(let p): website = p.website; username = p.username; password = p.password.value; notes = p.notes.value
        case .apiCredential(let p): service = p.service; apiKey = p.apiKey.value; apiSecret = p.apiSecret.value; environment = p.environment; notes = p.notes.value
        case .wallet(let p): walletName = p.name; chain = p.blockchain; address = p.publicAddress; derivation = p.derivationPath; notes = p.notes.value
            existingSeed = p.seedPhrase; existingPriv = p.privateKey; keepSeed = p.seedPhrase != nil; keepPriv = p.privateKey != nil
        case .secureNote(let p): body_ = p.body.value
        case .recoveryCodes(let p): service = p.service; codes = p.codes.value.joined(separator: "\n"); notes = p.notes.value
        }
    }
    private func payload() -> ItemPayload {
        switch kind {
        case .login: return .login(LoginPayload(website: website.trimmingCharacters(in: .whitespaces), username: username.trimmingCharacters(in: .whitespaces), password: Secret(password), notes: Secret(notes)))
        case .apiCredential: return .apiCredential(APICredentialPayload(service: service, apiKey: Secret(apiKey), apiSecret: Secret(apiSecret), environment: environment, notes: Secret(notes)))
        case .wallet:
            let seed: Tier2Value? = keepSeed ? existingSeed : (seedInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : .plaintext(Secret(seedInput.trimmingCharacters(in: .whitespacesAndNewlines))))
            let priv: Tier2Value? = keepPriv ? existingPriv : (privInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : .plaintext(Secret(privInput.trimmingCharacters(in: .whitespacesAndNewlines))))
            return .wallet(WalletPayload(name: walletName, blockchain: chain, publicAddress: address.trimmingCharacters(in: .whitespaces), seedPhrase: seed, privateKey: priv, derivationPath: derivation, notes: Secret(notes)))
        case .secureNote: return .secureNote(SecureNotePayload(body: Secret(body_)))
        case .recoveryCodes:
            let list = codes.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            return .recoveryCodes(RecoveryCodesPayload(service: service, codes: Secret(list), notes: Secret(notes)))
        }
    }
    private func save() async {
        busy = true; error = nil
        let tagList = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        var item = existing ?? VaultItem(title: "", payload: payload())
        item.title = title.trimmingCharacters(in: .whitespaces).isEmpty ? defaultTitle() : title.trimmingCharacters(in: .whitespaces)
        item.tags = tagList; item.favorite = favorite; item.payload = payload()
        do {
            try await model.save(item)
            clearFields()
            onSaved(item); dismiss()
        } catch { self.error = describe(error) }
        busy = false
    }
    private func defaultTitle() -> String {
        switch kind {
        case .login: return website.isEmpty ? (username.isEmpty ? "Login" : username) : website
        case .apiCredential: return service.isEmpty ? "API Credential" : service
        case .wallet: return walletName.isEmpty ? "Wallet" : walletName
        case .secureNote: return "Secure Note"
        case .recoveryCodes: return service.isEmpty ? "Recovery Codes" : service
        }
    }
    private func clearFields() {
        password = ""; apiKey = ""; apiSecret = ""; seedInput = ""; privInput = ""; body_ = ""; codes = ""; notes = ""
    }
}
