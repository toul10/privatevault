import SwiftUI
import VaultCore

struct ItemDetailView: View {
    @Environment(AppModel.self) private var model
    let item: VaultItem
    let onEdit: () -> Void
    @State private var confirmDelete = false
    @State private var newFolder = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                Form {
                    switch item.payload {
                    case .login(let p): loginSection(p)
                    case .apiCredential(let p): apiSection(p)
                    case .wallet(let p): walletSection(p)
                    case .secureNote(let p): SecretRow(label: "Note", value: p.body.value, itemID: item.id, multiline: true, monospaced: false)
                    case .recoveryCodes(let p): recoverySection(p)
                    }
                    Section {
                        LabeledContent("Folder") {
                            HStack {
                                if let f = model.folder(of: item) { Label(f.name, systemImage: "folder") } else { Text("No Folder").foregroundStyle(.secondary) }
                                Spacer()
                                MoveToFolderMenu(items: [item]) { newFolder = true }.menuStyle(.borderlessButton).fixedSize()
                            }
                        }
                        if !item.tags.isEmpty { LabeledContent("Tags") { Text(item.tags.joined(separator: ", ")) } }
                    }
                    Section {
                        LabeledContent("Created") { Text(item.createdAt.formatted(date: .abbreviated, time: .shortened)) }
                        LabeledContent("Modified") { Text(item.updatedAt.formatted(date: .abbreviated, time: .shortened)) }
                        if let u = item.lastUsedAt { LabeledContent("Last used") { Text(u.formatted(date: .abbreviated, time: .shortened)) } }
                    }
                }
                .formStyle(.grouped)
            }
            .padding(.top, 8)
        }
        .toolbar {
            ToolbarItemGroup {
                Button { Task { await model.toggleFavorite(item.id) } } label: { Image(systemName: item.favorite ? "star.fill" : "star") }.help("Favorite")
                Button("Edit", action: onEdit)
                Button(role: .destructive) { confirmDelete = true } label: { Image(systemName: "trash") }.help("Delete")
            }
        }
        .confirmationDialog("Delete “\(item.title)”?", isPresented: $confirmDelete) {
            Button("Delete", role: .destructive) { Task { try? await model.delete(item.id) } }
        } message: { Text("This cannot be undone.") }
        .sheet(isPresented: $newFolder) {
            FolderNameSheet(title: "New Folder for this item") { name in
                let f = try await model.createFolder(name: name)
                try await model.moveItems([item.id], toFolder: f.id)
            }.environment(model)
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: item.kind.symbolName).font(.system(size: 28)).foregroundStyle(.tint).frame(width: 44, height: 44)
                .background(RoundedRectangle(cornerRadius: 10).fill(.tint.opacity(0.12)))
            VStack(alignment: .leading) {
                Text(item.title.isEmpty ? "Untitled" : item.title).font(.title2.weight(.semibold))
                Text(item.kind.displayName).font(.subheadline).foregroundStyle(.secondary)
            }
            Spacer()
        }.padding(.horizontal, 20)
    }

    @ViewBuilder private func loginSection(_ p: LoginPayload) -> some View {
        Section("Login") {
            if !p.website.isEmpty {
                LabeledContent("Website") {
                    HStack { Text(p.website).textSelection(.disabled).lineLimit(1); Spacer(); CopyButton(value: p.website, itemID: nil) }
                }
            }
            LabeledContent("Username") { HStack { Text(p.username).textSelection(.disabled); Spacer(); CopyButton(value: p.username, itemID: item.id) } }
            SecretRow(label: "Password", value: p.password.value, itemID: item.id)
            if !p.notes.value.isEmpty { SecretRow(label: "Notes", value: p.notes.value, itemID: item.id, multiline: true, monospaced: false) }
        }
    }
    @ViewBuilder private func apiSection(_ p: APICredentialPayload) -> some View {
        Section("API Credential") {
            LabeledContent("Service") { Text(p.service) }
            if !p.environment.isEmpty { LabeledContent("Environment") { Text(p.environment) } }
            SecretRow(label: "API Key", value: p.apiKey.value, itemID: item.id)
            if !p.apiSecret.value.isEmpty { SecretRow(label: "API Secret", value: p.apiSecret.value, itemID: item.id) }
            if !p.notes.value.isEmpty { SecretRow(label: "Notes", value: p.notes.value, itemID: item.id, multiline: true, monospaced: false) }
        }
    }
    @ViewBuilder private func walletSection(_ p: WalletPayload) -> some View {
        Section("Wallet") {
            LabeledContent("Name") { Text(p.name) }
            LabeledContent("Blockchain") { Text(p.blockchain.displayName) }
            if !p.publicAddress.isEmpty {
                LabeledContent("Public address") { HStack { Text(p.publicAddress).font(.system(.body, design: .monospaced)).textSelection(.disabled).lineLimit(1); Spacer(); CopyButton(value: p.publicAddress, itemID: item.id) } }
            }
            if !p.derivationPath.isEmpty { LabeledContent("Derivation path") { Text(p.derivationPath).font(.system(.body, design: .monospaced)) } }
            if !p.notes.value.isEmpty { SecretRow(label: "Notes", value: p.notes.value, itemID: item.id, multiline: true, monospaced: false) }
        }
        Section {
            if p.seedPhrase != nil { Tier2Row(itemID: item.id, field: .seedPhrase) }
            if p.privateKey != nil { Tier2Row(itemID: item.id, field: .privateKey) }
            if p.seedPhrase == nil && p.privateKey == nil { Text("No seed phrase or private key stored.").foregroundStyle(.secondary) }
        } header: {
            Label("Highest sensitivity", systemImage: "exclamationmark.shield")
        } footer: {
            Text("Seed phrases and private keys stay encrypted in memory until you reveal them. Revealing requires Touch ID or your login password and hides again after 30 seconds. Never share them, never paste them into websites.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }
    @ViewBuilder private func recoverySection(_ p: RecoveryCodesPayload) -> some View {
        Section("Recovery Codes · \(p.service)") {
            ForEach(Array(p.codes.value.enumerated()), id: \.offset) { i, code in
                SecretRow(label: "Code \(i + 1)", value: code, itemID: item.id)
            }
            if !p.notes.value.isEmpty { SecretRow(label: "Notes", value: p.notes.value, itemID: item.id, multiline: true, monospaced: false) }
        }
    }
}

/// Seed phrase / private key: masked until an explicit, authenticated Reveal; auto-hides after 30 s.
struct Tier2Row: View {
    @Environment(AppModel.self) private var model
    let itemID: UUID
    let field: RecordCodec.Tier2Field
    @State private var revealed: String?
    @State private var error: String?
    @State private var hideAt: Date?
    @State private var now = Date()
    static let visibleSeconds: TimeInterval = 30

    var label: String { field == .seedPhrase ? "Seed phrase" : "Private key" }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(label).font(.body.weight(.medium))
                Spacer()
                if let revealed {
                    if let hideAt { Text("hides in \(max(0, Int(hideAt.timeIntervalSince(now).rounded(.up)))) s").font(.caption).foregroundStyle(.secondary) }
                    Button("Copy") { model.copySecret(revealed, itemID: itemID) }
                    Button("Hide") { hide() }
                } else {
                    Button { Task { await reveal() } } label: { Label("Reveal", systemImage: "touchid") }
                }
            }
            if let revealed {
                Text(revealed)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.disabled)   // use the Copy button (concealed, auto-clearing)
                    .padding(10).frame(maxWidth: .infinity, alignment: .leading)
                    .background(RoundedRectangle(cornerRadius: 6).fill(.red.opacity(0.07)))
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(.red.opacity(0.5)))
                    .accessibilityProtectedContent()
            } else {
                Text("••••••••••••••••••••••••").font(.system(.body, design: .monospaced)).foregroundStyle(.secondary)
            }
            ErrorBanner(message: error)
        }
        .onDisappear { hide() }
        .task(id: hideAt) {
            guard hideAt != nil else { return }
            while let at = hideAt, !Task.isCancelled {
                if Date() >= at { hide(); break }
                try? await Task.sleep(for: .seconds(1)); now = Date()
            }
        }
    }
    private func reveal() async {
        error = nil
        do {
            revealed = try await model.revealTier2(itemID: itemID, field: field)
            hideAt = Date().addingTimeInterval(Self.visibleSeconds); now = Date()
        } catch VaultError.userCancelled { }
        catch { self.error = describe(error) }
    }
    private func hide() { revealed = nil; hideAt = nil }
}
