import SwiftUI
import VaultCore

/// Create / rename a folder. The name is encrypted like every other vault field; it is validated by the session
/// (trimmed, ≤ 64 characters, unique).
struct FolderNameSheet: View {
    @Environment(\.dismiss) private var dismiss
    let title: String
    var initialName: String = ""
    var submitLabel: String = "Create"
    let onSubmit: (String) async throws -> Void
    @State private var name = ""
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(title).font(.title3.weight(.semibold))
            TextField("Folder name (e.g. Wallets, Work keys, Exchanges)", text: $name)
                .textFieldStyle(.roundedBorder).autocorrectionDisabled()
                .onSubmit { Task { await submit() } }
            Text("Folder names are stored encrypted, like everything else in the vault.").font(.caption).foregroundStyle(.secondary)
            ErrorBanner(message: error)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(busy ? "Saving…" : submitLabel) { Task { await submit() } }
                    .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                    .disabled(busy || name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(20).frame(width: 400)
        .onAppear { name = initialName }
    }
    private func submit() async {
        busy = true; error = nil
        do { try await onSubmit(name); dismiss() } catch { self.error = describe(error) }
        busy = false
    }
}

/// Folder chooser used by the item editor and the .env import: "No Folder", every folder, plus a "new folder" button.
struct FolderPicker: View {
    @Environment(AppModel.self) private var model
    @Binding var folderID: UUID?
    @State private var showNew = false
    var body: some View {
        HStack {
            Picker("Folder", selection: $folderID) {
                Text("No Folder").tag(UUID?.none)
                if !model.folders.isEmpty { Divider() }
                ForEach(model.folders) { f in Label(f.name, systemImage: "folder").tag(UUID?.some(f.id)) }
            }
            Button { showNew = true } label: { Image(systemName: "folder.badge.plus") }.help("New folder")
        }
        .onChange(of: model.folders) { _, folders in
            if let id = folderID, !folders.contains(where: { $0.id == id }) { folderID = nil }   // folder deleted meanwhile
        }
        .sheet(isPresented: $showNew) {
            FolderNameSheet(title: "New Folder") { name in folderID = try await model.createFolder(name: name).id }.environment(model)
        }
    }
}

/// "Move to Folder" submenu for one or more items.
struct MoveToFolderMenu: View {
    @Environment(AppModel.self) private var model
    let items: [VaultItem]
    let onNewFolder: () -> Void
    var body: some View {
        Menu {
            Button("No Folder") { move(to: nil) }.disabled(items.allSatisfy { model.folder(of: $0) == nil })
            if !model.folders.isEmpty { Divider() }
            ForEach(model.folders) { f in
                Button { move(to: f.id) } label: { Label(f.name, systemImage: "folder") }.disabled(items.allSatisfy { $0.folderID == f.id })
            }
            Divider()
            Button("New Folder…", action: onNewFolder)
        } label: { Label("Move to Folder", systemImage: "folder") }
    }
    private func move(to id: UUID?) { let ids = items.map(\.id); Task { try? await model.moveItems(ids, toFolder: id) } }
}
