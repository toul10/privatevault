import SwiftUI
import VaultCore

enum SidebarSection: Hashable, Identifiable {
    case all, kind(ItemKind), favorites, recent, folder(UUID), unfiled
    var id: String {
        switch self {
        case .all: "all"; case .kind(let k): k.rawValue; case .favorites: "favorites"; case .recent: "recent"
        case .folder(let id): "folder-" + id.uuidString; case .unfiled: "unfiled"
        }
    }
    /// Static title; folder titles come from the (decrypted) folder record, see `MainView.title(for:)`.
    var title: String {
        switch self {
        case .all: "All Items"; case .kind(let k): k.pluralName; case .favorites: "Favorites"; case .recent: "Recently Used"
        case .folder: "Folder"; case .unfiled: "Not in a Folder"
        }
    }
    var symbol: String {
        switch self {
        case .all: "tray.full"; case .kind(let k): k.symbolName; case .favorites: "star"; case .recent: "clock"
        case .folder: "folder"; case .unfiled: "folder.badge.questionmark"
        }
    }
    var folderID: UUID? { if case .folder(let id) = self { return id } else { return nil } }
}

struct MainView: View {
    @Environment(AppModel.self) private var model
    @State private var section: SidebarSection = .all
    @State private var selection: UUID?
    @State private var query = ""
    @State private var editing: EditorTarget?
    @State private var showGenerator = false
    @State private var envImport: EnvImportTarget?
    struct EnvImportTarget: Identifiable { let id = UUID(); let text: String; let fileName: String }
    @State private var columnVisibility = NavigationSplitViewVisibility.all
    @State private var folderPrompt: FolderPrompt?
    @State private var pendingFolderDelete: VaultFolder?

    struct EditorTarget: Identifiable { let id = UUID(); let item: VaultItem?; let kind: ItemKind; var folderID: UUID? = nil }
    /// Create a folder (optionally moving items into it right away) or rename one.
    enum FolderPrompt: Identifiable {
        case create(thenMove: [UUID])
        case rename(VaultFolder)
        var id: String { switch self { case .create: "create"; case .rename(let f): f.id.uuidString } }
    }

    var body: some View {
        VStack(spacing: 0) {
            if !model.integrityWarnings.isEmpty { integrityBanner }
            NavigationSplitView(columnVisibility: $columnVisibility) {
                sidebar
            } content: {
                ItemListView(items: filteredItems, selection: $selection, query: $query, showsFolder: section.folderID == nil,
                             emptyState: emptyState, onNewFolder: { ids in folderPrompt = .create(thenMove: ids) })
                    .navigationSplitViewColumnWidth(min: 260, ideal: 320)
                    // No navigationTitle on purpose: folder names must not become the window title (metadata other processes can read).
            } detail: {
                if let id = selection, let item = model.items.first(where: { $0.id == id }) {
                    ItemDetailView(item: item, onEdit: { editing = EditorTarget(item: item, kind: item.kind) })
                        .id(item.id)
                } else {
                    ContentUnavailableView("Select an item", systemImage: "lock.rectangle.stack", description: Text("Choose an item from the list, or add a new one."))
                }
            }
            ClipboardCountdownBar()
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Menu {
                    ForEach(ItemKind.allCases) { kind in
                        Button { editing = EditorTarget(item: nil, kind: kind, folderID: section.folderID) } label: { Label(kind.displayName, systemImage: kind.symbolName) }
                    }
                    Divider()
                    Button { folderPrompt = .create(thenMove: []) } label: { Label("New Folder…", systemImage: "folder.badge.plus") }
                    Button { chooseEnvFile() } label: { Label("Import .env file…", systemImage: "square.and.arrow.down") }
                } label: { Label("New Item", systemImage: "plus") }
                .help("Add a new item")
            }
            ToolbarItem {
                Button { showGenerator = true } label: { Label("Password Generator", systemImage: "dice") }.help("Generate a password")
            }
            ToolbarItem {
                SettingsLink { Label("Settings", systemImage: "gear") }.help("Settings (⌘,)")
            }
            ToolbarItem {
                Button { Task { await model.lock() } } label: { Label("Lock", systemImage: "lock") }.help("Lock the vault (⌘L)")
            }
        }
        .sheet(item: $editing) { target in
            ItemEditorView(existing: target.item, kind: target.kind, defaultFolderID: target.folderID) { saved in
                selection = saved.id
            }
            .environment(model)
        }
        .sheet(isPresented: $showGenerator) { PasswordGeneratorView().environment(model) }
        .sheet(item: $envImport) { t in EnvImportSheet(text: t.text, fileName: t.fileName, defaultFolderID: section.folderID).environment(model) }
        .sheet(item: $folderPrompt) { prompt in
            switch prompt {
            case .create(let ids):
                FolderNameSheet(title: ids.isEmpty ? "New Folder" : "New Folder for \(ids.count == 1 ? "this item" : "\(ids.count) items")") { name in
                    let f = try await model.createFolder(name: name)
                    if !ids.isEmpty { try await model.moveItems(ids, toFolder: f.id) }
                    section = .folder(f.id)
                }.environment(model)
            case .rename(let f):
                FolderNameSheet(title: "Rename Folder", initialName: f.name, submitLabel: "Rename") { name in
                    try await model.renameFolder(f.id, to: name)
                }.environment(model)
            }
        }
        .confirmationDialog("Delete folder “\(pendingFolderDelete?.name ?? "")”?", isPresented: Binding(get: { pendingFolderDelete != nil }, set: { if !$0 { pendingFolderDelete = nil } })) {
            Button("Delete Folder", role: .destructive) {
                if let f = pendingFolderDelete { Task { try? await model.deleteFolder(f.id) } }
                pendingFolderDelete = nil
            }
        } message: {
            let n = pendingFolderDelete.map { model.items(inFolder: $0.id).count } ?? 0
            Text(n == 0 ? "The folder is empty." : "The \(n == 1 ? "item" : "\(n) items") inside will NOT be deleted — \(n == 1 ? "it" : "they") will simply no longer be in a folder.")
        }
        .onChange(of: model.items) { _, items in
            if let sel = selection, !items.contains(where: { $0.id == sel }) { selection = nil }
        }
        .onChange(of: model.folders) { _, folders in
            if let id = section.folderID, !folders.contains(where: { $0.id == id }) { section = .all }
        }
    }

    private var emptyState: (title: String, description: String) {
        if let id = section.folderID {
            let name = model.folder(id)?.name ?? "This folder"
            return ("“\(name)” is empty", "Add an item with the + button, drag items here from another list, or right-click an item → Move to Folder.")
        }
        if section == .unfiled { return ("Every item is in a folder", "") }
        return ("No items yet", "Use the + button to add a login, API key, wallet, note or recovery codes.")
    }

    private func chooseEnvFile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.showsHiddenFiles = true
        panel.message = "Choose a .env / key file. Its contents will be encrypted into the vault; the original file is NOT deleted."
        guard panel.runModal() == .OK, let url = panel.url, let data = try? Data(contentsOf: url), data.count <= 1_000_000,
              let text = String(data: data, encoding: .utf8) else { return }
        envImport = EnvImportTarget(text: text, fileName: url.lastPathComponent)
    }
    private var sidebar: some View {
        List(selection: $section) {
            Section("Vault") {
                row(.all)
                ForEach(ItemKind.allCases) { row(.kind($0)) }
            }
            Section("Folders") {
                ForEach(model.folders) { folderRow($0) }
                if !model.folders.isEmpty { row(.unfiled).dropDestination(for: String.self) { ids, _ in drop(ids, into: nil) } }
                Button { folderPrompt = .create(thenMove: []) } label: { Label("New Folder…", systemImage: "folder.badge.plus") }
                    .buttonStyle(.borderless).foregroundStyle(.secondary)
            }
            Section("Collections") {
                row(.favorites)
                row(.recent)
            }
        }
        .listStyle(.sidebar)
        .navigationSplitViewColumnWidth(min: 180, ideal: 210)
        .safeAreaInset(edge: .bottom) {
            HStack(spacing: 6) {
                Image(systemName: "lock.shield").foregroundStyle(.green)
                Text("\(model.items.count) items · offline").font(.caption).foregroundStyle(.secondary)
            }.padding(8)
        }
    }
    private func row(_ s: SidebarSection) -> some View {
        NavigationLink(value: s) {
            Label(s.title, systemImage: s.symbol).badge(count(for: s))
        }
    }
    private func folderRow(_ f: VaultFolder) -> some View {
        NavigationLink(value: SidebarSection.folder(f.id)) {
            Label(f.name, systemImage: "folder").badge(model.items(inFolder: f.id).count)
        }
        .contextMenu {
            Button("Rename…") { folderPrompt = .rename(f) }
            Menu("New Item in Folder") {
                ForEach(ItemKind.allCases) { kind in
                    Button { editing = EditorTarget(item: nil, kind: kind, folderID: f.id) } label: { Label(kind.displayName, systemImage: kind.symbolName) }
                }
            }
            Divider()
            Button("Delete Folder…", role: .destructive) { pendingFolderDelete = f }
        }
        .dropDestination(for: String.self) { ids, _ in drop(ids, into: f.id) }
    }
    /// Items dragged from the list carry only their random record id (never any content).
    private func drop(_ payload: [String], into folderID: UUID?) -> Bool {
        let ids = payload.compactMap(UUID.init(uuidString:)).filter { id in model.items.contains { $0.id == id } }
        guard !ids.isEmpty else { return false }
        Task { try? await model.moveItems(ids, toFolder: folderID) }
        return true
    }
    private func count(for s: SidebarSection) -> Int { items(in: s).count }
    private func items(in s: SidebarSection) -> [VaultItem] {
        switch s {
        case .all: return model.items
        case .kind(let k): return model.items.filter { $0.kind == k }
        case .favorites: return model.items.filter(\.favorite)
        case .recent: return model.items.filter { $0.lastUsedAt != nil }.sorted { ($0.lastUsedAt ?? .distantPast) > ($1.lastUsedAt ?? .distantPast) }
        case .folder(let id): return model.items(inFolder: id)
        case .unfiled: return model.items(inFolder: nil)
        }
    }
    private var filteredItems: [VaultItem] {
        let base = items(in: section)
        let q = query.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return base }
        return base.filter { matches($0, q) }
    }
    private func matches(_ item: VaultItem, _ q: String) -> Bool {
        var hay = [item.title] + item.tags
        if let f = model.folder(of: item) { hay.append(f.name) }
        switch item.payload {
        case .login(let p): hay += [p.website, p.username]
        case .apiCredential(let p): hay += [p.service, p.environment]
        case .wallet(let p): hay += [p.name, p.blockchain.displayName, p.publicAddress]
        case .secureNote: break
        case .recoveryCodes(let p): hay += [p.service]
        }
        return hay.contains { $0.range(of: q, options: [.caseInsensitive, .diacriticInsensitive]) != nil }
    }
    private var integrityBanner: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(model.integrityWarnings, id: \.self) { w in
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.shield.fill").foregroundStyle(.orange)
                    Text(warningText(w)).font(.callout)
                    Spacer()
                    if w == .unreadableRecords {
                        Button("Remove unreadable records…") { confirmPurge = true }.buttonStyle(.bordered)
                    }
                }
            }
        }
        .padding(10).background(.orange.opacity(0.12))
        .confirmationDialog("Permanently remove the records that cannot be decrypted?", isPresented: $confirmPurge) {
            Button("Remove", role: .destructive) { Task { try? await model.purgeUnreadableRecords() } }
        } message: { Text("They were tampered with or corrupted and cannot be recovered. If you have an older backup, restore it instead.") }
    }
    @State private var confirmPurge = false
    private func warningText(_ w: IntegrityWarning) -> String {
        switch w {
        case .generationRollback: return "This vault file is OLDER than the one this Mac last opened (rolled back or restored from an old copy). Check that nothing is missing."
        case .fileRollback: return "This vault file's contents differ from what this Mac last saw — an older copy may have been put back. Check that nothing is missing."
        case .recordStateMismatch: return "Records were changed or deleted outside PrivateVault since the last unlock. Check that nothing is missing."
        case .unreadableRecords: return "Some records could not be decrypted (tampered or corrupted). They are hidden; the rest of the vault is intact."
        }
    }
}

struct ItemListView: View {
    @Environment(AppModel.self) private var model
    let items: [VaultItem]
    @Binding var selection: UUID?
    @Binding var query: String
    /// Show the folder name on each row (off when the list already is one folder).
    var showsFolder = true
    var emptyState: (title: String, description: String) = ("No items yet", "")
    var onNewFolder: ([UUID]) -> Void = { _ in }
    @State private var pendingDelete: VaultItem?
    var body: some View {
        List(items, selection: $selection) { item in
            HStack(spacing: 10) {
                Image(systemName: item.kind.symbolName).foregroundStyle(.tint).frame(width: 22)
                VStack(alignment: .leading, spacing: 2) {
                    Text(item.title.isEmpty ? "Untitled" : item.title).font(.body.weight(.medium)).lineLimit(1)
                    Text(subtitle(item)).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer()
                if showsFolder, let f = model.folder(of: item) {
                    Label(f.name, systemImage: "folder").font(.caption).foregroundStyle(.secondary).lineLimit(1).labelStyle(.titleAndIcon)
                }
                if item.favorite { Image(systemName: "star.fill").foregroundStyle(.yellow).font(.caption) }
            }
            .padding(.vertical, 3)
            .tag(item.id)
            .draggable(item.id.uuidString)   // drag onto a folder in the sidebar; the payload is only the random id
            .contextMenu {
                Button(item.favorite ? "Remove from Favorites" : "Add to Favorites") { Task { await model.toggleFavorite(item.id) } }
                MoveToFolderMenu(items: [item]) { onNewFolder([item.id]) }
                Divider()
                Button("Delete…", role: .destructive) { pendingDelete = item }
            }
        }
        .confirmationDialog("Delete “\(pendingDelete?.title ?? "")”?", isPresented: Binding(get: { pendingDelete != nil }, set: { if !$0 { pendingDelete = nil } })) {
            Button("Delete", role: .destructive) { if let p = pendingDelete { Task { try? await model.delete(p.id) } }; pendingDelete = nil }
        } message: { Text("This cannot be undone.") }
        .searchable(text: $query, placement: .sidebar, prompt: "Search titles, usernames, sites, tags")
        .overlay {
            if items.isEmpty {
                if query.isEmpty {
                    ContentUnavailableView(emptyState.title, systemImage: "plus.rectangle.on.folder", description: Text(emptyState.description))
                } else {
                    ContentUnavailableView("No matches", systemImage: "magnifyingglass")
                }
            }
        }
    }
    /// Never shows secret values in the list.
    private func subtitle(_ item: VaultItem) -> String {
        switch item.payload {
        case .login(let p): return p.username.isEmpty ? p.website : p.username
        case .apiCredential(let p): return [p.service, p.environment].filter { !$0.isEmpty }.joined(separator: " · ")
        case .wallet(let p): return p.blockchain.displayName + (p.publicAddress.isEmpty ? "" : " · " + String(p.publicAddress.prefix(10)) + "…")
        case .secureNote: return "Secure note"
        case .recoveryCodes(let p): return p.service
        }
    }
}


struct EnvImportSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let text: String
    let fileName: String
    var defaultFolderID: UUID? = nil
    @State private var mode: AppModel.EnvImportMode = .oneItemPerKey
    @State private var folderID: UUID?
    @State private var error: String?
    @State private var busy = false
    var body: some View {
        let entries = DotEnvParser.parse(text)
        VStack(alignment: .leading, spacing: 14) {
            Text("Import “\(fileName)”").font(.title3.weight(.semibold))
            Text("\(entries.count) KEY=VALUE lines found. Values are never shown here.").foregroundStyle(.secondary)
            Picker("Import as", selection: $mode) {
                Text("One API Credential per key (\(entries.count) items)").tag(AppModel.EnvImportMode.oneItemPerKey)
                Text("One Secure Note with the whole file").tag(AppModel.EnvImportMode.oneSecureNote)
            }.pickerStyle(.radioGroup)
            FolderPicker(folderID: $folderID)
            if !entries.isEmpty && mode == .oneItemPerKey {
                ScrollView { VStack(alignment: .leading, spacing: 2) { ForEach(entries, id: \.key) { Text($0.key).font(.system(.caption, design: .monospaced)) } } }.frame(maxHeight: 140)
            }
            Text("After importing, delete the original file (it is plaintext on disk) and empty the Trash. Copies may still exist in Time Machine backups.").font(.caption).foregroundStyle(.orange)
            ErrorBanner(message: error)
            HStack { Spacer(); Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(busy ? "Importing…" : "Import") { Task { await run() } }.buttonStyle(.borderedProminent).disabled(busy || (mode == .oneItemPerKey && entries.isEmpty)) }
        }.padding(20).frame(width: 520)
        .onAppear { folderID = defaultFolderID }
    }
    private func run() async {
        busy = true; error = nil
        do { _ = try await model.importDotEnv(text: text, fileName: fileName, mode: mode, folderID: folderID); dismiss() }
        catch { self.error = describe(error) }
        busy = false
    }
}
