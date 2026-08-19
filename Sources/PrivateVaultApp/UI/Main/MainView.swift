import SwiftUI
import VaultCore

enum SidebarSection: Hashable, Identifiable {
    case all, kind(ItemKind), favorites, recent
    var id: String {
        switch self { case .all: "all"; case .kind(let k): k.rawValue; case .favorites: "favorites"; case .recent: "recent" }
    }
    var title: String {
        switch self { case .all: "All Items"; case .kind(let k): k.pluralName; case .favorites: "Favorites"; case .recent: "Recently Used" }
    }
    var symbol: String {
        switch self { case .all: "tray.full"; case .kind(let k): k.symbolName; case .favorites: "star"; case .recent: "clock" }
    }
}

struct MainView: View {
    @Environment(AppModel.self) private var model
    @State private var section: SidebarSection = .all
    @State private var selection: UUID?
    @State private var query = ""
    @State private var editing: EditorTarget?
    @State private var showGenerator = false
    @State private var columnVisibility = NavigationSplitViewVisibility.all

    struct EditorTarget: Identifiable { let id = UUID(); let item: VaultItem?; let kind: ItemKind }

    var body: some View {
        VStack(spacing: 0) {
            if !model.integrityWarnings.isEmpty { integrityBanner }
            NavigationSplitView(columnVisibility: $columnVisibility) {
                sidebar
            } content: {
                ItemListView(items: filteredItems, selection: $selection, query: $query)
                    .navigationSplitViewColumnWidth(min: 260, ideal: 320)
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
                        Button { editing = EditorTarget(item: nil, kind: kind) } label: { Label(kind.displayName, systemImage: kind.symbolName) }
                    }
                } label: { Label("New Item", systemImage: "plus") }
                .help("Add a new item")
            }
            ToolbarItem {
                Button { showGenerator = true } label: { Label("Password Generator", systemImage: "dice") }.help("Generate a password")
            }
            ToolbarItem {
                Button { Task { await model.lock() } } label: { Label("Lock", systemImage: "lock") }.help("Lock the vault (⌘L)")
            }
        }
        .sheet(item: $editing) { target in
            ItemEditorView(existing: target.item, kind: target.kind) { saved in
                selection = saved.id
            }
            .environment(model)
        }
        .sheet(isPresented: $showGenerator) { PasswordGeneratorView().environment(model) }
        .onChange(of: model.items) { _, items in
            if let sel = selection, !items.contains(where: { $0.id == sel }) { selection = nil }
        }
    }

    private var sidebar: some View {
        List(selection: $section) {
            Section("Vault") {
                row(.all)
                ForEach(ItemKind.allCases) { row(.kind($0)) }
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
    private func count(for s: SidebarSection) -> Int { items(in: s).count }
    private func items(in s: SidebarSection) -> [VaultItem] {
        switch s {
        case .all: return model.items
        case .kind(let k): return model.items.filter { $0.kind == k }
        case .favorites: return model.items.filter(\.favorite)
        case .recent: return model.items.filter { $0.lastUsedAt != nil }.sorted { ($0.lastUsedAt ?? .distantPast) > ($1.lastUsedAt ?? .distantPast) }
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
                if item.favorite { Image(systemName: "star.fill").foregroundStyle(.yellow).font(.caption) }
            }
            .padding(.vertical, 3)
            .tag(item.id)
            .contextMenu {
                Button(item.favorite ? "Remove from Favorites" : "Add to Favorites") { Task { await model.toggleFavorite(item.id) } }
                Divider()
                Button("Delete…", role: .destructive) { pendingDelete = item }
            }
        }
        .confirmationDialog("Delete “\(pendingDelete?.title ?? "")”?", isPresented: Binding(get: { pendingDelete != nil }, set: { if !$0 { pendingDelete = nil } })) {
            Button("Delete", role: .destructive) { if let p = pendingDelete { Task { try? await model.delete(p.id) } }; pendingDelete = nil }
        } message: { Text("This cannot be undone.") }
        .searchable(text: $query, placement: .sidebar, prompt: "Search titles, usernames, sites, tags")
        .overlay {
            if items.isEmpty { ContentUnavailableView(query.isEmpty ? "No items yet" : "No matches", systemImage: query.isEmpty ? "plus.rectangle.on.folder" : "magnifyingglass") }
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
