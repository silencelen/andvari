import AndvariCore
import SwiftUI

/// The unlocked vault: search, favourites first, pull to refresh, and a row's quick copies on a long press.
struct VaultView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var path: [String] = []
    @State private var showSettings = false
    @State private var showNewLogin = false
    @State private var syncMessage: String?
    @State private var copies = 0

    var body: some View {
        NavigationStack(path: $path) {
            list
                .searchable(text: $query, prompt: "Search")
                .refreshable {
                    await sync()
                }
                .navigationTitle("Vault")
                .navigationDestination(for: String.self) { itemId in
                    ItemDetailView(itemId: itemId)
                }
                .toolbar {
                    toolbarContent
                }
                .toolbarBackground(Palette.background, for: .navigationBar)
        }
        .tint(Palette.goldText)
        .sensoryFeedback(.success, trigger: copies)
        .onAppear {
            query = model.state.query
        }
        .onChange(of: query) {
            model.setQuery(query)
        }
        .sheet(isPresented: $showSettings) {
            SettingsView()
                .environmentObject(model)
                .tint(Palette.goldText)
                .privacyShield()
        }
        .sheet(isPresented: $showNewLogin) {
            LoginEditorView(itemId: nil)
                .environmentObject(model)
                .tint(Palette.goldText)
                .privacyShield()
        }
    }

    private var list: some View {
        List {
            if model.state.mustChangePassword {
                Section {
                    temporaryPassword
                }
                .listRowBackground(Palette.raised)
            }
            if let syncMessage {
                Section {
                    Plate(text: syncMessage, tone: .error) {
                        self.syncMessage = nil
                    }
                }
                .listRowBackground(Color.clear)
                .listRowInsets(EdgeInsets())
            }
            if !favorites.isEmpty {
                Section {
                    rows(favorites)
                } header: {
                    SectionTitle("Favorites")
                }
            }
            if !others.isEmpty {
                Section {
                    rows(others)
                } header: {
                    if !favorites.isEmpty {
                        SectionTitle("Items")
                    }
                }
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Palette.background)
        .overlay {
            if model.state.items.isEmpty {
                emptyState
            }
        }
    }

    private func rows(_ items: [ItemSummary]) -> some View {
        ForEach(items, id: \.itemId) { item in
            NavigationLink(value: item.itemId) {
                ItemRow(item: item)
            }
            .listRowBackground(Palette.raised)
            .listRowSeparatorTint(Palette.edge)
            .contextMenu {
                quickCopies(item)
            }
        }
    }

    @ViewBuilder
    private func quickCopies(_ item: ItemSummary) -> some View {
        if let username = item.username {
            Button {
                copy(username)
            } label: {
                Label("Copy username", systemImage: "person")
            }
        }
        if item.type == "login" {
            Button {
                copySecret(item.itemId, .password)
            } label: {
                Label("Copy password", systemImage: "key")
            }
        }
        if item.hasTotp {
            Button {
                copyCode(item.itemId)
            } label: {
                Label("Copy one-time code", systemImage: "clock")
            }
        }
    }

    private var temporaryPassword: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Temporary password in use")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(Palette.danger)
            Text("Set a new master password in andvari on the web.")
                .font(.subheadline)
                .foregroundStyle(Palette.ink)
            if let server = model.state.server, let url = WebAddress.url(server) {
                Link("Open in Safari", destination: url)
                    .font(.subheadline.weight(.semibold))
            }
        }
        .padding(.vertical, 4)
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Sigil(size: 40)
                .opacity(0.7)
            Group {
                if query.trimmed.isEmpty {
                    Text("Nothing here yet")
                } else {
                    Text("No matches")
                }
            }
            .font(.headline)
            .foregroundStyle(Palette.inkDim)
        }
        .accessibilityElement(children: .combine)
    }

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItem(placement: .topBarLeading) {
            Button {
                showSettings = true
            } label: {
                Image(systemName: "gearshape")
            }
            .accessibilityLabel("Settings")
        }
        ToolbarItemGroup(placement: .topBarTrailing) {
            if model.state.syncing {
                ProgressView()
                    .accessibilityLabel("Syncing")
            }
            Button {
                model.lock()
            } label: {
                Image(systemName: "lock")
            }
            .accessibilityLabel("Lock")
            Button {
                showNewLogin = true
            } label: {
                Image(systemName: "plus")
            }
            .accessibilityLabel("New login")
        }
    }

    private var favorites: [ItemSummary] {
        model.state.items.filter { $0.favorite }
    }

    private var others: [ItemSummary] {
        model.state.items.filter { !$0.favorite }
    }

    private func sync() async {
        let outcome = await model.refresh()
        syncMessage = outcome.message
    }

    private func copy(_ value: String) {
        Clipboard.copy(value)
        copies += 1
    }

    private func copySecret(_ itemId: String, _ field: SecretField) {
        guard let value = model.revealSecret(itemId, field) else { return }
        copy(value)
    }

    private func copyCode(_ itemId: String) {
        guard let code = model.oneTimeCode(itemId) else { return }
        copy(code.code)
    }
}

/// One vault row: the tile, the name, the username or site, and a faint mark while a save waits to sync.
struct ItemRow: View {
    let item: ItemSummary

    var body: some View {
        HStack(spacing: 12) {
            ItemGlyph(name: item.name, type: item.type)
            VStack(alignment: .leading, spacing: 2) {
                Text(item.name)
                    .font(.body.weight(.semibold))
                    .foregroundStyle(Palette.ink)
                    .lineLimit(1)
                if let subtitle {
                    Text(subtitle)
                        .font(.footnote.monospaced())
                        .foregroundStyle(Palette.inkDim)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
            Spacer(minLength: 8)
            if item.pendingSync {
                Image(systemName: "arrow.up.circle")
                    .font(.footnote)
                    .foregroundStyle(Palette.inkFaint)
                    .accessibilityLabel("Not synced yet")
            }
        }
        .padding(.vertical, 3)
        .accessibilityElement(children: .combine)
    }

    private var subtitle: String? {
        if let username = item.username {
            return username
        }
        if let host = item.host {
            return host
        }
        switch item.type {
        case "note":
            return "Note"
        case "card":
            return "Card"
        default:
            return nil
        }
    }
}

private struct SectionTitle: View {
    let text: String

    init(_ text: String) {
        self.text = text
    }

    var body: some View {
        Text(text)
            .font(.footnote.weight(.semibold))
            .foregroundStyle(Palette.inkFaint)
    }
}
