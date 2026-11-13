import AndvariCore
import SwiftUI

/// The unlocked vault: search, favourites first, pull to refresh, and a row's quick copies on a long press.
struct VaultView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var path: [String] = []
    @State private var showSettings = false
    @State private var showNewLogin = false
    @State private var showNewCard = false
    @State private var showNewNote = false
    @State private var syncMessage: String?
    @State private var copies = 0
    @State private var undoAllFailure: String?
    /// The two-step setup the person left the app in the middle of (to add the key to an authenticator), back on its
    /// confirm step after the unlock (round-6 review L4).
    @State private var resumeTwoStep = false

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
        .onChange(of: model.state.twoStep?.resumed == true, initial: true) { _, resumed in
            if resumed, !showSettings { resumeTwoStep = true }
        }
        .sheet(isPresented: $resumeTwoStep) {
            NavigationStack {
                TwoStepView()
                    .toolbar {
                        ToolbarItem(placement: .confirmationAction) {
                            Button("Done") {
                                resumeTwoStep = false
                            }
                        }
                    }
            }
            .environmentObject(model)
            .tint(Palette.goldText)
            .privacyShield()
        }
        .sheet(isPresented: $showNewCard) {
            CardEditorView(itemId: nil)
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
        .sheet(isPresented: $showNewNote) {
            NoteEditorView(itemId: nil)
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
            if let notice = model.state.personalVault {
                Section {
                    PersonalVaultNotice(notice: notice)
                }
                .listRowBackground(Palette.raised)
            }
            if !model.state.vaultNotices.isEmpty {
                Section {
                    ForEach(model.state.vaultNotices, id: \.id) { notice in
                        VaultNoticeRow(notice: notice)
                    }
                }
                .listRowBackground(Palette.raised)
            }
            if !model.state.appliedSaves.isEmpty {
                Section {
                    ForEach(model.state.appliedSaves, id: \.id) { applied in
                        AppliedSaveRow(applied: applied)
                    }
                    HStack {
                        Button("Done") {
                            model.dismissAppliedSaves()
                        }
                        .font(.subheadline.weight(.semibold))
                        Spacer()
                        if model.state.appliedSaves.count > 1 {
                            Button("Undo all", role: .destructive) {
                                Task {
                                    let outcome = await model.undoAllAppliedSaves()
                                    undoAllFailure = outcome == .ok ? nil : (outcome.message ?? "Nothing was undone.")
                                }
                            }
                            .font(.subheadline)
                        }
                    }
                    .buttonStyle(.borderless)
                    .disabled(model.state.busy)
                    if let undoAllFailure {
                        Text(undoAllFailure)
                            .font(.footnote)
                            .foregroundStyle(Palette.danger)
                    }
                } header: {
                    SectionTitle(model.state.appliedSaves.count == 1 ? "Saved 1 login from AutoFill" : "Saved \(model.state.appliedSaves.count) logins from AutoFill")
                }
                .listRowBackground(Palette.raised)
            }
            if !model.state.pendingSaves.isEmpty {
                Section {
                    ForEach(model.state.pendingSaves, id: \.id) { pending in
                        PendingSaveRow(pending: pending)
                    }
                } header: {
                    SectionTitle("Logins not saved yet")
                } footer: {
                    Text("These could not be saved by themselves. Save or discard each one.")
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
        // Room under the last row: the search field floats over the bottom of the list.
        .contentMargins(.bottom, 72, for: .scrollContent)
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
            Menu {
                Button {
                    showNewLogin = true
                } label: {
                    Label("New login", systemImage: "key")
                }
                Button {
                    showNewCard = true
                } label: {
                    Label("New card", systemImage: "creditcard")
                }
                Button {
                    showNewNote = true
                } label: {
                    Label("New note", systemImage: "note.text")
                }
            } label: {
                Image(systemName: "plus")
            }
            .accessibilityLabel("New item")
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

/// A login an extension captured: shown in full, with its password on request, before the person saves or discards it.
private struct PendingSaveRow: View {
    @EnvironmentObject private var model: AppModel
    let pending: PendingSaveView
    @State private var shown: String?
    @State private var failure: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(pending.plainHttp ? "http://\(pending.host)" : pending.host)
                .font(.body.weight(.semibold))
                .foregroundStyle(Palette.ink)
            if pending.plainHttp {
                Text("Captured on a page that was not encrypted.")
                    .font(.footnote)
                    .foregroundStyle(Palette.danger)
            }
            Text(pending.username.isEmpty ? "No username" : pending.username)
                .font(.subheadline)
                .foregroundStyle(Palette.inkDim)
            Text(pending.replaces.map { "Replaces the password of \($0)" } ?? "A new login")
                .font(.footnote)
                .foregroundStyle(Palette.inkFaint)
            if let reason = pending.reason {
                Text(reason)
                    .font(.footnote)
                    .foregroundStyle(Palette.inkDim)
            }
            Text(pending.detail)
                .font(.footnote)
                .foregroundStyle(Palette.inkFaint)
            if let shown {
                // Not selectable, like every revealed secret: a copy goes through the expiring clipboard only.
                Text(shown)
                    .font(.footnote.monospaced())
                    .foregroundStyle(Palette.ink)
            }
            // Said once: a Save that fails for the reason already shown adds nothing.
            if let failure, failure != pending.reason {
                Text(failure)
                    .font(.footnote)
                    .foregroundStyle(Palette.danger)
            }
            HStack(spacing: 16) {
                Button("Save") {
                    Task {
                        let outcome = await model.confirmPendingSave(pending.id)
                        // A save that did nothing never passes silently.
                        failure = outcome == .ok ? nil : (outcome.message ?? "Not saved. Pull down to refresh, then try again.")
                    }
                }
                .font(.subheadline.weight(.semibold))
                Button(shown == nil ? "Show password" : "Hide password") {
                    shown = shown == nil ? model.pendingSavePassword(pending.id) : nil
                }
                .font(.subheadline)
                Spacer()
                Button("Discard", role: .destructive) {
                    model.discardPendingSave(pending.id)
                }
                .font(.subheadline)
            }
            .buttonStyle(.borderless)
            .disabled(model.state.busy)
        }
        .padding(.vertical, 4)
    }
}

/// A login the app saved by itself at unlock, with its Undo.
private struct AppliedSaveRow: View {
    @EnvironmentObject private var model: AppModel
    let applied: AppliedSaveView
    @State private var failure: String?

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Text(applied.plainHttp ? "http://\(applied.host)" : applied.host)
                    .font(.body.weight(.semibold))
                    .foregroundStyle(Palette.ink)
                Text(applied.username.isEmpty ? "No username" : applied.username)
                    .font(.subheadline)
                    .foregroundStyle(Palette.inkDim)
                Text(applied.replaced.map { "New password for \($0). The old one is in its history." } ?? "Added as a new login")
                    .font(.footnote)
                    .foregroundStyle(Palette.inkFaint)
                if let vault = applied.vault {
                    Text("In \(vault)")
                        .font(.footnote)
                        .foregroundStyle(Palette.inkFaint)
                } else {
                    Text("This login is not in your vault any more.")
                        .font(.footnote)
                        .foregroundStyle(Palette.danger)
                }
                if let failure {
                    Text(failure)
                        .font(.footnote)
                        .foregroundStyle(Palette.danger)
                }
            }
            Spacer()
            Button("Undo") {
                Task {
                    let outcome = await model.undoAppliedSave(applied.id)
                    failure = outcome == .ok ? nil : (outcome.message ?? "Nothing was undone.")
                }
            }
            .font(.subheadline)
            .buttonStyle(.borderless)
            .disabled(model.state.busy)
        }
        .padding(.vertical, 4)
    }
}

/// The personal-vault question (the core's sentences, as Android asks them): shown until this device has confirmed
/// which vault new items go to. Every choice goes through a confirmation that names the vault and who else holds it.
private struct PersonalVaultNotice: View {
    @EnvironmentObject private var model: AppModel
    let notice: PersonalVaultView
    @State private var password = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(notice.title)
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(Palette.danger)
            Text(notice.body)
                .font(.subheadline)
                .foregroundStyle(Palette.ink)
            if let proposal = notice.proposal {
                confirmation(proposal)
            } else {
                choices
            }
            if let error = notice.error {
                Text(error)
                    .font(.footnote)
                    .foregroundStyle(Palette.danger)
            }
        }
        .padding(.vertical, 4)
        .buttonStyle(.borderless)
    }

    @ViewBuilder
    private var choices: some View {
        if let keep = notice.keepLabel {
            if let detail = notice.keepDetail {
                Text(detail)
                    .font(.footnote)
                    .foregroundStyle(Palette.inkDim)
            }
            Button(keep) {
                Task { _ = await model.proposePersonalVault(nil) }
            }
            .font(.subheadline.weight(.semibold))
            .disabled(model.state.busy)
        }
        if let detail = notice.servedDetail {
            Text(detail)
                .font(.footnote)
                .foregroundStyle(Palette.inkDim)
        }
        if let use = notice.useServedLabel {
            Button(use) {
                _ = model.usePersonalVaultServed()
            }
            .font(.subheadline.weight(.semibold))
            .disabled(model.state.busy)
        } else if notice.lookupFailed {
            Text("Couldn't check who else holds it, so using it isn't offered yet.")
                .font(.footnote)
                .foregroundStyle(Palette.inkDim)
            Button("Try again") {
                Task { _ = await model.retryPersonalVaultDetails() }
            }
            .font(.subheadline)
        }
        ForEach(notice.choices, id: \.vaultId) { choice in
            option(choice)
        }
        if !notice.otherChoices.isEmpty {
            Text("To use another vault instead, choose it here (it asks for your master password).")
                .font(.footnote)
                .foregroundStyle(Palette.inkDim)
            ForEach(notice.otherChoices, id: \.vaultId) { choice in
                option(choice)
            }
        }
    }

    private func option(_ choice: PersonalChoiceView) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Button(choice.label) {
                Task { _ = await model.proposePersonalVault(choice.vaultId) }
            }
            .font(.subheadline.weight(.semibold))
            .disabled(model.state.busy)
            if !choice.detail.isEmpty {
                Text(choice.detail)
                    .font(.footnote)
                    .foregroundStyle(Palette.inkFaint)
            }
        }
    }

    @ViewBuilder
    private func confirmation(_ proposal: PersonalProposalView) -> some View {
        Text(proposal.title)
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(Palette.ink)
        ForEach(proposal.lines, id: \.self) { line in
            Text(line)
                .font(.footnote)
                .foregroundStyle(Palette.inkDim)
        }
        if let warning = proposal.warning {
            Text(warning)
                .font(.footnote)
                .foregroundStyle(Palette.danger)
        }
        if proposal.needsPassword {
            SecureField("Master password (required)", text: $password)
                .textContentType(.password)
                .font(.subheadline)
        }
        HStack(spacing: 16) {
            Button(proposal.confirmLabel) {
                let typed = password
                password = ""
                Task { _ = await model.confirmPersonalVault(password: proposal.needsPassword ? typed : nil) }
            }
            .font(.subheadline.weight(.semibold))
            .disabled(model.state.busy || (proposal.needsPassword && password.isEmpty))
            Button("Cancel") {
                password = ""
                model.cancelPersonalVaultProposal()
            }
            .font(.subheadline)
        }
    }
}

/// What happened to a shared vault since the last look (spec 03 §11): a deletion, a restore, a transfer, or something
/// the server said that could not be verified, which reads as a warning. Each goes when dismissed.
private struct VaultNoticeRow: View {
    @EnvironmentObject private var model: AppModel
    let notice: VaultNoticeView

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: notice.warning ? "exclamationmark.triangle" : "info.circle")
                .foregroundStyle(notice.warning ? Palette.danger : Palette.inkDim)
                .accessibilityHidden(true)
            Text(notice.text)
                .font(.subheadline)
                .foregroundStyle(notice.warning ? Palette.danger : Palette.ink)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
            Button("Dismiss") {
                model.dismissVaultNotice(notice.id)
            }
            .font(.subheadline)
            .buttonStyle(.borderless)
        }
        .padding(.vertical, 2)
    }
}

