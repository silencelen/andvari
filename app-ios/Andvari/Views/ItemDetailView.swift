import AndvariCore
import SwiftUI

/// An item without its secrets. A password or note is read only when it is shown or copied, and what was
/// shown is dropped when the screen closes.
struct ItemDetailView: View {
    let itemId: String

    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL
    @State private var detail: ItemDetail?
    @State private var password: String?
    @State private var notes: String?
    @State private var cardNumber: String?
    @State private var cardCode: String?
    @State private var copied: String?
    @State private var copies = 0
    @State private var editing = false
    @State private var gone = false
    @State private var moving = false
    /// The vaults this item can be copied to (and moved to, when [canMoveOut]), read with the item.
    @State private var moveTargets: [VaultChoiceView] = []
    /// Whether this account may take the item out of its vault; otherwise it can only be copied.
    @State private var canMoveOut = false
    /// Bumped whenever the item is read again: the previous-password rows start over, hidden, so nothing shown stays on
    /// screen under a list that may have changed underneath it.
    @State private var generation = 0
    @State private var historyOpen = false
    @State private var historyLoading = false
    @State private var historyMessage: String?
    @State private var confirmRestore: ItemVersionView?
    /// Passwords of earlier versions the person chose to show, by revision; dropped when the history closes.
    @State private var shownVersions: [Int64: String] = [:]

    init(itemId: String) {
        self.itemId = itemId
    }

    var body: some View {
        List {
            if let detail {
                content(detail)
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Palette.background)
        .navigationTitle(detail?.name ?? "")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                if detail?.editable == true {
                    Button("Edit") {
                        editing = true
                    }
                }
            }
        }
        .sheet(isPresented: $moving) {
            MoveCopySheet(itemId: itemId, targets: moveTargets, canMove: canMoveOut)
                .environmentObject(model)
                .tint(Palette.goldText)
                .privacyShield()
        }
        .sheet(isPresented: $editing, onDismiss: { editorClosed() }) {
            Group {
                if detail?.card != nil {
                    CardEditorView(itemId: itemId)
                } else if detail?.type == "note" {
                    NoteEditorView(itemId: itemId)
                } else {
                    LoginEditorView(itemId: itemId)
                }
            }
            .environmentObject(model)
            .tint(Palette.goldText)
            .privacyShield()
        }
        .sensoryFeedback(.success, trigger: copies)
        .onAppear {
            load()
        }
        .onChange(of: model.state.items) {
            load()
        }
        .onDisappear {
            password = nil
            notes = nil
            cardNumber = nil
            cardCode = nil
            closeHistory()
        }
        .confirmationDialog("Restore this version?", isPresented: restoreAsked, titleVisibility: .visible, presenting: confirmRestore) { version in
            Button("Restore") {
                restoreVersion(version)
            }
        } message: { version in
            Text("The item's current version will be replaced by the one from \(day(version.archivedAtMs)). The replaced version stays in the history.")
        }
    }

    // MARK: - Version history

    private var restoreAsked: Binding<Bool> {
        Binding(get: { confirmRestore != nil }, set: { if !$0 { confirmRestore = nil } })
    }

    @ViewBuilder
    private func historySection(_ detail: ItemDetail) -> some View {
        Section {
            if !historyOpen {
                Button("Show earlier versions") {
                    openHistory()
                }
            } else if let history = model.state.history, history.itemId == itemId {
                if history.versions.isEmpty {
                    Text("No earlier versions yet. The history starts with the next change.")
                        .foregroundStyle(Palette.inkDim)
                }
                ForEach(history.versions, id: \.rev) { version in
                    versionRow(version, canRestore: history.canRestore)
                }
                Button("Hide earlier versions") {
                    closeHistory()
                }
            } else if historyLoading {
                ProgressView()
                    .frame(maxWidth: .infinity)
            }
            if let historyMessage {
                Text(historyMessage)
                    .font(.footnote)
                    .foregroundStyle(Palette.danger)
            }
        } header: {
            Text("Version history")
        } footer: {
            Text("The server keeps up to the last 10 saves of each item.")
        }
        .listRowBackground(Palette.raised)
    }

    private func versionRow(_ version: ItemVersionView, canRestore: Bool) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(day(version.archivedAtMs, time: true))
                .font(.subheadline)
                .foregroundStyle(Palette.inkDim)
            Text([version.name, version.detail].compactMap { $0 }.joined(separator: " · "))
                .foregroundStyle(Palette.ink)
            if version.hasPassword {
                // Not selectable: a revealed secret is copied only through the expiring clipboard.
                Text(shownVersions[version.rev] ?? "••••••••")
                    .font(.body.monospaced())
                    .foregroundStyle(Palette.ink)
            }
            HStack(spacing: 16) {
                if version.hasPassword {
                    Button(shownVersions[version.rev] == nil ? "Show" : "Hide") {
                        if shownVersions[version.rev] == nil {
                            shownVersions[version.rev] = model.historyPassword(itemId, version.rev)
                        } else {
                            shownVersions[version.rev] = nil
                        }
                    }
                }
                if canRestore {
                    Button("Restore") {
                        confirmRestore = version
                    }
                    .disabled(model.state.busy)
                }
            }
            .font(.subheadline)
            .buttonStyle(.borderless)
        }
        .padding(.vertical, 2)
    }

    private func day(_ ms: Int64, time: Bool = false) -> String {
        Date(timeIntervalSince1970: TimeInterval(ms) / 1000).formatted(date: .abbreviated, time: time ? .shortened : .omitted)
    }

    private func openHistory() {
        historyOpen = true
        historyLoading = true
        historyMessage = nil
        Task {
            let outcome = await model.openItemHistory(itemId)
            historyLoading = false
            if outcome != .ok {
                historyOpen = false
                historyMessage = outcome.message
            }
        }
    }

    private func closeHistory() {
        historyOpen = false
        shownVersions = [:]
        model.closeItemHistory()
    }

    private func restoreVersion(_ version: ItemVersionView) {
        historyMessage = nil
        shownVersions = [:]
        Task {
            let outcome = await model.restoreItemVersion(itemId, version.rev)
            if outcome != .ok {
                historyMessage = outcome.message
            }
        }
    }

    @ViewBuilder
    private func content(_ detail: ItemDetail) -> some View {
        Section {
            header(detail)
        }
        .listRowBackground(Palette.raised)
        if detail.username != nil || detail.hasPassword {
            Section {
                credentials(detail)
            }
            .listRowBackground(Palette.raised)
        }
        if let card = detail.card {
            Section {
                cardFields(card)
            }
            .listRowBackground(Palette.raised)
        }
        if detail.hasTotp {
            Section {
                OneTimeCodeRow(itemId: itemId, onCopy: { copies += 1 })
            }
            .listRowBackground(Palette.raised)
        }
        if !detail.uris.isEmpty {
            Section("Websites") {
                ForEach(Array(detail.uris.enumerated()), id: \.offset) { _, uri in
                    website(uri)
                }
            }
            .listRowBackground(Palette.raised)
        }
        if detail.hasNotes {
            Section(detail.type == "note" ? "Note" : "Notes") {
                notesRow(isNote: detail.type == "note")
            }
            .listRowBackground(Palette.raised)
        }
        if detail.previousPasswords > 0 {
            Section {
                ForEach(historyRows) { row in
                    PreviousPasswordRow(itemId: itemId, index: row.index, retired: row.retired) { value in
                        copy(value, as: "previous-\(row.index)")
                    }
                }
            } header: {
                Text("Previous passwords")
            } footer: {
                Text("Kept when a password was replaced. Newest first.")
            }
            .listRowBackground(Palette.raised)
        }
        if !moveTargets.isEmpty {
            Section {
                Button(canMoveOut ? "Move or copy to another vault…" : "Copy to another vault…") {
                    moving = true
                }
            }
            .listRowBackground(Palette.raised)
        }
        historySection(detail)
        Section {
            Text("Updated \(updated(detail))")
                .font(.footnote)
                .foregroundStyle(Palette.inkFaint)
        }
        .listRowBackground(Color.clear)
    }

    private func header(_ detail: ItemDetail) -> some View {
        HStack(spacing: 14) {
            ItemGlyph(name: detail.name, type: detail.type)
            Text(detail.name)
                .font(.title3.weight(.semibold))
                .foregroundStyle(Palette.ink)
                .lineLimit(2)
            Spacer(minLength: 0)
            if detail.favorite {
                Image(systemName: "star.fill")
                    .foregroundStyle(Palette.gold)
                    .accessibilityLabel("Favorite")
            }
        }
        .padding(.vertical, 4)
    }

    @ViewBuilder
    private func credentials(_ detail: ItemDetail) -> some View {
        if let username = detail.username {
            HStack(spacing: 8) {
                field("Username", username)
                Spacer(minLength: 8)
                CopyButton(label: "Copy username", copied: copied == "username") {
                    copy(username, as: "username")
                }
            }
        }
        if detail.hasPassword {
            HStack(spacing: 8) {
                field("Password", password ?? "••••••••••••", hidden: password == nil)
                Spacer(minLength: 8)
                Button {
                    togglePassword()
                } label: {
                    Image(systemName: password == nil ? "eye" : "eye.slash")
                        .frame(minWidth: 32, minHeight: 32)
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(password == nil ? "Show password" : "Hide password")
                CopyButton(label: "Copy password", copied: copied == "password") {
                    copySecret(.password, as: "password")
                }
            }
        }
    }

    /// A card: the number and the security code are shown only on request and copied like a password; the rest is
    /// shown plainly and can be copied.
    @ViewBuilder
    private func cardFields(_ card: CardDetail) -> some View {
        if card.hasNumber {
            secretRow("Card number", shown: cardNumber, placeholder: card.summary, name: "card-number", secret: .cardNumber) {
                cardNumber = cardNumber == nil ? model.revealSecret(itemId, .cardNumber) : nil
            }
        }
        if let expiry = card.expiry {
            plainRow("Expires", expiry, name: "expiry")
        }
        if card.hasCode {
            secretRow("Security code", shown: cardCode, placeholder: "•••", name: "card-code", secret: .cardCode) {
                cardCode = cardCode == nil ? model.revealSecret(itemId, .cardCode) : nil
            }
        }
        if let holder = card.cardholder {
            plainRow("Cardholder", holder, name: "cardholder")
        }
        if let postal = card.postalCode {
            plainRow("Postal code", postal, name: "postal")
        }
    }

    private func plainRow(_ label: String, _ value: String, name: String) -> some View {
        HStack(spacing: 8) {
            field(label, value)
            Spacer(minLength: 8)
            CopyButton(label: "Copy \(label.lowercased())", copied: copied == name) {
                copy(value, as: name)
            }
        }
    }

    private func secretRow(_ label: String, shown: String?, placeholder: String, name: String, secret: SecretField, toggle: @escaping () -> Void) -> some View {
        HStack(spacing: 8) {
            field(label, shown ?? placeholder, hidden: shown == nil)
            Spacer(minLength: 8)
            Button {
                toggle()
            } label: {
                Image(systemName: shown == nil ? "eye" : "eye.slash")
                    .frame(minWidth: 32, minHeight: 32)
            }
            .buttonStyle(.borderless)
            .accessibilityLabel(shown == nil ? "Show \(label.lowercased())" : "Hide \(label.lowercased())")
            CopyButton(label: "Copy \(label.lowercased())", copied: copied == name) {
                copySecret(secret, as: name)
            }
        }
    }

    private func field(_ label: String, _ value: String, hidden: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            FieldLabel(text: label)
            Text(value)
                .font(.body.monospaced())
                .foregroundStyle(hidden ? Palette.inkFaint : Palette.ink)
                .lineLimit(hidden ? 1 : nil)
                .truncationMode(.middle)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(label)
        .accessibilityValue(hidden ? "Hidden" : value)
    }

    private func website(_ uri: String) -> some View {
        HStack(spacing: 8) {
            Text(uri)
                .font(.footnote.monospaced())
                .foregroundStyle(Palette.ink)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer(minLength: 8)
            if let url = WebAddress.url(uri) {
                Button {
                    openURL(url)
                } label: {
                    Image(systemName: "arrow.up.right.square")
                        .frame(minWidth: 32, minHeight: 32)
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Open \(uri)")
            }
        }
    }

    private func notesRow(isNote: Bool) -> some View {
        let toggleTitle = notes == nil ? "Show" : "Hide"
        return VStack(alignment: .leading, spacing: 10) {
            if let notes {
                Text(notes)
                    .font(.body)
                    .foregroundStyle(Palette.ink)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            HStack {
                Button(toggleTitle) {
                    toggleNotes()
                }
                .buttonStyle(.borderless)
                Spacer()
                CopyButton(label: isNote ? "Copy note" : "Copy notes", copied: copied == "notes") {
                    copySecret(.notes, as: "notes")
                }
            }
        }
    }

    private func updated(_ detail: ItemDetail) -> String {
        Date(timeIntervalSince1970: TimeInterval(detail.updatedAt) / 1000)
            .formatted(date: .abbreviated, time: .shortened)
    }

    /// One row per earlier password. The id names the entry (when it was retired, and where it sits now) and the read
    /// it came from, never the place alone: a row's shown password cannot end up beside another entry.
    private var historyRows: [HistoryRow] {
        model.passwordHistory(itemId).enumerated().map { index, retired in
            HistoryRow(id: "\(generation)|\(index)|\(retired.timeIntervalSince1970)", index: index, retired: retired)
        }
    }

    private func load() {
        generation += 1
        if let next = model.itemDetail(itemId) {
            detail = next
            moveTargets = model.moveTargets(itemId)
            canMoveOut = model.canMoveOut(itemId)
        } else if detail != nil {
            // The item is gone: deleted here, or by a sync. Leave once the editor, if open, has closed.
            detail = nil
            password = nil
            notes = nil
            if editing {
                gone = true
            } else {
                dismiss()
            }
        }
    }

    private func editorClosed() {
        if gone {
            dismiss()
        } else {
            // An edit may have changed what is shown: read it again, and let a revealed secret go.
            password = nil
            notes = nil
            load()
        }
    }

    private func togglePassword() {
        password = password == nil ? model.revealSecret(itemId, .password) : nil
    }

    private func toggleNotes() {
        notes = notes == nil ? model.revealSecret(itemId, .notes) : nil
    }

    private func copySecret(_ secret: SecretField, as name: String) {
        guard let value = model.revealSecret(itemId, secret) else { return }
        copy(value, as: name)
    }

    private func copy(_ value: String, as name: String) {
        Clipboard.copy(value)
        copies += 1
        copied = name
        AccessibilityNotification.Announcement("Copied").post()
        Task {
            try? await Task.sleep(for: .seconds(1.5))
            if copied == name {
                copied = nil
            }
        }
    }
}

/// The current one-time code, refreshed every second while it is on screen, with the time it has left.
struct OneTimeCodeRow: View {
    let itemId: String
    let onCopy: @MainActor () -> Void

    @EnvironmentObject private var model: AppModel
    @State private var code: OneTimeCode?
    @State private var copied = false

    init(itemId: String, onCopy: @escaping @MainActor () -> Void) {
        self.itemId = itemId
        self.onCopy = onCopy
    }

    var body: some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 3) {
                FieldLabel(text: "One-time code")
                Text(code.map { Self.grouped($0.code) } ?? "––– –––")
                    .font(.title3.monospaced().weight(.medium))
                    .foregroundStyle(Palette.goldBright)
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("One-time code")
            .accessibilityValue(spoken)
            Spacer(minLength: 8)
            if let code {
                CountdownRing(remaining: code.secondsRemaining, period: code.periodSeconds)
            }
            CopyButton(label: "Copy one-time code", copied: copied) {
                copy()
            }
        }
        .task {
            while !Task.isCancelled {
                code = model.oneTimeCode(itemId)
                try? await Task.sleep(for: .seconds(1))
            }
        }
        .onDisappear {
            code = nil
        }
    }

    private var spoken: String {
        guard let code else { return "Unavailable" }
        return "\(code.code), \(code.secondsRemaining) seconds left"
    }

    private static func grouped(_ code: String) -> String {
        guard code.count >= 6 else { return code }
        let half = code.count / 2
        return "\(code.prefix(half)) \(code.suffix(code.count - half))"
    }

    private func copy() {
        guard let current = model.oneTimeCode(itemId) else { return }
        Clipboard.copy(current.code)
        onCopy()
        copied = true
        AccessibilityNotification.Announcement("Copied").post()
        Task {
            try? await Task.sleep(for: .seconds(1.5))
            copied = false
        }
    }
}

/// The share of the code's period that is left, as a ring.
struct CountdownRing: View {
    let remaining: Int32
    let period: Int32
    @ScaledMetric(relativeTo: .body) private var size: CGFloat = 22

    init(remaining: Int32, period: Int32) {
        self.remaining = remaining
        self.period = period
    }

    var body: some View {
        ZStack {
            Circle()
                .stroke(Palette.edge, lineWidth: 3)
            Circle()
                .trim(from: 0, to: fraction)
                .stroke(Palette.gold, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }

    private var fraction: CGFloat {
        period > 0 ? CGFloat(remaining) / CGFloat(period) : 0
    }
}

/// Where one earlier password sits in the list read now.
private struct HistoryRow: Identifiable {
    let id: String
    let index: Int
    let retired: Date
}

/// One earlier password of a login: when it was retired, shown only on request, and copied like the current one.
private struct PreviousPasswordRow: View {
    @EnvironmentObject private var model: AppModel
    let itemId: String
    let index: Int
    let retired: Date
    let copy: (String) -> Void
    @State private var shown: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Replaced \(retired.formatted(date: .abbreviated, time: .shortened))")
                .font(.subheadline)
                .foregroundStyle(Palette.inkDim)
            // Not selectable: a copy goes through Copy, which keeps it on this device and lets it expire.
            Text(shown ?? "••••••••")
                .font(.body.monospaced())
                .foregroundStyle(Palette.ink)
            HStack(spacing: 16) {
                Button(shown == nil ? "Show" : "Hide") {
                    shown = shown == nil ? model.previousPassword(itemId, index) : nil
                }
                Button("Copy") {
                    if let value = model.previousPassword(itemId, index) {
                        copy(value)
                    }
                }
            }
            .font(.subheadline)
            .buttonStyle(.borderless)
        }
        .padding(.vertical, 2)
    }
}
