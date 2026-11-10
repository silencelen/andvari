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
    @State private var copied: String?
    @State private var copies = 0
    @State private var editing = false
    @State private var gone = false

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
        .sheet(isPresented: $editing, onDismiss: { editorClosed() }) {
            LoginEditorView(itemId: itemId)
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
            Section("Notes") {
                notesRow
            }
            .listRowBackground(Palette.raised)
        }
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

    private var notesRow: some View {
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
                CopyButton(label: "Copy notes", copied: copied == "notes") {
                    copySecret(.notes, as: "notes")
                }
            }
        }
    }

    private func updated(_ detail: ItemDetail) -> String {
        Date(timeIntervalSince1970: TimeInterval(detail.updatedAt) / 1000)
            .formatted(date: .abbreviated, time: .shortened)
    }

    private func load() {
        if let next = model.itemDetail(itemId) {
            detail = next
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
