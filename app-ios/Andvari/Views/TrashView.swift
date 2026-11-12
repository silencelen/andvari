import AndvariCore
import SwiftUI

/// The server's trash: items deleted in the last 30 days, each named from its last readable version. Restore brings one
/// back to its vault on every device (without its attachments); Delete forever removes it and its history now. What
/// was read is held only while this screen is open.
struct TrashView: View {
    @EnvironmentObject private var model: AppModel
    @State private var loading = true
    @State private var message: String?
    @State private var confirmPurge: TrashItemView?
    @State private var working: String?

    var body: some View {
        List {
            Section {
                Text(AppStateKt.TRASH_EXPLANATION)
                    .font(.footnote)
                    .foregroundStyle(Palette.inkDim)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .listRowBackground(Color.clear)

            if let message {
                Section {
                    Text(message)
                        .foregroundStyle(Palette.danger)
                }
                .listRowBackground(Color.clear)
            }

            if let items = model.state.trash {
                if items.isEmpty {
                    Section {
                        Text("Nothing here. Items you delete show up in this list for 30 days.")
                            .foregroundStyle(Palette.inkDim)
                    }
                    .listRowBackground(Palette.raised)
                } else {
                    Section {
                        ForEach(items, id: \.itemId) { item in
                            row(item)
                        }
                    }
                    .listRowBackground(Palette.raised)
                }
            } else if loading {
                Section {
                    ProgressView()
                        .frame(maxWidth: .infinity)
                }
                .listRowBackground(Color.clear)
            }
        }
        .scrollContentBackground(.hidden)
        .background(Palette.background)
        .navigationTitle("Trash")
        .navigationBarTitleDisplayMode(.inline)
        .refreshable {
            await load()
        }
        .task {
            await load()
        }
        .onDisappear {
            model.closeTrash()
        }
        .confirmationDialog("Delete forever?", isPresented: purgeAsked, titleVisibility: .visible, presenting: confirmPurge) { item in
            Button("Delete forever", role: .destructive) {
                purge(item)
            }
        } message: { _ in
            Text("This removes the item and its history from every device. It can't be undone.")
        }
    }

    private var purgeAsked: Binding<Bool> {
        Binding(get: { confirmPurge != nil }, set: { if !$0 { confirmPurge = nil } })
    }

    private func row(_ item: TrashItemView) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 12) {
                ItemGlyph(name: item.name ?? "", type: item.type ?? "")
                VStack(alignment: .leading, spacing: 2) {
                    Text(item.name ?? "Unrecoverable: no readable version")
                        .foregroundStyle(item.name == nil ? Palette.inkDim : Palette.ink)
                    Text(subtitle(item))
                        .font(.footnote)
                        .foregroundStyle(Palette.inkDim)
                }
            }
            if item.canRestore || item.canPurge {
                HStack(spacing: 20) {
                    if item.canRestore {
                        Button("Restore") {
                            restore(item)
                        }
                    }
                    if item.canPurge {
                        Button("Delete forever", role: .destructive) {
                            confirmPurge = item
                        }
                    }
                    if working == item.itemId {
                        ProgressView()
                    }
                }
                .font(.subheadline)
                .buttonStyle(.borderless)
                .disabled(working != nil || model.state.busy)
            }
        }
        .padding(.vertical, 2)
    }

    private func subtitle(_ item: TrashItemView) -> String {
        let deleted = Date(timeIntervalSince1970: TimeInterval(item.deletedAtMs) / 1000).formatted(date: .abbreviated, time: .omitted)
        var parts = ["Deleted \(deleted)"]
        if let detail = item.detail { parts.insert(detail, at: 0) }
        if let vault = item.vault { parts.append(vault) }
        if !item.canPurge { parts.append("view only") }
        return parts.joined(separator: " · ")
    }

    private func load() async {
        loading = true
        let outcome = await model.openTrash()
        loading = false
        message = outcome == .ok ? nil : outcome.message
    }

    private func restore(_ item: TrashItemView) {
        working = item.itemId
        message = nil
        Task {
            let outcome = await model.restoreFromTrash(item.itemId)
            working = nil
            if outcome != .ok { message = outcome.message }
        }
    }

    private func purge(_ item: TrashItemView) {
        working = item.itemId
        message = nil
        Task {
            let outcome = await model.purgeFromTrash(item.itemId)
            working = nil
            if outcome != .ok { message = outcome.message }
        }
    }
}
