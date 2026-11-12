import AndvariCore
import SwiftUI

/// The vaults this account holds (spec 03 §10, §11): create a shared vault, open one to rename, delete or leave it,
/// and bring back one deleted in the last 7 days. Members are added from the web app for now.
struct SharedVaultsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var loading = true
    @State private var message: String?
    @State private var creating = false
    @State private var newName = ""
    @State private var restoring: DeletedVaultView?

    var body: some View {
        List {
            if let sharing = model.state.sharing {
                Section {
                    ForEach(sharing.vaults, id: \.vaultId) { vault in
                        if vault.personal {
                            row(vault)
                        } else {
                            NavigationLink {
                                SharedVaultDetailView(vaultId: vault.vaultId)
                            } label: {
                                row(vault)
                            }
                        }
                    }
                    Button("New shared vault…") {
                        newName = ""
                        creating = true
                    }
                    .disabled(model.state.busy)
                } header: {
                    Text("Vaults")
                } footer: {
                    Text("Every item lives in exactly one vault. Everyone in a shared vault sees what is in it; only its owner manages it. Add members from the web app for now.")
                }
                .listRowBackground(Palette.raised)

                if let copying = sharing.copying {
                    Section {
                        ProgressView(value: Double(copying.done), total: Double(max(copying.total, 1))) {
                            Text("Copying items to your personal vault… \(copying.done) of \(copying.total)")
                                .font(.footnote)
                        }
                    }
                    .listRowBackground(Palette.raised)
                } else if let copied = sharing.copied {
                    Section {
                        Text(copied)
                            .font(.footnote)
                            .foregroundStyle(Palette.inkDim)
                    }
                    .listRowBackground(Palette.raised)
                }

                if !sharing.deleted.isEmpty {
                    Section {
                        ForEach(sharing.deleted, id: \.vaultId) { vault in
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("“\(vault.name)”")
                                    Text("Deleted \(day(vault.deletedAtMs)) · erased for good \(day(vault.purgeAtMs))")
                                        .font(.footnote)
                                        .foregroundStyle(Palette.inkDim)
                                }
                                Spacer()
                                Button("Restore") {
                                    restoring = vault
                                }
                                .buttonStyle(.borderless)
                                .disabled(model.state.busy)
                            }
                        }
                    } header: {
                        Text("Recently deleted")
                    } footer: {
                        Text("Shared vaults you deleted that you can still bring back, for every member, with everything that was in them.")
                    }
                    .listRowBackground(Palette.raised)
                }

                if !sharing.removed.isEmpty {
                    Section {
                        ForEach(sharing.removed, id: \.vaultId) { vault in
                            VStack(alignment: .leading, spacing: 2) {
                                Text("“\(vault.name)”")
                                Text(vault.line)
                                    .font(.footnote)
                                    .foregroundStyle(vault.warning ? Palette.danger : Palette.inkDim)
                            }
                        }
                    } header: {
                        Text("Recently removed")
                    } footer: {
                        Text("Vaults this account lost access to. A sealed copy is kept on this device for a while: if the vault is restored or you are added back, everything comes back.")
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

            if let message {
                Section {
                    InlineMessage(text: message)
                }
                .listRowBackground(Color.clear)
            }
        }
        .scrollContentBackground(.hidden)
        .background(Palette.background)
        .navigationTitle("Shared vaults")
        .navigationBarTitleDisplayMode(.inline)
        .task {
            let outcome = await model.openSharing()
            loading = false
            if outcome != .ok { message = outcome.message }
        }
        .onDisappear {
            model.closeSharing()
        }
        .alert("New shared vault", isPresented: $creating) {
            TextField("Name", text: $newName)
            Button("Create") {
                let name = newName
                act { await model.createSharedVault(name) }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("You own it, and it is shared with nobody until you add someone.")
        }
        .confirmationDialog("Restore this vault?", isPresented: restoreAsked, titleVisibility: .visible, presenting: restoring) { vault in
            Button("Restore “\(vault.name)”") {
                act { await model.restoreDeletedVault(vault.vaultId) }
            }
        } message: { _ in
            Text("It comes back for every member with everything that was in it.")
        }
    }

    private var restoreAsked: Binding<Bool> {
        Binding(get: { restoring != nil }, set: { if !$0 { restoring = nil } })
    }

    private func row(_ vault: SharingVaultView) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(vault.name)
                .foregroundStyle(Palette.ink)
            Text(vault.personal ? "Personal vault" : "Shared vault · \(vault.role ?? "member")")
                .font(.footnote)
                .foregroundStyle(Palette.inkDim)
        }
    }

    private func day(_ ms: Int64) -> String {
        Date(timeIntervalSince1970: TimeInterval(ms) / 1000).formatted(date: .abbreviated, time: .omitted)
    }

    private func act(_ action: @escaping () async -> Outcome) {
        message = nil
        Task {
            let outcome = await action()
            if outcome != .ok { message = outcome.message }
        }
    }
}

/// One shared vault: the owner renames it, copies its items into the personal vault, or deletes it (typing its name);
/// a member leaves it.
struct SharedVaultDetailView: View {
    let vaultId: String

    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var renaming = false
    @State private var newName = ""
    @State private var typedName = ""
    @State private var confirmLeave = false
    @State private var message: String?

    var body: some View {
        Form {
            if let vault {
                if vault.role == "owner" {
                    ownerSections(vault)
                } else {
                    memberSections(vault)
                }
            }
            if let message {
                Section {
                    InlineMessage(text: message)
                }
                .listRowBackground(Color.clear)
            }
        }
        .scrollContentBackground(.hidden)
        .background(Palette.background)
        .navigationTitle(vault?.name ?? "")
        .navigationBarTitleDisplayMode(.inline)
        .onChange(of: vault == nil) { _, gone in
            // Deleted or left: nothing more to show here.
            if gone { dismiss() }
        }
        .alert("Rename vault", isPresented: $renaming) {
            TextField("Name", text: $newName)
            Button("Save") {
                let name = newName
                act { await model.renameSharedVault(vaultId, name: name) }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The name is encrypted, readable only with this vault's key, and syncs to every member.")
        }
        .confirmationDialog("Leave this vault?", isPresented: $confirmLeave, titleVisibility: .visible) {
            Button("Leave vault", role: .destructive) {
                act { await model.leaveSharedVault(vaultId) }
            }
        } message: {
            Text("You'll lose access on all your devices, and edits you haven't synced are discarded. The items stay with the owner and other members; only the owner can add you back.")
        }
    }

    private var vault: SharingVaultView? {
        model.state.sharing?.vaults.first(where: { $0.vaultId == vaultId })
    }

    private var copying: CopyProgressView? {
        model.state.sharing?.copying
    }

    @ViewBuilder
    private func ownerSections(_ vault: SharingVaultView) -> some View {
        Section {
            LabeledContent("Name", value: vault.name)
            Button("Rename…") {
                newName = vault.name
                renaming = true
            }
            .disabled(model.state.busy)
        } footer: {
            Text((vault.ownershipConfirmed ? "You own this vault. " : "The server reports you as this vault's owner. ") + "Writers can add and edit items; readers can only view.")
        }
        .listRowBackground(Palette.raised)

        Section {
            Text(deleteExplanation(vault))
                .font(.footnote)
                .foregroundStyle(Palette.inkDim)
                .fixedSize(horizontal: false, vertical: true)
            if let copying, copying.vaultId == vaultId {
                ProgressView(value: Double(copying.done), total: Double(max(copying.total, 1))) {
                    Text("Copying… \(copying.done) of \(copying.total)")
                        .font(.footnote)
                }
            } else {
                Button("Copy items to my personal vault first") {
                    act { await model.copySharedVaultToPersonal(vaultId) }
                }
                .disabled(model.state.busy || copying != nil || vault.itemCount == 0)
            }
            if let copied = model.state.sharing?.copied {
                Text(copied)
                    .font(.footnote)
                    .foregroundStyle(Palette.inkDim)
            }
            Text("Deleting can't take back what people already saw: anyone who had access may have kept copies of items or the vault key. If a password really matters, change it at the website too.")
                .font(.footnote)
                .foregroundStyle(Palette.inkDim)
                .fixedSize(horizontal: false, vertical: true)
            TextField("Type “\(vault.name)” to delete it", text: $typedName)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
            Button("Delete vault", role: .destructive) {
                let typed = typedName
                act { await model.deleteSharedVault(vaultId, typedName: typed) }
            }
            .disabled(typedName != vault.name || model.state.busy || copying != nil)
        } header: {
            Text("Delete")
        }
        .listRowBackground(Palette.raised)
    }

    @ViewBuilder
    private func memberSections(_ vault: SharingVaultView) -> some View {
        Section {
            LabeledContent("Your role", value: vault.role ?? "member")
            Text(vault.role == "reader" ? "You can view what is in this vault." : "You can add and edit items in this vault.")
                .font(.footnote)
                .foregroundStyle(Palette.inkDim)
        }
        .listRowBackground(Palette.raised)
        Section {
            Button("Leave vault…", role: .destructive) {
                confirmLeave = true
            }
            .disabled(model.state.busy)
        }
        .listRowBackground(Palette.raised)
    }

    private func deleteExplanation(_ vault: SharingVaultView) -> String {
        let items = vault.itemCount == 1 ? "1 item" : "\(vault.itemCount) items"
        let files = vault.attachmentCount == 0 ? "" : (vault.attachmentCount == 1 ? " and 1 attachment" : " and \(vault.attachmentCount) attachments")
        return "This removes the vault from everyone's andvari now. The server keeps its \(items)\(files) for 7 days in case you change your mind, then erases them for good. To keep some of them, copy them to your personal vault first."
    }

    private func act(_ action: @escaping () async -> Outcome) {
        message = nil
        Task {
            let outcome = await action()
            if outcome != .ok { message = outcome.message }
        }
    }
}
