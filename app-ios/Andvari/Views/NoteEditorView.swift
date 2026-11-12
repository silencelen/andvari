import AndvariCore
import SwiftUI

struct NoteDraft: Equatable {
    var name = ""
    var text = ""
    var favorite = false
}

/// Add a secure note (no item) or edit one. The text is a secret like a password: it is read once, to fill the form,
/// and the form forgets it when it closes. It is never offered to AutoFill.
struct NoteEditorView: View {
    let itemId: String?

    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var draft = NoteDraft()
    @State private var loaded = false
    @State private var unreadable = false
    @State private var saving = false
    @State private var confirmDelete = false
    @State private var vaultChoices: [VaultChoiceView] = []
    @State private var vaultId: String?
    @State private var message: String?

    var body: some View {
        NavigationStack {
            Form {
                if itemId == nil {
                    VaultPickerSection(choices: vaultChoices, selection: $vaultId)
                }
                Section {
                    TextField("Name", text: $draft.name)
                    Toggle("Favorite", isOn: $draft.favorite)
                }
                .listRowBackground(Palette.raised)

                Section("Note") {
                    SecretTextEditor(text: $draft.text)
                        .frame(minHeight: 220)
                        .accessibilityLabel("Note")
                }
                .listRowBackground(Palette.raised)

                if let message {
                    Section {
                        Text(message)
                            .foregroundStyle(Palette.danger)
                    }
                    .listRowBackground(Color.clear)
                }

                if itemId != nil {
                    Section {
                        Button("Delete note", role: .destructive) {
                            confirmDelete = true
                        }
                        .disabled(saving)
                    }
                    .listRowBackground(Palette.raised)
                }
            }
            .scrollContentBackground(.hidden)
            .background(Palette.background)
            .navigationTitle(itemId == nil ? "New note" : "Edit note")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                    .disabled(saving)
                }
                ToolbarItem(placement: .confirmationAction) {
                    if saving {
                        ProgressView()
                    } else {
                        Button("Save") {
                            save()
                        }
                        .disabled(draft.name.trimmed.isEmpty || unreadable || model.state.busy)
                    }
                }
            }
            .toolbarBackground(Palette.background, for: .navigationBar)
            .confirmationDialog("Delete this note?", isPresented: $confirmDelete, titleVisibility: .visible) {
                Button("Delete note", role: .destructive) {
                    delete()
                }
            } message: {
                Text("It goes to the trash on your server.")
            }
        }
        .onAppear {
            load()
        }
        .onDisappear {
            draft = NoteDraft()
        }
    }

    private func load() {
        guard !loaded else { return }
        loaded = true
        guard let itemId else {
            vaultChoices = model.newItemVaults()
            vaultId = VaultPickerSection.initialSelection(vaultChoices)
            return
        }
        guard let detail = model.itemDetail(itemId), detail.type == "note" else {
            unreadable = true
            message = "This note is no longer available."
            return
        }
        var next = NoteDraft()
        next.name = detail.name
        next.favorite = detail.favorite
        // A save writes the whole note, so text that cannot be read now must not be saved as empty.
        if detail.hasNotes {
            guard let text = model.revealSecret(itemId, .notes) else {
                unreadable = true
                message = "This note can't be read right now."
                return
            }
            next.text = text
        }
        draft = next
    }

    private func save() {
        guard !saving else { return }
        message = nil
        let input = NoteInput(name: draft.name.trimmed, text: draft.text, favorite: draft.favorite)
        saving = true
        Task {
            let outcome = await model.saveNote(itemId: itemId, input: input, vaultId: itemId == nil ? vaultId : nil)
            saving = false
            if outcome == .ok {
                dismiss()
            } else {
                message = outcome.message
            }
        }
    }

    private func delete() {
        guard let itemId, !saving else { return }
        message = nil
        saving = true
        Task {
            let outcome = await model.deleteItem(itemId)
            saving = false
            if outcome == .ok {
                dismiss()
            } else {
                message = outcome.message
            }
        }
    }
}
