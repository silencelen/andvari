import AndvariCore
import SwiftUI

/// Where a new item goes: the personal vault, unless the person picks a shared one here. Nothing picks a shared vault
/// for them. Shown only when there is a choice to make.
struct VaultPickerSection: View {
    let choices: [VaultChoiceView]
    @Binding var selection: String?

    var body: some View {
        if choices.count > 1 || choices.contains(where: { !$0.personal }) {
            Section {
                Picker("Vault", selection: $selection) {
                    if selection == nil {
                        Text("Choose a vault").tag(String?.none)
                    }
                    ForEach(choices, id: \.vaultId) { vault in
                        Text(label(vault)).tag(String?.some(vault.vaultId))
                    }
                }
            } footer: {
                if let chosen = choices.first(where: { $0.vaultId == selection }), !chosen.personal {
                    Text("Everyone in “\(chosen.name)” will see this item.")
                }
            }
            .listRowBackground(Palette.raised)
        }
    }

    private func label(_ vault: VaultChoiceView) -> String {
        vault.personal ? vault.name : "\(vault.name) (shared)"
    }

    /// The vault a new item starts in: the personal one, or none when there is none (the person then chooses).
    static func initialSelection(_ choices: [VaultChoiceView]) -> String? {
        choices.first(where: { $0.personal })?.vaultId
    }
}

/// Move an item to another vault (copy, then delete it here), or copy it there. Attachments go with it.
struct MoveCopySheet: View {
    let itemId: String
    let targets: [VaultChoiceView]

    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var move = true
    @State private var target: String?
    @State private var working = false
    @State private var message: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("What to do", selection: $move) {
                        Text("Move").tag(true)
                        Text("Copy").tag(false)
                    }
                    .pickerStyle(.segmented)
                } footer: {
                    Text(move
                        ? "The item leaves this vault. Anyone who could see it here may still have a copy from before the move."
                        : "A copy goes to the other vault; this one stays as it is.")
                }
                .listRowBackground(Palette.raised)

                Section("To") {
                    ForEach(targets, id: \.vaultId) { vault in
                        Button {
                            target = vault.vaultId
                        } label: {
                            HStack {
                                Text(vault.personal ? vault.name : "\(vault.name) (shared)")
                                    .foregroundStyle(Palette.ink)
                                Spacer()
                                if target == vault.vaultId {
                                    Image(systemName: "checkmark")
                                        .foregroundStyle(Palette.goldText)
                                }
                            }
                        }
                        .accessibilityAddTraits(target == vault.vaultId ? .isSelected : [])
                    }
                }
                .listRowBackground(Palette.raised)

                if let chosen = targets.first(where: { $0.vaultId == target }), !chosen.personal {
                    Section {
                        Text("Everyone in “\(chosen.name)” will see this item.")
                            .font(.footnote)
                            .foregroundStyle(Palette.inkDim)
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
            .navigationTitle("Move or copy")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                    .disabled(working)
                }
                ToolbarItem(placement: .confirmationAction) {
                    if working {
                        ProgressView()
                    } else {
                        Button(move ? "Move" : "Copy") {
                            run()
                        }
                        .disabled(target == nil || model.state.busy)
                    }
                }
            }
            .toolbarBackground(Palette.background, for: .navigationBar)
        }
    }

    private func run() {
        guard let target, !working else { return }
        working = true
        message = nil
        Task {
            let outcome = await model.moveOrCopyItem(itemId, to: target, move: move)
            working = false
            if outcome == .ok {
                dismiss()
            } else {
                message = outcome.message
            }
        }
    }
}
