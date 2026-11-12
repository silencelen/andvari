import AndvariCore
import SwiftUI

struct CardDraft: Equatable {
    var name = ""
    var cardholder = ""
    var number = ""
    var expMonth = ""
    var expYear = ""
    var securityCode = ""
    var postalCode = ""
    var notes = ""
    var favorite = false
}

/// Add or edit a payment card. The core normalizes what is typed (digits only for the number and the code, a month
/// and a four-digit year for the expiry, the brand from the number) and refuses an expiry it cannot read.
struct CardEditorView: View {
    let itemId: String?

    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var draft = CardDraft()
    @State private var loaded = false
    @State private var unreadable = false
    @State private var saving = false
    @State private var showNumber = false
    @State private var showCode = false
    @State private var confirmDelete = false
    @State private var message: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Name", text: $draft.name)
                    Toggle("Favorite", isOn: $draft.favorite)
                }
                .listRowBackground(Palette.raised)

                Section("Card") {
                    secretField("Card number", text: $draft.number, shown: $showNumber)
                        .keyboardType(.numberPad)
                    HStack(spacing: 12) {
                        TextField("Month (MM)", text: $draft.expMonth)
                            .keyboardType(.numbersAndPunctuation)
                        TextField("Year (YYYY)", text: $draft.expYear)
                            .keyboardType(.numberPad)
                    }
                    .font(.body.monospaced())
                    secretField("Security code", text: $draft.securityCode, shown: $showCode)
                        .keyboardType(.numberPad)
                    TextField("Cardholder name", text: $draft.cardholder)
                        .textContentType(.name)
                        .autocorrectionDisabled()
                    TextField("Billing postal code", text: $draft.postalCode)
                        .textInputAutocapitalization(.characters)
                        .autocorrectionDisabled()
                }
                .listRowBackground(Palette.raised)

                Section("Notes") {
                    TextEditor(text: $draft.notes)
                        .frame(minHeight: 96)
                        .scrollContentBackground(.hidden)
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
                        Button("Delete card", role: .destructive) {
                            confirmDelete = true
                        }
                        .disabled(saving)
                    }
                    .listRowBackground(Palette.raised)
                }
            }
            .scrollContentBackground(.hidden)
            .background(Palette.background)
            .navigationTitle(itemId == nil ? "New card" : "Edit card")
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
            .confirmationDialog("Delete this card?", isPresented: $confirmDelete, titleVisibility: .visible) {
                Button("Delete card", role: .destructive) {
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
            draft = CardDraft()
        }
    }

    private func secretField(_ label: String, text: Binding<String>, shown: Binding<Bool>) -> some View {
        HStack(spacing: 8) {
            Group {
                if shown.wrappedValue {
                    TextField(label, text: text)
                } else {
                    SecureField(label, text: text)
                }
            }
            .font(.body.monospaced())
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            Button {
                shown.wrappedValue.toggle()
            } label: {
                Image(systemName: shown.wrappedValue ? "eye.slash" : "eye")
                    .frame(minWidth: 32, minHeight: 32)
            }
            .buttonStyle(.borderless)
            .accessibilityLabel(shown.wrappedValue ? "Hide" : "Show")
        }
    }

    private func load() {
        guard !loaded else { return }
        loaded = true
        guard let itemId else { return }
        guard let detail = model.itemDetail(itemId), let card = detail.card else {
            unreadable = true
            message = "This card is no longer available."
            return
        }
        var next = CardDraft()
        next.name = detail.name
        next.favorite = detail.favorite
        next.cardholder = card.cardholder ?? ""
        next.postalCode = card.postalCode ?? ""
        let halves = (card.expiry ?? "").split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        if halves.count == 2 {
            next.expMonth = halves[0]
            next.expYear = halves[1]
        } else if let only = halves.first, !only.isEmpty {
            // One half only: a four-digit value is the year.
            if only.count == 4 { next.expYear = only } else { next.expMonth = only }
        }
        // A save writes every field, so a secret that cannot be read now must not be saved as empty.
        let secrets: [(Bool, SecretField, WritableKeyPath<CardDraft, String>)] = [
            (card.hasNumber, SecretField.cardNumber, \CardDraft.number),
            (card.hasCode, SecretField.cardCode, \CardDraft.securityCode),
            (detail.hasNotes, SecretField.notes, \CardDraft.notes),
        ]
        for (present, secret, keyPath) in secrets where present {
            guard let value = model.revealSecret(itemId, secret) else {
                unreadable = true
                message = "This card can't be read right now."
                return
            }
            next[keyPath: keyPath] = value
        }
        draft = next
    }

    private func save() {
        guard !saving else { return }
        message = nil
        let input = CardInput(
            name: draft.name.trimmed,
            cardholder: draft.cardholder,
            number: draft.number,
            expMonth: draft.expMonth.trimmed,
            expYear: draft.expYear.trimmed,
            securityCode: draft.securityCode,
            postalCode: draft.postalCode,
            notes: draft.notes,
            favorite: draft.favorite
        )
        saving = true
        Task {
            let outcome = await model.saveCard(itemId: itemId, input: input)
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
