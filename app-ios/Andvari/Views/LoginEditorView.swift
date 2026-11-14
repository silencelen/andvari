import AndvariCore
import SwiftUI

struct UriEntry: Identifiable, Equatable {
    let id = UUID()
    var value = ""
}

struct LoginDraft: Equatable {
    var name = ""
    var username = ""
    var password = ""
    var uris: [UriEntry] = [UriEntry()]
    var notes = ""
    var totp = ""
    var favorite = false
}

/// The password generator's settings, starting from the core's standard ones.
struct GeneratorConfig: Equatable {
    static let lengthRange: ClosedRange<Double> = 8...64

    var length: Double
    var lower: Bool
    var upper: Bool
    var digits: Bool
    var symbols: Bool
    var avoidAmbiguous: Bool

    static var standard: GeneratorConfig {
        let settings = GeneratorSettings.companion.standard
        return GeneratorConfig(
            length: Double(settings.length),
            lower: settings.lower,
            upper: settings.upper,
            digits: settings.digits,
            symbols: settings.symbols,
            avoidAmbiguous: settings.avoidAmbiguous
        )
    }

    var settings: GeneratorSettings {
        GeneratorSettings(
            length: Int32(length.rounded()),
            lower: lower,
            upper: upper,
            digits: digits,
            symbols: symbols,
            avoidAmbiguous: avoidAmbiguous
        )
    }
}

/// Add a login (no item) or edit one. Editing reads the item's secrets once, to fill the form, and the
/// form forgets them when it closes.
struct LoginEditorView: View {
    let itemId: String?

    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var draft = LoginDraft()
    @State private var loaded = false
    @State private var unreadable = false
    @State private var showPassword = false
    @State private var showTotp = false
    @State private var showOptions = false
    @State private var generator = GeneratorConfig.standard
    @State private var lastGenerated = ""
    @State private var message: String?
    @State private var saving = false
    @State private var confirmDelete = false
    @State private var vaultChoices: [VaultChoiceView] = []
    @State private var vaultId: String?
    @StateObject private var files = FileAdding()

    init(itemId: String?) {
        self.itemId = itemId
    }

    var body: some View {
        NavigationStack {
            Form {
                if itemId == nil {
                    VaultPickerSection(choices: vaultChoices, selection: $vaultId)
                }
                basics
                passwordSection
                websites
                oneTimeCode
                notesSection
                Section {
                    Toggle("Favorite", isOn: $draft.favorite)
                }
                .listRowBackground(Palette.raised)
                AttachmentsEditorSection(adding: files)
                if let message {
                    Section {
                        InlineMessage(text: message)
                    }
                    .listRowBackground(Color.clear)
                }
                if itemId != nil {
                    Section {
                        Button("Delete login", role: .destructive) {
                            confirmDelete = true
                        }
                        .disabled(saving || model.state.busy)
                    }
                    .listRowBackground(Palette.raised)
                }
            }
            .scrollContentBackground(.hidden)
            .background(Palette.background)
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                toolbarContent
            }
            .toolbarBackground(Palette.background, for: .navigationBar)
            .confirmationDialog("Delete this login?", isPresented: $confirmDelete, titleVisibility: .visible) {
                Button("Delete", role: .destructive) {
                    delete()
                }
            } message: {
                Text("It goes to the trash on your server.")
            }
        }
        .modifier(FilePickers(adding: files, model: model))
        .interactiveDismissDisabled(saving || files.working)
        .onAppear {
            load()
        }
        // The form is not emptied when the editor leaves the screen: a sheet over it (a picker, the document camera) is
        // not its end, and a Save after it must not write empty fields (round-9 review 4). Its state goes with its sheet,
        // whose dismissal closes the files' draft (ItemDetailView, VaultView).
        .onChange(of: draft) {
            // Typing happens outside the window the touch watcher sees.
            model.userActivity()
        }
        .onChange(of: generator) {
            if generated {
                generate()
            }
        }
    }

    // MARK: - Sections

    private var basics: some View {
        Section {
            TextField("Name", text: $draft.name)
                .textInputAutocapitalization(.words)
            TextField("Username", text: $draft.username)
                .keyboardType(.emailAddress)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
        }
        .listRowBackground(Palette.raised)
    }

    private var passwordSection: some View {
        Section("Password") {
            secretField("Password", text: $draft.password, shown: $showPassword)
            Button(generated ? "Generate another" : "Generate") {
                generate()
            }
            DisclosureGroup("Options", isExpanded: $showOptions) {
                GeneratorOptionsView(config: $generator)
            }
        }
        .listRowBackground(Palette.raised)
    }

    private var websites: some View {
        Section("Websites") {
            ForEach($draft.uris) { $entry in
                TextField("example.com", text: $entry.value)
                    .font(.body.monospaced())
                    .keyboardType(.URL)
                    .textContentType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
            }
            .onDelete { offsets in
                draft.uris.remove(atOffsets: offsets)
            }
            Button("Add website") {
                draft.uris.append(UriEntry())
            }
        }
        .listRowBackground(Palette.raised)
    }

    private var oneTimeCode: some View {
        Section("One-time code") {
            secretField("Secret or otpauth:// link", text: $draft.totp, shown: $showTotp)
        }
        .listRowBackground(Palette.raised)
    }

    private var notesSection: some View {
        Section("Notes") {
            SecretTextEditor(text: $draft.notes)
                .frame(minHeight: 96)
                .accessibilityLabel("Notes")
        }
        .listRowBackground(Palette.raised)
    }

    private func secretField(_ label: String, text: Binding<String>, shown: Binding<Bool>) -> some View {
        HStack(spacing: 8) {
            // Hidden or shown, never corrected or learned by the keyboard (SecretFields.swift).
            SecretTextField(text: text, placeholder: label, secure: !shown.wrappedValue)
                .frame(minHeight: 24)
                .accessibilityLabel(label)
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

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItem(placement: .cancellationAction) {
            Button("Cancel") {
                dismiss()
            }
            .disabled(saving || files.working)
        }
        ToolbarItem(placement: .confirmationAction) {
            if saving {
                ProgressView()
            } else {
                Button("Save") {
                    save()
                }
                .disabled(!canSave)
            }
        }
    }

    // MARK: - State

    private var title: String {
        itemId == nil ? "New login" : "Edit login"
    }

    private var generated: Bool {
        !lastGenerated.isEmpty && draft.password == lastGenerated
    }

    private var canSave: Bool {
        !draft.name.trimmed.isEmpty && !unreadable && !model.state.busy && !files.working
    }

    private func load() {
        guard !loaded else { return }
        loaded = true
        guard let itemId else {
            vaultChoices = model.newItemVaults()
            vaultId = VaultPickerSection.initialSelection(vaultChoices)
            model.openAttachmentDraft(nil)
            return
        }
        guard let detail = model.itemDetail(itemId) else {
            unreadable = true
            message = "This login is no longer available."
            return
        }
        var next = LoginDraft()
        next.name = detail.name
        next.username = detail.username ?? ""
        next.uris = detail.uris.isEmpty ? [UriEntry()] : detail.uris.map { UriEntry(value: $0) }
        next.favorite = detail.favorite
        // A save writes every field, so a secret that cannot be read now must not be saved as empty.
        let secrets: [(Bool, SecretField, WritableKeyPath<LoginDraft, String>)] = [
            (detail.hasPassword, SecretField.password, \LoginDraft.password),
            (detail.hasNotes, SecretField.notes, \LoginDraft.notes),
            (detail.hasTotp, SecretField.totpSecret, \LoginDraft.totp),
        ]
        for (present, secret, keyPath) in secrets where present {
            guard let value = model.revealSecret(itemId, secret) else {
                unreadable = true
                message = "This login can't be read right now."
                return
            }
            next[keyPath: keyPath] = value
        }
        draft = next
        model.openAttachmentDraft(itemId)
    }

    private func generate() {
        let value = model.generatePassword(generator.settings)
        guard !value.isEmpty else { return }
        draft.password = value
        lastGenerated = value
        showPassword = true
    }

    private func save() {
        guard canSave, !saving else { return }
        message = nil
        let input = LoginInput(
            name: draft.name.trimmed,
            username: draft.username.trimmed,
            password: draft.password,
            uris: draft.uris.map { $0.value.trimmed }.filter { !$0.isEmpty },
            notes: draft.notes,
            totp: draft.totp.trimmed,
            favorite: draft.favorite
        )
        saving = true
        Task {
            let outcome = await model.saveLogin(itemId: itemId, input: input, vaultId: itemId == nil ? vaultId : nil)
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

struct GeneratorOptionsView: View {
    @Binding var config: GeneratorConfig

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Length")
                Spacer()
                Text("\(Int(config.length))")
                    .monospacedDigit()
                    .foregroundStyle(Palette.inkDim)
            }
            .accessibilityElement(children: .combine)
            Slider(value: $config.length, in: GeneratorConfig.lengthRange, step: 1)
                .accessibilityLabel("Length")
                .accessibilityValue("\(Int(config.length)) characters")
            Toggle("A–Z", isOn: $config.upper)
                .accessibilityLabel("Capital letters")
            Toggle("a–z", isOn: $config.lower)
                .accessibilityLabel("Small letters")
            Toggle("0–9", isOn: $config.digits)
                .accessibilityLabel("Digits")
            Toggle("Symbols", isOn: $config.symbols)
            Toggle("Avoid look-alikes", isOn: $config.avoidAmbiguous)
        }
        .padding(.vertical, 4)
    }
}
