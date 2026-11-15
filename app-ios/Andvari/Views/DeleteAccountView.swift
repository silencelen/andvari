import AndvariCore
import SwiftUI

/// Settings › Delete account (spec 03 §13): what deleting would do now, as the server says, first: what goes for good,
/// the shared vaults it leaves, and anything that stands in the way (a vault this account owns that other people use
/// must be deleted or handed over first). Then the account's email typed to confirm, the master password (proved on this
/// iPhone before anything is sent) and the two-step code when the account has one. Once the server has deleted it, this
/// iPhone keeps nothing of the account and the app stands on the server screen.
struct DeleteAccountView: View {
    @EnvironmentObject private var model: AppModel
    @State private var loading = true
    @State private var email = ""
    @State private var password = ""
    @State private var code = ""
    @State private var message: String?
    @State private var confirming = false

    var body: some View {
        Form {
            if let deletion = model.state.accountDeletion, let preview = deletion.preview {
                Section {
                    ForEach(preview.deleted, id: \.self) { line in
                        Text(line)
                            .font(.footnote)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    ForEach(preview.left, id: \.self) { line in
                        Text(line)
                            .font(.footnote)
                            .foregroundStyle(Palette.inkDim)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                } header: {
                    Text("What goes for good")
                }
                .listRowBackground(Palette.raised)
                if !preview.blockers.isEmpty {
                    Section {
                        ForEach(preview.blockers, id: \.self) { line in
                            Text(line)
                                .font(.footnote)
                                .foregroundStyle(Palette.danger)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        Button("Check again") {
                            act { await model.openAccountDeletion() }
                        }
                        .disabled(model.state.busy)
                    } header: {
                        Text("First")
                    } footer: {
                        Text("The account can't be deleted while any of these stands.")
                    }
                    .listRowBackground(Palette.raised)
                } else {
                    confirmSection(deletion, preview)
                }
                if deletion.outcomeUnknown {
                    Section {
                        Button("Check whether it went through") {
                            act { await model.checkAccountDeletion() }
                        }
                        .disabled(model.state.busy)
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
        .navigationTitle("Delete account")
        .navigationBarTitleDisplayMode(.inline)
        .task {
            let outcome = await model.openAccountDeletion()
            loading = false
            if outcome != .ok { message = outcome.message }
        }
        .onDisappear {
            password = ""
            model.closeAccountDeletion()
        }
        .confirmationDialog("Delete your account for good?", isPresented: $confirming, titleVisibility: .visible) {
            Button("Delete account", role: .destructive) {
                let typedEmail = email
                let typedPassword = password
                let typedCode = code
                password = ""
                act { await model.deleteAccount(email: typedEmail, password: typedPassword, code: typedCode) }
            }
        } message: {
            Text("This can't be undone: nobody, an admin of your server included, can bring the account back.")
        }
    }

    @ViewBuilder
    private func confirmSection(_ deletion: AccountDeletionView, _ preview: AccountDeletionPreviewView) -> some View {
        Section {
            TextField("Email address", text: $email)
                .keyboardType(.emailAddress)
                .textContentType(.emailAddress)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .accessibilityIdentifier(AccessID.field("Delete email"))
            SecureField("Master password", text: $password)
                .textContentType(.password)
                .accessibilityIdentifier(AccessID.field("Delete password"))
            if preview.totpRequired {
                TextField("Code from your authenticator app", text: $code)
                    .keyboardType(.numberPad)
                    .textContentType(.oneTimeCode)
                    .accessibilityIdentifier(AccessID.field("Delete code"))
            }
            Button("Delete account…", role: .destructive) {
                message = nil
                confirming = true
            }
            .disabled(email.trimmingCharacters(in: .whitespaces).isEmpty || password.isEmpty || (preview.totpRequired && code.isEmpty) || model.state.busy)
            .accessibilityIdentifier(AccessID.button("Delete account"))
        } header: {
            Text("Confirm it's you")
        } footer: {
            Text("Type \(deletion.email) to confirm. Your master password is checked on this iPhone before anything is sent.")
        }
        .listRowBackground(Palette.raised)
    }

    private func act(_ action: @escaping () async -> Outcome) {
        message = nil
        Task {
            let outcome = await action()
            if outcome != .ok { message = outcome.message }
        }
    }
}
