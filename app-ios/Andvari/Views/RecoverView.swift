import AndvariCore
import SwiftUI

/// Forgot the master password: the email and the recovery phrase, then a new master password. The phrase
/// never leaves the device, and the vault's keys stay the same; only the password that opens them changes.
/// The second step ends by itself after five idle minutes or when the app leaves the screen.
struct RecoverView: View {
    @EnvironmentObject private var model: AppModel
    @State private var email = ""
    @State private var phrase = ""
    @State private var password = ""
    @State private var confirm = ""
    @State private var message: String?
    @FocusState private var focus: Field?

    private enum Field {
        case email
        case phrase
        case password
        case confirm
    }

    var body: some View {
        AuthScroll {
            Brand()
            VStack(spacing: 8) {
                Text("Reset your master password")
                    .font(.title3.weight(.semibold))
                    .foregroundStyle(Palette.ink)
                    .accessibilityAddTraits(.isHeader)
                Text(verified
                    ? "Choose a new master password. Every device signed in to this account will have to sign in again."
                    : "Enter your email and the recovery phrase you saved when you set up this account.")
                    .font(.footnote)
                    .foregroundStyle(Palette.inkDim)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
            VStack(alignment: .leading, spacing: 14) {
                if verified {
                    newPasswordFields
                } else {
                    phraseFields
                }
                if let message {
                    InlineMessage(text: message)
                }
                PrimaryButton(title: verified ? "Reset master password" : "Continue", busy: model.state.busy, action: submit)
                    .disabled(!ready || model.state.busy)
                Button("Cancel") {
                    model.cancelRecover()
                }
                .buttonStyle(QuietButtonStyle())
            }
        }
        .onAppear {
            email = model.state.accountEmail ?? ""
        }
        .onChange(of: verified) { _, now in
            // The phrase is not kept on screen once it has been checked.
            if now {
                phrase = ""
                message = nil
                focus = .password
            }
        }
        .onDisappear {
            phrase = ""
            password = ""
            confirm = ""
        }
    }

    @ViewBuilder private var phraseFields: some View {
        InputField(
            "Email",
            text: $email,
            focus: $focus,
            field: .email,
            contentType: .username,
            keyboard: .emailAddress,
            onSubmit: { focus = .phrase }
        )
        InputField(
            "Recovery phrase",
            text: $phrase,
            focus: $focus,
            field: .phrase,
            secret: true,
            returnKey: .go,
            monospaced: true,
            onSubmit: submit
        )
        Text("Spaces and line breaks in the phrase don't matter.")
            .font(.footnote)
            .foregroundStyle(Palette.inkFaint)
            .fixedSize(horizontal: false, vertical: true)
    }

    @ViewBuilder private var newPasswordFields: some View {
        InputField(
            "New master password",
            text: $password,
            focus: $focus,
            field: .password,
            secure: true,
            contentType: .newPassword,
            onSubmit: { focus = .confirm }
        )
        InputField(
            "Type it again",
            text: $confirm,
            focus: $focus,
            field: .confirm,
            secure: true,
            contentType: .newPassword,
            submitLabel: .go,
            onSubmit: submit
        )
        if !confirm.isEmpty && confirm != password {
            Text("The two don't match yet.")
                .font(.footnote)
                .foregroundStyle(Palette.inkFaint)
        }
    }

    private var verified: Bool {
        model.state.recoverVerified
    }

    private var ready: Bool {
        if verified {
            return !password.isEmpty && password == confirm
        }
        return !email.trimmed.isEmpty && !phrase.trimmed.isEmpty
    }

    private func submit() {
        guard ready, !model.state.busy else { return }
        message = nil
        if verified {
            let chosen = password
            Task {
                // On success the screen has already moved on, with the core's notice.
                message = await model.recoverCommit(newPassword: chosen).message
            }
        } else {
            let typedEmail = email.trimmed
            let typedPhrase = phrase
            Task {
                message = await model.recoverVerify(email: typedEmail, phrase: typedPhrase).message
            }
        }
    }
}
