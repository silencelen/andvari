import AndvariCore
import SwiftUI

/// Signed out at a server: sign in, or enroll with an invite. The drafts live here, so switching between
/// the two keeps what was typed, and so does a Trust Gate raised by an invite for another server.
struct WelcomeView: View {
    enum Mode: Hashable {
        case signIn
        case enroll
    }

    @EnvironmentObject private var model: AppModel
    @State private var mode: Mode = .signIn
    @State private var signIn = SignInDraft()
    @State private var enroll = EnrollDraft()
    @State private var retrying = false

    var body: some View {
        AuthScroll {
            Brand()
            serverLine
            if enrollAllowed {
                ModeSwitch(mode: $mode)
            }
            if mode == .enroll && enrollAllowed {
                EnrollFormView(draft: $enroll)
            } else {
                SignInForm(draft: $signIn)
            }
        }
        .onDisappear {
            signIn.password = ""
            signIn.code = ""
            enroll.password = ""
            enroll.confirm = ""
        }
    }

    /// A server whose policy closes sign-up shows sign-in only.
    private var enrollAllowed: Bool {
        model.state.policy?.signupMode != "closed"
    }

    private var serverLine: some View {
        VStack(spacing: 8) {
            HStack(spacing: 10) {
                Text(model.state.server ?? "")
                    .font(.footnote.monospaced())
                    .foregroundStyle(Palette.inkDim)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .accessibilityLabel("Server")
                    .accessibilityValue(model.state.server ?? "")
                Button("Change") {
                    model.changeServer()
                }
                .font(.footnote.weight(.semibold))
                .disabled(model.state.busy)
            }
            if model.state.serverUnreachable {
                HStack(spacing: 10) {
                    Text("Can't reach this server.")
                        .font(.footnote)
                        .foregroundStyle(Palette.danger)
                    Button {
                        retry()
                    } label: {
                        if retrying {
                            ProgressView()
                        } else {
                            Text("Retry")
                        }
                    }
                    .font(.footnote.weight(.semibold))
                    .disabled(retrying || model.state.busy)
                }
            }
        }
        .frame(maxWidth: .infinity)
    }

    private func retry() {
        retrying = true
        Task {
            _ = await model.retryServer()
            retrying = false
        }
    }
}

struct SignInDraft {
    var email = ""
    var password = ""
    var code = ""
}

struct EnrollDraft {
    var invite = ""
    var email = ""
    var name = ""
    var password = ""
    var confirm = ""
    var hasSheet = false
    var sheetCode = ""
    var waivedAck = false
}

/// Two words with a gold rule under the chosen one.
private struct ModeSwitch: View {
    @Binding var mode: WelcomeView.Mode

    var body: some View {
        HStack(spacing: 28) {
            tab("Sign in", .signIn)
            tab("Enroll", .enroll)
        }
        .frame(maxWidth: .infinity)
    }

    private func tab(_ title: String, _ value: WelcomeView.Mode) -> some View {
        let selected = mode == value
        return Button {
            mode = value
        } label: {
            Text(title)
                .font(.headline)
                .foregroundStyle(selected ? Palette.ink : Palette.inkFaint)
                .padding(.bottom, 6)
                .overlay(alignment: .bottom) {
                    Rectangle()
                        .fill(selected ? Palette.gold : Color.clear)
                        .frame(height: 2)
                }
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

struct SignInForm: View {
    @EnvironmentObject private var model: AppModel
    @Binding private var draft: SignInDraft
    @State private var message: String?
    @FocusState private var focus: Field?

    private enum Field {
        case email
        case password
        case code
    }

    init(draft: Binding<SignInDraft>) {
        _draft = draft
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if let reason = model.state.lockReason {
                Text(reason)
                    .font(.footnote)
                    .foregroundStyle(Palette.inkDim)
                    .fixedSize(horizontal: false, vertical: true)
            }
            InputField(
                "Email",
                text: $draft.email,
                focus: $focus,
                field: .email,
                contentType: .username,
                keyboard: .emailAddress,
                onSubmit: { focus = .password }
            )
            InputField(
                "Master password",
                text: $draft.password,
                focus: $focus,
                field: .password,
                secure: true,
                contentType: .password,
                submitLabel: codeRequired ? .next : .go,
                onSubmit: passwordSubmitted
            )
            if codeRequired {
                InputField(
                    "One-time code",
                    text: $draft.code,
                    focus: $focus,
                    field: .code,
                    monospaced: true,
                    contentType: .oneTimeCode,
                    keyboard: .numberPad,
                    submitLabel: .go,
                    onSubmit: submit
                )
            }
            if let message {
                InlineMessage(text: message)
            }
            PrimaryButton(title: "Sign in", busy: model.state.busy, action: submit)
                .disabled(!ready || model.state.busy)
        }
        .onChange(of: codeRequired) { _, required in
            if required {
                focus = .code
            }
        }
    }

    private var codeRequired: Bool {
        model.state.totpRequired
    }

    private var ready: Bool {
        !draft.email.trimmed.isEmpty && !draft.password.isEmpty && (!codeRequired || !draft.code.trimmed.isEmpty)
    }

    private func passwordSubmitted() {
        if codeRequired {
            focus = .code
        } else {
            submit()
        }
    }

    private func submit() {
        guard ready, !model.state.busy else { return }
        message = nil
        let email = draft.email.trimmed
        let password = draft.password
        let code = draft.code.trimmed
        Task {
            let outcome = await model.signIn(email: email, password: password, totp: code.isEmpty ? nil : code)
            switch outcome {
            case .ok:
                draft.password = ""
                draft.code = ""
            case .needsCode(let wrongCode):
                draft.code = ""
                message = wrongCode ? "That code didn't work." : nil
                focus = .code
            default:
                message = outcome.message
            }
        }
    }
}

struct EnrollFormView: View {
    @EnvironmentObject private var model: AppModel
    @Binding private var draft: EnrollDraft
    @State private var message: String?
    @FocusState private var focus: Field?

    private enum Field {
        case invite
        case email
        case name
        case password
        case confirm
        case sheet
    }

    init(draft: Binding<EnrollDraft>) {
        _draft = draft
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            InputField(
                "Invite",
                text: $draft.invite,
                focus: $focus,
                field: .invite,
                prompt: "Code or link",
                monospaced: true,
                keyboard: .asciiCapable,
                onSubmit: { focus = .email }
            )
            InputField(
                "Email",
                text: $draft.email,
                focus: $focus,
                field: .email,
                contentType: .username,
                keyboard: .emailAddress,
                onSubmit: { focus = .name }
            )
            InputField(
                "Name",
                text: $draft.name,
                focus: $focus,
                field: .name,
                prompt: "Optional",
                contentType: .name,
                capitalization: .words,
                onSubmit: { focus = .password }
            )
            InputField(
                "Master password",
                text: $draft.password,
                focus: $focus,
                field: .password,
                secure: true,
                contentType: .newPassword,
                onSubmit: { focus = .confirm }
            )
            InputField(
                "Confirm password",
                text: $draft.confirm,
                focus: $focus,
                field: .confirm,
                secure: true,
                contentType: .newPassword,
                submitLabel: .done,
                onSubmit: { focus = nil }
            )
            if !draft.confirm.isEmpty && draft.confirm != draft.password {
                InlineMessage(text: "The passwords don't match.")
            }
            recovery
            if model.state.policy == nil && !model.state.serverUnreachable {
                HStack(spacing: 8) {
                    ProgressView()
                    Text("Checking the server…")
                        .font(.footnote)
                        .foregroundStyle(Palette.inkDim)
                }
            }
            if let message {
                InlineMessage(text: message)
            }
            PrimaryButton(title: "Create vault", busy: model.state.busy, action: submit)
                .disabled(!ready || model.state.busy)
        }
    }

    @ViewBuilder private var recovery: some View {
        Toggle(isOn: $draft.hasSheet) {
            Text("I have a printed recovery sheet")
        }
        .toggleStyle(CheckToggleStyle())
        if draft.hasSheet {
            sheetCheck
        } else {
            Text("Without a sheet there is no admin backstop: only your recovery phrase can restore this account.")
                .font(.footnote)
                .foregroundStyle(Palette.danger)
                .fixedSize(horizontal: false, vertical: true)
            Toggle(isOn: $draft.waivedAck) {
                Text("I understand that if I lose my master password and my recovery phrase, no one can recover this account.")
            }
            .toggleStyle(CheckToggleStyle())
        }
    }

    @ViewBuilder private var sheetCheck: some View {
        if let policy = model.state.policy, policy.recoveryFingerprintShort.isEmpty {
            InlineMessage(text: "This server has no recovery key yet, so a sheet can't be used.")
        } else {
            InputField(
                "Recovery sheet",
                text: $draft.sheetCode,
                focus: $focus,
                field: .sheet,
                prompt: "First 32 characters",
                monospaced: true,
                keyboard: .asciiCapable,
                submitLabel: .done,
                onSubmit: { focus = nil }
            )
            if sheetComplete {
                if sheetMatches {
                    Label("Matches this server's recovery key", systemImage: "checkmark.seal")
                        .font(.footnote)
                        .foregroundStyle(Palette.ok)
                } else {
                    InlineMessage(text: "This doesn't match the server's recovery key. If you copied it correctly, stop and contact your admin.")
                }
            }
        }
    }

    /// What was typed from the sheet, as the fingerprint's hex.
    private var sheetCode: String {
        draft.sheetCode.lowercased().filter(\.isHexDigit)
    }

    private var sheetComplete: Bool {
        sheetCode.count >= 32
    }

    private var sheetMatches: Bool {
        guard let fingerprint = model.state.policy?.recoveryFingerprintShort.lowercased(), !fingerprint.isEmpty else {
            return false
        }
        return sheetCode == fingerprint
    }

    private var ready: Bool {
        guard model.state.policy != nil,
              !draft.invite.trimmed.isEmpty,
              !draft.password.isEmpty,
              draft.password == draft.confirm
        else { return false }
        // A blank email takes the address an enroll link names.
        if draft.email.trimmed.isEmpty && !draft.invite.contains("://") {
            return false
        }
        return draft.hasSheet ? sheetMatches : draft.waivedAck
    }

    private func submit() {
        guard ready, !model.state.busy else { return }
        message = nil
        let form = EnrollForm(
            invite: draft.invite.trimmed,
            email: draft.email.trimmed,
            name: draft.name.trimmed,
            password: draft.password,
            hasRecoverySheet: draft.hasSheet,
            sheetCode: draft.hasSheet ? sheetCode : ""
        )
        Task {
            let outcome = await model.enroll(form)
            switch outcome {
            case .ok:
                draft = EnrollDraft()
            case .otherServer(let origin):
                // The invite is for another server: switch to it through the Trust Gate, then enroll there.
                if let invalid = model.chooseServer(origin) as? ServerChoice.Invalid {
                    message = invalid.message
                }
            default:
                message = outcome.message
            }
        }
    }
}
