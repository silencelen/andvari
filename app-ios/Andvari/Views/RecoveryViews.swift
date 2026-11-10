import AndvariCore
import SwiftUI

/// The shown-once recovery phrase, typed back to confirm it was saved. The phrase is read when the screen
/// opens and dropped when it closes.
struct RecoveryRevealView: View {
    @EnvironmentObject private var model: AppModel
    @State private var phrase: String?
    @State private var typed = ""
    @State private var message: String?
    @State private var copied = false
    @FocusState private var focus: Field?

    private enum Field {
        case typed
    }

    var body: some View {
        AuthScroll {
            VStack(alignment: .leading, spacing: 16) {
                Text("Save your recovery phrase")
                    .font(.title2.weight(.semibold))
                    .foregroundStyle(Palette.ink)
                    .accessibilityAddTraits(.isHeader)
                    .padding(.top, 28)
                if model.state.recoveryReplacedNotice {
                    Text(Wording.replacedPhrase)
                        .font(.footnote)
                        .foregroundStyle(Palette.danger)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Text(model.state.recoveryWaived ? waived : standard)
                    .font(.subheadline)
                    .foregroundStyle(model.state.recoveryWaived ? Palette.danger : Palette.inkDim)
                    .fixedSize(horizontal: false, vertical: true)
                phraseCard
                InputField(
                    "Type it back",
                    text: $typed,
                    focus: $focus,
                    field: .typed,
                    monospaced: true,
                    keyboard: .asciiCapable,
                    submitLabel: .done,
                    onSubmit: confirm
                )
                if let message {
                    InlineMessage(text: message)
                }
                PrimaryButton(title: "I've saved it", busy: model.state.busy, action: confirm)
                    .disabled(typed.trimmed.isEmpty || phrase == nil || model.state.busy)
            }
        }
        .onAppear {
            phrase = model.recoveryPhrase()
        }
        .onChange(of: model.state.recoveryReplacedNotice) {
            phrase = model.recoveryPhrase()
        }
        .onChange(of: typed) {
            message = nil
        }
        .onDisappear {
            phrase = nil
            typed = ""
        }
    }

    @ViewBuilder private var phraseCard: some View {
        if let phrase {
            VStack(alignment: .leading, spacing: 12) {
                Text(phrase)
                    .speechSpellsOutCharacters()
                    .font(.title3.monospaced())
                    .foregroundStyle(Palette.goldBright)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Button {
                    copy(phrase)
                } label: {
                    Label(copied ? "Copied" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc")
                        .font(.subheadline.weight(.semibold))
                }
                .buttonStyle(.borderless)
            }
            .padding(16)
            .background(Palette.raised, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .strokeBorder(Palette.edgeStrong, lineWidth: 1)
            )
        } else {
            ProgressView()
                .frame(maxWidth: .infinity)
        }
    }

    private var standard: String {
        "Write it down and keep it somewhere safe and offline. If you forget your master password, this phrase lets you back in."
    }

    private var waived: String {
        "There is no admin backstop for this account: only this phrase can restore it. If you lose both your master password and this phrase, the account is gone for good. Write it down and keep it safe and offline."
    }

    private func copy(_ value: String) {
        Clipboard.copy(value)
        copied = true
        AccessibilityNotification.Announcement("Copied").post()
        Task {
            try? await Task.sleep(for: .seconds(1.5))
            copied = false
        }
    }

    private func confirm() {
        let value = typed.trimmed
        guard !value.isEmpty, !model.state.busy else { return }
        message = nil
        Task {
            let outcome = await model.confirmRecoveryPhrase(value)
            switch outcome {
            case .ok:
                typed = ""
            case .mismatch:
                message = "That doesn't match. Check the phrase and type it exactly."
            default:
                message = outcome.message
            }
        }
    }
}

/// The vault-entry gate: a fresh recovery phrase is being committed before the vault opens.
struct RecoveryCaptureView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        AuthScroll {
            VStack(alignment: .leading, spacing: 16) {
                Text("Finish protecting your account")
                    .font(.title2.weight(.semibold))
                    .foregroundStyle(Palette.ink)
                    .accessibilityAddTraits(.isHeader)
                    .padding(.top, 28)
                Text("Your recovery phrase was never confirmed as saved. A new one is on its way; the vault opens once you have saved it.")
                    .font(.subheadline)
                    .foregroundStyle(Palette.inkDim)
                    .fixedSize(horizontal: false, vertical: true)
                if model.state.recoveryReplacedNotice {
                    Text(Wording.replacedPhrase)
                        .font(.footnote)
                        .foregroundStyle(Palette.danger)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let error = model.state.recoveryCaptureError {
                    InlineMessage(text: error)
                    PrimaryButton(title: "Try again", busy: model.state.busy, action: retry)
                        .disabled(model.state.busy)
                } else {
                    HStack(spacing: 10) {
                        ProgressView()
                        Text("Preparing your recovery phrase…")
                            .font(.footnote)
                            .foregroundStyle(Palette.inkDim)
                    }
                }
            }
        }
    }

    private func retry() {
        Task {
            _ = await model.retryRecoveryCapture()
        }
    }
}
