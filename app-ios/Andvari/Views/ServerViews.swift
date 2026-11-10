import AndvariCore
import SwiftUI

/// No server yet, or the person is changing it. A real change goes through the Trust Gate.
struct ChooseServerView: View {
    @EnvironmentObject private var model: AppModel
    @State private var address = ""
    @State private var message: String?
    @FocusState private var focus: Field?

    private enum Field {
        case address
    }

    var body: some View {
        AuthScroll {
            Brand()
            VStack(alignment: .leading, spacing: 14) {
                InputField(
                    "Server",
                    text: $address,
                    focus: $focus,
                    field: .address,
                    prompt: "https://vault.example.com",
                    monospaced: true,
                    contentType: .URL,
                    keyboard: .URL,
                    submitLabel: .go,
                    onSubmit: submit
                )
                if let message {
                    InlineMessage(text: message)
                }
                PrimaryButton(title: "Continue", busy: model.state.busy, action: submit)
                    .disabled(address.trimmed.isEmpty || model.state.busy)
                if model.state.server != nil {
                    Button("Cancel") {
                        cancel()
                    }
                    .buttonStyle(QuietButtonStyle())
                    .disabled(model.state.busy)
                }
            }
        }
        .onChange(of: address) {
            message = nil
        }
    }

    private func submit() {
        let input = address.trimmed
        guard !input.isEmpty, !model.state.busy else { return }
        // A real change raises the Trust Gate through the state; the server already chosen lands back.
        if let invalid = model.chooseServer(input) as? ServerChoice.Invalid {
            message = invalid.message
        }
    }

    /// Keeps the server already chosen: choosing it again changes nothing and lands back.
    private func cancel() {
        guard let current = model.state.server else { return }
        _ = model.chooseServer(current)
    }
}

/// The anti-phishing Trust Gate: the raw origin the app will dial, never a display name, with its
/// cautions. Cancel is the safe default; nothing changes unless the server answers Connect.
struct TrustGateSheet: View {
    @EnvironmentObject private var model: AppModel
    @State private var message: String?
    @State private var connecting = false

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                if let gate = model.state.trustGate {
                    details(gate)
                        .padding(24)
                }
            }
            buttons
                .padding(.horizontal, 24)
                .padding(.vertical, 16)
        }
        .background(Palette.background)
        .interactiveDismissDisabled(connecting)
    }

    private func details(_ gate: TrustGateView) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(SessionRulesKt.TRUST_GATE_TITLE)
                .font(.title3.weight(.semibold))
                .foregroundStyle(Palette.ink)
                .accessibilityAddTraits(.isHeader)
            Text(gate.origin)
                .font(.title3.monospaced())
                .foregroundStyle(Palette.ink)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(14)
                .background(Palette.input, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .strokeBorder(Palette.edgeStrong, lineWidth: 1)
                )
                .accessibilityLabel("Server address")
                .accessibilityValue(gate.origin)
            if gate.punycodeCaution {
                Caution(text: Wording.punycodeCaution, serious: true)
            }
            if gate.httpCaution {
                Caution(
                    text: gate.cleartextBlocked ? Wording.cleartextBlocked : Wording.loopbackHttp,
                    serious: gate.cleartextBlocked
                )
            }
            Text(SessionRulesKt.TRUST_GATE_BASELINE)
                .font(.subheadline)
                .foregroundStyle(Palette.inkDim)
                .fixedSize(horizontal: false, vertical: true)
            if model.gateForInvite {
                Text(SessionRulesKt.TRUST_GATE_ENROLLMENT_EXTRA)
                    .font(.subheadline)
                    .foregroundStyle(Palette.inkDim)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let message {
                InlineMessage(text: message)
            }
        }
    }

    private var buttons: some View {
        let blocked = model.state.trustGate?.cleartextBlocked ?? true
        return HStack(spacing: 12) {
            Button("Cancel") {
                model.cancelTrustGate()
            }
            .buttonStyle(QuietButtonStyle())
            .disabled(connecting)
            PrimaryButton(title: "Connect", busy: connecting, action: connect)
                .disabled(blocked || connecting || model.state.busy)
        }
    }

    private func connect() {
        guard !connecting else { return }
        message = nil
        connecting = true
        Task {
            let outcome = await model.confirmTrustGate()
            connecting = false
            message = outcome.message
        }
    }
}

private struct Caution: View {
    let text: String
    let serious: Bool

    var body: some View {
        Label {
            Text(text)
                .font(.subheadline)
                .foregroundStyle(serious ? Palette.danger : Palette.inkDim)
                .fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: serious ? "exclamationmark.triangle" : "info.circle")
                .foregroundStyle(serious ? Palette.danger : Palette.inkFaint)
        }
    }
}
