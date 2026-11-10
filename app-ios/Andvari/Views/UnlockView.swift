import AndvariCore
import SwiftUI

/// A stored session is locked: the master password, or Face ID when quick unlock can be used. Face ID is
/// offered by itself once each time this screen opens, as soon as the app is in front.
struct UnlockView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.scenePhase) private var scenePhase
    @State private var password = ""
    @State private var message: String?
    @State private var unsealing = false
    @State private var offered = false
    @State private var confirmSignOut = false
    @FocusState private var focus: Field?

    private enum Field {
        case password
    }

    var body: some View {
        AuthScroll {
            Brand()
            account
            VStack(alignment: .leading, spacing: 14) {
                if quick.enrolled && !quick.fresh {
                    Text("Unlock with your master password to keep \(Biometry.name) on.")
                        .font(.footnote)
                        .foregroundStyle(Palette.inkDim)
                        .fixedSize(horizontal: false, vertical: true)
                }
                InputField(
                    "Master password",
                    text: $password,
                    focus: $focus,
                    field: .password,
                    secure: true,
                    contentType: .password,
                    submitLabel: .go,
                    onSubmit: unlock
                )
                if let message {
                    InlineMessage(text: message)
                }
                PrimaryButton(title: "Unlock", busy: unsealing, action: unlock)
                    .disabled(password.isEmpty || model.state.busy)
                if unsealing {
                    Text("Unsealing your vault…")
                        .font(.footnote)
                        .foregroundStyle(Palette.inkFaint)
                        .frame(maxWidth: .infinity)
                }
                if quick.usable {
                    Button {
                        unlockWithBiometrics()
                    } label: {
                        Label("Unlock with \(Biometry.name)", systemImage: Biometry.symbol)
                    }
                    .buttonStyle(QuietButtonStyle())
                    .disabled(model.state.busy)
                }
            }
            Button("Sign out") {
                confirmSignOut = true
            }
            .font(.footnote)
            .foregroundStyle(Palette.inkDim)
            .disabled(model.state.busy)
        }
        .confirmationDialog(Wording.signOutTitle, isPresented: $confirmSignOut, titleVisibility: .visible) {
            Button("Sign out", role: .destructive) {
                signOut()
            }
        } message: {
            Text(Wording.signOutBody)
        }
        .onChange(of: canOffer, initial: true) { _, ready in
            if ready && !offered {
                offered = true
                unlockWithBiometrics()
            }
        }
        .onDisappear {
            password = ""
        }
    }

    private var account: some View {
        VStack(spacing: 6) {
            if let email = model.state.accountEmail {
                Text(email)
                    .font(.subheadline)
                    .foregroundStyle(Palette.inkDim)
            }
            if let reason = model.state.lockReason {
                Text(reason)
                    .font(.footnote)
                    .foregroundStyle(Palette.inkFaint)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity)
    }

    private var quick: QuickUnlockView {
        model.state.quickUnlock
    }

    /// The prompt can only show while the app is in front.
    private var canOffer: Bool {
        scenePhase == .active && quick.usable && !model.state.busy
    }

    private func unlock() {
        guard !password.isEmpty, !model.state.busy else { return }
        message = nil
        unsealing = true
        let typed = password
        Task {
            let outcome = await model.unlock(password: typed)
            unsealing = false
            if outcome != .ok {
                password = ""
                message = outcome.message
                focus = .password
            }
        }
    }

    private func unlockWithBiometrics() {
        guard !model.state.busy else { return }
        message = nil
        Task {
            let outcome = await model.unlockWithBiometrics()
            message = outcome.message
        }
    }

    private func signOut() {
        Task {
            let outcome = await model.signOut()
            message = outcome.message
        }
    }
}

/// This build is too old for the server: only an update helps.
struct UpgradeRequiredView: View {
    @EnvironmentObject private var model: AppModel
    @State private var message: String?
    @State private var confirmSignOut = false

    var body: some View {
        AuthScroll {
            Brand()
            VStack(spacing: 12) {
                Text("Update required")
                    .font(.title2.weight(.semibold))
                    .foregroundStyle(Palette.ink)
                    .accessibilityAddTraits(.isHeader)
                Text(model.state.upgradeMessage ?? "This version of andvari is too old for your server. Update it from the App Store.")
                    .font(.body)
                    .foregroundStyle(Palette.inkDim)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                if let message {
                    InlineMessage(text: message)
                }
            }
            if model.state.accountEmail != nil {
                Button("Sign out") {
                    confirmSignOut = true
                }
                .font(.footnote)
                .foregroundStyle(Palette.inkDim)
                .disabled(model.state.busy)
            }
        }
        .confirmationDialog(Wording.signOutTitle, isPresented: $confirmSignOut, titleVisibility: .visible) {
            Button("Sign out", role: .destructive) {
                signOut()
            }
        } message: {
            Text(Wording.signOutBody)
        }
    }

    private func signOut() {
        Task {
            let outcome = await model.signOut()
            message = outcome.message
        }
    }
}
