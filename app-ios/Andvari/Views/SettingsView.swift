import AndvariCore
import AuthenticationServices
import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var quickOn = false
    @State private var message: String?
    @State private var confirmSignOut = false
    @State private var identityCode: String?
    @State private var identityCodeFull: String?
    @State private var showFullCode = false
    /// Whether andvari is the AutoFill provider iOS uses (nil until the system has said).
    @State private var autofillOn: Bool?

    var body: some View {
        NavigationStack {
            Form {
                Section("Account") {
                    LabeledContent("Email", value: model.state.accountEmail ?? "–")
                    LabeledContent("Server") {
                        Text(model.state.server ?? "–")
                            .font(.footnote.monospaced())
                            .multilineTextAlignment(.trailing)
                    }
                }
                .listRowBackground(Palette.raised)

                if let identityCode {
                    Section {
                        Text(Self.grouped(identityCode))
                            .font(.callout.monospaced())
                            .textSelection(.enabled)
                            .accessibilityLabel("Your identity code")
                            .accessibilityValue(identityCode.map(String.init).joined(separator: " "))
                        if let identityCodeFull {
                            DisclosureGroup("Full fingerprint", isExpanded: $showFullCode) {
                                Text(Self.grouped(identityCodeFull))
                                    .font(.footnote.monospaced())
                                    .foregroundStyle(Palette.inkDim)
                                    .textSelection(.enabled)
                            }
                            .font(.footnote)
                        }
                    } header: {
                        Text("Your identity code")
                    } footer: {
                        Text("Someone sharing a vault with you sees this code for you on their screen. Compare it in person or on a call you trust: if it matches, they are really sharing with you.")
                    }
                    .listRowBackground(Palette.raised)
                }

                Section {
                    Toggle(isOn: $quickOn) {
                        Label(Biometry.name, systemImage: Biometry.symbol)
                    }
                    .disabled(model.state.busy || !(quick.available || quick.enrolled))
                    LabeledContent("Auto-lock", value: autoLock)
                } header: {
                    Text("Security")
                } footer: {
                    if let message {
                        Text(message)
                            .foregroundStyle(Palette.danger)
                    } else if let reason = quick.reason {
                        // Why the switch is unavailable (the core's sentence); nothing while it is merely off.
                        Text(reason)
                            .foregroundStyle(Palette.inkDim)
                    }
                }
                .listRowBackground(Palette.raised)

                Section {
                    LabeledContent("AutoFill", value: autofillOn.map { $0 ? "On" : "Off" } ?? "–")
                    if autofillOn == false {
                        Button("Open AutoFill settings") {
                            ASSettingsHelper.openCredentialProviderAppSettings { _ in }
                        }
                    }
                } header: {
                    Text("AutoFill and Safari")
                } footer: {
                    Text(Wording.safariExtensionHelp)
                }
                .listRowBackground(Palette.raised)

                Section {
                    Button("Lock now") {
                        model.lock()
                    }
                    Button("Sign out", role: .destructive) {
                        confirmSignOut = true
                    }
                    .disabled(model.state.busy)
                }
                .listRowBackground(Palette.raised)

                Section("About") {
                    LabeledContent("Version", value: appVersion)
                    LabeledContent("Core", value: AndvariBridge.shared.coreVersion())
                }
                .listRowBackground(Palette.raised)
            }
            .scrollContentBackground(.hidden)
            .background(Palette.background)
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") {
                        dismiss()
                    }
                }
            }
            .toolbarBackground(Palette.background, for: .navigationBar)
            .confirmationDialog(Wording.signOutTitle, isPresented: $confirmSignOut, titleVisibility: .visible) {
                Button("Sign out", role: .destructive) {
                    signOut()
                }
            } message: {
                Text(Wording.signOutBody)
            }
        }
        .onAppear {
            quickOn = quick.enrolled
            identityCode = model.identityCode()
            identityCodeFull = model.identityCodeFull()
            readAutofillState()
        }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.didBecomeActiveNotification)) { _ in
            readAutofillState() // back from the Settings app
        }
        .onChange(of: model.state.quickUnlock.enrolled) { _, enrolled in
            quickOn = enrolled
        }
        .onChange(of: quickOn) { _, on in
            if on != quick.enrolled {
                setQuickUnlock(on)
            }
        }
    }

    private func readAutofillState() {
        ASCredentialIdentityStore.shared.getState { state in
            Task { @MainActor in
                autofillOn = state.isEnabled
            }
        }
    }

    /// Hex in groups of four, so two people can read it to each other.
    private static func grouped(_ hex: String) -> String {
        stride(from: 0, to: hex.count, by: 4).map { start in
            let from = hex.index(hex.startIndex, offsetBy: start)
            let to = hex.index(from, offsetBy: 4, limitedBy: hex.endIndex) ?? hex.endIndex
            return String(hex[from..<to])
        }
        .joined(separator: " ")
    }

    private var quick: QuickUnlockView {
        model.state.quickUnlock
    }

    /// The server's idle window, already clamped; the vault also locks whenever the app leaves the screen.
    private var autoLock: String {
        guard let seconds = model.state.policy?.autoLockSeconds, seconds > 0 else { return "–" }
        return Format.duration(seconds: Int(seconds))
    }

    private var appVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "–"
    }

    private func setQuickUnlock(_ on: Bool) {
        message = nil
        if on {
            Task {
                let outcome = await model.enableQuickUnlock()
                if outcome != .ok {
                    quickOn = model.state.quickUnlock.enrolled
                    message = outcome.message
                }
            }
        } else {
            model.disableQuickUnlock()
        }
    }

    private func signOut() {
        Task {
            let outcome = await model.signOut()
            message = outcome.message
        }
    }
}
