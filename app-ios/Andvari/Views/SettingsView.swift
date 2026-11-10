import AndvariCore
import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var quickOn = false
    @State private var message: String?
    @State private var confirmSignOut = false

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
