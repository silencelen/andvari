import AndvariCore
import SwiftUI
import UIKit

/// Renders the screen the controller names. The Trust Gate is a sheet over the screen that raised it, so
/// that screen keeps what was typed into it.
struct RootView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.scenePhase) private var scenePhase
    @State private var baseScreen: Screen = .loading
    @State private var gateShown = false

    var body: some View {
        ZStack {
            TreasuryBackground()
            content
        }
        .safeAreaInset(edge: .bottom) {
            Banners()
        }
        .sheet(isPresented: $gateShown, onDismiss: { gateDismissed() }) {
            TrustGateSheet()
                .environmentObject(model)
                .tint(Palette.goldText)
                .privacyShield()
        }
        .privacyShield()
        .background {
            ActivityWatcher(onActivity: { model.userActivity() })
        }
        .tint(Palette.goldText)
        .onChange(of: model.screen, initial: true) { _, screen in
            if screen != .trustGate {
                baseScreen = screen
            }
            gateShown = screen == .trustGate
        }
        .onChange(of: scenePhase) { _, phase in
            model.scenePhaseChanged(to: phase)
        }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.willTerminateNotification)) { _ in
            model.close()
        }
    }

    @ViewBuilder private var content: some View {
        switch model.screen == .trustGate ? baseScreen : model.screen {
        case .loading, .trustGate:
            LoadingView()
        case .chooseServer:
            ChooseServerView()
        case .welcome:
            WelcomeView()
        case .unlock:
            UnlockView()
        case .recover:
            RecoverView()
        case .recoveryReveal:
            RecoveryRevealView()
        case .recoveryCapture:
            RecoveryCaptureView()
        case .vault:
            VaultView()
        case .upgradeRequired:
            UpgradeRequiredView()
        }
    }

    /// A swipe down is the gate's Cancel. After Connect or Cancel the screen has already moved on.
    private func gateDismissed() {
        if model.screen == .trustGate {
            model.cancelTrustGate()
        }
    }
}

/// The controller's error and notice, until dismissed. A notice also goes by itself after a while.
struct Banners: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(spacing: 8) {
            if let error = model.state.error {
                Plate(text: error, tone: .error) {
                    model.dismissError()
                }
            }
            // A save with files being finished after an unlock (an editor shows its own progress).
            if let upload = model.state.upload, model.state.attachmentDraft == nil {
                HStack(spacing: 10) {
                    ProgressView()
                        .tint(Palette.gold)
                    Text("Finishing a save with files: \(upload.done) of \(upload.total) sent.")
                        .font(.subheadline)
                        .foregroundStyle(Palette.ink)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
                .background(Palette.raised, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                .accessibilityElement(children: .combine)
            }
            if let notice = model.state.notice {
                Plate(text: notice, tone: .notice) {
                    model.dismissNotice()
                }
                .task(id: notice) {
                    try? await Task.sleep(for: .seconds(5))
                    if !Task.isCancelled && model.state.notice == notice {
                        model.dismissNotice()
                    }
                }
            }
        }
        .padding(.horizontal, 16)
        .padding(.bottom, 8)
        .animation(.easeOut(duration: 0.2), value: model.state.error)
        .animation(.easeOut(duration: 0.2), value: model.state.notice)
    }
}

struct LoadingView: View {
    var body: some View {
        VStack(spacing: 20) {
            Sigil(size: 56)
            ProgressView()
                .tint(Palette.gold)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Loading")
    }
}
