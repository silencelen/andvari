import LocalAuthentication
import SwiftUI
import UIKit
import UIKit.UIGestureRecognizerSubclass
import UniformTypeIdentifiers

extension String {
    var trimmed: String {
        trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

// MARK: - Clipboard

/// A copy stays on this device's own pasteboard (never Universal Clipboard) and expires.
@MainActor
enum Clipboard {
    /// The server policy has no clipboard-clear time the app can read, so every copy lives this long.
    static let lifetime: TimeInterval = 60

    static func copy(_ value: String) {
        UIPasteboard.general.setItems(
            [[UTType.utf8PlainText.identifier: value]],
            options: [
                .localOnly: true,
                .expirationDate: Date().addingTimeInterval(lifetime),
            ]
        )
    }
}

// MARK: - Device

/// The device's biometric, for labels and symbols.
enum Biometry {
    private static let kind: (name: String, symbol: String) = {
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        switch context.biometryType {
        case .touchID:
            return ("Touch ID", "touchid")
        case .opticID:
            return ("Optic ID", "opticid")
        default:
            return ("Face ID", "faceid")
        }
    }()

    static var name: String { kind.name }
    static var symbol: String { kind.symbol }
}

/// A stored web address as something Safari can open: http and https only.
enum WebAddress {
    static func url(_ raw: String) -> URL? {
        let value = raw.trimmed
        guard !value.isEmpty else { return nil }
        let candidate = value.contains("://") ? value : "https://" + value
        guard let url = URL(string: candidate),
              let scheme = url.scheme?.lowercased(),
              scheme == "https" || scheme == "http",
              let host = url.host(percentEncoded: false),
              !host.isEmpty
        else { return nil }
        return url
    }
}

enum Format {
    static func duration(seconds: Int) -> String {
        let formatter = DateComponentsFormatter()
        formatter.unitsStyle = .full
        formatter.allowedUnits = [.hour, .minute, .second]
        formatter.maximumUnitCount = 2
        return formatter.string(from: TimeInterval(seconds)) ?? "\(seconds) s"
    }
}

/// Sentences more than one screen uses.
enum Wording {
    static let genericFailure = "Something went wrong. Try again."
    static let punycodeCaution =
        "This address uses international characters, shown here as punycode (xn--). Check it is exactly the server you expect."
    static let loopbackHttp =
        "This is an unencrypted http:// address on this device. Its traffic never leaves the phone."
    static let cleartextBlocked =
        "iOS refuses unencrypted http:// to other devices. Put the server behind https first."
    static let signOutTitle = "Sign out of this device?"
    static let signOutBody =
        "This removes the vault copy, quick unlock and any unsynced changes from this device. Signing back in needs your master password and your server."
    static let replacedPhrase =
        "This phrase replaces one created earlier, possibly on another device. Discard any phrase you saved before."
}

// MARK: - Privacy cover

/// Covers the UI with a plain branded view whenever the scene is not active, so the app switcher never
/// shows the vault. Sheets carry their own, since they sit above the root view.
struct PrivacyShield: ViewModifier {
    @Environment(\.scenePhase) private var scenePhase

    func body(content: Content) -> some View {
        content.overlay {
            if scenePhase != .active {
                CoverView()
            }
        }
    }
}

extension View {
    func privacyShield() -> some View {
        modifier(PrivacyShield())
    }
}

struct CoverView: View {
    var body: some View {
        ZStack {
            Palette.background
            VStack(spacing: 14) {
                Sigil(size: 56)
                Wordmark()
            }
        }
        .ignoresSafeArea()
        .accessibilityHidden(true)
    }
}

// MARK: - User activity

/// Reports every touch in the window, without taking part in it, so the idle lock counts from the last
/// interaction. Touches in sheets reach the same window.
struct ActivityWatcher: UIViewRepresentable {
    let onActivity: @MainActor () -> Void

    func makeUIView(context: Context) -> WatcherView {
        let view = WatcherView()
        view.isUserInteractionEnabled = false
        view.onActivity = onActivity
        return view
    }

    func updateUIView(_ view: WatcherView, context: Context) {
        view.onActivity = onActivity
    }

    final class WatcherView: UIView, UIGestureRecognizerDelegate {
        var onActivity: (@MainActor () -> Void)?

        private lazy var recognizer: TouchRecognizer = {
            let recognizer = TouchRecognizer(target: nil, action: nil)
            recognizer.cancelsTouchesInView = false
            recognizer.delaysTouchesBegan = false
            recognizer.delaysTouchesEnded = false
            recognizer.delegate = self
            recognizer.onTouch = { [weak self] in
                self?.onActivity?()
            }
            return recognizer
        }()

        override func didMoveToWindow() {
            super.didMoveToWindow()
            guard recognizer.view !== window else { return }
            recognizer.view?.removeGestureRecognizer(recognizer)
            window?.addGestureRecognizer(recognizer)
        }

        func gestureRecognizer(
            _ gestureRecognizer: UIGestureRecognizer,
            shouldRecognizeSimultaneouslyWith otherGestureRecognizer: UIGestureRecognizer
        ) -> Bool {
            true
        }
    }
}

/// Notes that a touch began, then steps aside: it never recognises, so it never blocks another gesture.
final class TouchRecognizer: UIGestureRecognizer {
    var onTouch: (@MainActor () -> Void)?

    override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent) {
        super.touchesBegan(touches, with: event)
        onTouch?()
        state = .failed
    }
}
