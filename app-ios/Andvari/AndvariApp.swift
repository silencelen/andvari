import SwiftUI
import UIKit

@main
struct AndvariApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var model = AppModel()
    @AppStorage(Appearance.storageKey) private var appearance = Appearance.system.rawValue

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                .preferredColorScheme((Appearance(rawValue: appearance) ?? .system).scheme)
        }
    }
}

/// UIKit's application delegate, for what SwiftUI has no hook for: keeping other apps' keyboards out (round-6 review
/// M3). Only Apple's keyboards type into andvari unless the person allows others in Settings; the setting is read
/// every time UIKit asks.
final class AppDelegate: NSObject, UIApplicationDelegate {
    func application(_ application: UIApplication, shouldAllowExtensionPointIdentifier extensionPointIdentifier: UIApplication.ExtensionPointIdentifier) -> Bool {
        extensionPointIdentifier != .keyboard || ThirdPartyKeyboards.allowed
    }
}
