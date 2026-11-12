import SwiftUI

@main
struct AndvariApp: App {
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
