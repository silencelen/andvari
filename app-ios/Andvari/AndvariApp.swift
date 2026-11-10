import AndvariCore
import SwiftUI

@main
struct AndvariApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    @State private var generated = AndvariBridge.shared.generatePassword(length: 24)

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("andvari").font(.largeTitle.bold())
                Text("Core \(AndvariBridge.shared.coreVersion())").foregroundStyle(.secondary)
                Text("Generated password").font(.headline).padding(.top, 8)
                Text(generated).font(.body.monospaced()).textSelection(.enabled)
                Button("Generate another") { generated = AndvariBridge.shared.generatePassword(length: 24) }
                Text("Turn it on").font(.headline).padding(.top, 8)
                Text("AutoFill: Settings, General, AutoFill & Passwords, then turn on andvari.")
                Text("Safari: Settings, Apps, Safari, Extensions, then turn on andvari.")
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding()
        }
    }
}
