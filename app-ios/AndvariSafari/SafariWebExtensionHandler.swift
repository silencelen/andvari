import Foundation
import SafariServices

/// The extension's one native message: `{"type": "appServer"}` asks which server the andvari app uses, so the
/// extension can use the same one (extension/src/appserver.ts). The app writes the origin it confirmed through its
/// Trust Gate to the App Group (IosStorageConfig.sharedSuite in the Kotlin core); nothing else is shared there.
final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    /// The App Group the app shares with its extensions (IOS_APP_GROUP in the core).
    static let appGroup = "group.com.silencelen.andvari"
    /// The key the app writes its server origin under (IOS_APP_SERVER_KEY in the core).
    static let serverKey = "appServer"

    func beginRequest(with context: NSExtensionContext) {
        let item = context.inputItems.first as? NSExtensionItem
        let message = item?.userInfo?[SFExtensionMessageKey] as? [String: Any]
        let reply: [String: Any]
        if message?["type"] as? String == "appServer" {
            let origin = UserDefaults(suiteName: Self.appGroup)?.string(forKey: Self.serverKey)
            // NSNull reaches the extension as null: the app has no server yet.
            reply = ["ok": true, "type": "appServer", "url": origin.map { $0 as Any } ?? NSNull()]
        } else {
            reply = ["ok": false]
        }
        let response = NSExtensionItem()
        response.userInfo = [SFExtensionMessageKey: reply]
        context.completeRequest(returningItems: [response], completionHandler: nil)
    }
}
