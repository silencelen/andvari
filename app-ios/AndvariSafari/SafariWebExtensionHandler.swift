import Foundation
import SafariServices

// The extension talks only to its own background page and the user's server; there is no native
// messaging. This handler exists because a Safari Web Extension must have a principal class.
final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    func beginRequest(with context: NSExtensionContext) {
        let response = NSExtensionItem()
        response.userInfo = [SFExtensionMessageKey: ["ok": true]]
        context.completeRequest(returningItems: [response], completionHandler: nil)
    }
}
