import Foundation
import LocalAuthentication
import SafariServices
import Security

/// The extension's native messages. `{"type": "appServer"}` asks which server the andvari app uses, so the extension
/// can use the same one (extension/src/appserver.ts). The app writes the origin it confirmed through its Trust Gate to
/// the App Group. `{"type": "bioProbe"}` is a diagnostic: it reports whether this process can raise Face ID and see the
/// shared snapshot and quick-unlock key, as presence and status codes only.
final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    /// The App Group the app shares with its extensions (IOS_APP_GROUP in the core).
    static let appGroup = "group.com.silencelen.andvari"
    /// The key the app writes its server origin under (IOS_APP_SERVER_KEY in the core).
    static let serverKey = "appServer"
    /// The Keychain service of the quick-unlock blobs (IosStorageConfig in the core).
    static let quickUnlockService = "io.silencelen.andvari.quickunlock"

    func beginRequest(with context: NSExtensionContext) {
        let item = context.inputItems.first as? NSExtensionItem
        let message = item?.userInfo?[SFExtensionMessageKey] as? [String: Any]
        switch message?["type"] as? String {
        case "appServer":
            let origin = UserDefaults(suiteName: Self.appGroup)?.string(forKey: Self.serverKey)
            // NSNull reaches the extension as null: the app has no server yet.
            reply(["ok": true, "type": "appServer", "url": origin.map { $0 as Any } ?? NSNull()], to: context)
        case "bioProbe":
            probe { self.reply($0, to: context) }
        default:
            reply(["ok": false], to: context)
        }
    }

    private func reply(_ body: [String: Any], to context: NSExtensionContext) {
        let response = NSExtensionItem()
        response.userInfo = [SFExtensionMessageKey: body]
        context.completeRequest(returningItems: [response], completionHandler: nil)
    }

    /// What this process can reach. No vault data: booleans, sizes and status codes.
    private func probe(_ done: @escaping ([String: Any]) -> Void) {
        var out: [String: Any] = ["ok": true, "type": "bioProbe"]

        let defaults = UserDefaults(suiteName: Self.appGroup)
        out["server"] = defaults?.string(forKey: Self.serverKey) != nil
        out["sessionState"] = defaults?.string(forKey: "baseUrl") != nil

        if let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: Self.appGroup) {
            out["container"] = true
            let file = container.appendingPathComponent("autofill-snapshot.json")
            out["snapshot"] = FileManager.default.isReadableFile(atPath: file.path)
            out["snapshotBytes"] = (try? Data(contentsOf: file))?.count ?? -1
        } else {
            out["container"] = false
        }

        // Presence only: nothing is returned from the Keychain, and no prompt is allowed.
        let quiet = LAContext()
        quiet.interactionNotAllowed = true
        out["blobStatus"] = Int(SecItemCopyMatching([
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.quickUnlockService,
            kSecAttrAccessGroup: Self.appGroup,
            kSecMatchLimit: kSecMatchLimitOne,
        ] as CFDictionary, nil))
        out["keyStatus"] = Int(SecItemCopyMatching([
            kSecClass: kSecClassKey,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrAccessGroup: Self.appGroup,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecUseAuthenticationContext: quiet,
        ] as CFDictionary, nil))

        let context = LAContext()
        var error: NSError?
        out["canEvaluate"] = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        out["canError"] = error?.code ?? 0
        out["biometryType"] = context.biometryType.rawValue
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Check whether andvari's Safari extension can use Face ID") { ok, failure in
            out["evaluate"] = ok
            out["evaluateError"] = (failure as NSError?)?.code ?? 0
            done(out)
        }
    }
}
