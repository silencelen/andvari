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
            // nativeSave: on iOS 26.2 and later the system offers to save passwords to andvari itself (the AutoFill
            // extension's save request), so the web extension then shows no save prompt of its own.
            var nativeSave = false
            if #available(iOS 26.2, *) { nativeSave = true }
            reply(["ok": true, "type": "appServer", "url": origin.map { $0 as Any } ?? NSNull(), "nativeSave": nativeSave], to: context)
        case "saveKey":
            // The account a captured login may be sealed to, as the app published it (public material), or null.
            let key = Self.savesDirectory().flatMap { try? String(contentsOf: $0.appendingPathComponent("key.json"), encoding: .utf8) }
            reply(["ok": true, "type": "saveKey", "key": key.map { $0 as Any } ?? NSNull()], to: context)
        case "queueSave":
            reply(["ok": true, "type": "queueSave", "queued": Self.queueSave(id: message?["id"] as? String, entry: message?["entry"] as? String)], to: context)
        case "bioProbe":
            probe { self.reply($0, to: context) }
        default:
            reply(["ok": false], to: context)
        }
    }

    // The save queue, in the layout and bounds of the Kotlin core (FileSaveQueue, SaveQueue): `saves/q-<id>.json`,
    // at most 50 entries of at most 8 KiB. An entry is ciphertext sealed by the extension; this never sees a login.
    private static let maxEntries = 50
    private static let maxEntryBytes = 8 * 1024

    private static func savesDirectory() -> URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)?.appendingPathComponent("saves", isDirectory: true)
    }

    private static func queueSave(id: String?, entry: String?) -> Bool {
        guard let id, let entry, let dir = savesDirectory(),
              id.range(of: "^[A-Za-z0-9-]{1,64}$", options: .regularExpression) != nil,
              let data = entry.data(using: .utf8), !data.isEmpty, data.count <= maxEntryBytes
        else { return false }
        let fm = FileManager.default
        // Only while the app has published a key: no account, no queue.
        guard fm.fileExists(atPath: dir.appendingPathComponent("key.json").path) else { return false }
        let file = dir.appendingPathComponent("q-\(id).json")
        let queued = ((try? fm.contentsOfDirectory(atPath: dir.path)) ?? []).filter { $0.hasPrefix("q-") && $0.hasSuffix(".json") }
        if !fm.fileExists(atPath: file.path), queued.count >= maxEntries { return false }
        do {
            try data.write(to: file, options: [.atomic, .completeFileProtectionUnlessOpen])
            return true
        } catch {
            return false
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
