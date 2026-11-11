import AndvariCore
import Foundation
import SafariServices

/// The extension's native messages. `{"type": "appServer"}` asks which server the andvari app uses, so the extension
/// can use the same one (extension/src/appserver.ts). The app writes the origin it confirmed through its Trust Gate to
/// the App Group. `saveKey` and `queueSave` hand a login the extension sealed to the app's save queue. `vaultOpen`,
/// `vaultSecret` and `vaultClose` are the extension's only vault: the app's snapshot, opened behind Face ID
/// (AppVaultSession below).
final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    /// The App Group the app shares with its extensions (IOS_APP_GROUP in the core).
    static let appGroup = "group.com.silencelen.andvari"
    /// The key the app writes its server origin under (IOS_APP_SERVER_KEY in the core).
    static let serverKey = "appServer"

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
        case "vaultOpen":
            AppVaultSession.open { self.reply($0, to: context) }
        case "vaultSecret":
            AppVaultSession.secret(ticket: message?["ticket"] as? String, itemId: message?["itemId"] as? String) { self.reply($0, to: context) }
        case "vaultClose":
            AppVaultSession.close(ticket: message?["ticket"] as? String)
            reply(["ok": true, "type": "vaultClose"], to: context)
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
}

/// The Safari extension's vault (design 2026-11-09, "Safari extension"): it has no sign-in of its own. This opens the
/// app's encrypted snapshot behind Face ID through the same read-only core object as the AutoFill extension
/// (`IosAutofill`: the app's quick-unlock gates, no network, no password KDF, no tokens).
///
/// What crosses to the extension, and when:
/// - `open` answers with the logins' names, usernames and web addresses. No password and no one-time code.
/// - `secret` answers with one login's username, password and current one-time code, for the item asked.
///
/// How long an unlock lasts: one Face ID opens the vault for this process for at most `lifetime` seconds, under a
/// random ticket only the caller of `open` holds. `close` (the popup went away), the timer, or a new `open` wipes the
/// keys. iOS may end this process between two messages; `secret` then finds nothing open and runs Face ID again
/// itself, so a fill still completes, with a second prompt.
enum AppVaultSession {
    private static let lifetime: TimeInterval = 90
    private static var vault: IosAutofill?
    private static var ticket: String?
    private static var expiry: DispatchWorkItem?

    /// Kotlin suspend functions are called from the main thread.
    private static func onMain(_ work: @escaping @MainActor () async -> Void) {
        Task { @MainActor in await work() }
    }

    @MainActor
    private static func wipe() {
        expiry?.cancel()
        expiry = nil
        vault?.close()
        vault = nil
        ticket = nil
    }

    /// Face ID, then the snapshot. The result is one of: "open" (with a fresh ticket), "openApp" (with what to do
    /// in the app), or "cancelled".
    @MainActor
    private static func unlock() async -> (state: String, message: String?) {
        wipe()
        let fresh = IosAutofill()
        if let blocked = fresh.availability() as? FillAvailability.OpenApp {
            return ("openApp", blocked.message)
        }
        guard let result = try? await fresh.unlock(reason: "Unlock andvari in Safari") else {
            fresh.close()
            return ("cancelled", nil)
        }
        if let blocked = result as? FillUnlock.OpenApp {
            fresh.close()
            return ("openApp", blocked.message)
        }
        guard result is FillUnlock.Unlocked else {
            fresh.close()
            return ("cancelled", nil)
        }
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            fresh.close()
            return ("cancelled", nil)
        }
        vault = fresh
        ticket = bytes.map { String(format: "%02x", $0) }.joined()
        let timer = DispatchWorkItem { Task { @MainActor in wipe() } }
        expiry = timer
        DispatchQueue.main.asyncAfter(deadline: .now() + lifetime, execute: timer)
        return ("open", nil)
    }

    static func open(_ done: @escaping ([String: Any]) -> Void) {
        onMain {
            let (state, message) = await unlock()
            var body: [String: Any] = ["ok": true, "type": "vaultOpen", "state": state]
            if let message { body["message"] = message }
            if state == "open", let vault, let ticket {
                body["ticket"] = ticket
                if let ready = vault.availability() as? FillAvailability.Ready { body["email"] = ready.email }
                // Names, usernames and addresses only.
                body["items"] = vault.logins(hosts: []).map { login -> [String: Any] in
                    ["itemId": login.itemId, "name": login.name, "username": login.username, "uris": login.uris, "hasTotp": login.hasTotp]
                }
            }
            done(body)
        }
    }

    static func secret(ticket asked: String?, itemId: String?, _ done: @escaping ([String: Any]) -> Void) {
        onMain {
            guard let itemId, !itemId.isEmpty else {
                done(["ok": true, "type": "vaultSecret", "state": "refused"])
                return
            }
            // The open vault serves only the caller that opened it. Anything else is a new unlock, with its prompt.
            if vault == nil || asked == nil || asked != ticket {
                let (state, message) = await unlock()
                if state != "open" {
                    var body: [String: Any] = ["ok": true, "type": "vaultSecret", "state": state]
                    if let message { body["message"] = message }
                    done(body)
                    return
                }
            }
            guard let vault, let credential = vault.credential(itemId: itemId) else {
                done(["ok": true, "type": "vaultSecret", "state": "refused"])
                return
            }
            var body: [String: Any] = ["ok": true, "type": "vaultSecret", "state": "secret", "username": credential.username, "password": credential.password]
            if let code = vault.oneTimeCode(itemId: itemId) { body["totpCode"] = code }
            // A vault this call opened itself is not kept: its ticket was never handed out.
            if asked == nil || asked != ticket { wipe() }
            done(body)
        }
    }

    static func close(ticket asked: String?) {
        onMain {
            if asked != nil, asked == ticket { wipe() }
        }
    }
}
