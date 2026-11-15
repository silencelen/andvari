import CryptoKit
import Foundation
import SQLite3

/// The job's test site doubles as a remote control for what other devices and other people do
/// (app-ios/uitest/serve-site.py, tools/uitest-seed `vault` and `share`): the app then learns of it at its next sync.
enum OtherDevice {
    /// Create, delete or restore the shared vault named [name] from another device of the account. The error text when
    /// it failed, nil when it worked.
    static func vault(_ action: String, _ name: String) -> String? {
        control("vault-" + action, ["name": name])
    }

    /// A second account shares a new vault [vault] holding the login [item] read-only with the test account, and another
    /// device of the test account accepts it. The error text when it failed, nil when it worked.
    static func shareReadOnly(vault: String, item: String) -> String? {
        control("share-read-only", ["name": vault, "item": item])
    }

    /// As above, the second account made with [email] and [password] (no "+" in either: the query would read it as a
    /// space), so a test can sign in as the owner of a vault the test account uses.
    static func shareReadOnly(vault: String, item: String, ownerEmail email: String, ownerPassword password: String) -> String? {
        control("share-read-only", ["name": vault, "item": item, "email": email, "password": password])
    }

    /// Stop the vault server for [seconds] (20 at most), after which it goes on by itself: a network that stalls. The
    /// answer comes at once. The error text when it failed, nil when it worked.
    static func stallServer(seconds: Int) -> String? {
        control("server-stall", ["seconds": String(seconds)])
    }

    /// The test account, an admin, invites [email], as the web app's Administration does: the invite's code, for a test
    /// that enrolls with it in the app. Nil when it failed, with the reason in [problem].
    static func invite(_ email: String) -> (code: String?, problem: String?) {
        let answer = ask("invite", ["email": email])
        guard answer.ok else { return (nil, answer.text) }
        let line = answer.text.split(separator: "\n").last { $0.hasPrefix("invite: ") }
        guard let line else { return (nil, "the answer names no invite: " + String(answer.text.suffix(200))) }
        return (String(line.dropFirst("invite: ".count)).trimmingCharacters(in: .whitespacesAndNewlines), nil)
    }

    private static func control(_ action: String, _ query: [String: String]) -> String? {
        let answer = ask(action, query)
        return answer.ok ? nil : answer.text
    }

    /// One control request: whether it worked, and what it answered (the error, when it did not).
    private static func ask(_ action: String, _ query: [String: String]) -> (ok: Bool, text: String) {
        // Plain http to the loopback address first; the https name (trusted in the simulator) only when that one gave
        // no answer at all, so an action that answered with an error is never run twice.
        var last = "not tried"
        for origin in [Fixture.controlOrigin, Fixture.siteOrigin] {
            var components = URLComponents(string: origin + "/control/" + action)
            components?.queryItems = query.sorted { $0.key < $1.key }.map { URLQueryItem(name: $0.key, value: $0.value) }
            guard let url = components?.url else { continue }
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.timeoutInterval = 320
            let done = DispatchSemaphore(value: 0)
            var status = 0
            var text = ""
            URLSession.shared.dataTask(with: request) { data, response, error in
                status = (response as? HTTPURLResponse)?.statusCode ?? 0
                text = data.flatMap { String(data: $0, encoding: .utf8) } ?? error.map { "\($0)" } ?? ""
                done.signal()
            }.resume()
            if done.wait(timeout: .now() + 330) == .timedOut {
                last = "\(origin): no answer"
                continue
            }
            if status == 200 { return (true, text) }
            last = "\(origin): \(status) \(text.suffix(300))"
            if status != 0 { return (false, last) }
        }
        return (false, last)
    }
}

/// The simulator's disk, as the runner sees it. The runner is a simulator process and every app's containers are plain
/// folders there, so a test can put a file where an app will find it and read what an app left, without the app's help.
enum SimulatorDisk {
    /// <device>/data/Containers: the runner's own home is …/Containers/Data/Application/<id>.
    private static var containers: URL {
        URL(fileURLWithPath: NSHomeDirectory()).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    }

    private static func container(in folder: String, identifier: String) -> URL? {
        let root = containers.appendingPathComponent(folder, isDirectory: true)
        guard let dirs = try? FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil) else { return nil }
        for dir in dirs {
            let meta = NSDictionary(contentsOf: dir.appendingPathComponent(".com.apple.mobile_container_manager.metadata.plist"))
            if (meta?["MCMMetadataIdentifier"] as? String) == identifier { return dir }
        }
        return nil
    }

    /// The container of an App Group, nil while the simulator has made none for it.
    static func group(_ identifier: String) -> URL? {
        container(in: "Shared/AppGroup", identifier: identifier)
    }

    /// The App Groups the simulator has a container for, for a failure that has to say what it found.
    static func groups() -> [String] {
        let root = containers.appendingPathComponent("Shared/AppGroup", isDirectory: true)
        let dirs = (try? FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)) ?? []
        return dirs.compactMap { dir in
            NSDictionary(contentsOf: dir.appendingPathComponent(".com.apple.mobile_container_manager.metadata.plist"))?["MCMMetadataIdentifier"] as? String
        }.sorted()
    }

    /// An app's own data container.
    static func data(of bundleID: String) -> URL? {
        container(in: "Data/Application", identifier: bundleID)
    }

    /// Every regular file under [root], as paths from it ("folder/name.csv"), without hidden ones.
    static func files(under root: URL) -> [String] {
        guard let walker = FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey]) else { return [] }
        // The enumerator's paths may spell the root another way (/private/var for /var): compare resolved paths.
        let base = root.resolvingSymlinksInPath().path + "/"
        var out: [String] = []
        for case let url as URL in walker {
            guard (try? url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true else { continue }
            let full = url.resolvingSymlinksInPath().path
            guard full.hasPrefix(base) else { continue }
            let path = String(full.dropFirst(base.count))
            if !path.hasPrefix(".") && !path.contains("/.") { out.append(path) }
        }
        return out.sorted()
    }
}

/// The simulator's Files app, "On My iPhone": a test puts a file there for the system's file picker to offer, and reads
/// back a file the app saved or exported there.
enum FilesApp {
    /// The folder behind "On My iPhone": the File Provider Storage of the group com.apple.FileProvider.LocalStorage.
    /// Nil until the simulator has made that group's container (opening the Files app once does).
    static func localStorage() -> URL? {
        guard let group = SimulatorDisk.group("group.com.apple.FileProvider.LocalStorage") else { return nil }
        let storage = group.appendingPathComponent("File Provider Storage", isDirectory: true)
        try? FileManager.default.createDirectory(at: storage, withIntermediateDirectories: true)
        return storage
    }

    /// Write [data] as [name] at the top of "On My iPhone". False when the folder is not there or the write failed.
    @discardableResult
    static func put(_ name: String, _ data: Data) -> Bool {
        guard let storage = localStorage() else { return false }
        return (try? data.write(to: storage.appendingPathComponent(name), options: .atomic)) != nil
    }

    /// Every file under "On My iPhone", as paths from its top ("folder/name.csv").
    static func files() -> [String] {
        localStorage().map(SimulatorDisk.files(under:)) ?? []
    }

    static func read(_ path: String) -> Data? {
        localStorage().flatMap { try? Data(contentsOf: $0.appendingPathComponent(path)) }
    }

    static func remove(_ path: String) {
        guard let storage = localStorage() else { return }
        try? FileManager.default.removeItem(at: storage.appendingPathComponent(path))
    }
}

/// What andvari keeps on the simulator's disk for the account signed in, read from outside the app. The Keychain is
/// not a folder and cannot be read this way.
enum LocalState {
    static let appGroup = "group.com.silencelen.andvari"

    /// The address of the account the app is signed in to, from the snapshot it shares with its extensions (rows sealed
    /// under their vault keys, in plain JSON that names the account). Nil when the app is signed out, or has not
    /// unlocked since it signed in.
    static func signedInEmail() -> String? {
        guard let group = SimulatorDisk.group(appGroup),
              let data = try? Data(contentsOf: group.appendingPathComponent("autofill-snapshot.json")),
              let snapshot = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return nil }
        return snapshot["email"] as? String
    }

    /// Every file the app keeps for accounts: what is under Application Support/andvari in its own container (vault
    /// caches, device state, kept saves and their files, unfinished moves, the list of automatic saves), and the snapshot
    /// and the save queue in its App Group. Paths start "app/" or "group/".
    static func accountFiles() -> [String] {
        var out: [String] = []
        if let data = SimulatorDisk.data(of: "com.silencelen.andvari") {
            let support = data.appendingPathComponent("Library/Application Support/andvari", isDirectory: true)
            out += SimulatorDisk.files(under: support).map { "app/" + $0 }
        }
        if let group = SimulatorDisk.group(appGroup) {
            out += SimulatorDisk.files(under: group)
                .filter { $0 == "autofill-snapshot.json" || $0.hasPrefix("saves/") }
                .map { "group/" + $0 }
        }
        return out.sorted()
    }

    /// The sealed files of saves that are kept until their upload is done (Application Support/andvari/pending-files).
    static func filesSetAside() -> [String] {
        accountFiles().filter { $0.hasPrefix("app/pending-files/") }
    }

    /// What andvari's preferences hold on disk, its own ("app/<key>") and its App Group's ("group/<key>"), each value
    /// as text. The system writes them to disk a little after the app sets them.
    static func preferences() -> [String: String] {
        var out: [String: String] = [:]
        let files: [(place: String, url: URL?)] = [
            (place: "app", url: SimulatorDisk.data(of: "com.silencelen.andvari")?.appendingPathComponent("Library/Preferences/com.silencelen.andvari.plist")),
            (place: "group", url: SimulatorDisk.group(appGroup)?.appendingPathComponent("Library/Preferences/" + appGroup + ".plist")),
        ]
        for file in files {
            guard let url = file.url, let plist = NSDictionary(contentsOf: url) as? [String: Any] else { continue }
            for (key, value) in plist {
                out[file.place + "/" + key] = String(describing: value)
            }
        }
        return out
    }

    /// The preferences that are an account's or a server's: the session and the server address, whatever is kept by
    /// server ("ns.<server>.…": its policy, an account's keys there, pins), and any other key or value that names one
    /// of [markers] (the server's address, an account's email). Each as "place/key = value" (the value's beginning).
    /// What the device keeps for itself (the appearance, the keyboards switch) is not among them.
    static func accountPreferences(naming markers: [String]) -> [String] {
        let own: Set<String> = ["baseUrl", "pendingServer", "session", "mustChangePassword", "lastSyncAt"]
        var out: [String] = []
        for (place, value) in preferences() {
            let key = place.split(separator: "/", maxSplits: 1).last.map { String($0) } ?? place
            let named = markers.contains { !$0.isEmpty && (key.contains($0) || value.contains($0)) }
            if own.contains(key) || key.hasPrefix("ns.") || named {
                out.append(place + " = " + String(value.prefix(80)))
            }
        }
        return out.sorted()
    }
}

/// The simulator's Keychain, read from its database on the simulator's disk. An item's secret is sealed there; the
/// access group it belongs to is not, so a test can say whether andvari has any item left, though not which.
enum SimulatorKeychain {
    /// The rows that belong to an access group of andvari's (its own, and its App Group's, which holds the quick-unlock
    /// key), each as "table row N in <group>". [problem] says why the database could not be read, when it could not.
    static func andvariRows() -> (rows: [String], problem: String?) {
        let fm = FileManager.default
        // <device>/data: the runner's home is <device>/data/Containers/Data/Application/<id>.
        var device = URL(fileURLWithPath: NSHomeDirectory())
        for _ in 0..<4 { device.deleteLastPathComponent() }
        let folder = device.appendingPathComponent("Library/Keychains", isDirectory: true)
        guard let names = try? fm.contentsOfDirectory(atPath: folder.path) else {
            return ([], "there is no Library/Keychains in the simulator at " + folder.path)
        }
        guard let name = names.filter({ $0.hasPrefix("keychain-2") && $0.hasSuffix(".db") }).sorted().first else {
            return ([], "Library/Keychains holds no keychain database, only \(names)")
        }
        // A copy, with its write-ahead log: the system has the database open, and a copy is read at leisure.
        let copy = fm.temporaryDirectory.appendingPathComponent("uitest-keychain-" + UUID().uuidString, isDirectory: true)
        try? fm.createDirectory(at: copy, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: copy) }
        for suffix in ["", "-wal", "-shm"] {
            let from = folder.appendingPathComponent(name + suffix)
            if fm.fileExists(atPath: from.path) {
                try? fm.copyItem(at: from, to: copy.appendingPathComponent(name + suffix))
            }
        }
        var handle: OpaquePointer?
        guard sqlite3_open_v2(copy.appendingPathComponent(name).path, &handle, SQLITE_OPEN_READWRITE, nil) == SQLITE_OK, let db = handle else {
            if let handle { sqlite3_close(handle) }
            return ([], "the copy of " + name + " could not be opened")
        }
        defer { sqlite3_close(db) }
        var rows: [String] = []
        var problems: [String] = []
        for table in ["genp", "inet", "keys", "cert"] {
            var prepared: OpaquePointer?
            let sql = "SELECT agrp, rowid FROM " + table + " WHERE agrp LIKE '%silencelen.andvari%'"
            guard sqlite3_prepare_v2(db, sql, -1, &prepared, nil) == SQLITE_OK, let statement = prepared else {
                problems.append(table + ": " + String(cString: sqlite3_errmsg(db)))
                continue
            }
            while sqlite3_step(statement) == SQLITE_ROW {
                let group = sqlite3_column_text(statement, 0).map { String(cString: $0) } ?? "?"
                rows.append(table + " row \(sqlite3_column_int64(statement, 1)) in " + group)
            }
            sqlite3_finalize(statement)
        }
        return (rows, problems.isEmpty ? nil : problems.joined(separator: "; "))
    }
}

/// What the job's test site serves.
enum TestSite {
    /// The card test pages (extension/test-pages/card-*.html, copied under /test-pages/ by start-backend.sh), read from
    /// the site's own listing of that folder, so a page added to the extension is tested without a list kept here.
    static func cardPages() -> [String] {
        guard let url = URL(string: Fixture.controlOrigin + "/test-pages/") else { return [] }
        let done = DispatchSemaphore(value: 0)
        var listing = ""
        URLSession.shared.dataTask(with: url) { data, _, _ in
            listing = data.flatMap { String(data: $0, encoding: .utf8) } ?? ""
            done.signal()
        }.resume()
        _ = done.wait(timeout: .now() + 30)
        guard let pattern = try? NSRegularExpression(pattern: "href=\"(card-[A-Za-z0-9-]+\\.html)\"") else { return [] }
        let matches = pattern.matches(in: listing, range: NSRange(listing.startIndex..., in: listing))
        let names = matches.compactMap { Range($0.range(at: 1), in: listing).map { String(listing[$0]) } }
        return Array(Set(names)).sorted()
    }
}

/// RFC 6238 codes (SHA-1, 6 digits, 30 seconds) for a base32 key, as an authenticator app shows them.
enum Authenticator {
    static func code(base32 key: String, at date: Date = Date()) -> String? {
        guard let secret = decode(key) else { return nil }
        var counter = UInt64(date.timeIntervalSince1970 / 30).bigEndian
        let mac = Array(HMAC<Insecure.SHA1>.authenticationCode(for: Data(bytes: &counter, count: 8), using: SymmetricKey(data: secret)))
        let offset = Int(mac[19] & 0x0f)
        let binary = (UInt32(mac[offset] & 0x7f) << 24) | (UInt32(mac[offset + 1]) << 16) | (UInt32(mac[offset + 2]) << 8) | UInt32(mac[offset + 3])
        return String(format: "%06d", binary % 1_000_000)
    }

    /// Seconds left in the current 30-second step.
    static var secondsLeft: Int { 30 - Int(Date().timeIntervalSince1970) % 30 }

    private static func decode(_ text: String) -> Data? {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var bits = 0
        var value = 0
        var bytes: [UInt8] = []
        for character in text.uppercased() where character != " " && character != "=" {
            guard let index = alphabet.firstIndex(of: character) else { return nil }
            value = (value << 5) | index
            bits += 5
            if bits >= 8 {
                bytes.append(UInt8((value >> (bits - 8)) & 0xff))
                bits -= 8
            }
        }
        return bytes.isEmpty ? nil : Data(bytes)
    }
}
