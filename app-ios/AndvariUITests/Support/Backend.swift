import CryptoKit
import Foundation

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

    private static func control(_ action: String, _ query: [String: String]) -> String? {
        // Plain http to the loopback address first; the https name (trusted in the simulator) only when that one gave
        // no answer at all, so an action that answered with an error is never run twice.
        var last = "not tried"
        for origin in [Fixture.controlOrigin, Fixture.siteOrigin] {
            var components = URLComponents(string: origin + "/control/" + action)
            components?.queryItems = query.sorted { $0.key < $1.key }.map { URLQueryItem(name: $0.key, value: $0.value) }
            guard let url = components?.url else { continue }
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.timeoutInterval = 150
            let done = DispatchSemaphore(value: 0)
            var status = 0
            var text = ""
            URLSession.shared.dataTask(with: request) { data, response, error in
                status = (response as? HTTPURLResponse)?.statusCode ?? 0
                text = data.flatMap { String(data: $0, encoding: .utf8) } ?? error.map { "\($0)" } ?? ""
                done.signal()
            }.resume()
            if done.wait(timeout: .now() + 160) == .timedOut {
                last = "\(origin): no answer"
                continue
            }
            if status == 200 { return nil }
            last = "\(origin): \(status) \(text.suffix(300))"
            if status != 0 { return last }
        }
        return last
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
