import AndvariCore
import AuthenticationServices

/// The system's AutoFill suggestions (`ASCredentialIdentityStore`): which sites and usernames andvari can fill, so
/// iOS can offer them above the keyboard. It never holds a password, and nothing is written while the person has
/// andvari turned off under Settings > Passwords > Password Options.
///
/// Every change goes through one serial queue and carries a generation: a replace that was asked for before a
/// clear (sign-out) and reaches the store after it is dropped, so a cleared store stays clear.
enum CredentialIdentities {
    private static let queue = DispatchQueue(label: "io.silencelen.andvari.credential-identities")
    private static var generation = 0

    static func replace(_ identities: [CredentialIdentity]) {
        let wanted: [(host: String, user: String, record: String, totp: Bool)] = identities.map { ($0.host, $0.username, $0.itemId, $0.hasTotp) }
        queue.async {
            generation += 1
            let mine = generation
            let store = ASCredentialIdentityStore.shared
            let done = DispatchSemaphore(value: 0)
            store.getState { state in
                // Still the latest request? `generation` is only written on this queue, which is waiting on us.
                guard state.isEnabled, mine == generation else {
                    done.signal()
                    return
                }
                var all: [any ASCredentialIdentity] = wanted.map {
                    ASPasswordCredentialIdentity(serviceIdentifier: service($0.host), user: $0.user, recordIdentifier: $0.record)
                }
                if #available(iOS 18.0, *) {
                    all += wanted.filter(\.totp).map {
                        ASOneTimeCodeCredentialIdentity(serviceIdentifier: service($0.host), label: $0.user, recordIdentifier: $0.record)
                    }
                }
                store.replaceCredentialIdentities(all) { _, _ in done.signal() }
            }
            done.wait()
        }
    }

    static func clear() {
        queue.async {
            generation += 1
            let done = DispatchSemaphore(value: 0)
            ASCredentialIdentityStore.shared.removeAllCredentialIdentities { _, _ in done.signal() }
            done.wait()
        }
    }

    private static func service(_ host: String) -> ASCredentialServiceIdentifier {
        ASCredentialServiceIdentifier(identifier: host, type: .domain)
    }
}
