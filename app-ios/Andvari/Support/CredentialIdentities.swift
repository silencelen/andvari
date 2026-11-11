import AndvariCore
import AuthenticationServices

/// The system's AutoFill suggestions (`ASCredentialIdentityStore`): which sites and usernames andvari can fill, so
/// iOS can offer them above the keyboard. It never holds a password, and nothing is written while the person has
/// andvari turned off under Settings > Passwords > Password Options.
enum CredentialIdentities {
    static func replace(_ identities: [CredentialIdentity]) {
        let store = ASCredentialIdentityStore.shared
        store.getState { state in
            guard state.isEnabled else { return }
            var all: [any ASCredentialIdentity] = identities.map {
                ASPasswordCredentialIdentity(serviceIdentifier: service($0), user: $0.username, recordIdentifier: $0.itemId)
            }
            if #available(iOS 18.0, *) {
                all += identities.filter(\.hasTotp).map {
                    ASOneTimeCodeCredentialIdentity(serviceIdentifier: service($0), label: $0.username, recordIdentifier: $0.itemId)
                }
            }
            store.replaceCredentialIdentities(all) { _, _ in }
        }
    }

    static func clear() {
        ASCredentialIdentityStore.shared.removeAllCredentialIdentities { _, _ in }
    }

    private static func service(_ identity: CredentialIdentity) -> ASCredentialServiceIdentifier {
        ASCredentialServiceIdentifier(identifier: identity.host, type: .domain)
    }
}
