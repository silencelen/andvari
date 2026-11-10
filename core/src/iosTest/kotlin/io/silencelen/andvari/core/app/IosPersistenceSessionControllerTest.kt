package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.client.session.InMemorySecrets
import io.silencelen.andvari.core.client.session.PrefsSessionPersistence
import io.silencelen.andvari.core.client.session.SessionPersistence
import io.silencelen.andvari.core.ios.UserDefaultsPrefs
import platform.Foundation.NSUserDefaults
import kotlin.test.Test

/**
 * The controller's tests over the persistence the iOS app uses: [PrefsSessionPersistence] on NSUserDefaults (a
 * throwaway suite per test). The Keychain needs an app bundle, so the tokens stay in memory here.
 */
class IosPersistenceSessionControllerTest : SessionControllerTest() {
    override fun newStore(origin: String?): SessionPersistence {
        NSUserDefaults(suiteName = SUITE).removePersistentDomainForName(SUITE)
        val store = PrefsSessionPersistence(UserDefaultsPrefs(SUITE), InMemorySecrets())
        origin?.let(store::moveOrigin)
        return store
    }

    /** Named here as well, so it runs on this persistence whether or not the runner picks up inherited tests. */
    @Test
    fun aSignedInIosSessionHasAFreshPolicyFetchedAt() = policyIsFreshOnceInTheVault()

    private companion object {
        const val SUITE = "io.silencelen.andvari.test.controller"
    }
}
