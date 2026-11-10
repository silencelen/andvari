package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.client.session.InMemorySecrets
import io.silencelen.andvari.core.client.session.OriginStore
import io.silencelen.andvari.core.client.session.PrefsSessionPersistence
import io.silencelen.andvari.core.client.session.SessionPersistence
import io.silencelen.andvari.core.ios.UserDefaultsPrefs
import io.silencelen.andvari.core.model.AccountKeys
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
        return FixtureKeys(store)
    }

    /**
     * The real persistence, except for the cached account keys: the shared fixture enrolls at a KDF cost below the
     * floor (to keep the tests fast), and the real store rightly reads such keys as a cache miss.
     */
    private class FixtureKeys(private val real: SessionPersistence) : SessionPersistence by real {
        private val keys = HashMap<String, AccountKeys>()

        override fun clear() {
            keys.clear() // the real store drops the session's cached keys with it
            real.clear()
        }

        override fun origin(key: String): OriginStore {
            val originKey = key
            val inner = real.origin(key)
            return object : OriginStore by inner {
                override fun loadAccountKeys(userId: String): AccountKeys? = keys["$originKey/$userId"]

                override fun saveAccountKeys(userId: String, keys: AccountKeys) {
                    this@FixtureKeys.keys["$originKey/$userId"] = keys
                }

                override fun clearAccountKeys(userId: String) {
                    this@FixtureKeys.keys.remove("$originKey/$userId")
                    inner.clearAccountKeys(userId)
                }
            }
        }
    }

    /** Named here as well, so it runs on this persistence whether or not the runner picks up inherited tests. */
    @Test
    fun aSignedInIosSessionHasAFreshPolicyFetchedAt() = policyIsFreshOnceInTheVault()

    private companion object {
        const val SUITE = "io.silencelen.andvari.test.controller"
    }
}
