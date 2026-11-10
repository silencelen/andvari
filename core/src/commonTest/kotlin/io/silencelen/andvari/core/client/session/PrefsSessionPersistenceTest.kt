package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.OriginCanon
import io.silencelen.andvari.core.client.Tokens
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.AccountKeys
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The preferences-and-secrets store (iOS: NSUserDefaults and the Keychain), against in-memory stores. */
class PrefsSessionPersistenceTest {
    private val home = "https://home.example"
    private val homeKey = OriginCanon.originKey(home)

    /** Records which names reach which store, so a test can see where the tokens live. */
    private class SpyPrefs : KeyValuePrefs {
        val inner = InMemoryPrefs()
        val written = mutableSetOf<String>()
        override fun getString(key: String) = inner.getString(key)
        override fun putString(key: String, value: String?) {
            if (value != null) written += value
            inner.putString(key, value)
        }
    }

    private class SpySecrets(var accept: Boolean = true) : SecretStore {
        val inner = InMemorySecrets()
        override fun read(name: String) = inner.read(name)
        override fun write(name: String, value: String?): Boolean = if (!accept) false else inner.write(name, value)
    }

    private val prefs = SpyPrefs()
    private val secrets = SpySecrets()
    private val store = PrefsSessionPersistence(prefs, secrets).also { it.moveOrigin(home) }

    private fun session(user: String = "u1", refresh: String = "r1") = StoredSession(home, user, "u@example.com", "a1", refresh)

    @Test
    fun theFirstLaunchHasNoServerAndNoSession() {
        val fresh = PrefsSessionPersistence(InMemoryPrefs(), InMemorySecrets())
        assertNull(fresh.baseUrl, "no default server")
        assertNull(fresh.load())
        assertTrue(fresh.origin(homeKey).cacheAllowed, "the offline cache is allowed until a policy forbids it")
    }

    @Test
    fun theTokensLiveOnlyInTheSecretStore() {
        store.save(session())
        assertEquals(session(), store.load())
        assertFalse(prefs.written.any { "a1" in it || "r1" in it }, "no token in the preferences")
        assertTrue(secrets.read("session.tokens")!!.contains("r1"))
    }

    @Test
    fun aSessionWhoseTokensAreMissingIsNoSession() {
        store.save(session())
        secrets.write("session.tokens", null)
        assertNull(store.load())
    }

    @Test
    fun aRefusedSecretWriteIsNotSwallowed() {
        secrets.accept = false
        assertFailsWith<IllegalStateException> { store.save(session()) }
        assertNull(store.load(), "nothing half-saved")
    }

    @Test
    fun aRotationIsWrittenOnlyIntoTheSessionItWasFor() {
        store.save(session())
        assertFalse(store.replaceTokensIf(home, "u1", "r0", Tokens("x", "y")), "a stale refresh token writes nothing")
        assertFalse(store.replaceTokensIf(home, "u2", "r1", Tokens("x", "y")), "nor another user's")
        assertFalse(store.replaceTokensIf("https://other.example", "u1", "r1", Tokens("x", "y")), "nor another origin's")
        assertTrue(store.replaceTokensIf("https://HOME.example:443", "u1", "r1", Tokens("a2", "r2")))
        assertEquals(Tokens("a2", "r2"), store.load()?.tokens())
        assertTrue(store.replaceTokensIf(home, "u1", "r2", null), "a refused refresh ends the session")
        assertNull(store.load())
    }

    @Test
    fun clearEndsTheSessionWithItsCachedKeysAndFlag() {
        store.save(session())
        store.mustChangePassword = true
        val keys = AccountKeys("salt", KdfParams(), "w", "s", "p", "fp")
        store.origin(homeKey).saveAccountKeys("u1", keys)
        assertEquals(keys, store.origin(homeKey).loadAccountKeys("u1"))
        store.clear()
        assertNull(store.load())
        assertFalse(store.mustChangePassword)
        assertNull(store.origin(homeKey).loadAccountKeys("u1"))
        assertNull(secrets.read("session.tokens"))
    }

    @Test
    fun clearSessionTokensKeepsThePerOriginMaterial() {
        store.save(session())
        val keys = AccountKeys("salt", KdfParams(), "w", "s", "p", "fp")
        store.origin(homeKey).saveAccountKeys("u1", keys)
        store.origin(homeKey).setPasswordStamp("u1", PasswordStamp(10, 5, 5, "7"))
        store.clearSessionTokens()
        assertNull(store.load())
        assertEquals(keys, store.origin(homeKey).loadAccountKeys("u1"), "a server switch is not a wipe (§4.2)")
        assertEquals(PasswordStamp(10, 5, 5, "7"), store.origin(homeKey).passwordStamp("u1"))
    }

    @Test
    fun theOriginsAreSeparate() {
        val other = OriginCanon.originKey("https://other.example")
        store.origin(homeKey).cacheAllowed = false
        store.origin(homeKey).autoLockSeconds = 120
        store.origin(homeKey).policyFetchedAt = 99
        store.origin(homeKey).bumpServerTimeFloor(500)
        store.origin(homeKey).bumpServerTimeFloor(400)
        assertFalse(store.origin(homeKey).cacheAllowed)
        assertEquals(120, store.origin(homeKey).autoLockSeconds)
        assertEquals(99, store.origin(homeKey).policyFetchedAt)
        assertEquals(500, store.origin(homeKey).serverTimeFloorMs, "the floor never decreases")
        assertTrue(store.origin(other).cacheAllowed)
        assertEquals(0, store.origin(other).serverTimeFloorMs)
    }

    @Test
    fun keysWithSubFloorParamsAreACacheMiss() {
        store.origin(homeKey).saveAccountKeys("u1", AccountKeys("salt", KdfParams(ops = 1, memBytes = 8192), "w", "s", "p", "fp"))
        assertNull(store.origin(homeKey).loadAccountKeys("u1"), "H1: a poisoned cache is refetched through the fence")
    }

    @Test
    fun theStampsThePendingMarkerAndTheClocksRoundTrip() {
        store.origin(homeKey).setPasswordStamp("u1", PasswordStamp(10, 5, 5, null))
        assertEquals(PasswordStamp(10, 5, 5, null), store.origin(homeKey).passwordStamp("u1"))
        store.origin(homeKey).clearPasswordStamp("u1")
        assertNull(store.origin(homeKey).passwordStamp("u1"))
        val marker = PendingServer(origin = home, previousOrigin = "https://other.example", ts = 1)
        store.pendingServer = marker
        assertEquals(marker, store.pendingServer)
        store.pendingServer = null
        assertNull(store.pendingServer)
        assertEquals(50, store.bumpHighWater(50))
        assertEquals(50, store.bumpHighWater(40), "the high-water clock never runs back")
        store.lastSyncAt = 7
        assertEquals(7, store.lastSyncAt)
    }

    @Test
    fun theIdentityPinsArePerOrigin() {
        val pins = store.origin(homeKey).identityPins()
        assertNull(pins.pinFor("u@example.com", "u1"))
        assertNull(store.origin(OriginCanon.originKey("https://other.example")).identityPins().pinFor("u@example.com", "u1"))
    }
}
