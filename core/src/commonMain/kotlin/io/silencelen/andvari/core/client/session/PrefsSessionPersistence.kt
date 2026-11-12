package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.OriginCanon
import io.silencelen.andvari.core.client.SelfIdentityPin
import io.silencelen.andvari.core.client.Tokens
import io.silencelen.andvari.core.model.AccountKeys
import kotlinx.atomicfu.locks.SynchronizedObject
import kotlinx.atomicfu.locks.synchronized
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** Non-secret preferences: NSUserDefaults on iOS. Every value is a string. */
interface KeyValuePrefs {
    fun getString(key: String): String?

    /** Store [value] under [key]; null removes the key. */
    fun putString(key: String, value: String?)
}

/** Secret values: the iOS Keychain. Only the session's tokens go here. */
interface SecretStore {
    fun read(name: String): String?

    /** Store [value] under [name]; null deletes it. Returns whether the store took the change. */
    fun write(name: String, value: String?): Boolean
}

/**
 * Preferences one process owns, with a copy published for other processes that is never read back (iOS: the app's
 * private defaults, published to the App Group for its extensions). Every read comes from [own], so nothing another
 * process writes to [shared] changes what this one acts on: not the server it connects to, not who it is signed in as,
 * not its identity pins. Every write goes to [own] and, for each key [publish] admits, to [shared] as well.
 */
class PublishingPrefs(
    private val own: KeyValuePrefs,
    private val shared: KeyValuePrefs,
    private val publish: (String) -> Boolean = { it !in PREFS_PROCESS_LOCAL_KEYS },
) : KeyValuePrefs {
    override fun getString(key: String): String? = own.getString(key)

    override fun putString(key: String, value: String?) {
        own.putString(key, value)
        if (publish(key)) shared.putString(key, value)
    }
}

/**
 * Keys each process keeps for itself and never publishes: the high-water clock is advanced by every process that
 * checks freshness, so each keeps its own (a published one would let another process move this one's clock).
 */
val PREFS_PROCESS_LOCAL_KEYS: Set<String> = setOf("highWaterWallMs")

/** [KeyValuePrefs] in memory (tests, and a host that persists nothing). */
class InMemoryPrefs : KeyValuePrefs {
    private val lock = SynchronizedObject()
    private val map = HashMap<String, String>()

    override fun getString(key: String): String? = synchronized(lock) { map[key] }

    override fun putString(key: String, value: String?) {
        synchronized(lock) { if (value == null) map.remove(key) else map[key] = value }
    }
}

/** [SecretStore] in memory (tests, and a host that persists nothing). */
class InMemorySecrets : SecretStore {
    private val lock = SynchronizedObject()
    private val map = HashMap<String, String>()

    override fun read(name: String): String? = synchronized(lock) { map[name] }

    override fun write(name: String, value: String?): Boolean {
        synchronized(lock) { if (value == null) map.remove(name) else map[name] = value }
        return true
    }
}

/**
 * [SessionPersistence] over a preferences store and a secret store: the shape of a client with no
 * SharedPreferences of its own (iOS: NSUserDefaults and the Keychain). The session's tokens are the only
 * secrets, and they live in [secrets]; everything else is public material or ciphertext (the account keys
 * are wrapped blobs and KDF parameters), as on Android.
 *
 * Global: the origin the client dials, the pending-switch marker, the one stored session, the F58 flag,
 * the high-water clock and the last sync time. Per origin (`ns.<originKey>.`): the policy mirrors, the
 * offline copy of the account keys, the full-password stamps and the identity pins.
 *
 * Every read and write of the stored session holds one lock, so a token callback's compare-and-write
 * ([replaceTokensIf]) is one step against [save], [clear] and [clearSessionTokens].
 */
class PrefsSessionPersistence(
    private val prefs: KeyValuePrefs,
    private val secrets: SecretStore,
) : SessionPersistence {
    private val lock = SynchronizedObject()

    @Serializable
    private class SessionMeta(val baseUrl: String, val userId: String, val email: String)

    @Serializable
    private class TokenPair(val accessToken: String, val refreshToken: String)

    @Serializable
    private class Stamp(val wallMs: Long, val monotonicMs: Long, val bootRefMs: Long, val bootId: String? = null)

    override val baseUrl: String? get() = prefs.getString(BASE_URL)

    override fun moveOrigin(origin: String) = prefs.putString(BASE_URL, origin)

    override var pendingServer: PendingServer?
        get() = prefs.getString(PENDING)?.let { runCatching { json.decodeFromString(PendingServer.serializer(), it) }.getOrNull() }
        set(v) = prefs.putString(PENDING, v?.let { json.encodeToString(PendingServer.serializer(), it) })

    override fun load(): StoredSession? = synchronized(lock) { loadLocked() }

    override fun save(s: StoredSession) {
        synchronized(lock) {
            // The tokens first: a crash between the two writes leaves tokens no session names (the next save or
            // clear replaces them), never a session without the tokens it needs.
            check(secrets.write(TOKENS, json.encodeToString(TokenPair.serializer(), TokenPair(s.accessToken, s.refreshToken)))) {
                "the secret store refused the session's tokens"
            }
            prefs.putString(SESSION, json.encodeToString(SessionMeta.serializer(), SessionMeta(s.baseUrl, s.userId, s.email)))
        }
    }

    override fun updateTokens(t: Tokens?) {
        synchronized(lock) { updateTokensLocked(t) }
    }

    override fun replaceTokensIf(origin: String, userId: String, expectedRefreshToken: String, t: Tokens?): Boolean = synchronized(lock) {
        val s = loadLocked()
        if (s == null || s.userId != userId || !sessionBelongsTo(s.baseUrl, origin) || s.refreshToken != expectedRefreshToken) {
            false
        } else {
            updateTokensLocked(t) // null ends the session, as a refused refresh always has
            true
        }
    }

    override fun clear() {
        synchronized(lock) { clearLocked() }
    }

    override fun clearSessionTokens() {
        synchronized(lock) { dropSessionLocked() }
    }

    override var mustChangePassword: Boolean
        get() = prefs.getString(MUST_CHANGE) == "true"
        set(v) = prefs.putString(MUST_CHANGE, if (v) "true" else null)

    override var highWaterWallMs: Long
        get() = prefs.getString(HIGH_WATER)?.toLongOrNull() ?: 0L
        set(v) = prefs.putString(HIGH_WATER, v.toString())

    override var lastSyncAt: Long
        get() = prefs.getString(LAST_SYNC)?.toLongOrNull() ?: 0L
        set(v) = prefs.putString(LAST_SYNC, v.toString())

    override fun origin(key: String): OriginStore = PrefsOriginStore(key)

    // ---- under [lock] ----

    /** The session's non-secret half only: the secret store is not read, so a process without it still knows who is signed in. */
    override fun storedIdentity(): StoredIdentity? = synchronized(lock) {
        prefs.getString(SESSION)?.let { runCatching { json.decodeFromString(SessionMeta.serializer(), it) }.getOrNull() }?.let { StoredIdentity(it.baseUrl, it.userId, it.email) }
    }

    private fun loadLocked(): StoredSession? {
        val meta = prefs.getString(SESSION)?.let { runCatching { json.decodeFromString(SessionMeta.serializer(), it) }.getOrNull() } ?: return null
        val pair = secrets.read(TOKENS)?.let { runCatching { json.decodeFromString(TokenPair.serializer(), it) }.getOrNull() } ?: return null
        return StoredSession(meta.baseUrl, meta.userId, meta.email, pair.accessToken, pair.refreshToken)
    }

    private fun updateTokensLocked(t: Tokens?) {
        if (t == null) {
            clearLocked()
            return
        }
        if (prefs.getString(SESSION) == null) return // no session to rotate
        // The server has spent the old refresh token: a lost write here would replay it at the next refresh and
        // revoke the device, so a refused write is not swallowed.
        check(secrets.write(TOKENS, json.encodeToString(TokenPair.serializer(), TokenPair(t.accessToken, t.refreshToken)))) {
            "the secret store refused the rotated tokens"
        }
    }

    private fun dropSessionLocked() {
        prefs.putString(SESSION, null)
        secrets.write(TOKENS, null)
        prefs.putString(MUST_CHANGE, null)
    }

    /** The session and the material that dies with it: its account keys at the origin the client dials. */
    private fun clearLocked() {
        val userId = prefs.getString(SESSION)?.let { runCatching { json.decodeFromString(SessionMeta.serializer(), it) }.getOrNull() }?.userId
        dropSessionLocked()
        val originKey = baseUrl?.let(OriginCanon::originKey)
        if (originKey != null && userId != null) origin(originKey).clearAccountKeys(userId)
    }

    /** One origin's view of the `ns.<originKey>.` keys (design 2026-07-15 §4.2). */
    private inner class PrefsOriginStore(private val key: String) : OriginStore {
        private fun k(name: String) = "ns.$key.$name"

        /** A server-supplied user id, made safe for a key. */
        private fun user(userId: String) = OriginCanon.pathSafe(userId)

        override var cacheAllowed: Boolean
            get() = prefs.getString(k("cacheAllowed")) != "false" // allowed until a policy forbids it
            set(v) = prefs.putString(k("cacheAllowed"), v.toString())

        override var autoLockSeconds: Int
            get() = prefs.getString(k("autoLockSeconds"))?.toIntOrNull() ?: 0
            set(v) = prefs.putString(k("autoLockSeconds"), v.toString())

        override var policyFetchedAt: Long
            get() = prefs.getString(k("policyFetchedAt"))?.toLongOrNull() ?: 0L
            set(v) = prefs.putString(k("policyFetchedAt"), v.toString())

        override var serverTimeFloorMs: Long
            get() = prefs.getString(k("serverTimeFloor"))?.toLongOrNull() ?: 0L
            set(v) = prefs.putString(k("serverTimeFloor"), v.toString())

        override fun loadAccountKeys(userId: String): AccountKeys? =
            prefs.getString(k("accountKeys.${user(userId)}"))?.let { runCatching { json.decodeFromString(AccountKeys.serializer(), it) }.getOrNull() }
                // H1 cache belt (spec 05 T1): keys poisoned with sub-floor or absurd KDF params are a cache miss.
                ?.takeIf { runCatching { io.silencelen.andvari.core.client.KdfUpgrade.requireServerKdfParams(it.kdfParams) }.isSuccess }

        override fun saveAccountKeys(userId: String, keys: AccountKeys) =
            prefs.putString(k("accountKeys.${user(userId)}"), json.encodeToString(AccountKeys.serializer(), keys))

        override fun clearAccountKeys(userId: String) = prefs.putString(k("accountKeys.${user(userId)}"), null)

        override fun passwordStamp(userId: String): PasswordStamp? =
            prefs.getString(k("stamp.${user(userId)}"))
                ?.let { runCatching { json.decodeFromString(Stamp.serializer(), it) }.getOrNull() }
                ?.takeIf { it.wallMs > 0L }
                ?.let { PasswordStamp(it.wallMs, it.monotonicMs, it.bootRefMs, it.bootId) }

        override fun setPasswordStamp(userId: String, stamp: PasswordStamp) = prefs.putString(
            k("stamp.${user(userId)}"),
            json.encodeToString(Stamp.serializer(), Stamp(stamp.wallMs, stamp.monotonicMs, stamp.bootRefMs, stamp.bootId)),
        )

        override fun clearPasswordStamp(userId: String) = prefs.putString(k("stamp.${user(userId)}"), null)

        override fun identityPins(): SelfIdentityPin.KeyValueStore =
            SelfIdentityPin.KeyValueStore(get = { prefs.getString(k(it)) }, put = { name, value -> prefs.putString(k(name), value) })
    }

    private companion object {
        val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
        const val BASE_URL = "baseUrl"
        const val PENDING = "pendingServer"
        const val SESSION = "session"
        const val TOKENS = "session.tokens"
        const val MUST_CHANGE = "mustChangePassword"
        const val HIGH_WATER = "highWaterWallMs" // in PREFS_PROCESS_LOCAL_KEYS
        const val LAST_SYNC = "lastSyncAt"
    }
}
