package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.OriginCanon
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * The account an extension may seal a captured login to: published by the unlocked app, removed with the session.
 * Public material only. [identityPub] is the account's X25519 identity key, the one grants are sealed to.
 */
@Serializable
data class SaveKeyPublication(val v: Int = SaveQueue.VERSION, val origin: String, val userId: String, val identityPub: String)

/** One queued save as it is kept: who it is for, and the login sealed to that account's key. No plaintext. */
@Serializable
data class QueuedSave(val v: Int = SaveQueue.VERSION, val origin: String, val userId: String, val sealed: String)

/** What is inside the seal. It names its account again, so an entry moved to another account's queue does not open as theirs. */
@Serializable
data class CapturedLogin(
    val magic: String = SaveQueue.MAGIC,
    val origin: String,
    val userId: String,
    /** The page or app the login is for: an origin, a URL or a domain. */
    val site: String,
    val username: String,
    val password: String,
    val capturedAtMs: Long,
    /** "safari" or "autofill". */
    val source: String,
)

/**
 * Where the queue is kept: the published key and a bounded set of small entries (iOS: files in the App Group
 * container, which the Safari extension's native handler writes in the same layout). Never throws.
 */
interface SaveQueueStore {
    fun publication(): ByteArray?

    /** Publish the key, or remove it with null. */
    fun publish(bytes: ByteArray?)

    /** The entries, by id. */
    fun entries(): Map<String, ByteArray>

    /** Add or replace entry [id] (letters, digits and dashes). Returns whether it was written. */
    fun put(id: String, bytes: ByteArray): Boolean

    fun remove(id: String)

    /** Remove every entry and the key. */
    fun clear()

    /** A host with no extension that saves. */
    object None : SaveQueueStore {
        override fun publication(): ByteArray? = null
        override fun publish(bytes: ByteArray?) {}
        override fun entries(): Map<String, ByteArray> = emptyMap()
        override fun put(id: String, bytes: ByteArray) = false
        override fun remove(id: String) {}
        override fun clear() {}
    }
}

/** [SaveQueueStore] in memory (tests). */
class InMemorySaveQueue : SaveQueueStore {
    var key: ByteArray? = null
    val map = LinkedHashMap<String, ByteArray>()

    override fun publication(): ByteArray? = key

    override fun publish(bytes: ByteArray?) {
        key = bytes
    }

    override fun entries(): Map<String, ByteArray> = LinkedHashMap(map)

    override fun put(id: String, bytes: ByteArray): Boolean {
        map[id] = bytes
        return true
    }

    override fun remove(id: String) {
        map.remove(id)
    }

    override fun clear() {
        key = null
        map.clear()
    }
}

/** How queuing a captured login ended. */
enum class SaveQueued {
    QUEUED,

    /** The app has published no key: nobody is signed in, or the server's policy forbids keeping data here. */
    NO_ACCOUNT,

    /** The queue is full, or a field is too long, or there is no password. Nothing was written. */
    REFUSED,
}

/**
 * The saves an extension captured for the app to import (design 2026-11-09, "Saving"). The extensions never contact
 * the server and hold no vault key, so a new login is sealed (libsodium sealed box) to the account's public key and
 * queued; only the unlocked app can open it, and it writes nothing until the person confirms each one. Anything that
 * can write to the App Group can queue an entry, so an entry is a proposal, never a write.
 */
object SaveQueue {
    const val VERSION = 1
    const val MAGIC = "andvari-queued-save-v1"
    const val MAX_ENTRIES = 50
    const val MAX_ENTRY_BYTES = 8 * 1024
    const val MAX_FIELD_CHARS = 1024
    const val MAX_SITE_CHARS = 2048

    /** A capture nobody confirmed within this long is dropped: a stale password should not be offered as current. */
    const val MAX_AGE_MS = 30L * 24 * 60 * 60 * 1000

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val ID = Regex("[A-Za-z0-9-]{1,64}")

    fun validId(id: String): Boolean = ID.matches(id)

    fun publication(origin: String, account: Account): ByteArray =
        json.encodeToString(SaveKeyPublication.serializer(), SaveKeyPublication(origin = OriginCanon.canonicalOrigin(origin), userId = account.userId, identityPub = Bytes.toB64(account.identityPub)))
            .encodeToByteArray()

    fun decodePublication(bytes: ByteArray?): SaveKeyPublication? =
        bytes?.let { runCatching { json.decodeFromString(SaveKeyPublication.serializer(), it.decodeToString()) }.getOrNull() }?.takeIf { it.v == VERSION }

    /** Seal a captured login to the published account and queue it under [id]. */
    fun enqueue(store: SaveQueueStore, crypto: CryptoProvider, id: String, site: String, username: String, password: String, nowMs: Long, source: String): SaveQueued {
        val key = decodePublication(store.publication()) ?: return SaveQueued.NO_ACCOUNT
        if (!validId(id) || password.isEmpty() || password.length > MAX_FIELD_CHARS || username.length > MAX_FIELD_CHARS || site.isBlank() || site.length > MAX_SITE_CHARS) {
            return SaveQueued.REFUSED
        }
        val existing = store.entries()
        if (id !in existing && existing.size >= MAX_ENTRIES) return SaveQueued.REFUSED
        val bytes = runCatching {
            val plain = json.encodeToString(CapturedLogin.serializer(), CapturedLogin(origin = key.origin, userId = key.userId, site = site, username = username, password = password, capturedAtMs = nowMs, source = source))
            val sealed = crypto.sealTo(Bytes.fromB64(key.identityPub), plain.encodeToByteArray())
            json.encodeToString(QueuedSave.serializer(), QueuedSave(origin = key.origin, userId = key.userId, sealed = Bytes.toB64(sealed))).encodeToByteArray()
        }.getOrNull() ?: return SaveQueued.REFUSED
        if (bytes.size > MAX_ENTRY_BYTES) return SaveQueued.REFUSED
        return if (store.put(id, bytes)) SaveQueued.QUEUED else SaveQueued.REFUSED
    }

    /**
     * Open one entry as [account] at [origin]; null for anything that is not a save sealed to this account here: an
     * oversized or malformed entry, another account's, a seal that does not open, an inside that names another
     * account than its outside, or a capture older than [MAX_AGE_MS].
     */
    fun open(account: Account, origin: String, bytes: ByteArray, nowMs: Long): CapturedLogin? = runCatching {
        if (bytes.size > MAX_ENTRY_BYTES) return null
        val entry = json.decodeFromString(QueuedSave.serializer(), bytes.decodeToString())
        val here = OriginCanon.canonicalOrigin(origin)
        if (entry.v != VERSION || entry.userId != account.userId || entry.origin != here) return null
        val plain = account.openQueuedSave(Bytes.fromB64(entry.sealed))
        val login = try {
            json.decodeFromString(CapturedLogin.serializer(), plain.decodeToString())
        } finally {
            plain.fill(0)
        }
        login.takeIf {
            it.magic == MAGIC && it.userId == account.userId && it.origin == here && it.password.isNotEmpty() &&
                nowMs - it.capturedAtMs < MAX_AGE_MS &&
                it.password.length <= MAX_FIELD_CHARS && it.username.length <= MAX_FIELD_CHARS && it.site.isNotBlank() && it.site.length <= MAX_SITE_CHARS
        }
    }.getOrNull()
}
