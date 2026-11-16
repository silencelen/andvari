package io.silencelen.andvari.server

import io.silencelen.andvari.core.model.TokenPair
import java.util.concurrent.ConcurrentHashMap

/**
 * The refresh grace (spec 03 §2): for [windowMs] after a refresh rotated a pair, a REPEAT of that same refresh is
 * answered with the identical reply instead of being taken for token theft.
 *
 * Why: a refresh token is single-use, and presenting a spent one revokes the whole device (the theft signal). A client
 * whose reply was lost (a dropped connection, a request timed out after the server answered, a cancelled call, a second
 * tab or process that refreshed at the same moment) still holds only the spent token, so its next try revoked the
 * device, and the released Android app then wipes its local copy at once, unsynced offline edits included. Within the
 * window the repeat now gets the same pair the first answer carried.
 *
 * The rule, narrow on purpose:
 *  - only the same refresh token (keyed by its hash), only within [windowMs] of the rotation;
 *  - only while the pair it minted is UNTOUCHED: its access token has authenticated no request (a client that used it
 *    got the reply, so a later repeat is not a lost reply) and its successor session is neither revoked nor itself
 *    refreshed (the caller re-reads the session row to check that);
 *  - anything else is the old answer: reuse, the device revoked.
 *
 * In memory only, like the WebSocket tickets: nothing is persisted, so a restart forgets every entry and a repeat after
 * it is reuse as before. The pair is held in plain text for at most [windowMs] (it is what the server just sent); an
 * entry is dropped at first use of its access token, at expiry, or beyond [cap] (oldest first).
 */
class RefreshGrace(
    private val windowMs: Long = WINDOW_MS,
    private val cap: Int = 10_000,
    private val clock: () -> Long = ::now,
) {
    /** What a repeat of one refresh is answered with, and the session that answer minted. */
    class Entry(val pair: TokenPair, val successorSessionId: String, val deviceId: String, val mintedAt: Long, val accessHash: String)

    private val byRefresh = ConcurrentHashMap<String, Entry>()
    private val byAccess = ConcurrentHashMap<String, String>() // successor access hash -> spent refresh hash

    /** A refresh spending [spentRefreshHash] minted [pair] as session [successorSessionId]. */
    fun record(spentRefreshHash: String, pair: TokenPair, successorSessionId: String, deviceId: String) {
        val t = clock()
        sweep(t)
        val accessHash = ServerCrypto.hashToken(pair.accessToken)
        byRefresh[spentRefreshHash] = Entry(pair, successorSessionId, deviceId, t, accessHash)
        byAccess[accessHash] = spentRefreshHash
        while (byRefresh.size > cap) {
            val oldest = byRefresh.entries.minByOrNull { it.value.mintedAt } ?: break
            drop(oldest.key)
        }
    }

    /** The entry a repeat of [spentRefreshHash] may be answered from, or null (expired, used, or never recorded). */
    fun lookup(spentRefreshHash: String): Entry? {
        val e = byRefresh[spentRefreshHash] ?: return null
        if (clock() - e.mintedAt > windowMs) {
            drop(spentRefreshHash)
            return null
        }
        return e
    }

    /** An access token authenticated a request: if a grace entry minted it, the pair was received, so drop the entry. */
    fun accessUsed(accessHash: String) {
        if (byAccess.isEmpty()) return
        val spent = byAccess[accessHash] ?: return
        drop(spent)
    }

    internal val size: Int get() = byRefresh.size

    private fun drop(spentRefreshHash: String) {
        val e = byRefresh.remove(spentRefreshHash) ?: return
        byAccess.remove(e.accessHash, spentRefreshHash)
    }

    private fun sweep(t: Long) {
        byRefresh.entries.filter { t - it.value.mintedAt > windowMs }.forEach { drop(it.key) }
    }

    companion object {
        const val WINDOW_MS = 60_000L
    }
}
