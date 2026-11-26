package io.silencelen.andvari.server

import io.silencelen.andvari.core.model.wire.TokenPair
import java.util.concurrent.ConcurrentHashMap

/**
 * The sixty-second grace for a refresh that is repeated (spec 03 §2; decided for 0.30.0 on 2026-11-15, and for this line
 * on 2026-11-17). A refresh token is single-use, and a replaced one presented again is taken for the reuse of a stolen
 * token: every session of the device ends. A client whose answer was lost (a dropped connection, a request that timed out
 * after the server answered) still holds only the replaced token, so its next try used to sign the person out, with a
 * reuse on record that was no theft.
 *
 * The rule, narrow on purpose, as the release line keeps it:
 *  - only the very token that refresh replaced (keyed by its hash), within [windowMs] of the replacement, inclusive;
 *  - only on the token's own device row, and while the pair that refresh made is UNTOUCHED: its access token has
 *    authenticated no request (a client that used it got the answer, so a later repeat is no lost answer) and its
 *    session is neither ended nor itself refreshed (the refresh route reads the session's row to check that);
 *  - the repeat is answered with the same pair the first answer carried, not a fresh one. That is the released line's
 *    trade, said as it is: inside the minute, someone who holds the replaced token gets the same live pair as the device
 *    and can use it beside it until one of the two uses or refreshes it; the `refresh_grace` audit row written at each
 *    answer is what shows it. Only a later presentation, once the pair was used or refreshed, is taken for the reuse;
 *  - each answer draws the caller address's refresh allowance (the refresh route), so the grace is no free door;
 *  - anything else is the reuse rule, unchanged.
 *
 * In memory only: a restart forgets every entry, and a repeat after it is a reuse as before. The pair is held in plain
 * text for the window and no longer: an entry goes when its access token is first used, when its window has passed (at
 * the next record or lookup, and at the latest at the server's sweep, [sweepExpired], which runs every second), or beyond
 * [cap] entries (oldest first).
 */
class RefreshGrace(private val clock: Clock, private val windowMs: Long = WINDOW_MS, private val cap: Int = 10_000) {
    /** What a repeat of one refresh is answered with: the pair, the session it made, its device row, and when. */
    class Entry(val pair: TokenPair, val successorSessionId: String, val deviceId: String, val mintedAt: Long, val accessHash: String)

    private val byRefresh = ConcurrentHashMap<String, Entry>()
    private val byAccess = ConcurrentHashMap<String, String>() // the pair's access hash -> the replaced refresh hash

    /** A refresh that replaced [spentRefreshHash] answered [pair], session [successorSessionId] on [deviceId]. */
    fun record(spentRefreshHash: String, pair: TokenPair, successorSessionId: String, deviceId: String) {
        val t = clock.now()
        sweep(t)
        val accessHash = ServerCrypto.hashToken(pair.accessToken)
        byRefresh[spentRefreshHash] = Entry(pair, successorSessionId, deviceId, t, accessHash)
        byAccess[accessHash] = spentRefreshHash
        while (byRefresh.size > cap) {
            val oldest = byRefresh.entries.minByOrNull { it.value.mintedAt } ?: break
            drop(oldest.key)
        }
    }

    /** The entry a repeat of [spentRefreshHash] may be answered from, or null (window over, pair used, or none). */
    fun lookup(spentRefreshHash: String): Entry? {
        val e = byRefresh[spentRefreshHash] ?: return null
        if (clock.now() - e.mintedAt > windowMs) {
            drop(spentRefreshHash)
            return null
        }
        return e
    }

    /** An access token authenticated a request: when a refresh in the window made it, the answer was received. */
    fun accessUsed(accessHash: String) {
        if (byAccess.isEmpty()) return
        val spent = byAccess[accessHash] ?: return
        drop(spent)
    }

    /**
     * Drop every entry whose window has passed (the server calls this every second): an unused pair is not kept in plain
     * text after the minute it can be asked for, even on a server where nothing else is refreshed or looked up. Before,
     * such an entry stayed until the next refresh anywhere on the server, an hour or more on a quiet one.
     */
    fun sweepExpired() {
        if (byRefresh.isEmpty()) return
        sweep(clock.now())
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
