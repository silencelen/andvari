package io.silencelen.andvari.server

import java.util.concurrent.ConcurrentHashMap

/**
 * Single-use, short-TTL WebSocket auth tickets (spec 03 §6). Browsers cannot set an
 * Authorization header on a WS upgrade, so the web client mints a ticket over the
 * authenticated REST channel and passes THAT in the query instead of its long-lived
 * access token (LOW-9: query strings end up verbatim in edge logs; a 30 s single-use
 * capability is worthless to a log replayer). In-memory only — never persisted, so the
 * spec 02 §5 table is unchanged; a restart drops pending tickets and clients re-mint.
 */
class WsTicketStore(private val ttlMs: Long = 30_000) {
    private class Entry(val userId: String, val expiresAt: Long)

    private val tickets = ConcurrentHashMap<String, Entry>()

    fun mint(userId: String): String {
        val t = now()
        tickets.entries.removeIf { it.value.expiresAt < t } // opportunistic sweep of abandoned tickets
        val token = ServerCrypto.newToken()
        tickets[ServerCrypto.hashToken(token)] = Entry(userId, t + ttlMs)
        return token
    }

    /** Atomic single-use redeem: ConcurrentHashMap.remove guarantees at most one winner. */
    fun redeem(token: String): String? {
        val e = tickets.remove(ServerCrypto.hashToken(token)) ?: return null
        return if (e.expiresAt >= now()) e.userId else null
    }
}
