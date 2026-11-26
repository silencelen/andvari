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
class WsTicketStore(private val ttlMs: Long = 30_000, private val now: () -> Long = ::now) {
    private class Entry(val userId: String, val expiresAt: Long)

    private val tickets = ConcurrentHashMap<String, Entry>()

    fun mint(userId: String): String {
        val t = now()
        tickets.entries.removeIf { it.value.expiresAt <= t } // opportunistic sweep of abandoned tickets
        val token = ServerCrypto.newToken()
        tickets[ServerCrypto.hashToken(token)] = Entry(userId, t + ttlMs)
        return token
    }

    /** Atomic single-use redeem: ConcurrentHashMap.remove guarantees at most one winner. */
    fun redeem(token: String): String? {
        val e = tickets.remove(ServerCrypto.hashToken(token)) ?: return null
        // Expiry is exclusive (spec 03 §0.1): valid while now < expiresAt.
        return if (now() < e.expiresAt) e.userId else null
    }
}

/**
 * Events-channel variant of [WsTicketStore] that additionally binds the ticket to the minting
 * session's deviceId (M8) — so the WS registration knows which device the socket belongs to and a
 * single-device revoke can target it. A DISTINCT type (not a signature change on [WsTicketStore])
 * because the two-phase self-recovery flow reuses [WsTicketStore] and has no device concept.
 */
class EventsTicketStore(private val ttlMs: Long = 30_000, private val now: () -> Long = ::now) {
    /** [sessionId]: the minting session, so a revocation that ends only some sessions reaches only their sockets. */
    data class Redeemed(val userId: String, val deviceId: String, val sessionId: String)
    private class Entry(val userId: String, val deviceId: String, val sessionId: String, val expiresAt: Long)

    private val tickets = ConcurrentHashMap<String, Entry>()

    fun mint(userId: String, deviceId: String, sessionId: String): String {
        val t = now()
        tickets.entries.removeIf { it.value.expiresAt <= t }
        val token = ServerCrypto.newToken()
        tickets[ServerCrypto.hashToken(token)] = Entry(userId, deviceId, sessionId, t + ttlMs)
        return token
    }

    fun redeem(token: String): Redeemed? {
        val e = tickets.remove(ServerCrypto.hashToken(token)) ?: return null
        // Expiry is exclusive (spec 03 §0.1): valid while now < expiresAt.
        return if (now() < e.expiresAt) Redeemed(e.userId, e.deviceId, e.sessionId) else null
    }
}
