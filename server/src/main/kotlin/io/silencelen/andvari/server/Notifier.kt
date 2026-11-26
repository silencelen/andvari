package io.silencelen.andvari.server

import io.ktor.websocket.CloseReason
import io.ktor.websocket.Frame
import io.ktor.websocket.WebSocketSession
import io.ktor.websocket.close
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * WebSocket "dirty bell" (spec 03 §6). Server → client frames only: {"type":"rev","rev":N} when
 * anything the user can see changed, {"type":"revoked"} when their session/device dies (the client
 * drops to the lock screen; the server ALSO closes the socket so a revoked device stops receiving
 * the bell — M8, the metadata-leak fix). No data plane — clients pull /sync after a bell.
 *
 * Connections are tracked per-user, each tagged with its deviceId, so a single-device revoke targets
 * only that device while a user-wide revoke (disable / recovery) hits them all. The outer map stays
 * keyed by userId (O(1) user-wide fan-out) on a ConcurrentHashMap + newKeySet (weakly-consistent
 * iteration tolerates concurrent register/unregister from WS coroutines).
 *
 * F21 — the fan-out is FIRE-AND-FORGET, never awaited on the request path. `send` parks on the
 * session's bounded outgoing channel, so a peer that stops reading (a suspended tab on a stalled
 * TCP connection) used to hold the pushing member's `POST /sync/push` until the 60 s pong reaper
 * killed it — one member's client state degrading a CO-MEMBER's write latency, cross-tenant and
 * unmitigable by any per-user bucket. Every delivery now runs on this class's own scope, one
 * coroutine PER SOCKET (so a wedged peer can't delay the next one either) and bounded by
 * [SEND_TIMEOUT_MS]. Dropping a frame to a dead peer is correct: the bell is not a data plane and
 * clients re-pull /sync on every (re)open (spec 03 §6).
 */
class Notifier(
    /**
     * SupervisorJob: one socket's failure must never cancel a sibling's delivery. Dispatchers.IO
     * because a delivery's only job is to park on a socket. Process-lifetime, like the server —
     * nothing cancels it, and an idle scope holds no thread.
     */
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
    /** Wall time, for how long a refresh's rotation is kept ([ROTATION_KEEP_MS]). */
    private val clock: () -> Long = ::now,
) {
    /**
     * One socket: its device, and [sessionId], the session it was opened on, carried along the session's refresh chain
     * ([sessionRotated]), so that a revocation that ends only some sessions reaches exactly their sockets.
     */
    private class Conn(val deviceId: String, @Volatile var sessionId: String, val session: WebSocketSession, val seq: Long)

    private val conns = ConcurrentHashMap<String, MutableSet<Conn>>()
    private val seq = AtomicLong()

    /**
     * Recent refreshes, old session to new, kept [ROTATION_KEEP_MS]: a ticket minted on a session that a refresh rotated
     * away before the socket was opened still registers under the chain's current session. Pruned on every refresh.
     */
    private class Rotation(val to: String, val at: Long)
    private val rotations = ConcurrentHashMap<String, Rotation>()

    /**
     * Registers [session] for [deviceId]. A device holds at most [MAX_SOCKETS_PER_DEVICE] sockets
     * (one bearer used to open any number): registering one more closes that device's OLDEST socket
     * (`1008`, "too_many_sockets") rather than refusing the new one, because a device's oldest socket is
     * the likeliest to be a dead connection the 60 s pong reaper has not reached yet, and a reconnecting
     * client must not be locked out by it. The evicted socket leaves the set at once, so the count is
     * bounded even while its close is still in flight.
     */
    fun register(userId: String, deviceId: String, sessionId: String, session: WebSocketSession) {
        val set = conns.computeIfAbsent(userId) { ConcurrentHashMap.newKeySet() }
        val evicted: List<Conn>
        synchronized(set) {
            set.add(Conn(deviceId, currentOf(sessionId), session, seq.incrementAndGet()))
            val mine = set.filter { it.deviceId == deviceId }.sortedBy { it.seq }
            evicted = mine.take((mine.size - MAX_SOCKETS_PER_DEVICE).coerceAtLeast(0))
            set.removeAll(evicted.toSet())
        }
        for (c in evicted) {
            scope.launch { runCatching { withTimeoutOrNull(SEND_TIMEOUT_MS) { c.session.close(CloseReason(CloseReason.Codes.VIOLATED_POLICY, "too_many_sockets")) } } }
        }
    }

    /**
     * How often an open events socket re-checks that its device still has a live session on an active
     * account (spec 03 §6). The bell above reaches only sockets of THIS process; a change
     * made by another process (`andvari admin disable`) is caught by this re-check instead. Settable so a
     * test need not wait 30 s; never set in production.
     */
    @Volatile internal var recheckMs: Long = 30_000L

    /** Test hook: the live sockets registered for [deviceId]. */
    internal fun socketCount(userId: String, deviceId: String): Int = conns[userId]?.count { it.deviceId == deviceId } ?: 0

    fun unregister(userId: String, session: WebSocketSession) {
        conns[userId]?.removeIf { it.session === session }
    }

    fun notifyRev(userIds: Collection<String>, rev: Long) {
        val text = buildJsonObject { put("type", "rev"); put("rev", rev) }.toString()
        for (userId in userIds.toSet()) {
            conns[userId]?.forEach { deliver(it, text, closeAfter = false) }
        }
    }

    /**
     * Ring EVERY registered socket, of every account (spec 03 §6): the instance card chain changed (a new card
     * or rotation statement was stored, §17.2, §17.3). [rev] is the fresh global rev the store took, so it is
     * above every client's own and even a client that pulls only for a higher rev pulls. The frame is the
     * ordinary `rev` bell: it names no account and no card, and a client learns what changed only from the
     * chain it then fetches and verifies itself.
     */
    fun notifyEveryone(rev: Long) {
        val text = buildJsonObject { put("type", "rev"); put("rev", rev) }.toString()
        for (set in conns.values) set.forEach { deliver(it, text, closeAfter = false) }
    }

    /**
     * M8: revoke ONE device (spec 03 §6) — send {revoked} to that device's sockets, THEN close them.
     * Send-before-close so the frame flushes before the outgoing channel shuts; both ops guarded so a
     * dead/slow peer can't abort the fan-out. The handler's `finally` unregisters on close.
     */
    fun notifyRevokedDevice(userId: String, deviceId: String) {
        conns[userId]?.filter { it.deviceId == deviceId }?.forEach { deliver(it, REVOKED, closeAfter = true) }
    }

    /** M8: revoke the WHOLE user (disable / admin- or self-recovery — every session is gone) — lock + close all. */
    fun notifyRevokedUser(userId: String) = notifyRevokedUserExcept(userId, keepDeviceId = null)

    /**
     * M8: revoke every session EXCEPT one device's (a recovery's commit, whose new device is the one kept).
     * [keepDeviceId] = null hits every device (the user-wide revoke).
     */
    fun notifyRevokedUserExcept(userId: String, keepDeviceId: String?) {
        conns[userId]?.filter { keepDeviceId == null || it.deviceId != keepDeviceId }?.forEach { deliver(it, REVOKED, closeAfter = true) }
    }

    /**
     * Every session of [userId] but [keepSessionId] was ended (a password change, spec 03 §3): every socket opened on
     * another session is told so and closed, whichever device it belongs to, those of the kept session's own device
     * included; the kept session's sockets stay. Before 2026-11-17 the notice spared the whole changing device although
     * the revocation did not, so a second session there kept a live socket after its session had ended.
     */
    fun notifyRevokedUserExceptSession(userId: String, keepSessionId: String) {
        val keep = currentOf(keepSessionId)
        conns[userId]?.filter { it.sessionId != keep }?.forEach { deliver(it, REVOKED, closeAfter = true) }
    }

    /**
     * A sign-in gave [deviceId] the new session [keepSessionId] and ended the device's earlier ones: every socket of the
     * device opened on another session is told so and closed, as after a password change; the new session's stay.
     */
    fun notifyRevokedDeviceExceptSession(userId: String, deviceId: String, keepSessionId: String) {
        val keep = currentOf(keepSessionId)
        conns[userId]?.filter { it.deviceId == deviceId && it.sessionId != keep }?.forEach { deliver(it, REVOKED, closeAfter = true) }
    }

    /**
     * A sign-in on a browser's row ended exactly the sessions [sessionIds] (the one it named, spec 03 §2): the sockets
     * opened on them, or on an earlier session of their chain, are told so and closed; every other socket of the row stays.
     */
    fun notifyRevokedSessions(userId: String, sessionIds: Collection<String>) {
        if (sessionIds.isEmpty()) return
        val ended = sessionIds.toSet()
        conns[userId]?.filter { currentOf(it.sessionId) in ended || it.sessionId in ended }?.forEach { deliver(it, REVOKED, closeAfter = true) }
    }

    /**
     * A refresh rotated session [from] to [to] (spec 03 §2): the sockets opened on [from], or on an earlier session of
     * the same chain, now belong to [to]. Called after the refresh committed.
     */
    fun sessionRotated(userId: String, from: String, to: String) {
        val t = clock()
        rotations.entries.removeIf { t - it.value.at > ROTATION_KEEP_MS }
        rotations[from] = Rotation(to, t)
        conns[userId]?.forEach { if (it.sessionId == from) it.sessionId = to }
    }

    /** The chain's current session for [sessionId], following the refreshes kept in [rotations]. */
    private fun currentOf(sessionId: String): String {
        var id = sessionId
        repeat(MAX_ROTATION_HOPS) { id = rotations[id]?.to ?: return id }
        return id
    }

    /**
     * One coroutine per socket: send under a timeout, then close when the caller asked for it (the
     * revoke paths) OR when the send did not land — a peer that hasn't taken one small text frame in
     * [SEND_TIMEOUT_MS] is wedged, and closing frees the registration (the handler's `finally`
     * unregisters) instead of leaving it to the 60 s pong reaper. runCatching sits OUTSIDE
     * withTimeoutOrNull deliberately: catching the timeout's own CancellationException inside would
     * swallow the very signal the timeout raises.
     */
    private fun deliver(c: Conn, text: String, closeAfter: Boolean) {
        scope.launch {
            // Built per delivery: a Frame's buffer is consumed on send, so two sockets must never
            // share one instance (what the old frame.copy() bought).
            val sent = runCatching { withTimeoutOrNull(SEND_TIMEOUT_MS) { c.session.send(Frame.Text(text)) } }.getOrNull()
            if (closeAfter || sent == null) runCatching { withTimeoutOrNull(SEND_TIMEOUT_MS) { c.session.close() } }
        }
    }

    internal companion object {
        /** Sockets one device may hold (spec 03 §6): several windows or tabs, never an unbounded number. */
        const val MAX_SOCKETS_PER_DEVICE = 8

        /** A wedged peer holds one coroutine for at most this long — never a request. */
        const val SEND_TIMEOUT_MS = 2_000L

        /** How long a refresh's old-to-new pair is kept for a ticket minted before it: twice a ticket's 30 s. */
        const val ROTATION_KEEP_MS = 60_000L

        /** At most this many refreshes are followed from one session (a chain within [ROTATION_KEEP_MS] is short). */
        const val MAX_ROTATION_HOPS = 64
        val REVOKED = buildJsonObject { put("type", "revoked") }.toString()
    }
}
