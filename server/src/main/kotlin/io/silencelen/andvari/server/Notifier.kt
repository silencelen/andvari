package io.silencelen.andvari.server

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
) {
    private class Conn(val deviceId: String, val session: WebSocketSession)

    private val conns = ConcurrentHashMap<String, MutableSet<Conn>>()

    fun register(userId: String, deviceId: String, session: WebSocketSession) {
        conns.computeIfAbsent(userId) { ConcurrentHashMap.newKeySet() }.add(Conn(deviceId, session))
    }

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
     * M8: revoke every session EXCEPT one device's — a password change kills the user's OTHER sessions
     * but deliberately keeps the changing device's own, so its socket must stay live. [keepDeviceId] =
     * null hits every device (the user-wide revoke).
     */
    fun notifyRevokedUserExcept(userId: String, keepDeviceId: String?) {
        conns[userId]?.filter { keepDeviceId == null || it.deviceId != keepDeviceId }?.forEach { deliver(it, REVOKED, closeAfter = true) }
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

    private companion object {
        /** A wedged peer holds one coroutine for at most this long — never a request. */
        const val SEND_TIMEOUT_MS = 2_000L
        val REVOKED = buildJsonObject { put("type", "revoked") }.toString()
    }
}
