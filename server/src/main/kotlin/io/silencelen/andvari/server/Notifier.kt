package io.silencelen.andvari.server

import io.ktor.websocket.Frame
import io.ktor.websocket.WebSocketSession
import io.ktor.websocket.close
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
 */
class Notifier {
    private class Conn(val deviceId: String, val session: WebSocketSession)

    private val conns = ConcurrentHashMap<String, MutableSet<Conn>>()

    fun register(userId: String, deviceId: String, session: WebSocketSession) {
        conns.computeIfAbsent(userId) { ConcurrentHashMap.newKeySet() }.add(Conn(deviceId, session))
    }

    fun unregister(userId: String, session: WebSocketSession) {
        conns[userId]?.removeIf { it.session === session }
    }

    suspend fun notifyRev(userIds: Collection<String>, rev: Long) {
        val frame = Frame.Text(buildJsonObject { put("type", "rev"); put("rev", rev) }.toString())
        for (userId in userIds.toSet()) {
            conns[userId]?.forEach { runCatching { it.session.send(frame.copy()) } }
        }
    }

    /**
     * M8: revoke ONE device (spec 03 §6) — send {revoked} to that device's sockets, THEN close them.
     * Send-before-close so the frame flushes before the outgoing channel shuts; each op guarded so a
     * dead/slow peer can't abort the fan-out. The handler's `finally` unregisters on close.
     */
    suspend fun notifyRevokedDevice(userId: String, deviceId: String) {
        val frame = revokedFrame()
        conns[userId]?.filter { it.deviceId == deviceId }?.forEach { c ->
            runCatching { c.session.send(frame.copy()) }
            runCatching { c.session.close() }
        }
    }

    /** M8: revoke the WHOLE user (disable / admin- or self-recovery — every session is gone) — lock + close all. */
    suspend fun notifyRevokedUser(userId: String) = notifyRevokedUserExcept(userId, keepDeviceId = null)

    /**
     * M8: revoke every session EXCEPT one device's — a password change kills the user's OTHER sessions
     * but deliberately keeps the changing device's own, so its socket must stay live. [keepDeviceId] =
     * null hits every device (the user-wide revoke).
     */
    suspend fun notifyRevokedUserExcept(userId: String, keepDeviceId: String?) {
        val frame = revokedFrame()
        conns[userId]?.filter { keepDeviceId == null || it.deviceId != keepDeviceId }?.forEach { c ->
            runCatching { c.session.send(frame.copy()) }
            runCatching { c.session.close() }
        }
    }

    private fun revokedFrame() = Frame.Text(buildJsonObject { put("type", "revoked") }.toString())
}
