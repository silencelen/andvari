package io.silencelen.andvari.server

import io.ktor.websocket.Frame
import io.ktor.websocket.WebSocketSession
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.util.concurrent.ConcurrentHashMap

/**
 * WebSocket "dirty bell" (spec 03 §6). Server → client frames only: {"type":"rev","rev":N}
 * when anything the user can see changed, {"type":"revoked"} when their session dies.
 * No data plane — clients pull /sync after a bell.
 */
class Notifier {
    private val sessions = ConcurrentHashMap<String, MutableSet<WebSocketSession>>()

    fun register(userId: String, session: WebSocketSession) {
        sessions.computeIfAbsent(userId) { ConcurrentHashMap.newKeySet() }.add(session)
    }

    fun unregister(userId: String, session: WebSocketSession) {
        sessions[userId]?.remove(session)
    }

    suspend fun notifyRev(userIds: Collection<String>, rev: Long) {
        val frame = Frame.Text(buildJsonObject { put("type", "rev"); put("rev", rev) }.toString())
        for (userId in userIds.toSet()) {
            sessions[userId]?.forEach { runCatching { it.send(frame.copy()) } }
        }
    }

    suspend fun notifyRevoked(userId: String) {
        val frame = Frame.Text(buildJsonObject { put("type", "revoked") }.toString())
        sessions[userId]?.forEach { runCatching { it.send(frame.copy()) } }
    }
}
