package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.plugins.websocket.DefaultClientWebSocketSession
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocketSession
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.ktor.websocket.Frame
import io.ktor.websocket.close
import io.ktor.websocket.readText
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.TokenPair
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A device has one live session, and the server keeps that rule itself (spec 03 §2, decided on 2026-11-17): a sign-in on
 * a known device ends that device's earlier sessions in its own transaction. The case that asked for it: a refresh whose
 * answer was lost, then a sign-in on the same device. The client used to end the replaced session with the token it
 * held, which the server had already replaced; the server took that for a stolen token's reuse and ended every session of
 * the device, the new one too, so the person was signed in and at once signed out.
 */
class OneSessionPerDeviceTest {
    private val post = HttpMethod.Post
    private val get = HttpMethod.Get
    private val json = WireJson.json

    private suspend fun HttpClient.keys(token: String) = call(get, "/api/v1/account/keys", token = token)
    private suspend fun HttpClient.refresh(token: String) = call(post, "/api/v1/auth/refresh", """{"refreshToken":"$token"}""")
    private suspend fun HttpClient.endSession(token: String) = call(post, "/api/v1/auth/end-session", """{"refreshToken":"$token"}""")

    private fun live(s: Services, deviceId: String): Long =
        s.db.read { it.count("SELECT COUNT(*) FROM sessions WHERE deviceId=? AND revokedAt IS NULL AND refreshConsumedAt IS NULL", deviceId) }

    private fun audits(s: Services, type: String, meta: String? = null): Long = s.db.read {
        if (meta == null) it.count("SELECT COUNT(*) FROM audit WHERE type=?", type) else it.count("SELECT COUNT(*) FROM audit WHERE type=? AND meta=?", type, meta)
    }

    @Test
    fun aSignInAfterALostRefreshAnswer_endsTheEarlierSessions_andTheNewSessionSurvives() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val kept = me.session!!
        // The kept session's refresh is answered at the server, and the answer is lost: the device still holds the old pair.
        val lost = json.decodeFromString(TokenPair.serializer(), c.refresh(kept.refreshToken).bodyAsText())
        assertEquals(1L, live(s, me.deviceId))

        // The person signs in again on the same device.
        val r = c.call(post, "/api/v1/auth/login", me.loginBody(deviceId = me.deviceId))
        assertEquals(200, r.status.value, r.bodyAsText())
        val fresh = json.decodeFromString(SessionResponse.serializer(), r.bodyAsText())
        assertEquals(me.deviceId, fresh.deviceId)

        // The server ended the device's earlier sessions itself, the one the lost answer carried too, and recorded it once.
        assertEquals(1L, live(s, me.deviceId))
        assertEquals("invalid_credentials", c.keys(kept.accessToken).errorCode())
        assertEquals("invalid_credentials", c.keys(lost.accessToken).errorCode())
        assertEquals("session_revoked", c.refresh(lost.refreshToken).errorCode())
        assertEquals(1L, audits(s, "session_end", "sign_in"))
        assertEquals(200, c.keys(fresh.accessToken).status.value)

        // A client that follows the rule sends nothing more. An older client still ends the replaced session with the token
        // it holds, the one the lost answer replaced: that names an ended session now, so nothing more ends.
        val old = c.endSession(kept.refreshToken)
        assertEquals(200, old.status.value); assertEquals("ok", old.bodyAsText())
        assertEquals("session_revoked", c.refresh(kept.refreshToken).errorCode())
        assertEquals(0L, audits(s, "refresh_reuse"))
        assertEquals(200, c.keys(fresh.accessToken).status.value)
        assertEquals(1L, live(s, me.deviceId))

        // The reuse rule stands as it was for a live session's chain: the new session's token, once replaced and sent
        // again, ends every session of the device. (The answer is used first: a repeat of a refresh whose pair is still
        // untouched is answered inside its minute of grace, RefreshGraceTest.)
        val next = json.decodeFromString(TokenPair.serializer(), c.refresh(fresh.refreshToken).bodyAsText())
        assertEquals(200, c.keys(next.accessToken).status.value)
        assertEquals("refresh_reuse", c.refresh(fresh.refreshToken).errorCode())
        assertEquals("invalid_credentials", c.keys(next.accessToken).errorCode())
        assertEquals(0L, live(s, me.deviceId))
        assertEquals(1L, audits(s, "refresh_reuse"))
    }

    @Test
    fun aSignInOnAKnownDevice_closesTheEndedSessionsSockets_andLeavesOtherDevicesAndWebTabsAlone() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val other = c.login(me)
        val ws = createClient { install(WebSockets) }
        suspend fun ticket(token: String) = Regex("\"ticket\":\"([^\"]+)\"").find(c.call(post, "/api/v1/events/ticket", token = token).bodyAsText())!!.groupValues[1]
        suspend fun open(token: String): DefaultClientWebSocketSession = ws.webSocketSession("/api/v1/events?ticket=${ticket(token)}").also {
            it.send(Frame.Text("ping")); assertEquals("pong", (withTimeout(5_000) { it.incoming.receive() } as Frame.Text).readText())
        }
        val ended = open(me.token)
        val otherSocket = open(other.accessToken)

        val fresh = json.decodeFromString(SessionResponse.serializer(), c.call(post, "/api/v1/auth/login", me.loginBody(deviceId = me.deviceId)).bodyAsText())
        // The ended session's socket is told and closed, as after a password change.
        assertEquals("""{"type":"revoked"}""", (withTimeout(5_000) { ended.incoming.receive() } as Frame.Text).readText())
        val end = withTimeout(5_000) { ended.incoming.receiveCatching() }
        assertTrue(end.isClosed || end.getOrNull() is Frame.Close)
        // The new session's own socket, and the other device's, stay.
        val freshSocket = open(fresh.accessToken)
        otherSocket.send(Frame.Text("ping")); assertEquals("pong", (withTimeout(5_000) { otherSocket.incoming.receive() } as Frame.Text).readText())
        assertEquals(200, c.keys(other.accessToken).status.value)

        assertEquals(1L, live(s, me.deviceId))
        assertEquals(1L, audits(s, "session_end", "sign_in"))
        freshSocket.close(); otherSocket.close()
    }

    /**
     * The browser's exception follows the row, not the caller's word (decided on 2026-11-17). The check's probe: a caller
     * that says `web` (header and body) on a row made as an app's. Before, the header alone decided, so the earlier session
     * stayed live and the row held two; now the row's kind decides and the earlier session ends. And the other way round: a
     * caller that says `linux` on a row made as a browser's is a browser's tab there, so the other tabs stay, and its
     * session is a web session (every operator route refuses it).
     */
    @Test
    fun theBrowsersException_followsTheRowsKind_notTheCallersClaim() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val app = Flow.member(c, s, "app@example.com")
        val claimed = c.call(post, "/api/v1/auth/login", app.loginBody(deviceId = app.deviceId, platform = "web"), client = "web/1.0.0")
        assertEquals(200, claimed.status.value, claimed.bodyAsText())
        val claimedSession = json.decodeFromString(SessionResponse.serializer(), claimed.bodyAsText())
        assertEquals(app.deviceId, claimedSession.deviceId)
        assertEquals("invalid_credentials", c.keys(app.token).errorCode())
        assertEquals(1L, live(s, app.deviceId))
        assertEquals(1L, audits(s, "session_end", "sign_in"))

        val browser = Flow.member(c, s, "browser@example.com", platform = "web")
        val tab = json.decodeFromString(SessionResponse.serializer(), c.call(post, "/api/v1/auth/login", browser.loginBody(deviceId = browser.deviceId)).bodyAsText())
        assertEquals(browser.deviceId, tab.deviceId)
        assertEquals(200, c.keys(browser.token).status.value)
        assertEquals(2L, live(s, browser.deviceId))
        assertEquals(1L, audits(s, "session_end", "sign_in"))
        val platform = s.db.read { db -> db.queryOne("SELECT clientPlatform FROM sessions WHERE accessHash=?", ServerCrypto.hashToken(tab.accessToken)) { it.getString(1) } }
        assertEquals("web", platform)
    }
}
