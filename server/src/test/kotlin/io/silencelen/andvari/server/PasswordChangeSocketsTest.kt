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
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.TokenPair
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Row 21 (spec 03 §3, §6, rule of 2026-11-17): a password change ends every other session of the account, those of the
 * changing device included, and the notice on the open sockets follows that revocation session by session. A socket
 * whose session was ended is told `{"type":"revoked"}` and closed, whichever device it belongs to; the changing
 * session's own sockets stay, also one opened before the session's last refresh. Before, the notice spared the whole
 * changing device, so a second session there kept a live socket after its session had ended.
 */
class PasswordChangeSocketsTest {
    private val post = HttpMethod.Post

    private suspend fun ticket(c: HttpClient, token: String): String {
        val r = c.call(post, "/api/v1/events/ticket", token = token)
        assertEquals(200, r.status.value, r.bodyAsText())
        return Regex("\"ticket\":\"([^\"]+)\"").find(r.bodyAsText())!!.groupValues[1]
    }

    private suspend fun DefaultClientWebSocketSession.expectPong(what: String) {
        send(Frame.Text("ping"))
        val f = withTimeout(5_000) { incoming.receive() }
        assertEquals("pong", (f as? Frame.Text)?.readText(), "$what: the socket must stay open and silent")
    }

    private suspend fun DefaultClientWebSocketSession.expectRevokedThenClosed(what: String) {
        val f = withTimeout(5_000) { incoming.receive() }
        assertEquals("""{"type":"revoked"}""", (f as Frame.Text).readText(), what)
        val end = withTimeout(5_000) { incoming.receiveCatching() }
        assertTrue(end.isClosed || end.getOrNull() is Frame.Close, "$what: closed after the notice")
    }

    @Test
    fun aPasswordChange_closesEveryOtherSessionsSocket_onTheChangingDeviceToo_andKeepsTheChangingSessionsOwn() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        // A browser's row (made as `web`), so a second tab's sign-in leaves the first tab's session live.
        val me = Flow.member(c, s, "me@example.com", platform = "web")
        // A second session on the changing device's row (a second web tab: a sign-in on any other kind of row ends the
        // row's earlier sessions), and another device.
        val sibling = WireJson.json.decodeFromString(
            SessionResponse.serializer(), c.call(post, "/api/v1/auth/login", me.loginBody(deviceId = me.deviceId), client = "web/1.0.0").bodyAsText(),
        )
        assertEquals(me.deviceId, sibling.deviceId)
        val other = c.login(me)
        val ws = createClient { install(WebSockets) }
        suspend fun open(token: String): DefaultClientWebSocketSession =
            ws.webSocketSession("/api/v1/events?ticket=${ticket(c, token)}").also { it.expectPong("just opened") }

        // The changing session's socket, opened before its refresh ...
        val own = open(me.token)
        val rotated = WireJson.json.decodeFromString(
            TokenPair.serializer(), c.call(post, "/api/v1/auth/refresh", """{"refreshToken":"${me.session!!.refreshToken}"}""").bodyAsText(),
        )
        // ... and one opened after it on a ticket of the rotated-away access token (still valid until it expires).
        val ownLate = open(me.token)
        val siblingSocket = open(sibling.accessToken)
        val otherSocket = open(other.accessToken)

        val body = """{"currentAuthKey":"${me.authKey}","newAuthKey":"${b32()}","newKdfSalt":"${Bytes.toB64(ByteArray(16) { 5 })}",""" +
            """"newKdfParams":{"v":1,"alg":"argon2id13","ops":1,"memBytes":8388608},"newWrappedUvk":"AAAA"}"""
        val r = c.call(HttpMethod.Put, "/api/v1/account/password", body, rotated.accessToken)
        assertEquals(200, r.status.value, r.bodyAsText())

        // The ended sessions' sockets are told and closed: the second session on the changing device, and the other device.
        siblingSocket.expectRevokedThenClosed("the changing device's other session")
        otherSocket.expectRevokedThenClosed("the other device")
        // The changing session's own sockets stay.
        own.expectPong("the changing session's socket, opened before its refresh")
        ownLate.expectPong("the changing session's socket, opened on a ticket of its rotated-away token")
        // The revocation itself is as before: every other session ended, the changing one served.
        assertEquals("invalid_credentials", c.call(HttpMethod.Get, "/api/v1/account/keys", token = sibling.accessToken).errorCode())
        assertEquals("invalid_credentials", c.call(HttpMethod.Get, "/api/v1/account/keys", token = other.accessToken).errorCode())
        assertEquals(200, c.call(HttpMethod.Get, "/api/v1/account/keys", token = rotated.accessToken).status.value)
        own.close(); ownLate.close()
    }
}
