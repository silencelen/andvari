package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.plugins.websocket.DefaultClientWebSocketSession
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.plugins.websocket.webSocketSession
import io.ktor.websocket.close
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import io.ktor.websocket.Frame
import io.ktor.websocket.readReason
import io.ktor.websocket.readText
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.TokenPair
import io.silencelen.andvari.core.model.wire.WireJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The events socket (spec 03 §6) is torn down whenever its device's sessions die. Every wait here is for the server's
 * own frame or close, never for a time: a fixed five-second bound once failed a correct run on a loaded build host.
 */
class EventsSocketTest {
    private suspend fun ticket(c: HttpClient, token: String): String =
        Regex("\"ticket\":\"([^\"]+)\"").find(c.call(HttpMethod.Post, "/api/v1/events/ticket", token = token).bodyAsText())!!.groupValues[1]

    /** Open the socket on a fresh ticket, wait for the registration proof (`pong`), then run [whileOpen]. */
    private suspend fun ApplicationTestBuilder.withSocket(token: String, whileOpen: suspend DefaultClientWebSocketSession.() -> Unit) {
        val ws = createClient { install(WebSockets) }
        ws.webSocket("/api/v1/events?ticket=${ticket(client, token)}") {
            send(Frame.Text("ping"))
            assertEquals("pong", (incoming.receive() as Frame.Text).readText())
            whileOpen()
        }
    }

    /** The close reason the server sends on [path] (the first frame must be the close). */
    private suspend fun ApplicationTestBuilder.closeCodeOf(path: String, bearer: String? = null, send: Frame? = null): Short? {
        val ws = createClient { install(WebSockets) }
        var code: Short? = null
        ws.webSocket(path, request = { bearer?.let { header("Authorization", "Bearer $it") } }) {
            send?.let { outgoing.send(it) }
            // What this waits for is the server's close: its close frame, or the end of the channel, which completes
            // `closeReason`. No wall-clock bound of its own (a loaded build host once took longer than five seconds to
            // run the server's handler); a server that never closes is caught by the test framework's own limit.
            val f = runCatching { incoming.receive() }.getOrNull()
            code = (f as? Frame.Close)?.readReason()?.code ?: closeReason.await()?.code
        }
        return code
    }

    /** Index row 45: an unknown or spent ticket, a raw token in the query, a restricted bearer: 1008; a frame over the cap: 1009. */
    @Test
    fun refusals_1008_unauthorized_and_1009_tooBig() = testApplication {
        val s = TestKit.services(TestKit.config(totpRequired = true))
        application { andvariModule(s) }
        val restricted = TestKit.session(s, TestKit.seedAccount(s, "r@example.com"))
        assertEquals(1008.toShort(), closeCodeOf("/api/v1/events?ticket=${b32()}"))
        assertEquals(1008.toShort(), closeCodeOf("/api/v1/events?ticket=$restricted"), "an access token is not a ticket")
        assertEquals(1008.toShort(), closeCodeOf("/api/v1/events", bearer = restricted), "a restricted session gets no socket")
        assertEquals(1008.toShort(), closeCodeOf("/api/v1/events"))
        // An enrolled account's ticket works once; a frame over 4 KiB closes it with 1009.
        val ok = TestKit.seedAccount(s, "ok@example.com")
        s.db.tx { it.exec("UPDATE users SET totpSecret='JBSWY3DPEHPK3PXP' WHERE userId=?", ok.userId) }
        val tok = TestKit.session(s, ok)
        val t = ticket(client, tok)
        assertEquals(1009.toShort(), closeCodeOf("/api/v1/events?ticket=$t", send = Frame.Text("x".repeat(WS_MAX_FRAME_BYTES.toInt() + 1))))
        assertEquals(1008.toShort(), closeCodeOf("/api/v1/events?ticket=$t"), "a ticket is single-use")
    }

    /** The next frame is `{"type":"revoked"}` and then the server closes the socket. */
    private suspend fun DefaultClientWebSocketSession.expectRevokedThenClosed() {
        val f = incoming.receive()
        assertEquals("""{"type":"revoked"}""", (f as Frame.Text).readText())
        val end = incoming.receiveCatching()
        assertTrue(end.isClosed || end.getOrNull() is Frame.Close, "the socket must be closed after the revoke")
    }

    @Test
    fun logout_closesTheDevicesSocket() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        Flow.finishSetup(client, s)
        val me = Flow.member(client, s, "me@example.com")
        withSocket(me.token) {
            assertEquals(200, client.call(HttpMethod.Post, "/api/v1/auth/logout", token = me.token).status.value)
            expectRevokedThenClosed()
        }
    }

    @Test
    fun refreshReuse_closesTheDevicesSocket() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        Flow.finishSetup(client, s)
        val me = Flow.member(client, s, "me@example.com")
        val sess = WireJson.json.decodeFromString(SessionResponse.serializer(), client.call(HttpMethod.Post, "/api/v1/auth/login", me.loginBody()).bodyAsText())
        val rotated = WireJson.json.decodeFromString(TokenPair.serializer(), client.call(HttpMethod.Post, "/api/v1/auth/refresh", """{"refreshToken":"${sess.refreshToken}"}""").bodyAsText())
        withSocket(rotated.accessToken) {
            // The consumed refresh token comes back: theft is assumed and the device's sessions die.
            assertEquals("refresh_reuse", client.call(HttpMethod.Post, "/api/v1/auth/refresh", """{"refreshToken":"${sess.refreshToken}"}""").errorCode())
            expectRevokedThenClosed()
        }
        assertEquals("invalid_credentials", client.call(HttpMethod.Get, "/api/v1/account/keys", token = rotated.accessToken).errorCode())
    }

    /** A device holds at most 8 sockets; the ninth closes the device's oldest. */
    @Test
    fun aDevicesSockets_areCapped_theOldestIsClosed() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        Flow.finishSetup(client, s)
        val me = Flow.member(client, s, "me@example.com")
        val ws = createClient { install(WebSockets) }
        suspend fun open(): DefaultClientWebSocketSession =
            ws.webSocketSession("/api/v1/events") { header("Authorization", "Bearer ${me.token}") }.also {
                it.send(Frame.Text("ping"))
                assertEquals("pong", (it.incoming.receive() as Frame.Text).readText())
            }
        val first = open()
        val rest = (1..Notifier.MAX_SOCKETS_PER_DEVICE).map { open() }
        val end = first.incoming.receiveCatching()
        assertTrue(end.isClosed || end.getOrNull() is Frame.Close, "the device's oldest socket must be closed")
        for (r in rest) {
            r.send(Frame.Text("ping"))
            assertEquals("pong", (r.incoming.receive() as Frame.Text).readText())
        }
        rest.forEach { it.close() }
    }

    /** The bearer upgrade has a per-account bucket (`ws_bearer`, 60/min); past it the close is 1013. */
    @Test
    fun theBearerUpgrade_isBucketed() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        Flow.finishSetup(client, s)
        val me = Flow.member(client, s, "me@example.com")
        val ws = createClient { install(WebSockets) }
        repeat(WS_BEARER_PER_MINUTE) {
            ws.webSocket("/api/v1/events", request = { header("Authorization", "Bearer ${me.token}") }) {
                send(Frame.Text("ping"))
                assertEquals("pong", (incoming.receive() as Frame.Text).readText())
            }
        }
        assertEquals(1013.toShort(), closeCodeOf("/api/v1/events", bearer = me.token))
        // The ticket path is bounded by `ws_ticket` at mint, not by this bucket.
        withSocket(me.token) { }
    }

    /**
     * `andvari admin disable` runs in its own process (here: its own [Services] on the same
     * database, so its notifier reaches none of the server's sockets). The socket still gets `revoked` and the
     * close from the events loop's re-check, and the person still gets `account_disabled`, as from the panel.
     */
    @Test
    fun adminDisable_fromAnotherProcess_closesTheSocket_andQueuesTheNotice() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        Flow.finishSetup(client, s)
        val me = Flow.member(client, s, "me@example.com")
        s.notifier.recheckMs = 200
        withSocket(me.token) {
            val cli = TestKit.services(s.config)
            val out = java.io.ByteArrayOutputStream()
            AdminCommands(cli, java.io.File(TestKit.tempDir(), "andvari.env"), java.io.PrintStream(out))
                .run("disable", HostCli.Args(listOf("disable", "me@example.com", "--reason", "abuse")))
            assertEquals("disabled", out.toString().trim())
            expectRevokedThenClosed()
        }
        val disabled = Flow.sink(s).filter { it.first == "account_disabled" }
        assertEquals(1, disabled.size)
        assertTrue(disabled.single().third.contains("Reason: abuse"), disabled.single().third)
        // The command refuses a reason the panel refuses.
        val cli = TestKit.services(s.config)
        assertTrue(runCatching {
            AdminCommands(cli, java.io.File(TestKit.tempDir(), "andvari.env"), java.io.PrintStream(java.io.ByteArrayOutputStream()))
                .run("disable", HostCli.Args(listOf("disable", "me@example.com", "--reason", "anything")))
        }.exceptionOrNull() is HostCli.Usage)
    }

    @Test
    fun aDevicesLogout_leavesTheAccountsOtherSocketsOpen() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        Flow.finishSetup(client, s)
        val me = Flow.member(client, s, "me@example.com")
        val other = WireJson.json.decodeFromString(SessionResponse.serializer(), client.call(HttpMethod.Post, "/api/v1/auth/login", me.loginBody()).bodyAsText())
        withSocket(me.token) {
            assertEquals(200, client.call(HttpMethod.Post, "/api/v1/auth/logout", token = other.accessToken).status.value)
            // This socket still answers.
            send(Frame.Text("ping"))
            assertEquals("pong", (incoming.receive() as Frame.Text).readText())
        }
    }
}
