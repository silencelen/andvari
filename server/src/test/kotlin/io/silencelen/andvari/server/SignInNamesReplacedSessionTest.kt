package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.plugins.websocket.DefaultClientWebSocketSession
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocketSession
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.ApplicationTestBuilder
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
 * A sign-in names the session it replaces, and the server ends exactly that one (spec 03 §2, `replacesRefreshToken`,
 * decided on 2026-11-17). On a browser's row each tab holds its own session, so the server cannot end "the device's
 * earlier sessions" there; before, the browser sent nothing for the session its own sign-in replaced, which then stayed
 * live for up to thirty days, and sending its token after the login ended every tab of the row, the new one included, when
 * an earlier refresh answer had been lost. Every test here runs against the real routes.
 */
class SignInNamesReplacedSessionTest {
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

    /** A browser's row: [me] registered from a browser (tab 1) and two more tabs signed in on the same row. */
    private class Browser(val me: Me, val tab1: SessionResponse, val tab2: SessionResponse, val tab3: SessionResponse)

    private suspend fun ApplicationTestBuilder.browser(s: Services): Browser {
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com", platform = "web")
        suspend fun tab() = c.call(post, "/api/v1/auth/login", me.loginBody(deviceId = me.deviceId, platform = "web"), client = "web/1.0.0").let {
            assertEquals(200, it.status.value, it.bodyAsText())
            json.decodeFromString(SessionResponse.serializer(), it.bodyAsText()).also { r -> assertEquals(me.deviceId, r.deviceId) }
        }
        val b = Browser(me, me.session!!, tab(), tab())
        assertEquals(3L, live(s, me.deviceId))
        return b
    }

    private suspend fun HttpClient.signIn(me: Me, replaces: String?, authKey: String = me.authKey, deviceId: String = me.deviceId) =
        call(post, "/api/v1/auth/login", me.loginBody(deviceId = deviceId, platform = "web", replaces = replaces, authKey = authKey), client = "web/1.0.0")

    @Test
    fun aTabSigningInAgain_namesItsSession_andOnlyThatOneEnds_withItsSocket() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val b = browser(s)
        val c = client
        val ws = createClient { install(WebSockets) }
        suspend fun ticket(token: String) = Regex("\"ticket\":\"([^\"]+)\"").find(c.call(post, "/api/v1/events/ticket", token = token).bodyAsText())!!.groupValues[1]
        suspend fun open(token: String): DefaultClientWebSocketSession = ws.webSocketSession("/api/v1/events?ticket=${ticket(token)}").also {
            it.send(Frame.Text("ping")); assertEquals("pong", (withTimeout(5_000) { it.incoming.receive() } as Frame.Text).readText())
        }
        val socket1 = open(b.tab1.accessToken)
        val socket2 = open(b.tab2.accessToken)

        val r = c.signIn(b.me, replaces = b.tab1.refreshToken)
        assertEquals(200, r.status.value, r.bodyAsText())
        val fresh = json.decodeFromString(SessionResponse.serializer(), r.bodyAsText())

        // Tab 1's session ended; tabs 2 and 3 and the new session live.
        assertEquals("invalid_credentials", c.keys(b.tab1.accessToken).errorCode())
        assertEquals("session_revoked", c.refresh(b.tab1.refreshToken).errorCode())
        for (t in listOf(b.tab2, b.tab3, fresh)) assertEquals(200, c.keys(t.accessToken).status.value)
        assertEquals(3L, live(s, b.me.deviceId))
        assertEquals(1L, audits(s, "session_end", "sign_in_named"))
        assertEquals(0L, audits(s, "refresh_reuse"))
        // The ended session's socket is told and closed; the other tab's stays.
        assertEquals("""{"type":"revoked"}""", (withTimeout(5_000) { socket1.incoming.receive() } as Frame.Text).readText())
        val end = withTimeout(5_000) { socket1.incoming.receiveCatching() }
        assertTrue(end.isClosed || end.getOrNull() is Frame.Close)
        socket2.send(Frame.Text("ping")); assertEquals("pong", (withTimeout(5_000) { socket2.incoming.receive() } as Frame.Text).readText())
        socket2.close()

        // A sign-in that names nothing ends nothing on a browser's row, as before.
        assertEquals(200, c.signIn(b.me, replaces = null).status.value)
        assertEquals(4L, live(s, b.me.deviceId))
    }

    @Test
    fun aRefreshWhoseAnswerWasLost_thenASignInNamingTheReplacedToken_endsThatSessionAsItStandsNow() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val b = browser(s)
        val c = client
        // Tab 1's refresh is answered at the server and the answer is lost: the tab still holds the replaced token, and the
        // session the lost answer carried is live with nobody holding it.
        val lost = json.decodeFromString(TokenPair.serializer(), c.refresh(b.tab1.refreshToken).bodyAsText())
        val lost2 = json.decodeFromString(TokenPair.serializer(), c.refresh(lost.refreshToken).bodyAsText())
        assertEquals(3L, live(s, b.me.deviceId))

        val r = c.signIn(b.me, replaces = b.tab1.refreshToken)
        assertEquals(200, r.status.value, r.bodyAsText())
        val fresh = json.decodeFromString(SessionResponse.serializer(), r.bodyAsText())

        // The named chain ended as it stands now (two refreshes on), with a record that says the token named had been
        // replaced; the reuse rule's wider effect did not run: the other tabs and the new session live, no reuse record.
        assertEquals("invalid_credentials", c.keys(lost2.accessToken).errorCode())
        assertEquals("session_revoked", c.refresh(lost2.refreshToken).errorCode())
        for (t in listOf(b.tab2, b.tab3, fresh)) assertEquals(200, c.keys(t.accessToken).status.value)
        assertEquals(3L, live(s, b.me.deviceId))
        assertEquals(1L, audits(s, "session_end", "sign_in_named_replaced"))
        assertEquals(0L, audits(s, "refresh_reuse"))

        // The reuse rule for a replaced token of a live chain is unchanged, at end-session: tab 2 refreshes, and its
        // replaced token sent again ends every session of the row, the new one included.
        val tab2b = json.decodeFromString(TokenPair.serializer(), c.refresh(b.tab2.refreshToken).bodyAsText())
        assertEquals(200, c.endSession(b.tab2.refreshToken).status.value)
        assertEquals(1L, audits(s, "refresh_reuse"))
        for (t in listOf(tab2b.accessToken, b.tab3.accessToken, fresh.accessToken)) assertEquals("invalid_credentials", c.keys(t).errorCode())
        assertEquals(0L, live(s, b.me.deviceId))
    }

    @Test
    fun aFailedSignIn_endsNothing_andTheReuseRuleAtRefreshIsUnchanged() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val b = browser(s)
        val c = client
        // A wrong password naming a live session: refused, nothing ends.
        val wrong = c.signIn(b.me, replaces = b.tab1.refreshToken, authKey = b32())
        assertEquals("invalid_credentials", wrong.errorCode())
        for (t in listOf(b.tab1, b.tab2, b.tab3)) assertEquals(200, c.keys(t.accessToken).status.value)
        assertEquals(3L, live(s, b.me.deviceId))
        // A right password with the device's id but another secret is a new device: the named session is on another row,
        // so nothing ends there either.
        val otherSecret = c.call(post, "/api/v1/auth/login", b.me.loginBody(deviceId = b.me.deviceId, secret = b32(), platform = "web", replaces = b.tab1.refreshToken), client = "web/1.0.0")
        assertEquals(200, otherSecret.status.value, otherSecret.bodyAsText())
        assertEquals(200, c.keys(b.tab1.accessToken).status.value)
        assertEquals(0L, audits(s, "session_end"))

        // The reuse rule at refresh is unchanged: tab 3 refreshes, and its replaced token presented again ends the row.
        // (Tab 3 uses its answer first: a repeat whose pair is untouched is answered inside its minute of grace.)
        val tab3b = json.decodeFromString(TokenPair.serializer(), c.refresh(b.tab3.refreshToken).bodyAsText())
        assertEquals(200, c.keys(tab3b.accessToken).status.value)
        assertEquals("refresh_reuse", c.refresh(b.tab3.refreshToken).errorCode())
        assertEquals("invalid_credentials", c.keys(tab3b.accessToken).errorCode())
        assertEquals(0L, live(s, b.me.deviceId))
    }

    @Test
    fun aTokenOfAnotherRowOrAccount_orAnUnknownOne_isIgnored_andAValueThatIsNotAStringIsRefused() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val b = browser(s)
        val c = client
        val otherRow = c.login(b.me)
        val you = Flow.member(c, s, "you@example.com")
        for (named in listOf(otherRow.refreshToken, you.session!!.refreshToken, b32(), "", "x".repeat(500))) {
            val r = c.signIn(b.me, replaces = named)
            assertEquals(200, r.status.value, r.bodyAsText())
        }
        for (t in listOf(b.tab1, b.tab2, b.tab3, otherRow, you.session!!)) assertEquals(200, c.keys(t.accessToken).status.value)
        assertEquals(0L, audits(s, "session_end"))
        // An expired token names nothing either.
        s.db.tx { it.exec("UPDATE sessions SET refreshExpiresAt=0 WHERE refreshHash=?", ServerCrypto.hashToken(b.tab1.refreshToken)) }
        assertEquals(200, c.signIn(b.me, replaces = b.tab1.refreshToken).status.value)
        assertEquals(0L, audits(s, "session_end"))
        // The field's shape: a number is not the route's shape.
        val bad = c.call(post, "/api/v1/auth/login", b.me.loginBody(deviceId = b.me.deviceId, platform = "web").dropLast(1) + ""","replacesRefreshToken":7}""", client = "web/1.0.0")
        assertEquals("bad_request", bad.errorCode())
    }

    /** On an app's row every earlier session ends anyway; the name adds the record that the token named had been replaced. */
    @Test
    fun onAnAppsRow_theNameOnlyAddsTheRecord() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val kept = me.session!!
        val lost = json.decodeFromString(TokenPair.serializer(), c.refresh(kept.refreshToken).bodyAsText())
        val r = c.call(post, "/api/v1/auth/login", me.loginBody(deviceId = me.deviceId, replaces = kept.refreshToken))
        assertEquals(200, r.status.value, r.bodyAsText())
        val fresh = json.decodeFromString(SessionResponse.serializer(), r.bodyAsText())
        assertEquals("invalid_credentials", c.keys(lost.accessToken).errorCode())
        assertEquals(200, c.keys(fresh.accessToken).status.value)
        assertEquals(1L, live(s, me.deviceId))
        assertEquals(1L, audits(s, "session_end"))
        assertEquals(1L, audits(s, "session_end", "sign_in_named_replaced"))
        assertEquals(0L, audits(s, "refresh_reuse"))
    }
}
