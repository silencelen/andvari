package io.silencelen.andvari.hostile

import io.ktor.client.request.get
import io.ktor.client.request.header
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.engine.AppEngine
import io.silencelen.andvari.core.app.engine.EngineDesktopAppApi
import io.silencelen.andvari.core.app.engine.dialingTransport
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.session.SessionEndReason
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Handler
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.set
import io.silencelen.andvari.hostile.proxy.str
import io.silencelen.andvari.server.queryOne
import kotlinx.coroutines.Dispatchers
import kotlinx.serialization.json.JsonElement
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A refresh cut off while out, with no try left, against the REAL server. The proxy forwards the device's refresh and
 * then closes the connection without an answer: the server replaced the token, the device got nothing. The one second
 * try goes with the same token (the server's grace answers it with the same pair), and its answer is lost too. At the
 * next refresh no try is left: the device sends nothing, and the session ends on the device with an end of its own
 * ([SessionEndReason.SESSION_NOT_CONFIRMED]), not as one its server ended. The token is kept for one use: the next
 * sign-in names it, and the server ends that chain as replaced, records no reuse, and ends no other session of the
 * device. The second test answers what the server does where the sign-in on the same device row does NOT name it.
 *
 * (The window of fifty seconds is not walked here: the app engine's keeper reads the wall clock, which a test of the
 * real server cannot drive; the shared code's own tests walk it with a driven clock. A second try whose answer is lost
 * too leaves no try in the same way.)
 */
class RefreshNotConfirmedTest {
    private val crypto = createCryptoProvider()
    private val email = "alice@example.org"

    private fun World.desktop(tag: String): EngineDesktopAppApi {
        val state = MemoryDeviceState()
        val engine = AppEngine(AppPlatform.LINUX, "Desk", dialingTransport(state, server.httpFor(proxy.dial(tag)), AppPlatform.LINUX), state, MemoryDeviceState(),
            crypto, server::now, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.IO)
        return EngineDesktopAppApi(engine).also { it.start() }
    }

    private inline fun <reified T : EntryScreen> EngineDesktopAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private suspend fun World.signedInDesktop(tag: String): EngineDesktopAppApi {
        val app = desktop(tag)
        app.entry.openOwnServer(app.at())
        assertEquals(ServerResult.DONE, app.entry.submitServerAddress(app.at(), origin))
        assertEquals(ServerResult.DONE, app.entry.confirmTrustGate(app.at()))
        assertEquals(ServerResult.DONE, app.entry.signInHere(app.at()))
        assertEquals(SignInAnswer.DONE, app.entry.submitSignIn(app.at(), email, Steps.PASSWORD))
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase, "the vault opens")
        return app
    }

    /** One authenticated call of the keeper's; with [refreshFirst] its first answer is a 401, so it refreshes once. */
    private suspend fun World.call(app: EngineDesktopAppApi, tag: String, refreshFirst: Boolean): WireResult<String> {
        val rule = if (refreshFirst) proxy.on(WireRoute.ACCOUNT_KEYS, tag, times = 1, handler = Handler { _ -> Resp.error(401, "invalid_credentials") }) else null
        try {
            return app.keeper.clientFor(origin).call(WireRoute.ACCOUNT_KEYS, decode = { it })
        } finally {
            rule?.remove()
        }
    }

    /** What the server answers a bearer call made with [accessToken], straight to it. */
    private suspend fun World.statusWith(accessToken: String): Int =
        server.httpFor(proxy.dial("raw")).get(origin + WireRoute.ACCOUNT_KEYS.path) { header("Authorization", "Bearer $accessToken") }.status.value

    private fun World.audits(type: String, meta: String? = null): Long = server.services.db.read { c ->
        if (meta == null) c.queryOne("SELECT COUNT(*) FROM audit WHERE type=?", type) { it.getLong(1) }
        else c.queryOne("SELECT COUNT(*) FROM audit WHERE type=? AND meta=?", type, meta) { it.getLong(1) }
    } ?: 0L

    /**
     * Both tries of a refresh cut off after the real server answered them, then one more request: no try is left.
     * Returns the token the device still holds and the access token of the pair it never got.
     */
    private suspend fun World.noTryLeft(app: EngineDesktopAppApi, tag: String): Pair<String, String> {
        val lose = proxy.on(WireRoute.REFRESH, tag, times = 2, handler = Handler { x -> x.forward(); null })
        val first = proxy.mark()
        call(app, tag, refreshFirst = true)
        call(app, tag, refreshFirst = true)
        lose.remove()
        val tries = proxy.since(first).filter { it.req.route == WireRoute.REFRESH && it.req.tag == tag }
        assertEquals(2, tries.size, "the first try and the one second try: ${proxy.tail()}")
        assertTrue(tries.all { it.dropped && it.upstream?.status == 200 }, "the real server answered both, the device got neither: $tries")
        val token = assertNotNull(tries[0].req.json?.str("refreshToken"))
        assertEquals(token, tries[1].req.json?.str("refreshToken"), "the second try sends the same token")
        val lostAccess = assertNotNull(tries[0].upstream?.json?.str("accessToken"))
        assertEquals(lostAccess, tries[1].upstream?.json?.str("accessToken"), "the server's grace answered the same pair")

        val mark = proxy.mark()
        call(app, tag, refreshFirst = true)
        assertTrue(proxy.requests(WireRoute.REFRESH, tag, mark).isEmpty(), "no try left: nothing is sent: ${proxy.tail()}")
        assertEquals(SessionEndReason.SESSION_NOT_CONFIRMED, app.keeper.lastEnd, "an end of its own")
        val kept = assertNotNull(app.keeper.session, "the account and its copy stay")
        assertTrue(kept.endedByServer && kept.endedUnconfirmed)
        return token to lostAccess
    }

    @Test fun noTryLeftEndsTheSessionOnTheDeviceAndTheNextSignInNamesItSoTheServerEndsItAsReplaced() = world {
        operator()
        member("alice")
        val app = signedInDesktop("desk")
        app.lock()
        val reusesBefore = audits("refresh_reuse")
        val namedBefore = audits("session_end", "sign_in_named_replaced")
        val (token, lostAccess) = noTryLeft(app, "desk")
        assertEquals(reusesBefore, audits("refresh_reuse"), "nothing the device did reads as a reuse")
        assertEquals(200, statusWith(lostAccess), "the session at the server is still live until the sign-in")

        val mark = proxy.mark()
        assertIs<SignIn.SignedIn>(app.onboardingFor(origin).signIn(email, Steps.PASSWORD.toCharArray()))
        val login = assertNotNull(proxy.last(WireRoute.LOGIN, "desk"))
        assertEquals(token, login.req.json?.str("replacesRefreshToken"), "the sign-in names the token kept for it")
        // The server's records: that session ended as replaced, by the name; no reuse; the new session lives.
        assertEquals(namedBefore + 1, audits("session_end", "sign_in_named_replaced"))
        assertEquals(reusesBefore, audits("refresh_reuse"), "no reuse is recorded")
        assertEquals(401, statusWith(lostAccess), "the pair the device never got reaches nothing")
        assertIs<WireResult.Ok<String>>(call(app, "desk", refreshFirst = true), "the new session lives, through a refresh of its own: ${proxy.tail()}")
        assertFalse(assertNotNull(app.keeper.session).endedByServer)
        assertNull(app.keeper.signInReplaces(origin, email, app.keeper.session!!.deviceId).takeIf { it == token }, "its one use was had")
        assertTrue(proxy.requests(tag = "desk", since = mark).none { it.route == WireRoute.END_SESSION || it.route == WireRoute.LOGOUT },
            "nothing else ends a session from this device: ${proxy.tail()}")
        assertTrue(proxy.requests(WireRoute.REFRESH, "desk", mark).none { it.json?.str("refreshToken") == token }, "the kept token is never sent as a refresh")
        assertEquals(reusesBefore, audits("refresh_reuse"))
    }

    /**
     * The open question, answered against the real server: a sign-in on the same device row that does NOT name the
     * session it replaces (here the proxy takes the name out of the request). The server ends the row's earlier sessions
     * all the same (one live session per device on an app's row), the old chain included, and records that end as an
     * ordinary sign-in's (`sign_in`), not as a replaced token's; no reuse is recorded, and the new session lives. What the
     * name adds on an app's row is the record that the token named had been replaced.
     */
    @Test fun aSignInOnTheSameRowThatDoesNotNameItEndsTheOldChainAllTheSameWithoutTheReplacedRecord() = world {
        operator()
        member("alice")
        val app = signedInDesktop("desk")
        app.lock()
        val reusesBefore = audits("refresh_reuse")
        val namedBefore = audits("session_end", "sign_in_named_replaced")
        val plainBefore = audits("session_end", "sign_in")
        val (_, lostAccess) = noTryLeft(app, "desk")

        val strip = proxy.on(WireRoute.LOGIN, "desk", times = 1, handler = Handler { x -> x.forward(x.req.withJson { it.set("replacesRefreshToken", null as JsonElement?) }) })
        assertIs<SignIn.SignedIn>(app.onboardingFor(origin).signIn(email, Steps.PASSWORD.toCharArray()))
        strip.remove()
        assertEquals(401, statusWith(lostAccess), "the old chain is ended by the sign-in on the same row")
        assertEquals(plainBefore + 1, audits("session_end", "sign_in"), "recorded as an ordinary sign-in's end")
        assertEquals(namedBefore, audits("session_end", "sign_in_named_replaced"), "with no record of a replaced token")
        assertEquals(reusesBefore, audits("refresh_reuse"), "no reuse is recorded")
        assertIs<WireResult.Ok<String>>(call(app, "desk", refreshFirst = true), "the new session lives: ${proxy.tail()}")
    }
}
