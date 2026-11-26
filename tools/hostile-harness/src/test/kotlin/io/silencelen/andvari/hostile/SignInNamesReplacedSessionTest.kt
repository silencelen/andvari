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
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Handler
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.str
import io.silencelen.andvari.server.queryOne
import kotlinx.coroutines.Dispatchers
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A sign-in names the session it replaces, and the REAL server ends that one with the sign-in. Through a proxy that loses
 * the answer to a refresh: the server rotated the kept session's tokens, the device still holds the replaced refresh
 * token. The sign-in on the same device row names that token. The new session lives; the old one is ended by the server,
 * whose record of that end says the token named had already been replaced (the sign of a lost answer); no reuse is
 * recorded; and the device sends no end-session and no sign-out. Before, the login named nothing, and a server that ends
 * a row's earlier sessions anyway kept no record that the token named had been replaced.
 */
class SignInNamesReplacedSessionTest {
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

    /** How many rows of the server's audit record have [type] (and [meta], when given). */
    private fun World.audits(type: String, meta: String? = null): Long = server.services.db.read { c ->
        if (meta == null) c.queryOne("SELECT COUNT(*) FROM audit WHERE type=?", type) { it.getLong(1) }
        else c.queryOne("SELECT COUNT(*) FROM audit WHERE type=? AND meta=?", type, meta) { it.getLong(1) }
    } ?: 0L

    @Test fun aSignInAfterALostRefreshAnswerNamesTheTokenItHoldsAndTheServerEndsThatSessionAsReplaced() = world {
        operator()
        member("alice")
        val app = signedInDesktop("desk")
        app.lock()
        // A refresh the real server answers, whose answer the device never gets.
        val lose = proxy.on(WireRoute.REFRESH, "desk", times = 1, handler = Handler { x -> x.forward(); Resp.error(502, "bad_gateway") })
        call(app, "desk", refreshFirst = true)
        lose.remove()
        val refresh = assertNotNull(proxy.last(WireRoute.REFRESH, "desk"))
        assertEquals(200, assertNotNull(refresh.upstream, "the real server answered the refresh").status)
        val replaced = assertNotNull(refresh.req.json?.str("refreshToken"))
        val lostAccess = assertNotNull(refresh.upstream?.json?.str("accessToken"))
        val namedBefore = audits("session_end", "sign_in_named_replaced")
        val reusesBefore = audits("refresh_reuse")

        val mark = proxy.mark()
        val r = app.onboardingFor(origin).signIn(email, Steps.PASSWORD.toCharArray())
        assertIs<SignIn.SignedIn>(r, "signed in: $r")
        val login = assertNotNull(proxy.last(WireRoute.LOGIN, "desk"))
        assertEquals(replaced, login.req.json?.str("replacesRefreshToken"), "the login names the token the device still holds")
        assertTrue(proxy.requests(tag = "desk", since = mark).none { it.route == WireRoute.END_SESSION || it.route == WireRoute.LOGOUT },
            "no end-session and no sign-out from this device: ${proxy.tail()}")

        // The new session lives, through a refresh of its own.
        assertIs<WireResult.Ok<String>>(call(app, "desk", refreshFirst = true), "the new session answers after its refresh: ${proxy.tail()}")
        assertFalse(assertNotNull(app.keeper.session).endedByServer)
        // The old one is ended: the token pair of the lost answer reaches nothing.
        assertEquals(401, statusWith(lostAccess))
        // The server's record: that session ended because the sign-in named a token it had replaced; no reuse.
        assertEquals(namedBefore + 1, audits("session_end", "sign_in_named_replaced"), "the end is recorded as a named, replaced token")
        assertEquals(reusesBefore, audits("refresh_reuse"), "no reuse is recorded")
        assertTrue(proxy.requests(tag = "desk", since = mark).none { it.route == WireRoute.END_SESSION || it.route == WireRoute.LOGOUT },
            "and none afterwards either: ${proxy.tail()}")
    }
}
