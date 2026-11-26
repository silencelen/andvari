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
import kotlinx.coroutines.Dispatchers
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A device has one live session, and the server keeps that rule itself: a sign-in on a known device ends that device's
 * earlier session. Against the REAL server, through a proxy that loses the answer to a refresh: the server rotated the
 * kept session's tokens, the device still holds the replaced ones. A sign-in then takes the kept session's place. The
 * device sends nothing with the kept session's token (the server ended that session at the sign-in); before, it ended it
 * by that replaced token, which the server read as a stolen token's reuse, ending every session of the device, the new
 * one too: the person was signed in, then at once signed out by the server. A session the device itself refuses, or the
 * session of a call the person left, is still ended by the device by its own token.
 */
class SignInOverLostRefreshTest {
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

    /** One authenticated call of the keeper's whose first answer is a 401, so it refreshes once. */
    private suspend fun World.call(app: EngineDesktopAppApi, tag: String, refreshFirst: Boolean): WireResult<String> {
        val rule = if (refreshFirst) proxy.on(WireRoute.ACCOUNT_KEYS, tag, times = 1, handler = Handler { _ -> Resp.error(401, "invalid_credentials") }) else null
        try {
            return app.keeper.clientFor(origin).call(WireRoute.ACCOUNT_KEYS, decode = { it })
        } finally {
            rule?.remove()
        }
    }

    /**
     * A refresh the real server answers, whose answer the device never gets: returns the replaced refresh token (the one
     * the device still holds) and the access token of the answer it lost.
     */
    private suspend fun World.refreshAnswerLost(app: EngineDesktopAppApi, tag: String): Pair<String, String> {
        val lose = proxy.on(WireRoute.REFRESH, tag, times = 1, handler = Handler { x -> x.forward(); Resp.error(502, "bad_gateway") })
        call(app, tag, refreshFirst = true)
        lose.remove()
        val refresh = assertNotNull(proxy.last(WireRoute.REFRESH, tag))
        assertEquals(200, assertNotNull(refresh.upstream, "the real server answered the refresh").status)
        val replaced = assertNotNull(refresh.req.json?.str("refreshToken"))
        val lostAccess = assertNotNull(refresh.upstream?.json?.str("accessToken"))
        return replaced to lostAccess
    }

    /** What the server answers a bearer call made with [accessToken], straight to it. */
    private suspend fun World.statusWith(accessToken: String): Int =
        server.httpFor(proxy.dial("raw")).get(origin + WireRoute.ACCOUNT_KEYS.path) { header("Authorization", "Bearer $accessToken") }.status.value

    private fun World.endsSentWith(tag: String, mark: Int, refreshToken: String) =
        proxy.requests(tag = tag, since = mark).filter { (it.route == WireRoute.END_SESSION || it.route == WireRoute.REFRESH) && String(it.body).contains(refreshToken) }

    @Test fun aSignInAfterALostRefreshAnswerKeepsTheNewSessionAndSendsNothingWithTheReplacedToken() = world {
        operator()
        member("alice")
        val app = signedInDesktop("desk")
        app.lock()
        val (replaced, lostAccess) = refreshAnswerLost(app, "desk")
        val mark = proxy.mark()
        val r = app.onboardingFor(origin).signIn(email, Steps.PASSWORD.toCharArray())
        assertIs<SignIn.SignedIn>(r, "signed in: $r")
        assertTrue(proxy.requests(tag = "desk", since = mark).none { it.route == WireRoute.END_SESSION || it.route == WireRoute.LOGOUT },
            "nothing ends a session from this device: ${proxy.tail()}")
        assertEquals(emptyList(), endsSentWith("desk", mark, replaced), "nothing is sent with the kept session's replaced token")
        // The new session lives, through a refresh of its own.
        assertIs<WireResult.Ok<String>>(call(app, "desk", refreshFirst = true), "the new session answers after its refresh: ${proxy.tail()}")
        assertFalse(assertNotNull(app.keeper.session).endedByServer)
        // The old session is ended: the token pair of the lost answer reaches nothing.
        assertEquals(401, statusWith(lostAccess))
    }

    /**
     * The same edge for the session of a call the person left: it is ended by the device alone, by its own token, after
     * its own refresh's answer was lost. The device holds nothing live there afterwards, the kept session's replaced
     * token is still never sent, and the next sign-in signs in.
     */
    @Test fun aLeftSignInsSessionIsEndedAloneAndTheNextSignInWorks() = world {
        operator()
        member("alice")
        val app = signedInDesktop("desk")
        app.lock()
        val (replaced, _) = refreshAnswerLost(app, "desk")
        val takes = app.keeper.takes
        val mark = proxy.mark()
        assertIs<SignIn.SignedIn>(app.onboardingFor(origin).signIn(email, Steps.PASSWORD.toCharArray()))
        // The new session's own refresh answer is lost too, then the person turns out to have left the call.
        refreshAnswerLost(app, "desk")
        val end = assertNotNull(app.keeper.endTakenSince(takes), "the left call's session is ended")
        end()
        assertEquals(emptyList(), endsSentWith("desk", mark, replaced), "the kept session's replaced token is never sent")
        assertTrue(proxy.requests(WireRoute.LOGOUT, "desk", mark).isEmpty(), "never a sign-out")
        val kept = assertNotNull(app.keeper.session)
        assertTrue(kept.endedByServer, "the kept record comes back without tokens")
        assertIs<SignIn.SignedIn>(app.onboardingFor(origin).signIn(email, Steps.PASSWORD.toCharArray()), "the next sign-in signs in")
        assertIs<WireResult.Ok<String>>(call(app, "desk", refreshFirst = true))
    }
}
