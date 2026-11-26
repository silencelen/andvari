package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * An entry intent the person left must not complete. After the engine's call the screen is
 * checked again; what a left call established is ended (its logout to its own origin), a different kept session is
 * never replaced, and a call that waits on a server has a time limit.
 */
class EngineEntryLateTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val aOrigin = "https://a.example"

    /** Server A, whose login answer waits until [gate] is completed (a hostile server chooses when to answer). */
    private class Held(val inner: FakeInstance) : WireClient by inner {
        var gate: CompletableDeferred<Unit>? = null
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            if (route == WireRoute.LOGIN) gate?.await()
            return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
        }
    }

    private class Env(val a: Held, val h: FakeInstance, val transport: BearerTransport)

    private fun env(): Env {
        val a = Held(FakeInstance(crypto, aOrigin, "abababab-abab-4bab-8bab-abababababab"))
        val h = FakeInstance(crypto)
        return Env(a, h, BearerTransport(mapOf(aOrigin to a, h.origin to h)))
    }

    private fun Env.app(): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", transport, MemoryDeviceState(), MemoryDeviceState(), crypto, { h.now }, baked = null,
            storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
    ).also { it.start() }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** Sign-up at [address] from the first screen, through the kit: the vault is open. */
    private suspend fun signUp(x: EngineAppApi, address: String, email: String) {
        x.entry.openOwnServer(x.at())
        assertEquals(ServerResult.DONE, x.entry.submitServerAddress(x.at(), address))
        assertEquals(ServerResult.DONE, x.entry.confirmTrustGate(x.at()))
        assertEquals(ServerResult.DONE, x.entry.createAccountHere(x.at()))
        assertEquals(SignUpStartResult.DONE, x.entry.startSignUp(x.at(), email, true))
        assertEquals(CodeResult.DONE, x.entry.verifySignUpCode(x.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, x.entry.createAccount(x.at(), NewAccountInput("", "Someone", strong, true)))
        val kit = x.at<EntryScreen.Kit>()
        val doc = assertNotNull(x.kit.kitDocument(kit.kit))
        x.kit.proceedToConfirm(kit.kit)
        val confirm = x.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, x.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, x.snapshot.phase)
    }

    /** An account at A made on another device, and this device on A's sign-in form. */
    private suspend fun Env.signInFormAtA(b: EngineAppApi): EntryScreen.SignIn {
        signUp(app(), "a.example", "alice@example.com")
        b.entry.openSignIn(b.at())
        b.entry.openPasswordSignIn(b.at())
        assertEquals(ServerResult.DONE, b.entry.chooseOwnServer(b.at(), aOrigin))
        assertEquals(ServerResult.DONE, b.entry.confirmTrustGate(b.at<EntryScreen.TrustGate>()))
        return b.at()
    }

    private fun Env.logoutsTo(origin: String) = transport.sent.count { it.route == WireRoute.LOGOUT && it.origin == origin }

    /** A refused session is ended by its own refresh token: that ends it alone, where a logout ends every session of the device there. */
    private fun Env.sessionEndsAt(origin: String) = transport.sent.count { it.route == WireRoute.END_SESSION && it.origin == origin }

    /** Server A answers after the person made an account at H and locked. Nothing of A's sign-in completes. */
    @Test fun aSignInAnsweredAfterThePersonMovedOnDoesNotReplaceTheOtherSession() = runBlocking<Unit> {
        val e = env()
        val b = e.app()
        val form = e.signInFormAtA(b)
        val gate = CompletableDeferred<Unit>().also { e.a.gate = it }
        val pending = async(start = CoroutineStart.UNDISPATCHED) { b.entry.submitSignIn(form, "alice@example.com", strong) }
        b.entry.startOver()
        signUp(b, "h.example", "bob@example.com")
        b.lock()
        val bob = b.keeper.session!!
        gate.complete(Unit)
        assertEquals(SignInAnswer.STALE, pending.await())
        assertEquals(AppPhase.LOCKED, b.snapshot.phase)
        val kept = assertNotNull(b.keeper.session)
        assertEquals(e.h.origin, kept.origin, "the session made at H is still the one kept")
        assertEquals(bob.userId, kept.userId)
        assertNull(b.keeper.established, "and still locked")
        assertEquals(1, e.sessionEndsAt(aOrigin), "A's session, and only that one, is ended at A")
        assertEquals(0, e.logoutsTo(aOrigin), "never every session of the device there")
        assertEquals(0, e.logoutsTo(e.h.origin))
    }

    /** The person went back to the first screen and stayed there: A's late session is ended, nothing is kept. */
    @Test fun aSignInAnsweredAfterThePersonLeftItEndsTheSessionItMade() = runBlocking<Unit> {
        val e = env()
        val b = e.app()
        val form = e.signInFormAtA(b)
        val gate = CompletableDeferred<Unit>().also { e.a.gate = it }
        val pending = async(start = CoroutineStart.UNDISPATCHED) { b.entry.submitSignIn(form, "alice@example.com", strong) }
        b.entry.startOver()
        val first = b.at<EntryScreen.FirstRun>()
        gate.complete(Unit)
        assertEquals(SignInAnswer.STALE, pending.await())
        assertEquals(AppPhase.ENTRY, b.snapshot.phase)
        assertTrue(b.snapshot.entry === first, "the screen the person is on stays")
        assertNull(b.keeper.session)
        assertEquals(1, e.sessionEndsAt(aOrigin), "the session it made, and only that one, is ended at A")
        assertEquals(0, e.logoutsTo(aOrigin), "never every session of the device there")
    }

    /** A server that never answers: the sign-in answers UNREACHABLE in time, and nothing is kept. */
    @Test fun aSignInThatWaitsTooLongIsUnreachable() = runBlocking<Unit> {
        val e = env()
        val b = e.app()
        val form = e.signInFormAtA(b)
        e.a.gate = CompletableDeferred()
        b.entryCallMs = 50
        // (The test's own limit: without the binding's, the call would wait for ever.)
        val answer = kotlinx.coroutines.withTimeoutOrNull(10_000) { b.entry.submitSignIn(form, "alice@example.com", strong) }
        assertEquals(SignInAnswer.UNREACHABLE, answer)
        assertNull(b.keeper.session)
        assertTrue(b.snapshot.entry === form, "the form stays, to try again")
    }
}
