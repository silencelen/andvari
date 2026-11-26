package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** A lock reaches the keys and passwords the journey holds. */
class EngineLockTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    private fun app(server: FakeInstance): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.origin to server)), MemoryDeviceState(), MemoryDeviceState(), crypto,
            { server.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
    ).also { it.start() }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** Sign-up up to the kit on show. */
    private suspend fun toKit(a: EngineAppApi): EntryScreen.Kit {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(a.at()))
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), "alice@example.com", true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "Alice", strong, true)))
        return a.at()
    }

    /**
     * An unexpected exception in the app interface's own scope is contained by the scope itself and published as a count
     * the apps can say, with no text of it kept; the app goes on. A platform's own handler, handed in with `main`, is kept.
     * Before, the scope had no handler: on a platform that passed none, the exception ended the process.
     */
    @Test fun anUnexpectedFaultInTheAppInterfacesOwnWorkIsContainedAndSaid() = runBlocking<Unit> {
        val a = app(FakeInstance(crypto))
        assertEquals(0, a.snapshot.containedFaults)
        a.scope.launch { throw IllegalStateException("secret text that must not show") }.join()
        assertEquals(1, a.snapshot.containedFaults)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.CONTAINED_FAULT, a.snapshot.containedFaultLine)
        // It goes on: the next work in the scope runs.
        var ran = false
        a.scope.launch { ran = true }.join()
        assertTrue(ran)
        assertIs<EntryScreen.FirstRun>(a.snapshot.entry)

        // A platform's own handler stays the one that answers.
        var theirs = 0
        val server = FakeInstance(crypto)
        val b = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.origin to server)), MemoryDeviceState(), MemoryDeviceState(), crypto,
                { server.now }, baked = null, storeBuild = false, stores = null,
                main = Dispatchers.Unconfined + kotlinx.coroutines.CoroutineExceptionHandler { _, _ -> theirs++ }, work = Dispatchers.Unconfined),
        ).also { it.start() }
        b.scope.launch { throw IllegalStateException("x") }.join()
        assertEquals(1, theirs)
        assertEquals(0, b.snapshot.containedFaults)
    }

    /** A lock while the kit is on show wipes the kit and the keys; the next unlock makes a fresh kit. */
    @Test fun aLockOnTheKitStepWipesTheKitAndTheKeys() = runBlocking<Unit> {
        val a = app(FakeInstance(crypto))
        val kit = toKit(a)
        assertNotNull(a.kit.kitDocument(kit.kit))
        a.lock()
        assertEquals(AppPhase.LOCKED, a.snapshot.phase)
        assertNull(a.keeper.established, "the keys are wiped")
        assertNull(a.kit.kitDocument(kit.kit), "the kit's secret is no longer readable")
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        val fresh = a.at<EntryScreen.Kit>()
        assertFalse(fresh.kit === kit.kit, "a fresh kit")
    }

    /** Sign-out works on the kit step. */
    @Test fun signingOutOnTheKitStepEndsTheSession() = runBlocking<Unit> {
        val a = app(FakeInstance(crypto))
        toKit(a)
        assertEquals(PlainResult.DONE, a.signOut())
        assertEquals(AppPhase.ENTRY, a.snapshot.phase)
        assertNull(a.keeper.session)
        assertNull(a.keeper.established)
    }

    /** Sign-in at [server] up to its code step, from another device's account there. */
    private suspend fun toCodeStep(server: FakeInstance): Pair<EngineAppApi, EntryScreen.SignIn> {
        val first = app(server)
        toKit(first)
        server.account("alice@example.com").totp = "JBSWY3DPEHPK3PXP"
        val b = app(server)
        b.entry.openSignIn(b.at())
        b.entry.openPasswordSignIn(b.at())
        assertEquals(ServerResult.DONE, b.entry.chooseOwnServer(b.at(), server.origin))
        assertEquals(ServerResult.DONE, b.entry.confirmTrustGate(b.at<EntryScreen.TrustGate>()))
        assertEquals(SignInAnswer.CODE_NEEDED, b.entry.submitSignIn(b.at(), "alice@example.com", strong))
        val code = b.at<EntryScreen.SignIn>()
        assertTrue(code.codeNeeded)
        return b to code
    }

    /** The password kept at a code step lasts the two-step key's ten minutes; past them the step goes. */
    @Test fun thePasswordKeptAtACodeStepLastsTenMinutes() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val (b, code) = toCodeStep(server)
        server.now += 10 * 60_000L + 1
        assertEquals(SignInAnswer.STALE, b.entry.submitSignInCode(code, "123456"))
        assertFalse(b.at<EntryScreen.SignIn>().codeNeeded, "the password is asked again")
        assertNull(b.keeper.session)
    }

    /** A lock during the journey wipes the password kept at a code step, and the step with it. */
    @Test fun aLockAtACodeStepWipesTheKeptPassword() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val (b, code) = toCodeStep(server)
        b.lock()
        assertEquals(SignInAnswer.STALE, b.entry.submitSignInCode(code, "123456"))
        assertFalse(b.at<EntryScreen.SignIn>().codeNeeded)
    }
}
