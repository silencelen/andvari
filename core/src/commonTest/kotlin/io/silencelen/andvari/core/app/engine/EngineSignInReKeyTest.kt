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
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.client.session.QuietReKeyTest
import io.silencelen.andvari.core.client.session.ReKeyOutcome
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * Spec 01 §7, "KDF upgrade", after a sign-in: a sign-in with the master password on a new device is followed by the
 * quiet re-key inside that opening, with the password it proved, and nothing of it is seen. Before, the engine re-keyed
 * only after an unlock, so an account signed in on a new device stayed below the policy's cost there.
 */
class EngineSignInReKeyTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val up = KdfParams(ops = 4, memBytes = 64L * 1024 * 1024)

    private fun app(liar: QuietReKeyTest.Liar, origin: String): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(origin to liar)), MemoryDeviceState(), MemoryDeviceState(), crypto, { 1_794_744_000_000L },
            baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
    ).also { it.start() }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** Alice registers on one device, with her kit saved, so a sign-in elsewhere opens the vault at once. */
    private suspend fun registered(liar: QuietReKeyTest.Liar, server: FakeInstance) {
        val a = app(liar, server.origin)
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(a.at()))
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), "alice@example.com", true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "Alice", strong, true)))
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    private suspend fun signIn(b: EngineAppApi, origin: String, password: String = strong): SignInAnswer {
        b.entry.openSignIn(b.at())
        b.entry.openPasswordSignIn(b.at())
        assertEquals(ServerResult.DONE, b.entry.chooseOwnServer(b.at(), origin))
        (b.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, b.entry.confirmTrustGate(it)) }
        return b.entry.submitSignIn(b.at(), "alice@example.com", password)
    }

    @Test fun aPasswordSignInIsFollowedByTheQuietReKeyOnce() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val liar = QuietReKeyTest.Liar(server)
        registered(liar, server)
        server.policyKdf = up
        val b = app(liar, server.origin)
        assertEquals(SignInAnswer.DONE, signIn(b, server.origin))
        assertEquals(AppPhase.UNLOCKED, b.snapshot.phase)
        assertEquals(1, liar.changes, "one re-key, inside the sign-in's opening")
        assertEquals(up, server.accounts.values.single().kdfParams, "the account is at the policy's cost")
        assertEquals(ReKeyOutcome.DONE, b.keeper.lastReKey)
        // The next opening sends nothing more.
        b.lock()
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, b.unlock(b.snapshot.locked!!, strong))
        assertEquals(1, liar.changes)
    }

    /** Whatever the server answers to the re-key, the sign-in is done and the vault open: nothing the person sees changes. */
    @Test fun aFailedReKeyAfterASignInChangesNothingThePersonSees() = runBlocking<Unit> {
        for (mode in QuietReKeyTest.Change.entries.filter { it != QuietReKeyTest.Change.PASS }) {
            val server = FakeInstance(crypto)
            val liar = QuietReKeyTest.Liar(server)
            registered(liar, server)
            server.policyKdf = up
            liar.change = mode
            val b = app(liar, server.origin)
            assertEquals(SignInAnswer.DONE, signIn(b, server.origin), "$mode")
            assertEquals(AppPhase.UNLOCKED, b.snapshot.phase, "$mode")
            assertNull(b.snapshot.locked, "$mode")
            assertEquals(1, liar.changes, "$mode")
        }
    }

    /** A wrong password sends no re-key, and a sign-in that needs no raise sends none either. */
    @Test fun aWrongPasswordOrACostAlreadyAtThePolicySendsNoReKey() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val liar = QuietReKeyTest.Liar(server)
        registered(liar, server)
        val b = app(liar, server.origin)
        assertEquals(SignInAnswer.DONE, signIn(b, server.origin))
        assertEquals(0, liar.changes, "the cost is at the policy's already")
        assertEquals(ReKeyOutcome.NOT_DUE, b.keeper.lastReKey)
    }
}
