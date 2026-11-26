package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.QuickEnrolResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.client.session.QuickUnlockKeeper
import io.silencelen.andvari.core.client.session.TestClocks
import io.silencelen.andvari.core.client.session.TestKeyWrap
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.ClientPolicy
import io.silencelen.andvari.core.model.wire.SignupMode
import io.silencelen.andvari.core.model.wire.SignupPolicy
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Quick unlock and a server's policy that forbids keeping data on the device: the quick-unlock key is the account's key,
 * sealed, and it does not stay on the device under such a policy, also where the policy is recorded while the
 * enrolment's prompt is on show. Over the real engine and its test server.
 */
class EnginePolicyQuickUnlockTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    private class Env(val server: FakeInstance, val secure: MemoryDeviceState, val wrap: TestKeyWrap, val app: EngineAppApi)

    private fun env(): Env {
        val server = FakeInstance(crypto)
        val secure = MemoryDeviceState()
        val wrap = TestKeyWrap()
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.origin to server)), MemoryDeviceState(), secure, crypto,
                { server.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
                keyWrap = wrap, clocks = TestClocks(wall = server.now)),
        ).also { it.start() }
        return Env(server, secure, wrap, app)
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private suspend fun open(a: EngineAppApi) {
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

    private fun Env.forbidding() =
        ClientPolicy(emptyMap(), KdfParams.DEFAULT, 300, 30, false, 3600, 30, 1, 1, server.now, SignupPolicy(SignupMode.OPEN, false, true, 0), false)

    /**
     * An enrolment whose prompt is on show when a forbidding policy is recorded writes no key when the prompt completes:
     * it looks at the policy again before it writes. Nothing sealed is kept, the platform key is gone, and the locked
     * screen offers no quick unlock.
     */
    @Test fun anEnrolmentWhosePromptWasUpWhenAForbiddingPolicyWasRecordedWritesNoKey() = runBlocking<Unit> {
        val e = env()
        open(e.app)
        val setting = assertNotNull(e.app.snapshot.account).quickUnlock
        assertTrue(setting.offerNow, "quick unlock is offered under the policy that allows keeping")
        val up = CompletableDeferred<Unit>()
        e.wrap.promptUp = up
        val answer = async(start = CoroutineStart.UNDISPATCHED) { e.app.settings.turnOnQuickUnlock(setting) }
        assertEquals(1, e.wrap.prompts, "the prompt is on show")
        // The policy is recorded while the prompt is up (as an answer of a read that was out is).
        e.app.policies.record(e.server.origin, e.forbidding(), e.server.now)
        up.complete(Unit)
        assertNotEquals(QuickEnrolResult.DONE, answer.await())
        assertNull(e.secure.get(QuickUnlockKeeper.KEY_SEALED), "no sealed key was written")
        assertTrue(e.wrap.keys.isEmpty(), "the platform key made for it is gone")
        e.app.lock()
        assertFalse(assertNotNull(e.app.snapshot.locked).quickUnlock, "no quick unlock is offered")
        assertNull(e.secure.get(QuickUnlockKeeper.KEY_SEALED))
    }
}
