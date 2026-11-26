package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PasswordChangeResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.engine.AppEngine
import io.silencelen.andvari.core.app.engine.EngineAppApi
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * Spec 01 §7, "KDF upgrade", through the app engine the Android and desktop apps run: an unlock with the master
 * password raises the account's KDF cost to the policy's, inline, after the vault opened, and the person sees nothing
 * of it, whatever the server answers.
 */
class EngineQuietReKeyTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val newer = "a whole New master password 7 here"
    private val up = KdfParams(ops = 4, memBytes = 64L * 1024 * 1024)

    private class Env(val server: FakeInstance, val liar: QuietReKeyTest.Liar, val app: EngineAppApi)

    private suspend fun env(): Env {
        val server = FakeInstance(crypto)
        val liar = QuietReKeyTest.Liar(server)
        val a = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.origin to liar)), MemoryDeviceState(), MemoryDeviceState(), crypto, { server.now },
                baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
        ).also { it.start() }
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
        return Env(server, liar, a)
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private suspend fun EngineAppApi.relock(password: String, putOff: Boolean? = null): VaultUnlockResult {
        lock()
        val screen = snapshot.locked!!
        // The Android overlay's way: the engine's FastUnlock, asked for as the overlay asks for it.
        val fast = (this as io.silencelen.andvari.core.app.AppApi) as? io.silencelen.andvari.core.app.FastUnlock
        return if (putOff == true) assertNotNull(fast).unlockPuttingOffReKey(screen, password) else unlock(screen, password)
    }

    private val Env.account get() = server.accounts.values.single()

    /** Before, the engine raised the cost only at a password change: an unlock left the account at 3 passes and 64 MiB. */
    @Test fun anUnlockWithTheMasterPasswordRaisesTheCostToThePolicysAndTheSamePasswordStillOpens() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        e.server.policyKdf = up
        assertEquals(KdfParams.DEFAULT, e.account.kdfParams)
        assertEquals(VaultUnlockResult.DONE, a.relock(strong))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        assertEquals(up, e.account.kdfParams, "the account is at the policy's cost")
        assertEquals(VaultUnlockResult.DONE, a.relock(strong), "the same password opens it")
        assertEquals(e.account.wrappedUvk, a.keeper.established!!.accountKeys.wrappedUvk, "from exactly the wrap the server holds")
        assertEquals(VaultUnlockResult.WRONG_PASSWORD, a.relock(newer))
        assertEquals(VaultUnlockResult.DONE, a.relock(strong))
        // The in-session proof follows the new wrap: a password change goes through.
        assertEquals(PasswordChangeResult.DONE, a.settings.changeMasterPassword(strong, newer))
        assertEquals(up, e.account.kdfParams, "never lower than the account already had")
    }

    @Test fun theAutofillOverlaysUnlockPutsItOffToTheNextUnlock() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        e.server.policyKdf = up
        assertEquals(VaultUnlockResult.DONE, a.relock(strong, putOff = true))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        assertEquals(0, e.liar.changes)
        assertEquals(ReKeyOutcome.PUT_OFF, a.keeper.lastReKey)
        // The switch is off by default, and a host that does not implement it unlocks as before.
        assertEquals(VaultUnlockResult.DONE, a.relock(strong, putOff = false))
        assertEquals(up, e.account.kdfParams)
    }

    @Test fun aFailedReKeyChangesNothingThePersonSees() = runBlocking<Unit> {
        for (mode in QuietReKeyTest.Change.entries.filter { it != QuietReKeyTest.Change.PASS }) {
            val e = env()
            val a = e.app
            e.server.policyKdf = up
            e.liar.change = mode
            assertEquals(VaultUnlockResult.DONE, a.relock(strong), "$mode")
            assertEquals(AppPhase.UNLOCKED, a.snapshot.phase, "$mode")
            assertNull(a.snapshot.locked, "$mode")
            assertEquals(1, e.liar.changes, "$mode")
            e.liar.change = QuietReKeyTest.Change.PASS
            // The account opens with the same password, and later openings converge on what the server holds.
            assertEquals(VaultUnlockResult.DONE, a.relock(strong), "$mode")
            assertEquals(VaultUnlockResult.DONE, a.relock(strong), "$mode")
            assertEquals(AppPhase.UNLOCKED, a.snapshot.phase, "$mode")
        }
    }

    /**
     * A server that answers "done" to a re-key it never stored, or stores one and answers a refusal, leaves this device's
     * own wrap and the server's verifier apart. Before, the account still opened with the same password, but every
     * re-authentication from this device (a password change here) was refused by the server as a wrong password until the
     * person signed in again: nothing at an opening settled a wrap that is neither the device's nor its pending one. The
     * next full-password opening now tries the served wrap with the password it verified and adopts it, since it opens to
     * the account's own key.
     */
    @Test fun aDoneNeverStoredOrARefusalThatWasStoredLeavesReAuthenticationWorking() = runBlocking<Unit> {
        for (mode in listOf(QuietReKeyTest.Change.DONE_NOT_APPLIED, QuietReKeyTest.Change.REFUSE_APPLIED)) {
            val e = env()
            val a = e.app
            e.server.policyKdf = up
            e.liar.change = mode
            assertEquals(VaultUnlockResult.DONE, a.relock(strong), "$mode")
            e.liar.change = QuietReKeyTest.Change.PASS
            assertEquals(VaultUnlockResult.DONE, a.relock(strong), "$mode")
            assertEquals(ServedWrap.ADOPTED, a.keeper.lastServedWrap, "$mode")
            assertEquals(false, a.keeper.session?.serverKeysNotKnownHere, "$mode")
            assertEquals(PasswordChangeResult.DONE, a.settings.changeMasterPassword(strong, newer), "$mode")
            assertEquals(VaultUnlockResult.DONE, a.relock(newer), "$mode")
        }
    }

    @Test fun aQuickUnlockAndAnOfflineUnlockSendNothing() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        e.server.policyKdf = up
        e.liar.policyAnswers = false
        assertEquals(VaultUnlockResult.DONE, a.relock(strong))
        assertEquals(ReKeyOutcome.NO_POLICY, a.keeper.lastReKey)
        assertEquals(0, e.liar.changes)
        e.liar.policyAnswers = true
        assertEquals(VaultUnlockResult.DONE, a.relock(strong))
        assertEquals(ReKeyOutcome.DONE, a.keeper.lastReKey)
    }
}
