package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.RecoveryChangeResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A kit made in Settings is not confirmed until it is. The server voids the old kit
 * the moment it takes the new one, so the kept "kit confirmed" is false at once on this device, and on every other
 * device at its next opening; every unlock then makes a fresh kit until one is confirmed, as after registration.
 */
class EngineKitInSettingsTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    private fun app(server: FakeInstance, transport: BearerTransport): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", transport, MemoryDeviceState(), MemoryDeviceState(), crypto, { server.now }, baked = null, storeBuild = false,
            stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
    ).also { it.start() }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private suspend fun confirmKit(a: EngineAppApi) {
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
    }

    private suspend fun signUp(a: EngineAppApi) {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(a.at()))
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), "alice@example.com", true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "Alice", strong, true)))
        confirmKit(a)
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    private suspend fun signIn(b: EngineAppApi, origin: String) {
        b.entry.openSignIn(b.at())
        b.entry.openPasswordSignIn(b.at())
        assertEquals(ServerResult.DONE, b.entry.chooseOwnServer(b.at(), origin))
        (b.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, b.entry.confirmTrustGate(it)) }
        assertEquals(SignInAnswer.DONE, b.entry.submitSignIn(b.at(), "alice@example.com", strong))
        assertEquals(AppPhase.UNLOCKED, b.snapshot.phase)
    }

    /** Lock, unlock: true when the unlock asked for a fresh kit before the vault (the phase is the journey's). */
    private suspend fun kitAskedAtUnlock(a: EngineAppApi): Boolean {
        a.lock()
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        val kit = (a.snapshot.entry as? EntryScreen.Kit) ?: return false
        assertEquals(KitReason.NEVER_SAVED, kit.kit.reason)
        return a.snapshot.phase == AppPhase.ENTRY
    }

    @Test fun aKitMadeInSettingsAndNeverConfirmedIsAskedForAtEveryUnlock() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val transport = BearerTransport(mapOf(server.origin to server))
        val a = app(server, transport)
        signUp(a)
        // The screen says, before the person starts, that a new kit voids the one they hold (named by its key, so this
        // holds whatever its words are).
        assertEquals(PlainResult.DONE, a.recovery.openRecovery())
        val line = assertNotNull(a.snapshot.account!!.recovery).kitVoidsOldLine
        assertEquals(CopyKey.KIT_NEW_VOIDS_OLD, line.key)

        assertEquals(RecoveryChangeResult.DONE, a.recovery.makeKit(strong))
        assertFalse(server.accounts.values.single().recoveryConfirmed, "the server replaced the kit and holds it unconfirmed")
        assertFalse(a.keeper.session!!.recoveryConfirmed, "and so does this device, at once")
        // A lock (or the app killed) before the type-back: every unlock makes a fresh kit until one is confirmed.
        assertTrue(kitAskedAtUnlock(a), "the kit is asked for at the next unlock")
        confirmKit(a)
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        assertTrue(a.keeper.session!!.recoveryConfirmed)
        assertFalse(kitAskedAtUnlock(a), "and no more once one is confirmed")
    }

    @Test fun anotherDeviceLearnsAtItsNextOpeningThatTheKitIsUnconfirmed() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val transport = BearerTransport(mapOf(server.origin to server))
        val a = app(server, transport)
        signUp(a)
        val b = app(server, transport)
        signIn(b, server.origin)
        assertTrue(b.keeper.session!!.recoveryConfirmed)

        assertEquals(RecoveryChangeResult.DONE, a.recovery.makeKit(strong))
        // B's next opening reads the account's state: its kit is unconfirmed, so the unlock after asks for one.
        b.lock()
        assertEquals(VaultUnlockResult.DONE, b.unlock(b.snapshot.locked!!, strong))
        assertFalse(b.keeper.session!!.recoveryConfirmed, "B learned it at its opening")
        assertTrue(kitAskedAtUnlock(b), "and B's next unlock asks for a fresh kit")
    }
}
