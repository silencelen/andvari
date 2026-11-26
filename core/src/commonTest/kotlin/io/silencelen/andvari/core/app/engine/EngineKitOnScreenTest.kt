package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.KitScreen
import io.silencelen.andvari.core.app.KitStep
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.RecoveryChangeResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.UnlockForFilling
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.ClientPolicy
import io.silencelen.andvari.core.model.wire.SignupPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * What the apps need from the shared code to keep the rules of a recovery kit on the screen, over the real engine:
 * every kit carries its idle limit and warning (the policy this device keeps for its server, five minutes where it keeps
 * none), a kit that replaces one shown here and never confirmed says so on its first step, and an unlock from a surface
 * that only fills makes no kit.
 */
class EngineKitOnScreenTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    private fun app(server: FakeInstance, transport: BearerTransport, state: MemoryDeviceState = MemoryDeviceState(), secure: MemoryDeviceState = MemoryDeviceState()): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", transport, state, secure, crypto, { server.now }, baked = null, storeBuild = false,
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

    /** A registration up to its first kit, on show and not confirmed. */
    private suspend fun signUpToKit(a: EngineAppApi) {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(a.at()))
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), "alice@example.com", true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "Alice", strong, true)))
        assertEquals(KitReason.FIRST_KIT, a.at<EntryScreen.Kit>().kit.reason)
    }

    private suspend fun signIn(b: EngineAppApi, origin: String) {
        b.entry.openSignIn(b.at())
        b.entry.openPasswordSignIn(b.at())
        assertEquals(ServerResult.DONE, b.entry.chooseOwnServer(b.at(), origin))
        (b.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, b.entry.confirmTrustGate(it)) }
        assertEquals(SignInAnswer.DONE, b.entry.submitSignIn(b.at(), "alice@example.com", strong))
        assertEquals(AppPhase.UNLOCKED, b.snapshot.phase)
    }

    /** The server's policy as this device keeps it, with [autoLockSeconds]. */
    private fun keepPolicy(a: EngineAppApi, server: FakeInstance, autoLockSeconds: Long) {
        a.policies.record(server.origin, ClientPolicy(emptyMap(), KdfParams.DEFAULT, autoLockSeconds, 30, true, 3600, 30, 1, 1, server.now,
            SignupPolicy("open", false, true, 0), false), server.now)
    }

    /** [warned] false: the limit is not longer than the warning's thirty seconds, so the warning is shown from the start. */
    private fun assertLimit(kit: KitScreen, limitMs: Long, warned: Boolean, where: String) {
        assertEquals(limitMs, kit.idleLockAfterMs, "$where: the limit")
        assertEquals(if (warned) 30_000L else limitMs, kit.idleWarnBeforeMs, "$where: the warning's lead")
        // Every kit has the warning; where no thirty seconds are left, the line of its own that names the limit.
        assertEquals(if (warned) CopyKey.KIT_IDLE_WARNING else CopyKey.KIT_IDLE_WARNING_SHORT, kit.idleWarningLine, "$where: every kit has the warning")
        val line = assertNotNull(kit.idleWarning, where)
        assertEquals(kit.idleWarningLine, line.key, where)
        assertEquals(if (warned) emptyList() else listOf(((limitMs + 999) / 1000).toString()), line.values, "$where: the limit, never 30 where untrue")
    }

    @Test fun everyKitCarriesTheLockTimeOfThePolicyKeptForItsServerWithItsWarning() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val a = app(server, BearerTransport(mapOf(server.origin to server)))
        signUpToKit(a)
        // A registration's first kit, before this device keeps any policy for the server: five minutes, warned.
        assertNull(a.policies.get(server.origin), "no policy is kept yet")
        assertLimit(a.at<EntryScreen.Kit>().kit, 300_000L, warned = true, where = "first kit")
        confirmKit(a)
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)

        // The server's policy says one minute: a kit in Settings (the account open) goes at it, with the warning.
        keepPolicy(a, server, 60)
        assertEquals(RecoveryChangeResult.DONE, a.recovery.makeKit(strong))
        assertLimit(assertNotNull(a.snapshot.account!!.kit), 60_000L, warned = true, where = "Settings kit")

        // The lock takes it; the unlock's kit in the journey (no account open, the apps see no policy) has the same figure.
        a.lock()
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        val kit = a.at<EntryScreen.Kit>().kit
        assertEquals(KitReason.NEVER_SAVED, kit.reason)
        assertLimit(kit, 60_000L, warned = true, where = "never-saved kit")
        a.kit.proceedToConfirm(kit)
        assertLimit(a.at<EntryScreen.Kit>().kit, 60_000L, warned = true, where = "its confirm step")

        // A policy of twenty seconds: the lock comes at it, and the warning is on show from the start of the screen.
        keepPolicy(a, server, 20)
        a.lock()
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertLimit(a.at<EntryScreen.Kit>().kit, 20_000L, warned = false, where = "short policy")
    }

    @Test fun theSmallestLockTimeAPolicyCanGiveStillWarnsFromTheStartOfTheKit() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val a = app(server, BearerTransport(mapOf(server.origin to server)))
        signUpToKit(a)
        confirmKit(a)
        // One second: the smallest the server takes and the device keeps (a policy of 0 or less is read as the largest).
        assertEquals(1, io.silencelen.andvari.core.client.session.clampAutoLockSeconds(1))
        keepPolicy(a, server, 1)
        assertEquals(1, a.policies.get(server.origin)!!.autoLockSeconds)
        assertEquals(RecoveryChangeResult.DONE, a.recovery.makeKit(strong))
        val settings = assertNotNull(a.snapshot.account!!.kit)
        assertEquals(1_000L, settings.idleLockAfterMs)
        assertEquals(1_000L, settings.idleWarnBeforeMs, "the warning stands from the start: a touch keeps the kit")
        assertEquals(CopyKey.KIT_IDLE_WARNING_SHORT, settings.idleWarningLine)
        assertEquals(listOf("1"), assertNotNull(settings.idleWarning).values)
        a.lock()
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertLimit(a.at<EntryScreen.Kit>().kit, 1_000L, warned = false, where = "one-second policy, in the journey")
        // Exactly thirty seconds is not longer than the warning: from the start too, with the short line (the long one's
        // "in thirty seconds" would be untrue there); a second more, thirty seconds before, with the long line.
        assertEquals(Triple(30_000L, 30_000L, CopyKey.KIT_IDLE_WARNING_SHORT), KitScreen.idleLimits(30, notKept = true))
        assertEquals(Triple(31_000L, 30_000L, CopyKey.KIT_IDLE_WARNING), KitScreen.idleLimits(31, notKept = false))
    }

    @Test fun aKitShownWithARefusalIsNeverLeftLongerThanFiveMinutes() {
        // The limits as the engine hands them out for each kind of kit (the refusal's road itself is walked in EngineKeptStopsTest).
        assertEquals(Triple(300_000L, 30_000L, CopyKey.KIT_IDLE_WARNING), KitScreen.idleLimits(900, notKept = true))
        assertEquals(Triple(60_000L, 30_000L, CopyKey.KIT_IDLE_WARNING), KitScreen.idleLimits(60, notKept = true))
        assertEquals(Triple(900_000L, 30_000L, CopyKey.KIT_IDLE_WARNING), KitScreen.idleLimits(900, notKept = false))
        assertEquals(Triple(300_000L, 30_000L, CopyKey.KIT_IDLE_WARNING), KitScreen.idleLimits(null, notKept = false))
        assertEquals(Triple(30_000L, 30_000L, CopyKey.KIT_IDLE_WARNING_SHORT), KitScreen.idleLimits(30, notKept = false))
    }

    @Test fun aKitThatReplacesOneShownHereAndNeverConfirmedSaysSoOnItsFirstStepAlsoAfterARestart() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val transport = BearerTransport(mapOf(server.origin to server))
        val state = MemoryDeviceState()
        val secure = MemoryDeviceState()
        val a = app(server, transport, state, secure)
        signUpToKit(a)
        assertNull(a.at<EntryScreen.Kit>().kit.earlierKitVoidLine, "the first kit replaces none")

        // A lock takes the first kit before it was typed back; the next unlock's kit says, on its reveal, that it is void.
        a.lock()
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        val next = a.at<EntryScreen.Kit>().kit
        assertEquals(KitStep.REVEAL, next.step)
        assertEquals(CopyKey.KIT_EARLIER_NOT_CONFIRMED_VOID, next.earlierKitVoidLine)
        a.kit.proceedToConfirm(next)
        assertNull(a.at<EntryScreen.Kit>().kit.earlierKitVoidLine, "only the first step carries it")
        a.kit.showKitAgain(a.at<EntryScreen.Kit>().kit)
        assertEquals(CopyKey.KIT_EARLIER_NOT_CONFIRMED_VOID, a.at<EntryScreen.Kit>().kit.earlierKitVoidLine, "the reveal again says it again")
        confirmKit(a)
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)

        // Confirmed: a kit made in Settings now replaces a confirmed one, and says nothing of the kind.
        assertEquals(RecoveryChangeResult.DONE, a.recovery.makeKit(strong))
        assertNull(assertNotNull(a.snapshot.account!!.kit).earlierKitVoidLine)

        // A lock takes the Settings kit; the app is closed and started again: the unlock's kit still says it.
        a.lock()
        a.close()
        val again = app(server, transport, state, secure)
        assertEquals(AppPhase.LOCKED, again.snapshot.phase)
        assertEquals(VaultUnlockResult.DONE, again.unlock(again.snapshot.locked!!, strong))
        assertEquals(CopyKey.KIT_EARLIER_NOT_CONFIRMED_VOID, again.at<EntryScreen.Kit>().kit.earlierKitVoidLine)
        // Nothing of the kit is in the mark: only the origin and the address.
        val marks = state.keys().filter { it.startsWith(EngineKit.SHOWN_KEY) }
        assertEquals(listOf(EngineKit.SHOWN_KEY + server.origin + "|alice@example.com"), marks)
        assertEquals("1", state.get(marks.single()))
        confirmKit(again)
        assertTrue(state.keys().none { it.startsWith(EngineKit.SHOWN_KEY) }, "a confirmed kit takes the mark")
    }

    @Test fun aDeviceThatNeverShowedTheEarlierKitCannotSayItIsVoid() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val transport = BearerTransport(mapOf(server.origin to server))
        val a = app(server, transport)
        signUpToKit(a)
        confirmKit(a)
        val b = app(server, transport)
        signIn(b, server.origin)
        // A's kit made in Settings and never confirmed; B learns at its opening that the account's kit is unconfirmed.
        assertEquals(RecoveryChangeResult.DONE, a.recovery.makeKit(strong))
        b.lock()
        assertEquals(VaultUnlockResult.DONE, b.unlock(b.snapshot.locked!!, strong))
        b.lock()
        assertEquals(VaultUnlockResult.DONE, b.unlock(b.snapshot.locked!!, strong))
        val kit = b.at<EntryScreen.Kit>().kit
        assertEquals(KitReason.NEVER_SAVED, kit.reason)
        assertNull(kit.earlierKitVoidLine, "B never showed A's kit, so it cannot know whether one was copied")
    }

    @Test fun anUnlockFromASurfaceThatOnlyFillsMakesNoKitAndLeavesItToTheAppsNextOpening() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val a = app(server, BearerTransport(mapOf(server.origin to server)))
        signUpToKit(a)
        confirmKit(a)
        assertEquals(RecoveryChangeResult.DONE, a.recovery.makeKit(strong))
        a.lock()
        val account = server.accounts.values.single()
        val piece = account.pieceId
        assertFalse(account.recoveryConfirmed)

        val fill = assertIs<UnlockForFilling>(a as io.silencelen.andvari.core.app.AppApi)
        assertEquals(VaultUnlockResult.DONE, fill.unlockForFilling(a.snapshot.locked!!, strong))
        // The vault is open for filling; the server's kit was not replaced, and no kit is on show anywhere.
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        assertEquals(piece, account.pieceId, "the server's kit stays as it was")
        assertNull(a.snapshot.entry)
        assertNull(a.snapshot.account!!.kit)
        assertTrue(a.snapshot.account!!.kitDueAtOpening, "the app's next opening is told to lock first")
        assertFalse(a.keeper.session!!.recoveryConfirmed)

        // The app's own unlock, after the lock its opening calls, makes the kit as before.
        a.lock()
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertEquals(KitReason.NEVER_SAVED, a.at<EntryScreen.Kit>().kit.reason)
        assertTrue(piece != account.pieceId, "now the server's kit is replaced")
        confirmKit(a)
        assertFalse(a.snapshot.account!!.kitDueAtOpening)

        // With the kit confirmed, an unlock to fill is an ordinary unlock.
        a.lock()
        assertEquals(VaultUnlockResult.DONE, fill.unlockForFilling(a.snapshot.locked!!, strong))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        assertFalse(a.snapshot.account!!.kitDueAtOpening)
    }
}
