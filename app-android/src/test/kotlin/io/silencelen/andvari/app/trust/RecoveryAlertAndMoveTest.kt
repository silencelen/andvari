package io.silencelen.andvari.app.trust

import io.silencelen.andvari.app.autofill.overlayUnlock
import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AppApi
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.FastUnlock
import io.silencelen.andvari.core.app.LockedScreen
import io.silencelen.andvari.core.app.MoveStage
import io.silencelen.andvari.core.app.ReplacePasswordResult
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.content.SpaceVerdict
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * What the shared code offers and asks, on the screens, against the fake's switches: the alert for a recovery request
 * on a signed-in device, the account-ID check's second step, the answer that was replaced, the space and stop lines of
 * "Move everything", and the overlay's fast unlock.
 */
class RecoveryAlertAndMoveTest {
    private fun at(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        return api to TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L }, { false }, {})
    }

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    private fun FakeAppApi.alert(): AccountPrompt.RecoveryRequest? =
        snapshot.account?.prompts?.filterIsInstance<AccountPrompt.RecoveryRequest>()?.singleOrNull()

    @Test
    fun aRecoveryRequestRaisesTheAlertWithItsDetailsCancelAndThisWasMe() {
        val (api, m) = at(FakeScene.RECOVERY)
        assertNull(api.alert())
        assertNotNull(api.script.someoneAsksOperator(AppPlatform.IOS))
        val p = assertNotNull(api.alert(), "the alert is raised on the signed-in device")
        val lines = alertLines(p)
        assertEquals(listOf(UiText.of(CopyKey.RECOVERY_REQUEST_ALERT).shown()), lines.map { it.shown() }, "the alert's own line, nothing more")
        val r = p.requests.single()
        val row = alertRowLine(p, r)
        assertEquals(CopyKey.RECOVERY_REQUEST_DETAILS, p.rowLine, "the details' sentence is the shared code's")
        assertTrue(row.shown().contains(Dates.dateTime(r.askedAtMs)) && row.shown().contains(Dates.dateTime(r.holdEndsAtMs)), row.shown())
        assertTrue(row.shown().contains(r.reportedPlatform.wireName), row.shown())
        assertFalse(row.shown().contains("{"), row.shown())
        assertTrue(requestFlagLines(r).isEmpty(), "an honest, holding request has no flag")

        // "This was me": the alert goes on this device. (The engine's Settings still lists the request; the fake's list
        // leaves it out too, so that is not asserted here.)
        m.act { recovery.recoveryRequestWasMe(p) }
        assertNull(api.alert())

        // A later request raises it again; Cancel from the alert ends it.
        assertNotNull(api.script.someoneAsksOperator(AppPlatform.ANDROID))
        val again = assertNotNull(api.alert())
        val other = again.requests.single()
        m.run({ recovery.cancelRecoveryRequest(other) })
        assertNull(api.alert(), "said: ${m.said.value?.text?.shown()}")

        // The alert is drawn by its own view, with both buttons, from the prompts list.
        val view = src("RecoverySettingsScreens.kt").substringAfter("fun RecoveryRequestAlert(").substringBefore("\n}\n")
        assertTrue(view.contains("recovery.cancelRecoveryRequest(r)") && view.contains("recovery.recoveryRequestWasMe(p)"))
        assertTrue(view.contains("requestFlagLines(r)") && view.contains("alertRowLine(p, r)") && view.contains("p.unreadable"))
        assertTrue(src("PeopleScreens.kt").contains("is AccountPrompt.RecoveryRequest -> RecoveryRequestAlert(model, s, p)"))
    }

    @Test
    fun eachFlagAndTheUnreadableCaseSayTheSharedCodesSentence() {
        assertEquals(
            listOf(CopyKey.RECOVERY_REQUEST_ANSWERED, CopyKey.RECOVERY_REQUEST_HOLD_CUT_SHORT, CopyKey.RECOVERY_REQUEST_CANCEL_NOT_TAKEN).map { UiText.of(it).shown() },
            requestFlagLines(answered = true, holdCutShort = true, cancelNotTaken = true).map { it.shown() },
        )
        assertEquals(listOf(UiText.of(CopyKey.RECOVERY_REQUEST_HOLD_CUT_SHORT).shown()), requestFlagLines(false, true, false).map { it.shown() })
        assertTrue(requestFlagLines(false, false, false).isEmpty())
        val unreadable = alertLines(CopyKey.RECOVERY_REQUEST_ALERT, unreadable = true).map { it.shown() }
        assertEquals(listOf(UiText.of(CopyKey.RECOVERY_REQUEST_ALERT).shown(), UiText.of(CopyKey.RECOVERY_REQUEST_UNREADABLE).shown()), unreadable)
        // Settings' list shows the same flags under each request.
        assertTrue(src("RecoverySettingsScreens.kt").substringAfter("fun RecoverySection(").contains("requestFlagLines(r)"))
    }

    @Test
    fun theAccountIdCheckTakesASecondStepWithItsSentence() {
        val (api, m) = at(FakeScene.OPERATOR_HELP_CHECK_ACCOUNT)
        api.script.checkAccountConfirmStep = true
        val first = assertIs<EntryScreen.CheckAccount>(api.snapshot.entry)
        assertFalse(first.confirming)
        assertEquals(listOf(UiText.of(CopyKey.RECOVERY_CHECK_ACCOUNT_KIT).shown()), checkAccountLines(first).map { it.shown() })
        m.act { entry.acceptRecoveredAccount(first) }
        val second = assertIs<EntryScreen.CheckAccount>(api.snapshot.entry, "one tap does not pass the check")
        assertTrue(second.confirming)
        assertEquals(
            listOf(UiText.of(CopyKey.RECOVERY_CHECK_ACCOUNT_KIT).shown(), UiText.of(CopyKey.RECOVERY_CHECK_ACCOUNT_CONFIRM).shown()),
            checkAccountLines(second).map { it.shown() },
        )
        m.act { entry.acceptRecoveredAccount(second) }
        assertIs<EntryScreen.ReplacePassword>(api.snapshot.entry, "the second tap goes on to a new password")
        val screen = src("LinkAndRecoveryScreens.kt").substringAfter("fun CheckAccountScreen(").substringBefore("\n}\n")
        assertTrue(screen.contains("checkAccountLines(screen)"))
    }

    @Test
    fun anAnswerThatWasReplacedSaysSoAndNeverStartAgain() {
        val words = assertNotNull(UiText.forResult(ReplacePasswordResult.ANSWER_REPLACED, 0)).shown()
        assertEquals(UiText.of(CopyKey.ASSIST_ANSWER_REPLACED).shown(), words)
        val (api, _) = at(FakeScene.OPERATOR_HELP_AWAITING)
        assertNull(assertIs<EntryScreen.OperatorHelp>(api.snapshot.entry).answerReplaced, "an ordinary wait says nothing of it")
        val help = src("LinkAndRecoveryScreens.kt").substringAfter("fun OperatorHelpScreen(").substringBefore("\n}\n")
        assertTrue(help.contains("screen.answerReplaced?.let { Say(UiText.of(it)"))
    }

    @Test
    fun moveEverythingSaysWhichLimitAndByHowMuchAndTheDeleteThatWaits() {
        val (api, m) = at(FakeScene.MEMBERS)
        api.script.noSpaceForVaults = true
        m.run({ vaults.openMoveEverything(assertNotNull(api.snapshot.account).vaults.first { it.name == "Family" }) })
        var screen = assertNotNull(assertNotNull(api.snapshot.account).moving)
        assertNull(moveSpaceLine(screen), "nothing before a check")
        startMove(m, screen, "Family 2")
        screen = assertNotNull(assertNotNull(api.snapshot.account).moving)
        val space = assertNotNull(screen.space)
        assertEquals(SpaceVerdict.NOT_ENOUGH, space.verdict)
        assertEquals(UiText.of(assertNotNull(space.line)).shown(), assertNotNull(moveSpaceLine(screen)).shown())
        assertTrue(src("VaultScreens.kt").substringAfter("private fun MoveEverythingView(").contains("moveSpaceLine(screen)"))

        // The old vault's delete went without an answer: the stop says it is signed and waiting, and how to finish.
        val (api2, m2) = at(FakeScene.MEMBERS)
        api2.script.moveDeleteUnanswered = true
        val me = assertNotNull(api2.script.publicInstance.accounts[FakeScenes.EMAIL])
        // Only members this phone can add, so nothing keeps the old vault and its delete is sent.
        me.vaults.first { it.name == "Family" }.members.removeAll { it.contact == null && it.userId != me.userId && it.role != RoleInVault.OWNER }
        api2.script.changed()
        m2.run({ vaults.openMoveEverything(assertNotNull(api2.snapshot.account).vaults.first { it.name == "Family" }) })
        startMove(m2, assertNotNull(assertNotNull(api2.snapshot.account).moving), "Family 2")
        val waiting = assertNotNull(assertNotNull(api2.snapshot.account).moving)
        val stop = assertNotNull(waiting.stopped)
        assertEquals(MoveStage.DELETE_OLD_VAULT, stop.stage)
        assertEquals(VaultActionResult.SENT_PENDING, stop.result)
        val lines = moveStopLines(waiting).map { it.shown() }
        assertEquals(UiText.of(CopyKey.MOVE_DELETE_UNCONFIRMED, "Family 2", "Family", stop.copied.toString(), stop.total.toString()).shown(), lines[1])
        assertTrue(lines[1].contains("signed and waiting") && !lines[1].contains("{"), lines[1])
    }

    @Test
    fun aMoveThatIsNotFinishedIsSaidOnItsRowAndOfferedOnTheFirstScreen() {
        val (api, m) = at(FakeScene.MEMBERS)
        api.script.moveDeleteUnanswered = true
        val me = assertNotNull(api.script.publicInstance.accounts[FakeScenes.EMAIL])
        me.vaults.first { it.name == "Family" }.members.removeAll { it.contact == null && it.userId != me.userId && it.role != RoleInVault.OWNER }
        api.script.changed()
        m.run({ vaults.openMoveEverything(assertNotNull(api.snapshot.account).vaults.first { it.name == "Family" }) })
        startMove(m, assertNotNull(assertNotNull(api.snapshot.account).moving), "Family 2")
        m.act { vaults.closeMoveEverything() }
        val account = assertNotNull(api.snapshot.account)
        val move = account.unfinishedMoves.single()
        assertTrue(move.deleteWaiting)
        assertEquals(CopyKey.MOVE_DELETE_WAITING, move.line.key)
        assertTrue(UiText.of(move.line).shown().contains("Family"), UiText.of(move.line).shown())
        assertNotNull(account.vaults.first { it.name == "Family" }.unfinishedMove, "the vault's row says it too")
        // "Later" puts the offer off; "finish the move" opens the move's screen on that vault.
        m.act { vaults.unfinishedMoveLater(move) }
        assertTrue(assertNotNull(api.snapshot.account).unfinishedMoves.isEmpty())
        m.run({ vaults.openMoveEverything(move.vault) })
        assertNotNull(assertNotNull(api.snapshot.account).moving)
        val lines = src("AccountScreens.kt")
        assertTrue(lines.contains("for (move in account.unfinishedMoves) UnfinishedMoveOffer(model, s, move)"))
        val offer = src("VaultScreens.kt").substringAfter("internal fun UnfinishedMoveOffer(").substringBefore("\n}\n")
        assertTrue(offer.contains("vaults.openMoveEverything(move.vault)") && offer.contains("vaults.unfinishedMoveLater(move)"))
        assertTrue(src("VaultScreens.kt").contains("v.unfinishedMove?.let { Say(UiText.of(it)"))
    }

    /** The engine's app interface, as the overlay sees it: it offers the fast unlock. */
    private class Fast(val inner: FakeAppApi) : AppApi by inner, FastUnlock {
        var fast = 0

        override suspend fun unlockPuttingOffReKey(screen: LockedScreen, password: String): VaultUnlockResult {
            fast++
            return inner.unlock(screen, password)
        }
    }

    @Test
    fun theOverlayUnlocksTheFastWayWhereTheAppInterfaceOffersIt() = runBlocking<Unit> {
        val fake = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.LOCKED)
        val api = Fast(fake)
        assertEquals(VaultUnlockResult.DONE, overlayUnlock(api, assertNotNull(fake.snapshot.locked), FakeScenes.PASSWORD))
        assertEquals(1, api.fast, "the quiet re-key is put off: the overlay must be fast")
        assertEquals(AppPhase.UNLOCKED, fake.snapshot.phase)

        // Without it (the fake), the plain unlock.
        val plain = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.LOCKED)
        assertEquals(VaultUnlockResult.DONE, overlayUnlock(plain, assertNotNull(plain.snapshot.locked), FakeScenes.PASSWORD))
        val overlay = File("src/main/kotlin/io/silencelen/andvari/app/autofill/AutofillUnlockActivity.kt").readText()
        assertTrue(overlay.contains("overlayUnlock(model.api, locked, password)"))
        assertFalse(overlay.contains("model.api.unlock(locked, password)"))
    }
}
