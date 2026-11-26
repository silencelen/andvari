package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.MoveStage
import io.silencelen.andvari.core.app.PersonName
import io.silencelen.andvari.core.app.ReplacePasswordResult
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.ShareChoice
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.VaultLogState
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.trust.MemberRole
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * What the shared code asks of the screens since the recovery-request alert, the two-step account-ID check, the answer
 * that was replaced, the check for space and the held delete of "Move everything", vaults attached to a link, and a
 * session the server ended after another device re-keyed: each against the fake's switches, and the screens' code.
 */
class SharedCodeAsksTest {
    private fun at(scene: FakeScene): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(scene)
        return api to TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
    }

    private fun source(name: String) = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/$name").readText()

    private fun alert(api: FakeDesktopAppApi): AccountPrompt.RecoveryRequest? =
        api.snapshot.account?.prompts?.filterIsInstance<AccountPrompt.RecoveryRequest>()?.singleOrNull()

    // ---- the alert for a recovery request ----

    @Test
    fun theAlertShowsEachRequestInTheSharedRowLineAndThisWasMePutsItAway() {
        val (api, m) = at(FakeScene.VAULTS)
        assertNotNull(api.script.someoneAsksOperator(AppPlatform.ANDROID))
        val p = assertNotNull(alert(api))
        assertEquals(CopyKey.RECOVERY_REQUEST_ALERT, p.line)
        assertEquals(UiText.of(CopyKey.RECOVERY_REQUEST_ALERT).shown(), promptLine(p).shown())
        val row = p.requests.single()
        val line = requestDetailLine(p.rowLine, row)
        assertEquals(CopyKey.RECOVERY_REQUEST_DETAILS, p.rowLine, "the shared code's line")
        assertEquals(p.rowLine.awaitingOwner, line.isPlaceholder, "marked as awaiting exactly while it awaits its words")
        assertTrue(line.shown().contains(row.reportedPlatform.wireName), "the device as the server says it")
        assertFalse(line.shown().contains("{"), "every value filled: ${line.shown()}")
        assertTrue(requestFlags(row).isEmpty(), "a request in its hold, nothing more to say")

        m.act { recovery.recoveryRequestWasMe(p) }
        assertNull(alert(api), "this was me: the alert goes on this device")
    }

    @Test
    fun cancelFromTheAlertEndsTheRequest() {
        val (api, m) = at(FakeScene.VAULTS)
        val request = assertNotNull(api.script.someoneAsksOperator(AppPlatform.LINUX))
        val p = assertNotNull(alert(api))
        var answer: Any? = null
        m.run({ recovery.cancelRecoveryRequest(p.requests.single()) }) { answer = it }
        assertEquals("DONE", answer.toString())
        assertNull(alert(api))
        assertEquals(io.silencelen.andvari.core.app.OperatorHelpStage.VETOED, request.stage)
    }

    @Test
    fun eachFlagAndTheUnreadableCaseSayTheSharedCodesWords() {
        assertEquals(
            listOf(CopyKey.RECOVERY_REQUEST_ANSWERED, CopyKey.RECOVERY_REQUEST_HOLD_CUT_SHORT, CopyKey.RECOVERY_REQUEST_CANCEL_NOT_TAKEN),
            requestFlagKeys(answered = true, holdCutShort = true, cancelNotTaken = true),
        )
        assertEquals(listOf(CopyKey.RECOVERY_REQUEST_HOLD_CUT_SHORT), requestFlagKeys(answered = false, holdCutShort = true, cancelNotTaken = false))
        assertEquals(listOf(CopyKey.RECOVERY_REQUEST_CANCEL_NOT_TAKEN), requestFlagKeys(answered = false, holdCutShort = false, cancelNotTaken = true))
        assertEquals(listOf(CopyKey.RECOVERY_REQUEST_ANSWERED), requestFlagKeys(answered = true, holdCutShort = false, cancelNotTaken = false))
        for (k in requestFlagKeys(true, true, true) + CopyKey.RECOVERY_REQUEST_UNREADABLE + CopyKey.RECOVERY_REQUEST_WAS_ME) {
            assertEquals(k.awaitingOwner, UiText.of(k).isPlaceholder, "$k is marked as awaiting exactly while it awaits its words")
            assertEquals(k.english, UiText.of(k).shown(), "$k is said in the shared code's words")
        }

        val people = source("PeopleScreens.kt").substringAfter("private fun RecoveryRequestAlert(").substringBefore("\n}\n")
        assertTrue(people.contains("if (p.unreadable) {") && people.contains("CopyKey.RECOVERY_REQUEST_UNREADABLE") && people.contains("openRecovery()"))
        assertTrue(people.contains("requestDetailLine(p.rowLine, r)") && people.contains("for (flag in requestFlags(r))"))
        assertTrue(people.contains("recovery.cancelRecoveryRequest(r)") && people.contains("recovery.recoveryRequestWasMe(p)"))
        assertTrue(people.indexOf("cancelRecoveryRequest") < people.indexOf("recoveryRequestWasMe"), "Cancel comes before \"This was me\"")
        // The way to Settings' recovery section, where an unreadable request is listed and cancelled.
        val area = source("AccountScreens.kt").substringAfter("private fun AttentionArea(").substringBefore("\n}\n")
        assertTrue(area.contains("go(SignedInPage.SETTINGS)") && area.contains("recovery.openRecovery()"))
        val settings = source("SettingsScreens.kt").substringAfter("internal fun RecoverySection(").substringBefore("\n}\n")
        assertTrue(settings.contains("requestDetailLine(CopyKey.RECOVERY_REQUEST_DETAILS, r)") && settings.contains("for (flag in requestFlags(r))"))
        assertTrue(Placeholder.entries.none { it.name == "RECOVERY_REQUEST_ROW" }, "the desktop's own row placeholder is gone")
    }

    // ---- the account-ID check, in two steps ----

    @Test
    fun theAccountIdCheckNamesTheKitAndTakesASecondTap() {
        val (api, m) = at(FakeScene.OPERATOR_HELP_CHECK_ACCOUNT)
        api.script.checkAccountConfirmStep = true
        val first = assertIs<EntryScreen.CheckAccount>(api.snapshot.entry)
        assertEquals(CopyKey.RECOVERY_CHECK_ACCOUNT_KIT, first.compareLine)
        assertNull(first.confirmLine)
        m.act { entry.acceptRecoveredAccount(first) }
        val second = assertIs<EntryScreen.CheckAccount>(api.snapshot.entry, "one tap does not pass the check")
        assertTrue(second.confirming)
        assertEquals(CopyKey.RECOVERY_CHECK_ACCOUNT_CONFIRM, second.confirmLine)
        m.act { entry.acceptRecoveredAccount(second) }
        assertIs<EntryScreen.ReplacePassword>(api.snapshot.entry, "the second tap goes on")

        val check = source("LinkAndRecoveryScreens.kt").substringAfter("internal fun CheckAccountScreen(").substringBefore("\n}\n")
        assertTrue(check.contains("Say(UiText.of(screen.compareLine))"))
        assertTrue(check.contains("screen.confirmLine?.let {"))
        assertFalse(check.contains("RECOVERY_CHECK_ACCOUNT.body"), "the email-only sentence is replaced by the shared line")
    }

    // ---- the answer that was replaced ----

    @Test
    fun anAnswerThatWasReplacedIsSaidInTheSharedWordsAndNeverAsStartAgain() {
        val said = assertNotNull(UiText.forResult(ReplacePasswordResult.ANSWER_REPLACED, 0))
        assertEquals(UiText.of(CopyKey.ASSIST_ANSWER_REPLACED).shown(), said.shown())
        val help = source("LinkAndRecoveryScreens.kt").substringAfter("internal fun OperatorHelpScreen(").substringBefore("\n}\n")
        assertTrue(help.contains("screen.answerReplaced?.let { Say(UiText.of(it)"))
    }

    // ---- Move everything ----

    @Test
    fun aMoveShortOfSpaceSaysWhichLimitAndByHowMuch() {
        val (api, m) = at(FakeScene.VAULTS)
        api.script.noSpaceForVaults = true
        m.run({ vaults.openMoveEverything(assertNotNull(api.snapshot.account).vaults.first { it.name == "Family" }) })
        m.run({ vaults.moveEverything(assertNotNull(api.snapshot.account?.moving), "Family 2") })
        val screen = assertNotNull(api.snapshot.account?.moving)
        val space = assertNotNull(screen.space)
        val line = assertNotNull(moveSpaceLine(screen))
        assertEquals(UiText.of(assertNotNull(space.line)).shown(), line.shown())
        assertTrue(line.shown().contains(space.limits.first().by.toString()), "by how much: ${line.shown()}")
        val view = source("VaultScreens.kt").substringAfter("private fun MoveEverythingView(").substringBefore("\n}\n")
        assertTrue(view.contains("space?.let { Say(it"))
        assertTrue(view.contains("&& space == null) Say(UiText.ph(Placeholder.MOVE_SHORT_OF_SPACE))"), "the desktop's own line only where the shared code gives none")
    }

    @Test
    fun aMoveWhoseDeleteWaitsSaysItIsSignedAndWaiting() {
        val (api, m) = at(FakeScene.VAULTS)
        api.script.moveDeleteUnanswered = true
        m.run({ vaults.openMembers(assertNotNull(api.snapshot.account).vaults.first { it.name == "Family" }) })
        val dan = assertNotNull(api.snapshot.account?.members).members.first { it.who is PersonName.Unverified }
        m.run({ vaults.openMoveEverythingRemoving(dan) })
        m.run({ vaults.moveEverything(assertNotNull(api.snapshot.account?.moving), "Family 2") })
        val screen = assertNotNull(api.snapshot.account?.moving)
        val stop = assertNotNull(screen.stopped)
        assertEquals(MoveStage.DELETE_OLD_VAULT, stop.stage)
        assertEquals(CopyKey.MOVE_DELETE_UNCONFIRMED, stop.line)
        val lines = moveStopLines(screen, 0).map { it.shown() }
        assertEquals(UiText.ph(Placeholder.MOVE_STOPPED_DELETING).shown(), lines[0])
        assertTrue(lines[1].contains("signed and waiting") && lines[1].contains("Family 2"), lines[1])
        assertFalse(lines.any { it.contains("deleted") && !it.contains("deletion") }, "never said as deleted: $lines")
    }

    // ---- vaults attached to a link ----

    @Test
    fun aVaultAttachedToALinkWaitsThenSharesOnlyBehindTheWarning() {
        val (api, m) = at(FakeScene.VAULTS)
        m.run({ links.openLinks() })
        val vault = assertNotNull(api.snapshot.account).vaults.first { it.role == RoleInVault.OWNER && it.log == VaultLogState.VERIFIED && it.writable && it.purgeAtMs == 0L }
        m.run({ links.createConnectLink(listOf(ShareChoice(vault.vaultId, MemberRole.READER)), 15) })
        val link = assertNotNull(api.snapshot.account?.links).links.first()
        assertNotNull(api.script.someoneAnswers(link, "Cy"))
        val waiting = assertNotNull(api.snapshot.account?.links).waitingShares.single()
        assertEquals(CopyKey.SHARE_ONCE_COMPARED, waiting.line.key)
        var answer: Any? = null
        m.run({ links.releaseShare(waiting) }) { answer = it }
        assertEquals(VaultActionResult.NEEDS_UNCOMPARED_WARNING.toString(), answer.toString())
        val warning = assertNotNull(api.snapshot.account?.shareWarning, "never shared by itself")
        m.run({ vaults.confirmUncomparedShare(warning) }) { answer = it }
        assertEquals("DONE", answer.toString())
        assertTrue(assertNotNull(api.snapshot.account?.links).waitingShares.isEmpty())

        val links = source("LinksScreens.kt")
        val section = links.substringAfter("internal fun LinksSection(").substringBefore("\n}\n")
        assertTrue(section.contains("for (w in screen.waitingShares) {") && section.contains("links.releaseShare(w)"))
        assertTrue(section.contains("account.shareWarning?.let { UncomparedWarningView(model, s, it) }"))
        val warn = links.substringAfter("private fun UncomparedWarningView(").substringBefore("\n}\n")
        assertTrue(warn.indexOf("cancelUncomparedShare") in 0 until warn.indexOf("confirmUncomparedShare"), "Cancel comes first")
    }

    // ---- another device of the account re-keyed ----

    @Test
    fun aSessionEndedAfterAnotherDeviceReKeyedIsToldWithoutAlarm() {
        val (api, _) = at(FakeScene.LOCKED)
        api.script.sessionEndedByServer()
        assertTrue(assertNotNull(api.snapshot.locked).signedOutByServer)
        val words = UiText.ph(Placeholder.SIGNED_OUT_BY_SERVER).shown().lowercase()
        for (alarm in listOf("compromis", "attack", "stolen", "hack", "suspicious", "someone", "breach", "unsafe", "danger")) {
            assertFalse(words.contains(alarm), "\"$alarm\" in: $words")
        }
        assertTrue(words.contains("read-only") && words.contains("sign in again"))
    }
}
