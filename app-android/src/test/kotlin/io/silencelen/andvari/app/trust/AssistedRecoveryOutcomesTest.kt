package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.LateRecoveryResult
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
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
 * What the shared code knows about an assisted recovery, on the phone's screens: a change of the server's recovery key
 * while a request is open (signed: one line; not signed: the warning, "stop" first), a request the server no longer
 * knows, a recovery left whose outcome arrives late, and the requests this device could not read.
 */
class AssistedRecoveryOutcomesTest {
    private fun at(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(api.snapshot)
        return api to m
    }

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    private val DAY = 24 * 60 * 60_000L

    private fun help(api: FakeAppApi) = assertIs<EntryScreen.OperatorHelp>(api.snapshot.entry)

    @Test
    fun aKeyChangeIsTheWarningWhenNotSignedAndOneLineWhenSigned() {
        val (api, m) = at(FakeScene.OPERATOR_HELP_HOLDING)
        api.script.advance(7 * DAY)
        assertTrue(api.script.operatorAnswers(forged = false))
        assertTrue(api.script.recoveryKeyChangesWhileRequestOpen(byOldKey = false))
        m.run({ entry.refreshOperatorHelp(help(api)) })
        val warned = assertNotNull(help(api).keyChange)
        assertFalse(warned.byOldKey)
        assertNull(keyChangeLine(warned), "no line beside the stage: the warning stands in its place")
        assertEquals(CopyKey.ASSIST_KEY_CHANGED_STOP, warned.stop)
        // The screen: the warning with its title and body, "stop" as the main (first) button, "keep waiting" after it.
        val screen = src("LinkAndRecoveryScreens.kt")
        val view = screen.substringAfter("private fun KeyChangedWarning(").substringBefore("\n}\n")
        assertTrue(view.indexOf("change.warningTitle") < view.indexOf("change.warningBody"))
        assertTrue(view.indexOf("Main(UiText.of(change.stop)") in 0 until view.indexOf("UiText.of(change.keepWaiting)"))
        assertTrue(view.contains("entry.abandonOperatorHelp(screen)"))
        assertFalse(view.substringAfter("UiText.of(change.keepWaiting)").substringBefore("}").contains("model."), "keep waiting sends nothing")
        // Signed later: the request goes on, and the account check carries the one line, dated.
        assertTrue(api.script.recoveryKeyChangeSignedLater())
        m.run({ entry.refreshOperatorHelp(help(api)) })
        val check = assertIs<EntryScreen.CheckAccount>(api.snapshot.entry)
        val signed = assertNotNull(check.keyChange)
        assertTrue(signed.byOldKey)
        val line = assertNotNull(keyChangeLine(signed)).shown()
        assertTrue(line.contains(Dates.date(signed.rotatedAtMs)), line)
        assertTrue(screen.substringAfter("internal fun CheckAccountScreen(").contains("keyChangeLine(screen.keyChange)"))
    }

    @Test
    fun aRequestTheServerNoLongerKnowsIsSaidWithWaitAndStartAgain() {
        val (api, m) = at(FakeScene.OPERATOR_HELP_HOLDING)
        assertTrue(api.script.serverForgetsRequest())
        m.run({ entry.refreshOperatorHelp(help(api)) })
        assertEquals(CopyKey.ASSIST_REQUEST_UNKNOWN, help(api).requestUnknown)
        val body = src("LinkAndRecoveryScreens.kt").substringAfter("internal fun OperatorHelpScreen(").substringBefore("\n}\n")
        val unknown = body.substringAfter("if (unknown != null) {").substringBefore("return@AuthColumn")
        assertTrue(unknown.contains("CopyKey.ASSIST_REQUEST_UNKNOWN_WAIT") && unknown.contains("entry.refreshOperatorHelp(screen)"))
        assertTrue(unknown.contains("CopyKey.ASSIST_REQUEST_UNKNOWN_START_AGAIN") && unknown.contains("entry.abandonOperatorHelp(screen)"))
        // It stands in place of the stage's line: the stage is drawn only after it.
        assertTrue(body.indexOf("if (unknown != null)") < body.indexOf("Say(operatorHelpLine(screen))"))
    }

    @Test
    fun aRecoveryLeftWhoseOutcomeArrivesLateIsOnTheFirstScreenUntilDismissed() {
        val (api, m) = at(FakeScene.OPERATOR_HELP_HOLDING)
        m.act { entry.startOver() }
        assertTrue(api.script.leftRecoveryAnswered(LateRecoveryResult.REFUSED))
        val first = assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
        assertEquals(CopyKey.LATE_RECOVERY_REFUSED, first.lateRecovery?.line?.key)
        val firstRun = src("EntryScreens.kt").substringAfter("internal fun FirstRunScreen(").substringBefore("\n}\n")
        val late = firstRun.substringAfter("screen.lateRecovery?.let").substringBefore("Gap()")
        assertTrue(late.contains("Say(late.line") && late.contains("entry.dismissNotice(screen)"))
        m.act { entry.dismissNotice(first) }
        assertNull(assertIs<EntryScreen.FirstRun>(api.snapshot.entry).lateRecovery)
    }

    @Test
    fun theRequestsThisDeviceCouldNotReadAreTheTwoLinesUnderTheList() {
        val (api, m) = at(FakeScene.VAULTS)
        if (api.snapshot.phase == AppPhase.LOCKED) m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        m.run({ recovery.openRecovery() })
        assertTrue(requestListLines(assertNotNull(assertNotNull(api.snapshot.account).recovery)).isEmpty())
        api.script.requestListServed(unreadableRows = 2)
        var screen = assertNotNull(assertNotNull(api.snapshot.account).recovery)
        assertEquals(2, screen.unreadableRequests)
        assertEquals(listOf(UiText.of(assertNotNull(screen.unreadableLine)).shown()), requestListLines(screen).map { it.shown() })
        api.script.requestListServed(unreadable = true)
        screen = assertNotNull(assertNotNull(api.snapshot.account).recovery)
        assertTrue(requestListLines(screen).any { it.shown() == UiText.of(CopyKey.RECOVERY_REQUESTS_NOT_READ).shown() })
        val section = src("RecoverySettingsScreens.kt")
        assertTrue(section.contains("for (line in requestListLines(screen)) Say(line"))
    }
}
