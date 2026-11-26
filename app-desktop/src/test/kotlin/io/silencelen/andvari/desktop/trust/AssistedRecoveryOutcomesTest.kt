package io.silencelen.andvari.desktop.trust

import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.unit.Density
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.LateRecoveryResult
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
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
 * What the shared code now knows about an assisted recovery, on the desktop's screens: the server's recovery key changed
 * while a request was open (signed: one line; not signed: the warning with "stop" first and "keep waiting"); a request
 * the server no longer knows; a recovery the person left whose outcome arrives late, on the first window with a dismiss;
 * the requests this device could not read, as the two lines under the list.
 */
class AssistedRecoveryOutcomesTest {
    private val day = 86_400_000L
    private val dir = "src/main/kotlin/io/silencelen/andvari/desktop/trust/"
    private fun body(file: String, head: String) = File(dir + file).readText().substringAfter(head).substringBefore("\n}\n")

    private fun at(scene: FakeScene): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(scene)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        m.onSnapshot(api.snapshot)
        return api to m
    }

    private fun draw(m: TrustModel, api: FakeDesktopAppApi) {
        val s = api.snapshot
        val scene = ImageComposeScene(480, 900, Density(1f)) { MaterialTheme { s.entry?.let { EntryScreens(m, s, it) } } }
        try {
            scene.render()
        } finally {
            scene.close()
        }
    }

    @Test
    fun aKeyChangeIsTheWarningWhenUnsignedAndALineWhenSignedThenARequestTheServerForgotIsSaidAndKept() {
        val (api, m) = at(FakeScene.OPERATOR_HELP_HOLDING)
        val script = api.script
        script.advance(7 * day)
        assertTrue(script.operatorAnswers(forged = false))
        // Unsigned: the warning, the request kept, nothing opened.
        assertTrue(script.recoveryKeyChangesWhileRequestOpen(byOldKey = false))
        m.run({ entry.refreshOperatorHelp(assertIs<EntryScreen.OperatorHelp>(api.snapshot.entry)) })
        val warned = assertIs<EntryScreen.OperatorHelp>(api.snapshot.entry)
        val unsigned = assertNotNull(warned.keyChange)
        assertFalse(unsigned.byOldKey)
        assertNull(keyChangeLine(unsigned), "no line for an unsigned change: the warning instead")
        assertNotNull(unsigned.warningTitle)
        assertEquals(CopyKey.ASSIST_RECOVERY_KEY_CHANGED_BODY, unsigned.warningBody)
        draw(m, api)
        // Signed later: the request goes on, and the account check says so in one line with the date.
        assertTrue(script.recoveryKeyChangeSignedLater())
        m.run({ entry.refreshOperatorHelp(warned) })
        val check = assertIs<EntryScreen.CheckAccount>(api.snapshot.entry)
        val signed = assertNotNull(check.keyChange)
        assertTrue(signed.byOldKey)
        val line = assertNotNull(keyChangeLine(signed))
        assertFalse(line.shown().contains("{0}"), line.shown())
        assertEquals(UiText.filled(CopyKey.ASSIST_RECOVERY_KEY_ROTATED, java.text.DateFormat.getDateInstance(java.text.DateFormat.MEDIUM).format(java.util.Date(signed.rotatedAtMs))).shown(), line.shown())
        draw(m, api)
        m.act { entry.acceptRecoveredAccount(check) }
        // Unknown to the server: said and kept, with "wait" and "start again".
        assertTrue(script.serverForgetsRequest())
        m.run({ entry.chooseReplacementPassword(assertIs<EntryScreen.ReplacePassword>(api.snapshot.entry), "a brand new master password") })
        val unknown = assertIs<EntryScreen.OperatorHelp>(api.snapshot.entry)
        assertEquals(CopyKey.ASSIST_REQUEST_UNKNOWN, unknown.requestUnknown)
        draw(m, api)

        val help = body("LinkAndRecoveryScreens.kt", "internal fun OperatorHelpScreen(")
        val warning = help.substringAfter("if (unsigned != null) {").substringBefore("screen.requestUnknown?.let")
        assertTrue(warning.indexOf("Main(UiText.of(unsigned.stop)") in 0 until warning.indexOf("Quieter(UiText.of(unsigned.keepWaiting)"), "stop first, the default")
        assertTrue(warning.contains("entry.abandonOperatorHelp(screen)") && warning.contains("{ keptWaiting = true }"), "keep waiting sends nothing")
        val forgot = help.substringAfter("screen.requestUnknown?.let")
        assertTrue(forgot.indexOf("ASSIST_REQUEST_UNKNOWN_WAIT") in 0 until forgot.indexOf("ASSIST_REQUEST_UNKNOWN_START_AGAIN"))
        assertTrue(forgot.contains("entry.refreshOperatorHelp(screen)") && forgot.contains("entry.abandonOperatorHelp(screen)"))
        assertTrue(help.contains("keyChangeLine(screen.keyChange)?.let { Quiet(it) }"), "the signed line beside the stage")
        assertTrue(body("LinkAndRecoveryScreens.kt", "internal fun CheckAccountScreen(").contains("keyChangeLine(screen.keyChange)?.let { Quiet(it) }"))
    }

    @Test
    fun aRecoveryLeftWhoseOutcomeArrivesLateIsSaidOnTheFirstWindowUntilDismissed() {
        val (api, m) = at(FakeScene.OPERATOR_HELP_HOLDING)
        m.act { entry.startOver() }
        assertTrue(api.script.leftRecoveryAnswered(LateRecoveryResult.UNKNOWN))
        val first = assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
        val late = assertNotNull(first.lateRecovery)
        assertEquals(CopyKey.LATE_RECOVERY_UNKNOWN, late.line.key)
        assertTrue(body("EntryScreens.kt", "internal fun FirstRunScreen(").contains("screen.lateRecovery?.let { late ->\n            Say(UiText.of(late.line))\n            Quieter(UiText.ph(Placeholder.DISMISS)) { model.act { entry.dismissNotice(screen) } }"))
        draw(m, api)
        m.act { entry.dismissNotice(first) }
        assertNull(assertIs<EntryScreen.FirstRun>(api.snapshot.entry).lateRecovery)
    }

    @Test
    fun theRequestsThisDeviceCouldNotReadAreTheTwoLinesUnderTheList() {
        val (api, m) = at(FakeScene.VAULTS)
        api.script.requestListServed(unreadableRows = 2)
        m.run({ recovery.openRecovery() })
        val some = assertNotNull(api.snapshot.account?.recovery)
        assertEquals(2, some.unreadableRequests)
        assertEquals(listOf(UiText.of(assertNotNull(some.unreadableLine)).shown()), requestListLines(some).map { it.shown() })
        m.act { recovery.closeRecovery() }
        api.script.requestListServed(unreadable = true)
        m.run({ recovery.openRecovery() })
        val none = assertNotNull(api.snapshot.account?.recovery)
        assertTrue(none.requestsNotRead)
        assertTrue(requestListLines(none).any { it.shown() == UiText.of(CopyKey.RECOVERY_REQUESTS_NOT_READ).shown() })
        val section = body("SettingsScreens.kt", "internal fun RecoverySection(")
        assertTrue(section.indexOf("for (line in requestListLines(screen))") > section.indexOf("for (r in screen.requests)"), "under the list")
    }
}
