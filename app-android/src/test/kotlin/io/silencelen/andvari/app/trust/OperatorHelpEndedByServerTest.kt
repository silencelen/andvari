package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.OperatorHelpStage
import io.silencelen.andvari.core.app.ReplacePasswordResult
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
 * A request for the operator's help that is over, whoever ended it: the account's side or whoever runs the server. The
 * device is told the same states in every case, so the phone draws the shared code's three lines, each true of every
 * cause: the ended request's line ([EntryScreen.OperatorHelp.endedLine]), the line of a request cancelled before its
 * mailed code, and the sentence of a commit the request can no longer finish ([ReplacePasswordResult.REQUEST_ENDED]).
 */
class OperatorHelpEndedByServerTest {
    private fun at(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(api.snapshot)
        return api to m
    }

    private fun help(api: FakeAppApi) = assertIs<EntryScreen.OperatorHelp>(api.snapshot.entry)

    @Test
    fun aRequestTheServerEndedInItsWaitDrawsTheSharedEndedLine() {
        val (api, m) = at(FakeScene.OPERATOR_HELP_HOLDING)
        assertNull(help(api).endedLine, "a request in its wait has no ended line")
        assertTrue(api.script.serverEndsRequest())
        runBlocking { m.run({ entry.refreshOperatorHelp(assertIs(snapshot.entry)) }).join() }
        m.onSnapshot(api.snapshot)
        val screen = help(api)
        assertEquals(OperatorHelpStage.VETOED, screen.stage)
        assertEquals(CopyKey.ASSIST_REQUEST_ENDED, screen.endedLine)
        val line = operatorHelpLine(screen)
        WalkPrint.draws("a request the server ended, its screen", listOf(line))
        assertEquals(UiText.of(CopyKey.ASSIST_REQUEST_ENDED).shown(), line.shown(), "the shared code's line, as handed")
        assertTrue(operatorHelpEnded(screen.stage), "nothing to wait for")
    }

    @Test
    fun aRequestASignedInDeviceRefusedDrawsTheSameLine() {
        val (api, _) = at(FakeScene.OPERATOR_HELP_VETOED)
        val screen = help(api)
        assertEquals(CopyKey.ASSIST_REQUEST_ENDED, screen.endedLine)
        assertEquals(UiText.of(CopyKey.ASSIST_REQUEST_ENDED).shown(), operatorHelpLine(screen).shown())
        assertEquals(operatorHelpLine(screen).shown(), operatorHelpStageLine(OperatorHelpStage.VETOED).shown(), "one line for the stage")
    }

    @Test
    fun aRequestTheServerEndedBeforeItsMailedCodeSaysTheWidenedCancelledLine() {
        val (api, m) = at(FakeScene.OPERATOR_HELP_CODE_NEEDED)
        assertTrue(api.script.serverEndsRequest())
        var answer: io.silencelen.andvari.core.app.IntentResult? = null
        runBlocking { m.run({ entry.verifyOperatorHelp(assertIs(snapshot.entry), "123456") }) { answer = it }.join() }
        m.onSnapshot(api.snapshot)
        assertEquals(CodeResult.REQUEST_CANCELLED, answer)
        assertEquals(CopyKey.ASSIST_REQUEST_CANCELLED, CodeResult.REQUEST_CANCELLED.sentence)
        val said = assertNotNull(m.saidOn(api.snapshot), "said where the person now is").text
        WalkPrint.draws("a request the server ended before its code, said", listOf(said))
        assertEquals(UiText.of(CopyKey.ASSIST_REQUEST_CANCELLED).shown(), said.shown())
    }

    @Test
    fun aCommitTheRequestCanNoLongerFinishSaysTheResultsOwnSentenceOnTheFirstScreen() {
        val (api, m) = at(FakeScene.REPLACE_PASSWORD_AFTER_HELP)
        val screen = assertIs<EntryScreen.ReplacePassword>(api.snapshot.entry)
        assertTrue(api.script.serverEndsRequest())
        var answer: io.silencelen.andvari.core.app.IntentResult? = null
        runBlocking { m.run({ entry.chooseReplacementPassword(screen, "a new long master password 7") }) { answer = it }.join() }
        m.onSnapshot(api.snapshot)
        assertEquals(ReplacePasswordResult.REQUEST_ENDED, answer)
        assertFalse(api.snapshot.entry is EntryScreen.ReplacePassword, "what was opened of the answer is dropped")
        assertTrue(api.snapshot.phase == AppPhase.ENTRY)
        val said = assertNotNull(m.saidOn(api.snapshot), "said where the person now is").text
        WalkPrint.draws("a commit the request can no longer finish, said", listOf(said))
        assertEquals(UiText.of(CopyKey.ASSIST_ANSWERED_REQUEST_ENDED).shown(), said.shown())
        assertTrue(said.shown() != UiText.forResult(ReplacePasswordResult.TOO_LATE, 0)?.shown(), "not the kit's own line")
    }

    @Test
    fun theScreenDrawsTheRequestsOwnLine() {
        val body = File("src/main/kotlin/io/silencelen/andvari/app/trust/LinkAndRecoveryScreens.kt").readText()
            .substringAfter("internal fun OperatorHelpScreen(").substringBefore("\n}\n")
        assertTrue(body.contains("Say(operatorHelpLine(screen))"))
        assertFalse(body.contains("operatorHelpStageLine(screen.stage)"), "never the stage's line beside the shared one")
    }
}
