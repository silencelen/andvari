package io.silencelen.andvari.desktop.trust

import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.unit.Density
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.OperatorHelpStage
import io.silencelen.andvari.core.app.ReplacePasswordResult
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * A request for the operator's help that is over, on the desktop, in the shared code's three lines, each true whether the
 * account's side or whoever runs the server ended it: the stage line of a request the server says is vetoed is the
 * shared code's ended line, in place of where the request stands; a code typed for a request ended before its mailed
 * code says the cancelled line; and setting a new master password after an answer that can no longer be finished says
 * the operator route's own line, never a result without wording. The desktop keeps no line of its own for any of them.
 */
class OperatorHelpEndedTest {
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

    private fun bare(t: UiText?): Boolean = (t as? UiText.Ph)?.placeholder in setOf(Placeholder.REFUSAL, Placeholder.TROUBLE)

    @Test
    fun aRequestTheServerEndedAfterItsCodeSaysTheSharedEndedLineInPlaceOfItsStage() {
        val (api, m) = at(FakeScene.OPERATOR_HELP_HOLDING)
        val holding = assertIs<EntryScreen.OperatorHelp>(api.snapshot.entry)
        assertNull(holding.endedLine)
        assertEquals(UiText.ph(Placeholder.OPERATOR_HELP_STAGE, holding.stage.name).shown(), operatorHelpStageLine(holding).shown(), "a request on its way says where it stands")

        assertTrue(api.script.serverEndsRequest(), "this computer holds the request")
        m.run({ entry.refreshOperatorHelp(holding) })
        val ended = assertIs<EntryScreen.OperatorHelp>(api.snapshot.entry)
        assertEquals(OperatorHelpStage.VETOED, ended.stage)
        assertEquals(CopyKey.ASSIST_REQUEST_ENDED, ended.endedLine)
        assertNull(operatorHelpStop(ended), "no stop stands, so the stage line is drawn")
        val line = operatorHelpStageLine(ended)
        assertEquals(UiText.of(CopyKey.ASSIST_REQUEST_ENDED).shown(), line.shown(), "the shared code's ended line")
        assertNotEquals(UiText.ph(Placeholder.OPERATOR_HELP_STAGE, ended.stage.name).shown(), line.shown(), "never the stage's name")
        draw(m, api)
    }

    @Test
    fun aRequestTheAccountsOwnDeviceRefusedSaysTheSameEndedLine() {
        val (api, m) = at(FakeScene.OPERATOR_HELP_VETOED)
        val ended = assertIs<EntryScreen.OperatorHelp>(api.snapshot.entry)
        assertEquals(OperatorHelpStage.VETOED, ended.stage)
        assertEquals(UiText.of(CopyKey.ASSIST_REQUEST_ENDED).shown(), operatorHelpStageLine(ended).shown(), "the device cannot tell the causes apart")
        draw(m, api)
    }

    @Test
    fun aCodeForARequestTheServerEndedBeforeItsCodeSaysTheCancelledLine() {
        val (api, m) = at(FakeScene.OPERATOR_HELP_CODE_NEEDED)
        val screen = assertIs<EntryScreen.OperatorHelp>(api.snapshot.entry)
        assertTrue(api.script.serverEndsRequest(), "this computer holds the request")
        var answer: CodeResult? = null
        m.run({ entry.verifyOperatorHelp(screen, api.script.emailCode) }) { answer = it }
        assertSame(CodeResult.REQUEST_CANCELLED, answer)
        val said = UiText.forResult(CodeResult.REQUEST_CANCELLED, 0)
        assertEquals(UiText.of(CopyKey.ASSIST_REQUEST_CANCELLED).shown(), said?.shown(), "the shared code's widened line")
        assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
        draw(m, api)
    }

    @Test
    fun aNewPasswordAfterAnAnswerTheServerEndedSaysTheOperatorRoutesOwnLineAndCommitsNothing() {
        val (api, m) = at(FakeScene.REPLACE_PASSWORD_AFTER_HELP)
        val choose = assertIs<EntryScreen.ReplacePassword>(api.snapshot.entry)
        assertTrue(api.script.serverEndsRequest(), "this computer holds the request")
        var answer: ReplacePasswordResult? = null
        m.run({ entry.chooseReplacementPassword(choose, "a brand new master password") }) { answer = it }
        assertSame(ReplacePasswordResult.REQUEST_ENDED, answer)
        val said = assertNotNull(UiText.forResult(ReplacePasswordResult.REQUEST_ENDED, 0))
        assertEquals(UiText.of(CopyKey.ASSIST_ANSWERED_REQUEST_ENDED).shown(), said.shown())
        assertEquals(false, bare(said), "never a result without wording")
        assertIs<EntryScreen.FirstRun>(api.snapshot.entry, "back at the first screen")
        draw(m, api)
    }
}
