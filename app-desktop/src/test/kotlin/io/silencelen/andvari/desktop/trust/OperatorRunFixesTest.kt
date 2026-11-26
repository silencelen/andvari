package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.OperatorDeleteWhy
import io.silencelen.andvari.core.app.OperatorResult
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** What a run against a local test server found on the console's screens, each pinned. */
class OperatorRunFixesTest {
    private val screens = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/OperatorScreens.kt").readText()

    @Test
    fun aRequestersAccountIdIsNotCalledYours() {
        val section = screens.substringAfter("private fun RecoverySection(").substringBefore("\n}\n") +
            screens.substringAfter("private fun RequestRows(").substringBefore("\n}\n")
        assertFalse(section.contains("fillCopy(CopyKey.KIT_ACCOUNT_ID"), "\"Your account ID\" named the operator's own")
        // The server's account ID is not shown as a value at all now (OperatorStepsTest).
        assertFalse(section.contains("r.accountId"))
    }

    @Test
    fun noPlaceholderIsNestedInAnother() {
        assertFalse(Regex("UiText\\.ph\\([^\\n]*UiText\\.ph\\(Placeholder\\.OP_SIGNUP_NOTHING_STORED\\)\\.shown\\(\\)").containsMatchIn(screens))
        assertTrue(Placeholder.OP_SIGNUP_NOTHING_STORED.gloss.startsWith("mode: "))
    }

    @Test
    fun theDeletionRuleIsSaidOnceAndTheRecordStandsApartFromThePasswordLine() {
        assertEquals("", deleteWhyDetail(OperatorDeleteWhy.DISABLED_30_DAYS).shown())
        // The record is the last line of the deletion's password step, in the error tone, and the step's
        // lines are said, with a gap, before its values and its password field.
        val model = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/OperatorModel.kt").readText()
            .substringAfter("fun checkDelete(").substringBefore("\n    }\n")
        assertTrue(model.contains("StepLine(deleteRecordLine(why), warn = true))"))
        val step = screens.substringAfter("private fun StepIntro(").substringBefore("\n}\n")
        assertTrue(step.contains("for (line in step.lines) Say(line.text, color = if (line.warn) MaterialTheme.colorScheme.error else Color.Unspecified)\n    Gap(8)"))
    }

    @Test
    fun aCardChangeThatIsDoneShowsWithoutASecondReadAndKeepsItsAnswer() {
        val api = FakeScenes.desktopAt(FakeScene.OPERATOR_CONSOLE)
        val m = TrustModel(api, CoroutineScope(SupervisorJob() + Dispatchers.Unconfined), { 0L }, SignInKeeping.Never, { 0L })
        m.onSnapshot(api.snapshot)
        m.operator.rename("Renamed family", FakeScenes.PASSWORD)
        assertEquals(OperatorResult.DONE, m.operator.answerAt(OperatorModel.Area.CARD, OperatorModel.CARD_RENAME)?.result, "the answer stays")
        assertEquals("Renamed family", assertNotNull(api.operatorApi.console).instance.name)
        // The shared code republishes the console after a card intent: the one read left is "read again".
        val model = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/OperatorModel.kt").readText()
        assertEquals(1, Regex("operatorApi\\.refreshConsole\\(\\)").findAll(model).count(), "only refresh() reads the console again")
        assertFalse(model.contains("cardDone("))
    }
}
