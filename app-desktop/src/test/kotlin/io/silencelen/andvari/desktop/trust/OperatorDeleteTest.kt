package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.DisableWhy
import io.silencelen.andvari.core.app.OperatorDeleteWhy
import io.silencelen.andvari.core.app.OperatorResult
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Deleting an account as the operator. The 30-day rule and the one fixed reason, "under the minimum
 * age", offered as a choice and never typed; what the server will record is said before the password is asked.
 */
class OperatorDeleteTest {
    private val crashes = ArrayList<Throwable>()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined + CoroutineExceptionHandler { _, t -> crashes += t })
    private val pw = FakeScenes.PASSWORD

    private fun console(): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(FakeScene.OPERATOR_CONSOLE)
        val m = TrustModel(api, scope, { 0L }, SignInKeeping.Never, { 0L })
        m.onSnapshot(api.snapshot)
        return api to m
    }

    private fun idOf(api: FakeDesktopAppApi, email: String): String? = api.operatorApi.console?.accounts?.firstOrNull { it.email == email }?.userId

    private fun answerPh(m: TrustModel, area: OperatorModel.Area, key: String?): Placeholder =
        assertIs<UiText.Ph>(assertNotNull(m.operator.answerAt(area, key)).text).placeholder

    @Test
    fun anAccountDisabledThirtyDaysIsDeletedWithTheRightPasswordOnly() {
        val (api, m) = console()
        val cy = assertNotNull(idOf(api, "cy@family.example"))
        m.operator.delete(cy, "cy@family.example", OperatorDeleteWhy.DISABLED_30_DAYS, "not the password")
        assertEquals(Placeholder.OP_WRONG_PASSWORD, answerPh(m, OperatorModel.Area.ACCOUNT, cy))
        assertNotNull(idOf(api, "cy@family.example"), "nothing was deleted")

        m.operator.delete(cy, "cy@family.example", OperatorDeleteWhy.DISABLED_30_DAYS, pw)
        assertNull(idOf(api, "cy@family.example"), "the row is gone")
        val done = assertNotNull(m.operator.answerAt(OperatorModel.Area.CONSOLE))
        assertEquals(Placeholder.OP_DELETED, assertIs<UiText.Ph>(done.text).placeholder)
        assertEquals(listOf("cy@family.example"), (done.text as UiText.Ph).args)
        assertTrue(crashes.isEmpty(), "$crashes")
    }

    @Test
    fun underTheMinimumAgeLiftsTheThirtyDaysAndNothingElse() {
        val (api, m) = console()
        val bo = assertNotNull(idOf(api, "bo@family.example"))
        // Still active: refused for either reason.
        m.operator.delete(bo, "bo@family.example", OperatorDeleteWhy.UNDER_MINIMUM_AGE, pw)
        assertEquals(OperatorResult.NOT_DISABLED_LONG_ENOUGH, m.operator.answerAt(OperatorModel.Area.ACCOUNT, bo)?.result)
        assertEquals(Placeholder.OP_NOT_DISABLED_LONG_ENOUGH, answerPh(m, OperatorModel.Area.ACCOUNT, bo))

        // Disabled today: the 30-day rule refuses, the minimum age does not.
        m.operator.disable(bo, DisableWhy.OTHER, pw)
        m.operator.delete(bo, "bo@family.example", OperatorDeleteWhy.DISABLED_30_DAYS, pw)
        assertEquals(OperatorResult.NOT_DISABLED_LONG_ENOUGH, m.operator.answerAt(OperatorModel.Area.ACCOUNT, bo)?.result)
        assertNotNull(idOf(api, "bo@family.example"))
        m.operator.delete(bo, "bo@family.example", OperatorDeleteWhy.UNDER_MINIMUM_AGE, pw)
        assertNull(idOf(api, "bo@family.example"))
        assertTrue(crashes.isEmpty(), "$crashes")
    }

    @Test
    fun theReasonIsAChoiceNeverTypedAndTheRecordIsSaidBeforeThePassword() {
        // Exactly the two reasons, each its own label; each says the record outlives the account.
        assertEquals(2, OperatorDeleteWhy.entries.map { deleteWhyLabel(it).shown() }.toSet().size)
        for (w in OperatorDeleteWhy.entries) {
            val record = assertIs<UiText.Ph>(deleteRecordLine(w)).placeholder.gloss
            assertTrue(record.contains("after the account itself is gone"), "$w")
        }
        assertTrue(Placeholder.OP_DELETE_RECORD_UNDER_AGE.gloss.contains("under the minimum age"))
        assertFalse(Placeholder.OP_DELETE_RECORD.gloss.contains("minimum age"), "the 30-day deletion records no reason")

        val step = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/OperatorScreens.kt").readText()
            .substringAfter("private fun DeleteAccountStep(").substringBefore("\n}\n")
        assertFalse(Regex("\\bField\\(").containsMatchIn(step), "no reason is typed: the step's only field is its password")
        assertTrue(step.contains("for (w in OperatorDeleteWhy.entries)"))
        assertTrue(step.contains("OperatorDesignWords.DELETE_RULE"), "the 30-day rule, with the choice")
        // The password is asked in the deletion's own step, whose lines (the rule, the reason, then the
        // record) come before it (OperatorStepsTest drives it).
        val (api, m) = console()
        val cy = assertNotNull(api.operatorApi.console).accounts.first { it.email == "cy@family.example" }
        val chosen = assertNotNull(m.operator.chooseFor(OperatorModel.Action.DELETE, cy))
        val lines = assertNotNull(m.operator.checkDelete(chosen, OperatorDeleteWhy.UNDER_MINIMUM_AGE)).lines.map { it.text.shown() }
        assertEquals(listOf(OperatorDesignWords.DELETE_RULE, deleteWhyLabel(OperatorDeleteWhy.UNDER_MINIMUM_AGE).shown(), deleteRecordLine(OperatorDeleteWhy.UNDER_MINIMUM_AGE).shown()), lines)
        // The model sends the reason as the closed choice it is.
        val model = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/OperatorModel.kt").readText()
        assertTrue(model.contains("operatorApi.deleteAccountFor(userId, why, password)"))
        assertFalse(model.contains("operatorApi.deleteAccount("))
    }
}
