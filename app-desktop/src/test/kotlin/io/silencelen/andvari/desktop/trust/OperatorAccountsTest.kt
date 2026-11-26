package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.DisableWhy
import io.silencelen.andvari.core.app.OperatorResult
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.model.wire.AccountStatus
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

/** The accounts as the server lists them; disable and enable for a closed reason; one account's quota. */
class OperatorAccountsTest {
    private val crashes = ArrayList<Throwable>()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined + CoroutineExceptionHandler { _, t -> crashes += t })

    private fun console(): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(FakeScene.OPERATOR_CONSOLE)
        val m = TrustModel(api, scope, { 0L }, SignInKeeping.Never, { 0L })
        m.onSnapshot(api.snapshot)
        return api to m
    }

    private fun row(api: FakeDesktopAppApi, email: String) = assertNotNull(api.operatorApi.console).accounts.first { it.email == email }

    private val pw = FakeScenes.PASSWORD

    @Test
    fun eachRowShowsWhatTheServerSaysOfItAndNothingElse() {
        val screens = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/OperatorScreens.kt").readText()
        val src = screens.substringAfter("private fun AccountsSection(").substringBefore("\n}\n") +
            screens.substringAfter("private fun AccountRows(").substringBefore("\n}\n")
        // Every field of the row the server sends is on show, and the row's own status mark for a disabled account.
        for (field in listOf("a.email", "a.displayName", "a.role", "a.status", "a.createdAt", "a.lastSeenAt", "a.recovery", "a.usedBytes", "a.itemCount", "a.ownedVaultCount", "a.liveDeviceCount", "a.disabledAt")) {
            assertTrue(src.contains(field), field)
        }
        assertTrue(src.contains("countsDisagreeLine(c)"))
        // No left accent bar: the state mark is a small icon in the row.
        assertFalse(src.contains("drawBehind") || src.contains("border("))
        val (api, _) = console()
        assertEquals(AccountStatus.DISABLED, row(api, "cy@family.example").status)
    }

    @Test
    fun aCountThatDisagreesWithTheListIsOneLineAndAnAgreeingOneSaysNothing() {
        val (api, _) = console()
        val c = assertNotNull(api.operatorApi.console)
        assertNull(countsDisagreeLine(c))
        // The server's status counts one account more than its list holds: the fake sets the flag as the engine does.
        assertNotNull(api.script.server(c.instance.origin)).userCountOffBy = 1
        api.script.changed()
        val lying = assertNotNull(api.operatorApi.console)
        assertTrue(lying.countsDisagree)
        val line = assertIs<UiText.Ph>(assertNotNull(countsDisagreeLine(lying)))
        assertEquals(Placeholder.OP_COUNTS_DISAGREE, line.placeholder)
        assertEquals(listOf(lying.status!!.userCount.toString(), lying.accounts.size.toString()), line.args)
        assertEquals(lying.accounts.size + 1L, lying.status!!.userCount)
    }

    @Test
    fun disableTakesOneOfTheClosedReasonsAndTheRightPasswordAndEnableUndoesIt() {
        val (api, m) = console()
        val op = m.operator
        val bo = row(api, "bo@family.example").userId

        op.disable(bo, DisableWhy.ABUSE, "not the password")
        val wrong = assertNotNull(op.answerAt(OperatorModel.Area.ACCOUNT, bo))
        assertEquals(OperatorResult.WRONG_PASSWORD, wrong.result)
        assertEquals(Placeholder.OP_WRONG_PASSWORD, assertIs<UiText.Ph>(wrong.text).placeholder)
        assertEquals(AccountStatus.ACTIVE, row(api, "bo@family.example").status, "nothing was done")

        var cleared = false
        op.disable(bo, DisableWhy.REQUEST, pw) { if (it.done) cleared = true }
        assertTrue(cleared, "the screen clears the password on done")
        assertEquals(AccountStatus.DISABLED, row(api, "bo@family.example").status)
        assertEquals(OperatorResult.DONE, op.answerAt(OperatorModel.Area.ACCOUNT, bo)?.result)

        op.enable(bo, pw)
        assertEquals(AccountStatus.ACTIVE, row(api, "bo@family.example").status)

        // The closed list: one label for each reason the wire has, and nowhere a field to type one.
        assertEquals(DisableWhy.entries.size, DisableWhy.entries.map { disableWhyLabel(it).shown() }.toSet().size)
        val panel = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/OperatorScreens.kt").readText()
            .substringAfter("private fun AccountPanel(").substringBefore("\n}\n")
        assertFalse(Regex("\\bField\\(").containsMatchIn(panel), "no reason is typed")
        assertTrue(crashes.isEmpty(), "$crashes")
    }

    @Test
    fun aQuotaIsSentOnlyAsWholeNumbersAndAnEmptyFieldIsTheDefault() {
        val (api, m) = console()
        val op = m.operator
        val bo = row(api, "bo@family.example").userId

        // Not a whole number: said in place, nothing sent (the armed hold is never reached).
        api.script.holdNext()
        assertNull(op.setQuota(bo, QuotaTyped("ten", "", "", ""), pw))
        assertNull(op.setQuota(bo, QuotaTyped("", "-1", "", ""), pw))
        assertFalse(api.script.holding, "nothing was sent")
        assertEquals(Placeholder.OP_NOT_A_WHOLE_NUMBER, assertIs<UiText.Ph>(assertNotNull(op.answerAt(OperatorModel.Area.ACCOUNT, bo)).text).placeholder)

        assertNotNull(op.setQuota(bo, QuotaTyped(" 1048576 ", "", "3", ""), pw))
        api.script.releaseHold()
        assertEquals(OperatorResult.DONE, op.answerAt(OperatorModel.Area.ACCOUNT, bo)?.result)
        val limits = assertNotNull(QuotaTyped(" 1048576 ", "", "3", "").limits())
        assertEquals(1_048_576L, limits.accountBytes)
        assertNull(limits.items)
        assertEquals(3L, limits.ownedSharedVaults)
        assertNull(limits.openLinks)
        assertTrue(crashes.isEmpty(), "$crashes")
    }
}
