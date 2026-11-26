package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.OperatorResult
import io.silencelen.andvari.core.app.Trouble
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

/** The way in to the operator's console, its first read, and what a lock does to it. */
class OperatorConsoleTest {
    private val crashes = ArrayList<Throwable>()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined + CoroutineExceptionHandler { _, t -> crashes += t })
    private var clock = 0L

    private fun at(scene: FakeScene): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(scene)
        val m = TrustModel(api, scope, { clock }, SignInKeeping.Never, { clock })
        m.onSnapshot(api.snapshot)
        return api to m
    }

    private val dir = "src/main/kotlin/io/silencelen/andvari/desktop/trust/"

    @Test
    fun onlyTheOperatorAccountHasTheWayInAndNoOtherRoleReachesAnIntent() {
        val (opApi, op) = at(FakeScene.OPERATOR_CONSOLE)
        assertTrue(op.operator.available(), "the operator account's open vault has the console")
        assertNotNull(opApi.operatorApi.console)

        // An ordinary account, its vault open: no way in, and every intent of the console sends nothing.
        val (api, m) = at(FakeScene.VAULTS)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        assertFalse(m.operator.available())
        assertNull(m.operator.open(), "nothing is launched")
        assertNull(m.operator.refresh())
        assertNull(api.operatorApi.console)
        assertNull(m.operator.answers.value)
        assertTrue(crashes.isEmpty(), "$crashes")

        // The top bar offers the console's icon only behind that check, and the page itself shows nothing without it.
        val shell = File(dir + "AccountScreens.kt").readText()
        assertTrue(shell.contains("if (operator) BarIcon(Icons.Default.AdminPanelSettings, Placeholder.OPERATOR_CONSOLE) { go(SignedInPage.OPERATOR) }"))
        assertTrue(shell.contains("val operator = model.operator.available(s)"))
        assertTrue(shell.contains("(wanted == SignedInPage.OPERATOR && !operator)) SignedInPage.VAULT"))
        val page = File(dir + "OperatorScreens.kt").readText().substringAfter("internal fun OperatorPage(").substringBefore("\n}\n")
        assertTrue(page.contains("if (!op.available(s)) return"))

        // No screen calls the operator interface itself: OperatorModel is the one place, behind its own check.
        val callers = File(dir).listFiles()!!.filter { it.name.endsWith(".kt") && it.readText().contains("operatorApi") }.map { it.name }.sorted()
        assertEquals(listOf("OperatorModel.kt"), callers)
    }

    @Test
    fun theFirstReadShowsNothingUntilItAnswersAndARefusedOneSaysWhyAndOffersAgain() {
        val (api, m) = at(FakeScene.OPERATOR_CONSOLE)
        val op = m.operator
        op.close()
        assertNull(api.operatorApi.console)

        // Under way: nothing of the server, and the console says it is reading.
        api.script.holdNext()
        op.open()
        assertEquals(OperatorModel.Opening.READING, op.opening.value)
        assertNull(api.operatorApi.console, "nothing is shown before the read answered")
        api.script.releaseHold()
        assertNotNull(api.operatorApi.console)
        assertEquals(OperatorModel.Opening.NOT_ASKED, op.opening.value)
        assertNull(op.answers.value, "an answered read says nothing")

        // Refused: still nothing shown, the reason in place, and another try offered (the page's REFUSED state).
        op.close()
        api.script.failNext(Trouble.UNREACHABLE)
        op.open()
        assertNull(api.operatorApi.console)
        assertEquals(OperatorModel.Opening.REFUSED, op.opening.value)
        val said = assertNotNull(op.answerAt(OperatorModel.Area.CONSOLE))
        assertEquals(OperatorResult.UNREACHABLE, said.result)
        assertFalse(said.previousKept)
        op.open()
        assertNotNull(api.operatorApi.console, "the next try reads it")
        assertTrue(crashes.isEmpty(), "$crashes")
    }

    @Test
    fun aRefusedReadKeepsWhatWasShownAndSaysSo() {
        val (api, m) = at(FakeScene.OPERATOR_CONSOLE)
        val before = assertNotNull(api.operatorApi.console).accounts.map { it.userId }
        assertTrue(before.isNotEmpty())
        api.script.failNext(Trouble.UNREACHABLE)
        m.operator.refresh()
        assertEquals(before, assertNotNull(api.operatorApi.console).accounts.map { it.userId }, "the list on show stays")
        val said = assertNotNull(m.operator.answerAt(OperatorModel.Area.CONSOLE))
        assertTrue(said.previousKept, "and the screen says it is the list as last read")
        assertEquals(OperatorResult.UNREACHABLE, said.result)
    }

    @Test
    fun aLockClosesTheConsoleAndAReadItOvertakesIsSaidAsTheLock() {
        val (api, m) = at(FakeScene.OPERATOR_CONSOLE)
        api.script.holdNext()
        m.operator.refresh()
        assertTrue(api.script.holding)
        m.lockNow()
        api.script.releaseHold()
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        assertNull(api.operatorApi.console, "a lock closes the console")
        assertFalse(m.operator.available())
        val said = assertNotNull(m.saidOn(api.snapshot), "the lock screen says it")
        assertEquals(Placeholder.LOCK_OVERTOOK, assertIs<UiText.Ph>(said.text).placeholder)
        assertNull(m.operator.answers.value, "nothing of the console is kept")
        // Leaving the page after the lock does not clear what the lock screen says.
        m.operator.close()
        assertNotNull(m.saidOn(api.snapshot))
        assertTrue(crashes.isEmpty(), "$crashes")
    }

    @Test
    fun everyRefusalOfTheConsoleHasASentence() {
        for (r in OperatorResult.entries) {
            val w = operatorWords(r, 30)
            if (r == OperatorResult.DONE) assertNull(w) else assertNotNull(w, "$r")
        }
        assertFalse(assertNotNull(operatorWords(OperatorResult.NOT_AN_ADDRESS, 0)).isPlaceholder, "the address grammar's sentence is core's")
    }
}
