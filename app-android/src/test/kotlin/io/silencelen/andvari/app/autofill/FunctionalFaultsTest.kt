package io.silencelen.andvari.app.autofill

import io.silencelen.andvari.app.InProcessOverlays
import io.silencelen.andvari.app.trust.ProcessStop
import io.silencelen.andvari.app.trust.processStop
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The four functional faults that would have failed the dev build's
 * first run. The platform parts (an activity's task, a cold process) cannot run on the JVM, so the wiring is pinned by
 * source text (the AutofillAuthBindingTest idiom) and the lock rule is a plain function.
 */
class FunctionalFaultsTest {
    private fun code(path: String): String = File("src/main/kotlin/io/silencelen/andvari/app/$path").readText()
        .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
        .lines().joinToString("\n") { it.substringBefore("//") }

    private fun seamBuild(): String = code("trust/TrustSeam.kt").substringAfter("private fun build(app: Context)").substringBefore("internal fun bakedInstance(")

    /** Fault 1: the API is started where it is built, so a cold process reached first by autofill is started too. */
    @Test
    fun theApiIsStartedWhereItIsBuilt() {
        val build = seamBuild()
        // Through the model, which contains a fault in it: the model is made first, so it can say one.
        assertTrue(build.contains("model.start()"), "TrustSeam.build starts the API")
        assertTrue(build.indexOf("AppFaults.sink = model::fault") < build.indexOf("model.start()"), "the model can say a fault of the start")
        assertTrue(build.indexOf("model.start()") < build.indexOf("return model"), "before the model is handed out")
    }

    /** Fault 2: the engine gets the platform clocks (quick unlock exists only with them) and the namespace mover. */
    @Test
    fun theEngineGetsTheClocksAndTheNamespaceMover() {
        val build = seamBuild()
        assertTrue(build.contains("clocks = AndroidClocks"), "quick unlock needs the clocks")
        assertTrue(build.contains("namespaceMover = AndroidNamespaceMover(dir)"), "a followed move takes the folders along")
    }

    /** Fault 3: an autofill window closing holds the vault for the idle window; the person leaving andvari locks it. */
    @Test
    fun anUnlockMadeForAFillHoldsForTheIdleWindowWhateverTheAppsState() {
        // The app was open in the background: its screen stopped earlier, then the unlock window opened and closed.
        InProcessOverlays.noteStarted(isOverlay = false)
        InProcessOverlays.noteStopped(isOverlay = false)
        InProcessOverlays.noteStarted(isOverlay = true)
        InProcessOverlays.noteVaultOpenedByFillWindow() // the unlock made for the fill opened the vault
        InProcessOverlays.noteStopped(isOverlay = true)
        assertEquals(ProcessStop.HOLD_UNTIL_IDLE, processStop(excursionConsumed = false, lastStopWasFillWindow = InProcessOverlays.lastStopWasOverlay()))
        // The person leaves andvari's own screen: it locks, as before.
        InProcessOverlays.noteStarted(isOverlay = false)
        InProcessOverlays.noteStopped(isOverlay = false)
        assertEquals(ProcessStop.LOCK, processStop(excursionConsumed = false, lastStopWasFillWindow = InProcessOverlays.lastStopWasOverlay()))
        assertEquals(ProcessStop.EXCURSION, processStop(excursionConsumed = true, lastStopWasFillWindow = false))
        assertEquals(ProcessStop.HOLD_UNTIL_IDLE, processStop(excursionConsumed = true, lastStopWasFillWindow = true))

        // The observer acts on the rule: the hold arms the hard lock, only LOCK locks.
        val app = code("trust/TrustApp.kt")
        assertTrue(app.contains("processStop(ExternalExcursion.consume(), InProcessOverlays.lastStopWasOverlay())"))
        assertTrue(Regex("ProcessStop\\.HOLD_UNTIL_IDLE -> ContentFillSession\\.HardLock\\.arm\\(").containsMatchIn(app))
        assertTrue(Regex("ProcessStop\\.LOCK -> model\\.backgrounded\\(\\)").containsMatchIn(app))
        assertEquals(1, Regex("model\\.backgrounded\\(\\)").findAll(app).count(), "nothing else in the observer locks")
    }

    /** Fault 4: the trust row's activity is started in the browser's task, so its result reaches the fill session. */
    @Test
    fun theTrustActivityReturnsItsResultToTheBrowser() {
        val db = code("autofill/DatasetBuilder.kt")
        val trust = db.substring(db.indexOf("private fun trustBrowserDataset("), db.indexOf("fun lockedPresentation("))
        assertFalse(trust.contains("FLAG_ACTIVITY_NEW_TASK"), "a new task cancels the result")
        assertTrue(trust.contains("b.setAuthentication(pi.intentSender)"))
        val activity = code("autofill/TrustBrowserActivity.kt")
        assertTrue(activity.contains("setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response))"))
    }
}
