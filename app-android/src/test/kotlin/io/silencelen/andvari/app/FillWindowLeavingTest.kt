package io.silencelen.andvari.app

import io.silencelen.andvari.app.trust.ProcessStop
import io.silencelen.andvari.app.trust.processStop
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Leaving andvari locks it as before unless the vault was
 * opened by that same autofill window in this run.
 *
 * The review's path: the person leaves the unlocked main app for app H. H fires one of the autofill senders it holds
 * within the 700 ms before the process stop. When that window closes, its stop is the last one, the process stop was
 * read as "an autofill window closing", and the vault stayed open for the idle window, so H's later card confirms
 * needed no unlock.
 */
class FillWindowLeavingTest {
    /** What the process stop does, from the state the activity callbacks left. */
    private fun atProcessStop(): ProcessStop = processStop(excursionConsumed = false, lastStopWasFillWindow = InProcessOverlays.lastStopWasOverlay())

    @Test
    fun theReviewsPathLeavingTheUnlockedAppLocksEvenIfAnAppRaisesAFillWindow() {
        InProcessOverlays.noteStarted(isOverlay = false) // the person in andvari's own window, the vault open there
        InProcessOverlays.noteStopped(isOverlay = false) // they leave for app H
        InProcessOverlays.noteStarted(isOverlay = true) // H fires a confirm sender within the stop's debounce
        InProcessOverlays.noteStopped(isOverlay = true) // the confirm closes (it found the vault open: it opened nothing)
        assertFalse(InProcessOverlays.lastStopWasOverlay())
        assertEquals(ProcessStop.LOCK, atProcessStop())
    }

    @Test
    fun aVaultTheFillUnlockOpenedHoldsForTheIdleWindowThroughTheWindowsAfterIt() {
        InProcessOverlays.noteStarted(isOverlay = false)
        InProcessOverlays.noteStopped(isOverlay = false)
        InProcessOverlays.noteStarted(isOverlay = true) // the fill unlock
        InProcessOverlays.noteVaultOpenedByFillWindow() // it opened the vault
        InProcessOverlays.noteStopped(isOverlay = true)
        assertEquals(ProcessStop.HOLD_UNTIL_IDLE, atProcessStop())
        // The chooser and a confirm after it, in the same run: the same vault, still the fill's.
        InProcessOverlays.noteStarted(isOverlay = true)
        InProcessOverlays.noteStopped(isOverlay = true)
        assertEquals(ProcessStop.HOLD_UNTIL_IDLE, atProcessStop())
    }

    @Test
    fun onceThePersonIsBackInAndvarisOwnWindowLeavingLocksAgain() {
        InProcessOverlays.noteStarted(isOverlay = true)
        InProcessOverlays.noteVaultOpenedByFillWindow()
        InProcessOverlays.noteStopped(isOverlay = true)
        InProcessOverlays.noteStarted(isOverlay = false) // the person opens andvari: the open vault is theirs now
        InProcessOverlays.noteStopped(isOverlay = false)
        InProcessOverlays.noteStarted(isOverlay = true) // an app raises a window as they leave
        InProcessOverlays.noteStopped(isOverlay = true)
        assertEquals(ProcessStop.LOCK, atProcessStop())
    }

    @Test
    fun onlyTheFillUnlockThatOpenedTheVaultSaysSo() {
        val unlock = File("src/main/kotlin/io/silencelen/andvari/app/autofill/AutofillUnlockActivity.kt").readText()
        val opened = unlock.substringAfter("private suspend fun unlocked(").substringBefore("private fun finishFromContent(")
        assertTrue(opened.contains("InProcessOverlays.noteVaultOpenedByFillWindow()"), "the unlock that opened the vault")
        val fast = unlock.substringAfter("private fun begin(").substringBefore("val locked = model.api.snapshot.locked")
        assertFalse(fast.contains("noteVaultOpenedByFillWindow"), "the fast path found the vault open: it opened nothing")
        assertEquals(1, Regex("noteVaultOpenedByFillWindow\\(\\)").findAll(unlock).count())
        // No other window claims it.
        for (f in File("src/main/kotlin/io/silencelen/andvari/app/autofill").listFiles()!!.filter { it.name != "AutofillUnlockActivity.kt" }) {
            assertFalse(f.readText().contains("noteVaultOpenedByFillWindow"), f.name)
        }
    }
}
