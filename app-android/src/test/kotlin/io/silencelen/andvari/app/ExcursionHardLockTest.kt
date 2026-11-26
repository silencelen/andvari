package io.silencelen.andvari.app

import io.silencelen.andvari.app.trust.ProcessStop
import io.silencelen.andvari.app.trust.processStop
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * A vault left open behind an excursion (share, pick a file, open site, print)
 * had no timer on the new path, since the main screen's idle ticker runs only while it is resumed. Every consumed
 * excursion now arms the hard lock.
 */
class ExcursionHardLockTest {
    private fun code(path: String) = File("src/main/kotlin/io/silencelen/andvari/app/$path").readText()

    @Test
    fun aConsumedExcursionArmsTheHardLock() {
        assertEquals(ProcessStop.EXCURSION, processStop(excursionConsumed = true, lastStopWasFillWindow = false))
        val app = code("trust/TrustApp.kt").lines().joinToString("\n") { it.substringBefore("//") }
        assertTrue(Regex("ProcessStop\\.EXCURSION -> ContentFillSession\\.HardLock\\.arm\\(appContext\\)").containsMatchIn(app))
        assertFalse(app.contains("ProcessStop.EXCURSION -> Unit"))
    }

    @Test
    fun theExcursionCommentNoLongerPromisesAnIdleTimer() {
        val doc = code("ExternalExcursion.kt")
        assertFalse(doc.contains("the inactivity timer still stands behind it"))
        assertTrue(doc.contains("arms the autofill hard lock"))
    }
}
