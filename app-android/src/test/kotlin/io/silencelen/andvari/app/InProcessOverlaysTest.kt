package io.silencelen.andvari.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Audit 2026-09-13 H09 — the lock-on-background exemption for the three in-process autofill
 * overlays (design 2026-08-23 §7, ratified in 0.26.0, never built). The state machine is pure
 * ([InProcessOverlays.noteStarted] / [InProcessOverlays.noteStopped]); the manifest pin below
 * keeps the exemption list honest against the activities the app actually declares.
 */
class InProcessOverlaysTest {
    private fun sourceFile(relative: String): File =
        listOf(File(relative), File("app-android/$relative")).firstOrNull { it.isFile }
            ?: error("could not locate $relative from ${File(".").absolutePath}")

    /** THE BUG, fixed: an overlay's own finish() is the last stop before the process ON_STOP. */
    @Test
    fun anOverlayClosingIsNotLeavingTheApp() {
        InProcessOverlays.noteStarted(isOverlay = false)
        InProcessOverlays.noteStopped(isOverlay = true)
        assertTrue(InProcessOverlays.lastStopWasOverlay(), "the ON_STOP this stop causes must be skipped")
    }

    /** The load-bearing 0.26.0 pin stands: MainActivity stopping still locks. */
    @Test
    fun mainActivityStoppingStillCountsAsLeaving() {
        InProcessOverlays.noteStarted(isOverlay = false)
        InProcessOverlays.noteStopped(isOverlay = true)
        InProcessOverlays.noteStarted(isOverlay = false) // MainActivity comes back…
        InProcessOverlays.noteStopped(isOverlay = false) // …and the user leaves it
        assertFalse(InProcessOverlays.lastStopWasOverlay())
    }

    /** Any start resets the verdict — a stale overlay stop must not exempt a later, unrelated stop. */
    @Test
    fun aLaterStartClearsTheOverlayVerdict() {
        InProcessOverlays.noteStarted(isOverlay = false)
        InProcessOverlays.noteStopped(isOverlay = true)
        InProcessOverlays.noteStarted(isOverlay = false)
        assertFalse(InProcessOverlays.lastStopWasOverlay())
    }

    /** R12: the start side — an overlay coming forward is a process ON_START that is NOT the user
     *  returning to the app (the deferred background lock reads this). */
    @Test
    fun anOverlayStartingIsNotReturningToTheApp() {
        InProcessOverlays.noteStarted(isOverlay = true)
        assertTrue(InProcessOverlays.lastStartWasOverlay())
        InProcessOverlays.noteStarted(isOverlay = false) // MainActivity comes forward
        assertFalse(InProcessOverlays.lastStartWasOverlay())
    }

    /** …and the install seam feeds the same verdict on both legs. */
    @Test
    fun theInstallSeamReportsOverlayOnBothLegs() {
        val src = sourceFile("src/main/kotlin/io/silencelen/andvari/app/InProcessOverlays.kt").readText()
        assertTrue(src.contains("override fun onActivityStarted(activity: Activity) = noteStarted(isOverlay(activity))"))
        assertTrue(src.contains("override fun onActivityStopped(activity: Activity) = noteStopped(isOverlay(activity))"))
    }

    /** The exemption names exactly the overlays the manifest declares — every translucent,
     *  no-history activity that runs in this process and is not MainActivity. */
    @Test
    fun theExemptionListMatchesTheManifestsOverlayActivities() {
        val manifest = sourceFile("src/main/AndroidManifest.xml").readText()
        val declared = Regex("android:name=\"(io\\.silencelen\\.andvari\\.app\\.autofill\\.\\w+Activity)\"")
            .findAll(manifest).map { it.groupValues[1] }.toSet()
        assertTrue(declared.isNotEmpty(), "the manifest declares no autofill activities?")
        kotlin.test.assertEquals(declared, InProcessOverlays.OVERLAY_ACTIVITIES, "exemption list vs manifest")
    }
}
