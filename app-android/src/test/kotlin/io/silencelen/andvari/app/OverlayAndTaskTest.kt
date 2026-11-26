package io.silencelen.andvari.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Only the app-fill confirm hid other apps' overlays, and MainActivity could
 * be started inside another app's task. Every window of andvari hides overlays (API 31+), and MainActivity is
 * `singleTask`, the root of andvari's own task.
 */
class OverlayAndTaskTest {
    private fun src(path: String) = File("src/main/kotlin/io/silencelen/andvari/app/$path").readText()

    @Test
    fun everyWindowHidesOtherAppsOverlays() {
        for (name in listOf(
            "MainActivity.kt",
            "autofill/AutofillUnlockActivity.kt",
            "autofill/SaveConfirmActivity.kt",
            "autofill/TrustBrowserActivity.kt",
            "autofill/AppFillConfirmActivity.kt",
            "autofill/CardFillConfirmActivity.kt",
        )) {
            assertTrue(src(name).contains("window.setHideOverlayWindows(true)"), "$name hides overlays")
        }
    }

    @Test
    fun mainActivityIsTheRootOfItsOwnTask() {
        val manifest = File("src/main/AndroidManifest.xml").readText()
        val main = manifest.substringAfter("android:name=\"io.silencelen.andvari.app.MainActivity\"").substringBefore("<intent-filter")
        assertTrue(main.contains("android:launchMode=\"singleTask\""))
    }
}
