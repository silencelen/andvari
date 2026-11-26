package io.silencelen.andvari.app.autofill

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The defences every autofill window shares:
 * - the confirmation, trust and unlock windows are opaque and cover the screen: nothing of the requesting app shows
 *   around them to frame the card with its own words;
 * - on Android 10 and 11, where overlays cannot be hidden, a touch that arrives while the window is obscured, wholly
 *   or partly, is dropped (`filterTouchesWhenObscured` looks only at the touch point, so an overlay could cover the
 *   card's words and leave the button bare).
 */
class FillWindowShieldTest {
    private val windows = listOf(
        "AutofillUnlockActivity", "AppFillConfirmActivity", "CardFillConfirmActivity", "TrustBrowserActivity", "FillChooserActivity",
    )

    /** The retired save card finishes before it draws anything (OLD_SAVE_CONFIRM_RETIRED); its declaration is opaque too. */
    private val declared = windows + "SaveConfirmActivity"

    @Test
    fun onAndroid10And11ATouchWhileAnyPartOfTheWindowIsCoveredIsDropped() {
        val partly = FillWindow.FLAG_PARTIALLY_OBSCURED
        val wholly = FillWindow.FLAG_OBSCURED
        for (sdk in listOf(29, 30)) {
            assertTrue(FillWindow.dropsTouch(sdk, partly), "API $sdk: an overlay covering the card's words, the touch on the bare button")
            assertTrue(FillWindow.dropsTouch(sdk, wholly), "API $sdk: a touch through another window")
            assertTrue(FillWindow.dropsTouch(sdk, partly or wholly))
            assertFalse(FillWindow.dropsTouch(sdk, 0), "API $sdk: an uncovered window takes its touches")
        }
        // Android 12 and later hide other apps' overlays while the window is shown; a touch through a window is still dropped.
        for (sdk in listOf(31, 35)) {
            assertFalse(FillWindow.dropsTouch(sdk, partly), "API $sdk: overlays are hidden here")
            assertTrue(FillWindow.dropsTouch(sdk, wholly))
        }
        // The platform's own values.
        assertEquals(0x1, FillWindow.FLAG_OBSCURED)
        assertEquals(0x2, FillWindow.FLAG_PARTIALLY_OBSCURED)
        val fw = code("FillWindow.kt")
        assertTrue(fw.contains("cancel.action = MotionEvent.ACTION_CANCEL"), "a press already under way is cancelled, never completed")
        assertTrue(fw.contains("if (!dropsTouch(Build.VERSION.SDK_INT, ev.flags)) return deliver(ev)"))
    }

    @Test
    fun everyAutofillWindowDropsSuchTouchesAndIsASecureWindow() {
        for (w in windows) {
            val src = code("$w.kt")
            assertTrue(
                src.contains("override fun dispatchTouchEvent(ev: android.view.MotionEvent): Boolean = FillWindow.dispatch(this, ev, obscuredTold) { super.dispatchTouchEvent(it) }"),
                "$w drops a touch while it is covered",
            )
            assertTrue(src.contains("window.decorView.filterTouchesWhenObscured = true"), "$w drops a touch through another window")
            assertTrue(src.contains("FLAG_SECURE, ") , "$w is a secure window")
            assertTrue(src.contains("window.setHideOverlayWindows(true)"), "$w hides overlays where it can")
        }
    }

    @Test
    fun everyAutofillWindowIsOpaqueAndCoversTheScreen() {
        val manifest = File("src/main/AndroidManifest.xml").readText()
        for (w in declared) {
            val decl = manifest.substringAfter("io.silencelen.andvari.app.autofill.$w\"").substringBefore("/>")
            assertTrue(decl.contains("android:theme=\"@style/Theme.Andvari.FillWindow\""), "$w: $decl")
        }
        assertFalse(manifest.contains("Theme.Andvari.Translucent"), "no window of andvari is translucent")
        val themes = File("src/main/res/values/themes.xml").readText()
        val style = themes.substringAfter("<style name=\"Theme.Andvari.FillWindow\">").substringBefore("</style>")
        assertTrue(style.contains("<item name=\"android:windowIsTranslucent\">false</item>"))
        assertTrue(style.contains("<item name=\"android:windowIsFloating\">false</item>"))
        assertTrue(style.contains("<item name=\"android:backgroundDimEnabled\">false</item>"))
        assertFalse(style.contains("windowBackground"), "it keeps Theme.Andvari's solid background, light and dark")
        assertTrue(themes.contains("<item name=\"android:windowBackground\">#FBF8F1</item>"))
        assertTrue(File("src/main/res/values-night/themes.xml").readText().contains("<item name=\"android:windowBackground\">#14120E</item>"))
        // The cards fill the window: every one is laid out on the whole screen.
        for (w in windows) {
            assertTrue(code("$w.kt").contains("Modifier.fillMaxSize()"), "$w lays its card out on the whole window")
        }
    }

    private fun code(name: String): String = File("src/main/kotlin/io/silencelen/andvari/app/autofill/$name").readText()
        .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
        .lines().joinToString("\n") { it.substringBefore("//") }
}
