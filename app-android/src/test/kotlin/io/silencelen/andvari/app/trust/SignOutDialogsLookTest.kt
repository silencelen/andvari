package io.silencelen.andvari.app.trust

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * What looking at the drawn sign-out, switch and restore confirmations found, each fixed: at the largest font the second
 * confirmation's line, which stood as its title, filled the dialog and pushed its button out of reach, and the first
 * confirmation's lines and "try sending them first" were cut off below; with nothing waiting, the first confirmation
 * said nothing of what signing out removes, where the current app's says it. Also: the drawing-only hooks that open
 * these dialogs are read by the screens and provided by nothing in the app.
 */
class SignOutDialogsLookTest {
    private val dir = File("src/main/kotlin/io/silencelen/andvari/app/trust")

    private fun src(name: String) = File(dir, name).readText()

    private fun body(file: String, start: String): String = src(file).substringAfter(start).substringBefore("\n}\n")

    @Test
    fun theSecondConfirmationHasItsOwnTitleAndItsLineScrolls() {
        val second = body("SignOutConfirm.kt", "internal fun SecondSignOutConfirm(")
        // A title that asks the question and a button that names the act, one pair for a sign-out and one for the switch
        // to another server, as the desktop's (the same four keys).
        assertTrue("title = { Say(UiText.ph(if (ask.switching) Placeholder.SWITCH_SECOND_CONFIRM else Placeholder.SIGN_OUT_SECOND_CONFIRM)) }" in second)
        assertTrue("UiText.ph(if (ask.switching) Placeholder.SWITCH_ALL_THE_SAME else Placeholder.SIGN_OUT_ALL_THE_SAME)" in second)
        assertTrue("text = { Column(Modifier.verticalScroll(rememberScrollState())) { Say(UiText.of(line)" in second, "the line is the text, and it scrolls")
        assertFalse("title = { Say(UiText.of(line)) }" in second)
        assertTrue("switching = true" in src("TrustModel.kt").substringAfter("fun switchAsk(").substringBefore("\n\n"), "only the switch's confirmation is a switch")
        assertFalse("switching = true" in src("TrustModel.kt").substringAfter("fun signOutAsk(").substringBefore("\n"))
    }

    /** Seen in the drawing at the largest font: a long label on "sign out all the same" ran over "Stay signed in". */
    @Test
    fun atTheLargestFontTheSecondConfirmationsButtonsStandOneAboveTheOther() {
        val second = body("SignOutConfirm.kt", "internal fun SecondSignOutConfirm(")
        assertTrue("val large = largeFont()" in second)
        val stacked = second.substringAfter("if (large) {").substringBefore("} else {")
        assertTrue("Column(horizontalAlignment = androidx.compose.ui.Alignment.End)" in stacked && "confirm()" in stacked && "TextButton(onClick = onBack) { Say(dismiss) }" in stacked)
        assertTrue("dismissButton = if (large) null else ({ TextButton(onClick = onBack) { Say(dismiss) } })" in second, "never both: the way out once")
    }

    @Test
    fun theFirstConfirmationScrollsAndSaysWhatSigningOutRemoves() {
        val first = body("SignOutConfirm.kt", "internal fun SignOutConfirm(")
        assertTrue("Column(Modifier.verticalScroll(rememberScrollState())) {" in first.substringAfter("SignOutAsk.Step.FIRST ->"))
        assertTrue(first.indexOf("body?.let { Say(it) }") < first.indexOf("UnsentLines(ask, s)"), "what it removes, then the lines about changes not sent")
        val button = body("AccountScreens.kt", "internal fun SignOutButton(")
        assertTrue("body = UiText.ph(Placeholder.SIGN_OUT_BODY)" in button)
    }

    @Test
    fun theDrawingHooksAreReadByTheScreensAndProvidedByNothingInTheApp() {
        val main = dir.parentFile.walkTopDown().filter { it.isFile && it.name.endsWith(".kt") }.joinToString("\n") { it.readText() }
        assertFalse("LocalDrawnAsk provides" in main, "only the screen images provide an open confirmation")
        assertFalse(Regex("restoreAsked\\s*=\\s*true").containsMatchIn(main), "only the screen images open the restore question")
        for ((file, start) in listOf("AccountScreens.kt" to "internal fun SignOutButton(", "KeptAccountScreens.kt" to "internal fun KeptAccountSignOut(")) {
            assertTrue("val ask = drawn ?: remember(" in body(file, start), "$file: its own confirmation on a phone")
        }
        assertTrue("val ask = drawn ?: remember(model, opened) { model.switchAsk(opened).also { it.open() } }" in src("LinksScreens.kt"))
    }
}
