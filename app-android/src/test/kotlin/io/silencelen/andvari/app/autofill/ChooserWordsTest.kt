package io.silencelen.andvari.app.autofill

import io.silencelen.andvari.app.trust.Placeholder
import io.silencelen.andvari.app.trust.UiText
import io.silencelen.andvari.core.app.CopyKey
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Andvari's own chooser shows no unmarked words. Its Cancel is the design's
 * word ([CopyKey.CANCEL]); its toasts are the app's own lines, named by their [Placeholder] keys.
 */
class ChooserWordsTest {
    private val src = File("src/main/kotlin/io/silencelen/andvari/app/autofill/FillChooserActivity.kt").readText()

    @Test
    fun theChoosersCancelIsTheDesignsWordAndItsToastsAreNamedByTheirKeys() {
        assertFalse(Regex("Toast\\.makeText\\([^,]+,\\s*\"").containsMatchIn(src), "no toast of the chooser shows a literal")
        assertFalse(Regex("Text\\(\\s*\"").containsMatchIn(src), "no text of the chooser is a literal")
        assertTrue(src.contains("UiText.of(io.silencelen.andvari.core.app.CopyKey.CANCEL).shown()"))
        assertEquals("Cancel", UiText.of(CopyKey.CANCEL).shown())
        for (p in listOf(Placeholder.FILL_CHOOSER_APP_CHANGED_BEFORE, Placeholder.FILL_CHOOSER_APP_CHANGED, Placeholder.FILL_CHOOSER_NOT_FILLED, Placeholder.FILL_CHOOSER_NOTHING)) {
            assertTrue(src.contains("Placeholder.${p.name})"), p.name)
            // Each toast is the app's line for its key (a marked placeholder until it has words, then those words).
            assertTrue(UiText.ph(p).shown().isNotBlank(), "${p.name} says something")
        }
    }

    /** The two fill confirms' four toasts are marked placeholders too; no toast shows a literal. */
    @Test
    fun theTwoConfirmsToastsAreNamedByTheirKeys() {
        val app = File("src/main/kotlin/io/silencelen/andvari/app/autofill/AppFillConfirmActivity.kt").readText()
        val card = File("src/main/kotlin/io/silencelen/andvari/app/autofill/CardFillConfirmActivity.kt").readText()
        for (s in listOf(app, card)) assertFalse(Regex("Toast\\.makeText\\([^,]+,\\s*\"").containsMatchIn(s), "no toast of a confirm shows a literal")
        for (p in listOf(Placeholder.FILL_CONFIRM_APP_CHANGED_BEFORE, Placeholder.FILL_CONFIRM_APP_CHANGED)) {
            assertEquals(1, Regex("Placeholder\\.${p.name}\\)").findAll(app).count(), "app confirm: ${p.name}")
            assertEquals(1, Regex("Placeholder\\.${p.name}\\)").findAll(card).count(), "card confirm: ${p.name}")
        }
        assertEquals(2, Regex("Placeholder\\.FILL_CONFIRM_LOGIN_NOT_FILLED\\)").findAll(app).count())
        assertEquals(2, Regex("Placeholder\\.FILL_CONFIRM_CARD_NOT_FILLED\\)").findAll(card).count())
        for (p in listOf(Placeholder.FILL_CONFIRM_APP_CHANGED_BEFORE, Placeholder.FILL_CONFIRM_APP_CHANGED, Placeholder.FILL_CONFIRM_LOGIN_NOT_FILLED, Placeholder.FILL_CONFIRM_CARD_NOT_FILLED)) {
            // Each toast is the app's line for its key (a marked placeholder until it has words, then those words).
            assertTrue(UiText.ph(p).shown().isNotBlank(), "${p.name} says something")
        }
    }
}
