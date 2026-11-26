package io.silencelen.andvari.app.trust

import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue

/** The kit screen says what printing hands over, before the Print button. */
class KitPrintSentenceTest {
    @Test
    fun theKitSaysWhatPrintingHandsOver() {
        val kit = File("src/main/kotlin/io/silencelen/andvari/app/trust/KitScreens.kt").readText()
        val said = kit.indexOf("Quiet(UiText.ph(Placeholder.KIT_PRINT_HANDS_OVER))")
        assertTrue(said >= 0 && said < kit.indexOf("Second(UiText.ph(Placeholder.KIT_PRINT)"), "said before the button")
        val gloss = Placeholder.KIT_PRINT_HANDS_OVER.gloss
        assertTrue(gloss.contains("print service") && gloss.contains("printer app") && gloss.contains("failed job"))
    }
}
