package io.silencelen.andvari.desktop.trust

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Print stays (the owner's decision), and the kit screen says what printing leaves. */
class KitPrintNoticeTest {
    private val src: String =
        listOf(File("src/main/kotlin/io/silencelen/andvari/desktop/trust/KitScreens.kt"), File("app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/trust/KitScreens.kt"))
            .first { it.isFile }.readText()

    @Test
    fun theOneSentenceStandsBesideThePrintButton() {
        val reveal = src.substringAfter("private fun KitReveal(").substringBefore("\n}\n")
        val notice = reveal.indexOf("Placeholder.KIT_PRINT_LEAVES")
        val print = reveal.indexOf("Placeholder.KIT_PRINT)")
        assertTrue(notice in 0 until print, "said right before Print")
        assertEquals(1, Regex("""UiText\.ph\(Placeholder\.KIT_PRINT_LEAVES\)""").findAll(src).count(), "one sentence, once")
        // Named by its key; whatever its words are, they say the print system may keep a copy.
        assertTrue("print system" in UiText.ph(Placeholder.KIT_PRINT_LEAVES).shown(), "says what printing leaves")
    }
}
