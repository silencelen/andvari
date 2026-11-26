package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Alignment
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.Density
import org.jetbrains.skia.Bitmap
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Small things that did not follow the current desktop app yet: the sort chip's menu names each order without the word
 * "sort" (the chip says it once), and the loading pages show the current app's mark and a spinner that a still frame
 * never catches as a dot.
 */
class CatchUpTest {
    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/$name").readText()
    private fun body(text: String, head: String) = text.substringAfter(head).substringBefore("\n}\n")

    @Test
    fun theSortMenuNamesEachOrderAndTheChipSaysSortOnce() {
        // Each order has a key of its own for its line in the menu, never the chip's key.
        for (s in ListSort.entries) assertNotEquals(s.label, s.choice, "${s.name}: the menu line is not the chip's words")
        assertEquals(ListSort.entries.size, ListSort.entries.map { it.choice }.toSet().size)
        assertEquals(Placeholder.SORT_CHOICE_NAME, ListSort.NAME.choice)
        assertEquals(Placeholder.SORT_CHOICE_RECENT, ListSort.RECENT.choice)
        // The chip shows the chosen order's chip words; its menu lists every order's own line.
        val chip = body(src("VaultItemsScreens.kt"), "private fun SortChoice(")
        assertTrue(chip.contains("ChoiceChip(UiText.ph(sort.label), ListSort.entries.map { it to UiText.ph(it.choice) }, onPick)"), chip)
    }

    @Test
    fun theOpeningPagesAreTheCurrentAppsLoadingPage() {
        val opening = body(src("VaultItemsScreens.kt"), "internal fun VaultOpening(")
        // The current app's Loading: its brand mark at its own size, 16 dp, then the 18 dp spinner.
        assertTrue(opening.contains("BrandRune()") && opening.contains("Gap(16)") && opening.contains("OpeningSpinner("), opening)
        assertTrue(opening.indexOf("BrandRune()") < opening.indexOf("OpeningSpinner(") && opening.indexOf("OpeningSpinner(") < opening.indexOf("Placeholder.VAULT_OPENING)"))
        val spinner = body(src("VaultItemsScreens.kt"), "internal fun OpeningSpinner(")
        assertTrue(spinner.contains("Modifier.size(18.dp)") && spinner.contains("strokeWidth = 2.dp") && spinner.contains("trackColor ="))
        // The start of the app, too, shows the spinner under the brand head, as the current app's start did.
        val start = src("TrustApp.kt").substringAfter("AppPhase.STARTING -> Centered {").substringBefore("AppPhase.ENTRY")
        assertTrue(start.indexOf("Sigil()") < start.indexOf("OpeningSpinner()"), start)
        // The busy spinner on a filled button draws its ring too (caught as a dot on the unlock button).
        assertTrue(body(src("TrustUi.kt"), "internal fun Main(").contains("trackColor ="))
    }

    /** An item in the trash again is plain information, in the notice bar; the server not doing it stays a warning. */
    @Test
    fun anItemInTheTrashAgainIsANoticeNotAWarning() {
        assertTrue(!noticeIsWarning(io.silencelen.andvari.core.app.content.ContentNoticeKind.IN_TRASH_AGAIN))
        assertTrue(noticeIsWarning(io.silencelen.andvari.core.app.content.ContentNoticeKind.NOT_DONE_ON_SERVER))
        val said = body(src("VaultItemsScreens.kt"), "internal fun ContentSaid(")
        assertTrue(said.contains("if (noticeIsWarning(state.noticeKind)) ErrorBar(") && said.contains("else NoticeBar("))
    }

    /** Seen on the virtual display: the spinner was caught as a dot. Whatever frame is drawn, it reads as a ring. */
    @Test
    fun theSpinnerIsARingInEveryFrame() {
        for (at in listOf(0L, 130_000_000L, 400_000_000L, 777_000_000L, 1_200_000_000L)) {
            val scene = ImageComposeScene(40, 40, Density(1f)) {
                MaterialTheme { Surface(Modifier.fillMaxSize()) { Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { OpeningSpinner() } } }
            }
            try {
                scene.render(0L)
                val image = scene.render(at)
                val bitmap = Bitmap.makeFromImage(image)
                val background = bitmap.getColor(1, 1)
                // Something is drawn in every quarter of the circle, not in one spot.
                val quarters = listOf(10..19 to 10..19, 20..29 to 10..19, 10..19 to 20..29, 20..29 to 20..29)
                for ((xs, ys) in quarters) {
                    val drawn = xs.any { x -> ys.any { y -> bitmap.getColor(x, y) != background } }
                    assertTrue(drawn, "frame at ${at / 1_000_000} ms: a quarter of the ring is empty")
                }
            } finally {
                scene.close()
            }
        }
    }
}
