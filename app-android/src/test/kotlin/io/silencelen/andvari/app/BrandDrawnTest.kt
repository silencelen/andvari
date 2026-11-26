package io.silencelen.andvari.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The brand on the phone's screens (decided on 21 November 2026): the name is one drawing in the theme's text color,
 * never text in a serif, and a screen reader still reads it as "andvari"; the line under it stays text, word for
 * word; the vault's top bar keeps the name as plain text in its title style. The drawing's outline and the rune's
 * points are compared with assets/brand/ by web/src/ui/brand-assets.test.ts; here, that the screens use them.
 */
class BrandDrawnTest {
    private fun source(relative: String): String =
        (listOf(File(relative), File("app-android/$relative")).firstOrNull { it.isFile }
            ?: error("could not locate $relative from ${File(".").absolutePath}")).readText()

    private fun body(text: String, head: String): String {
        assertTrue(text.contains(head), "missing $head")
        return text.substringAfter(head).substringBefore("\n}\n")
    }

    private val kt = "src/main/kotlin/io/silencelen/andvari/app/"

    @Test
    fun theDrawnNameIsNamedForAScreenReaderAndTintedInTheTextColor() {
        val wordmark = body(source(kt + "Theme.kt"), "fun Wordmark(")
        assertTrue(wordmark.contains("contentDescription = \"andvari\""), "the drawing keeps the name for a screen reader")
        assertTrue(wordmark.contains("color: Color = MaterialTheme.colorScheme.onSurface"), "the theme's text color, one color")
        assertTrue(wordmark.contains("ColorFilter.tint(color)"))
        assertTrue(wordmark.contains("R.drawable.andvari_wordmark"))
        assertEquals(3017f / 980f, WORDMARK_ASPECT, "the drawing keeps the box of assets/brand/wordmark.svg")
    }

    @Test
    fun theFirstScreenTheSignInAndTheLockDrawTheNameAndKeepTheLine() {
        val sigil = body(source(kt + "MainActivity.kt"), "internal fun Sigil(")
        assertTrue(sigil.contains("SigilMark(BrandSigil, 46.dp)"))
        assertTrue(sigil.contains("Wordmark(MaterialTheme.typography.titleLarge.fontSize)"), "the name at the size of the title it stands in for")
        assertFalse(sigil.contains("Text(\"andvari\""), "the name is never text in the platform serif")
        assertTrue(sigil.contains("Text(\"the keeper of the hoard\""), "the line stays text, word for word")
        // Every screen that shows the brand head shows it through Sigil(): the first screen, the sign-in, the lock.
        assertTrue(body(source(kt + "trust/AccountScreens.kt"), "internal fun LockScreen(").contains("Sigil()"))
        assertTrue(source(kt + "trust/EntryScreens.kt").contains("Sigil()"))
    }

    @Test
    fun thePlainTitleBarKeepsTheNameAsText() {
        assertTrue(source(kt + "trust/VaultHome.kt").contains("title = { Text(\"andvari\", style = MaterialTheme.typography.titleLarge"))
    }

    @Test
    fun theDrawableIsTheOutlineInItsOwnBox() {
        val xml = source("src/main/res/drawable/andvari_wordmark.xml")
        assertTrue(xml.contains("android:viewportWidth=\"3017\"") && xml.contains("android:viewportHeight=\"980\""))
        assertTrue(xml.contains("<group android:translateY=\"740\">"), "the outline's baseline is 740 units down its box")
        assertEquals(1, Regex("android:pathData=").findAll(xml).count(), "one drawing")
    }
}
