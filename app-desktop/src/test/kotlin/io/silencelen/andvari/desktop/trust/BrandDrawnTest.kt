package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Alignment
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.unit.Density
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.desktop.AndvariDesktopTheme
import io.silencelen.andvari.desktop.ThemeMode
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import org.jetbrains.skia.Bitmap
import org.jetbrains.skia.EncodedImageFormat
import org.jetbrains.skia.Image
import java.io.File
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The brand on the desktop's screens (decided on 21 November 2026): the name is one drawing in the theme's text color
 * (bone on dark, ink on light), at the size of the title it stands in for, never text in a serif; a screen reader
 * still reads it as "andvari"; the line under it stays text, word for word. The drawing's outline and the rune's
 * points are compared with assets/brand/ by web/src/ui/brand-assets.test.ts; here, that the screens draw them.
 *
 * The first window and the lock screen are also drawn, dark and light, to `build/brand-pictures/` for looking at.
 */
class BrandDrawnTest {
    private fun src(path: String) = File("src/main/kotlin/io/silencelen/andvari/desktop/$path").readText()
    private fun body(text: String, head: String): String {
        assertTrue(text.contains(head), "missing $head")
        return text.substringAfter(head).substringBefore("\n}\n")
    }

    @Test
    fun theNameIsOneDrawingNamedForAScreenReader() {
        val wordmark = body(src("Ui.kt"), "internal fun Wordmark(")
        assertTrue(wordmark.contains("contentDescription = \"andvari\""), "the drawing keeps the name for a screen reader")
        assertTrue(wordmark.contains("color: Color = MaterialTheme.colorScheme.onSurface") && wordmark.contains("ColorFilter.tint(color)"))
        val sigil = body(src("trust/TrustUi.kt"), "internal fun Sigil(")
        assertTrue(sigil.contains("Wordmark(MaterialTheme.typography.titleLarge.fontSize)"), "the name at the size of the title it stands in for")
        assertFalse(sigil.contains("Text(\"andvari\""), "the name is never text in the platform serif")
        assertTrue(sigil.contains("Text(BRAND_LINE"), "the line stays text")
        // About: the name drawn, then the line as text, on one line as before ("andvari — the keeper of the hoard").
        val about = body(src("trust/AboutDialog.kt"), "internal fun AboutDialog(")
        assertTrue(about.contains("Wordmark(") && about.contains("Text(\" — \$BRAND_LINE\""))
        assertTrue(about.contains("title = { Text(\"About andvari\") }"), "a dialog's title stays text")
    }

    /** The head alone, in one theme: the name's own pixels are the theme's text color, in a box the size of the title. */
    @Test
    fun theNameIsDrawnInTheThemesTextColorAtTheTitlesSize() {
        for ((mode, ink) in listOf(ThemeMode.Dark to Color(0xFFEDE4D0), ThemeMode.Light to Color(0xFF2C2517))) {
            val scene = ImageComposeScene(320, 200, Density(1f)) {
                AndvariDesktopTheme(mode) {
                    Surface(color = MaterialTheme.colorScheme.background) {
                        Column(Modifier.fillMaxSize(), horizontalAlignment = Alignment.CenterHorizontally) { Sigil() }
                    }
                }
            }
            val image = try { scene.render() } finally { scene.close() }
            val bitmap = Bitmap.makeFromImage(image)
            val want = ink.toArgb()
            var minX = Int.MAX_VALUE; var maxX = -1; var minY = Int.MAX_VALUE; var maxY = -1; var n = 0
            // The rune is gold, the line dim, the ground the background: only the name is drawn in the text color.
            for (y in 0 until bitmap.height) for (x in 0 until bitmap.width) {
                if (bitmap.getColor(x, y) == want) { n++; minX = minOf(minX, x); maxX = maxOf(maxX, x); minY = minOf(minY, y); maxY = maxOf(maxY, y) }
            }
            // At 22 px the strokes are thin: about 140 pixels are fully inside the outline, the rest are its edges.
            assertTrue(n > 80, "$mode: the name is drawn in the text color ($n pixels)")
            // titleLarge is 22 sp: the drawing's box is 21.56 px tall, its ink (the d's top to the a's foot) about 16 px
            // tall and 65 px wide at a density of 1.
            val w = maxX - minX + 1
            val h = maxY - minY + 1
            assertTrue(w in 60..70 && h in 13..18, "$mode: the name's ink is $w x $h px")
        }
    }

    @Test
    fun theFirstWindowAndTheLockAreDrawnDarkAndLight() {
        val out = File("build/brand-pictures").apply { mkdirs() }
        for (scene in listOf(FakeScene.FIRST_RUN, FakeScene.LOCKED)) for (mode in listOf(ThemeMode.Dark, ThemeMode.Light)) {
            val api = FakeScenes.desktopAt(scene)
            val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
            m.onSnapshot(api.snapshot)
            val s = api.snapshot
            val image = ImageComposeScene(1000, 720, Density(1f)) {
                AndvariDesktopTheme(mode) {
                    Surface(color = MaterialTheme.colorScheme.background) {
                        val locked = s.locked
                        val entry = s.entry
                        when {
                            locked != null -> LockScreen(m, s, locked)
                            entry != null -> EntryScreens(m, s, entry)
                        }
                    }
                }
            }
            val drawn: Image = try { image.render() } finally { image.close() }
            val png = requireNotNull(drawn.encodeToData(EncodedImageFormat.PNG)) { "the picture of $scene does not encode" }
            File(out, "${scene.name.lowercase()}-${mode.storeValue}.png").writeBytes(png.bytes)
        }
    }
}
