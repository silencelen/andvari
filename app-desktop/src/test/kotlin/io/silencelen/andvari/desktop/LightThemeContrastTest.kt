package io.silencelen.andvari.desktop

import java.io.File
import kotlin.math.pow
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The light theme's success green, in which the window draws small text (the lines that have no words yet among them),
 * reads at 4.5 to 1 at least on the light ground and on the surface (WCAG 2 for small text): `#4C7538`, 4.69 to 1 on
 * `#F4EFE4`. The green it replaced, `#4F7A3A`, was 4.38 to 1.
 */
class LightThemeContrastTest {
    private val light = File("src/main/kotlin/io/silencelen/andvari/desktop/Main.kt").readText()
        .substringAfter("private val LightColors = lightColorScheme(").substringBefore("\n)\n")

    private fun colour(name: String): Int {
        val hex = Regex("\\b$name = Color\\(0xFF([0-9A-Fa-f]{6})\\)").find(light)?.groupValues?.get(1) ?: error("no $name in the light theme")
        return hex.toInt(16)
    }

    private fun luminance(rgb: Int): Double {
        fun channel(c: Int): Double = (c / 255.0).let { if (it <= 0.03928) it / 12.92 else ((it + 0.055) / 1.055).pow(2.4) }
        return 0.2126 * channel(rgb shr 16 and 0xFF) + 0.7152 * channel(rgb shr 8 and 0xFF) + 0.0722 * channel(rgb and 0xFF)
    }

    private fun contrast(a: Int, b: Int): Double {
        val (hi, lo) = listOf(luminance(a), luminance(b)).sortedDescending()
        return (hi + 0.05) / (lo + 0.05)
    }

    @Test
    fun theSuccessGreenReadsOnTheLightGroundAndSurface() {
        val green = colour("tertiary")
        assertEquals(0x4C7538, green)
        for (ground in listOf("background", "surface")) {
            val ratio = contrast(green, colour(ground))
            println("CONTRAST|tertiary on $ground|${"%.2f".format(ratio)}")
            assertTrue(ratio >= 4.5, "tertiary on $ground: $ratio")
        }
        assertEquals(4.69, "%.2f".format(contrast(green, 0xF4EFE4)).toDouble())
        assertEquals(4.38, "%.2f".format(contrast(0x4F7A3A, 0xF4EFE4)).toDouble(), "the green it replaced")
    }
}
