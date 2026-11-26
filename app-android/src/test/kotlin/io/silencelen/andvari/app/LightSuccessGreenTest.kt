package io.silencelen.andvari.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The light theme's success green (its `tertiary`, also the tone of a placeholder's text) reads as small text on the
 * light theme's ground and surface: a contrast of at least 4.5 to 1.
 */
class LightSuccessGreenTest {
    private fun color(scheme: String, name: String): Int {
        val hex = Regex("\\b$name = Color\\(0xFF([0-9A-Fa-f]{6})\\)").find(scheme)?.groupValues?.get(1) ?: error("no $name in the scheme")
        return hex.toInt(16)
    }

    private fun luminance(rgb: Int): Double {
        fun channel(c: Int): Double = (c / 255.0).let { if (it <= 0.04045) it / 12.92 else Math.pow((it + 0.055) / 1.055, 2.4) }
        return 0.2126 * channel(rgb shr 16 and 0xFF) + 0.7152 * channel(rgb shr 8 and 0xFF) + 0.0722 * channel(rgb and 0xFF)
    }

    private fun contrast(a: Int, b: Int): Double {
        val (hi, lo) = listOf(luminance(a), luminance(b)).sortedDescending()
        return (hi + 0.05) / (lo + 0.05)
    }

    @Test
    fun theLightSuccessGreenReadsAsSmallTextOnTheLightGroundAndSurface() {
        val light = File("src/main/kotlin/io/silencelen/andvari/app/Theme.kt").readText()
            .substringAfter("private val AndvariLight = lightColorScheme(").substringBefore("\n)\n")
        val green = color(light, "tertiary")
        assertEquals(0x4C7538, green)
        for (ground in listOf("background", "surface")) {
            val c = contrast(green, color(light, ground))
            assertTrue(c >= 4.5, "the success green on the light $ground: $c to 1")
        }
        assertTrue(contrast(0x4F7A3A, color(light, "background")) < 4.5, "the earlier green did not read on the ground")
    }
}
