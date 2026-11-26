package io.silencelen.andvari.app.trust

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The test build for a real phone installs beside every other andvari build and can never replace or be mistaken for
 * one: the debug build type adds `.dev` to the application id and shows "andvari dev"; every visible name in the
 * manifest comes from that one placeholder; and the build bakes no public instance while the spec holds placeholders.
 */
class DevBuildIdentityTest {
    private val gradle = File("build.gradle.kts").readText()
    private val manifest = File("src/main/AndroidManifest.xml").readText()

    private fun block(name: String): String {
        val start = Regex("""\n\s*$name\s*\{""").find(gradle) ?: error("no $name block")
        var depth = 0
        var i = start.range.last
        while (i < gradle.length) {
            when (gradle[i]) {
                '{' -> depth++
                '}' -> if (--depth == 0) return gradle.substring(start.range.first, i + 1)
            }
            i++
        }
        error("unclosed $name block")
    }

    @Test
    fun theDebugBuildHasItsOwnIdAndName() {
        val debug = block("debug")
        assertTrue(Regex("""applicationIdSuffix\s*=\s*"\.dev"""").containsMatchIn(debug), "debug adds .dev to the id")
        assertTrue(Regex("""manifestPlaceholders\["appLabel"]\s*=\s*"andvari dev"""").containsMatchIn(debug))
        assertTrue(Regex("""manifestPlaceholders\["appLabel"]\s*=\s*"andvari"""").containsMatchIn(block("defaultConfig")))
        assertFalse(block("release").contains("applicationIdSuffix"), "the release id is the plain one")
        assertTrue(gradle.contains("""val appOwnId = "com.andvaripass.app"""") && gradle.contains("?: appOwnId"), "the default id the suffix is added to")
    }

    @Test
    fun everyVisibleNameInTheManifestIsThePlaceholder() {
        val labels = Regex("""android:label="([^"]*)"""").findAll(manifest).map { it.groupValues[1] }.toList()
        assertTrue(labels.isNotEmpty())
        assertEquals(listOf("\${appLabel}"), labels.distinct(), "no hard-coded label left to read \"andvari\" in a dev build")
    }

    @Test
    fun theBuildBakesNoServerWhileTheSpecHasPlaceholders() {
        val spec = File("../spec/public-instance.json").readText()
        if (spec.contains("\"instanceId\": \"PLACEHOLDER:")) assertFalse(BuildConstants.BAKES_PUBLIC_INSTANCE)
    }
}
