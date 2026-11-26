package io.silencelen.andvari.app

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Android 16 (API 36). Google Play accepts no upload, on any track, whose app targets less (since 2026-08-31), so the
 * level is read off the debug manifest exactly as the build merged it, not off the build script.
 *
 * Android 16's changes for an app that targets it, where the app relies on something, are pinned here too:
 * - Back is predictive: the Back key no longer reaches `dispatchKeyEvent`, where a key counts as activity for the idle
 *   lock. Every screen takes Back through [io.silencelen.andvari.app.trust.ActiveBackHandler], which counts it.
 * - Edge to edge can no longer be refused: no theme may try (`windowOptOutEdgeToEdgeEnforcement`), and the app may not
 *   turn predictive Back off (`enableOnBackInvokedCallback="false"`).
 * - On a screen 600 dp wide or wider a fixed orientation, size or aspect ratio is ignored: the manifest declares none.
 */
class TargetSdkPinTest {

    private fun moduleFile(relative: String): File =
        listOf(File(relative), File("app-android/$relative")).firstOrNull { it.exists() }
            ?: error("could not locate $relative from ${File(".").absolutePath}")

    private val androidNs = "http://schemas.android.com/apk/res/android"

    @Test
    fun theBuiltDebugManifestTargetsAndroid16OrLater() {
        val path = System.getProperty("andvari.debugManifest") ?: fail("the test task names no built debug manifest")
        val file = File(path)
        assertTrue(file.isFile, "the built debug manifest is missing: $path")
        val doc = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }.newDocumentBuilder().parse(file)
        val usesSdk = doc.getElementsByTagName("uses-sdk")
        assertEquals(1, usesSdk.length, "the built manifest has one uses-sdk")
        val el = usesSdk.item(0) as org.w3c.dom.Element
        val target = el.getAttributeNS(androidNs, "targetSdkVersion").toIntOrNull() ?: fail("no targetSdkVersion in $path")
        assertTrue(target >= 36, "the debug manifest targets $target; Google Play takes nothing below 36")
        val min = el.getAttributeNS(androidNs, "minSdkVersion").toIntOrNull() ?: fail("no minSdkVersion in $path")
        assertEquals(29, min, "the oldest Android the app runs on is unchanged")
    }

    @Test
    fun noThemeRefusesEdgeToEdgeAndPredictiveBackIsNotTurnedOff() {
        val res = moduleFile("src/main/res")
        val themes = res.walkTopDown().filter { it.isFile && it.extension == "xml" }.toList()
        assertTrue(themes.isNotEmpty())
        themes.forEach { f ->
            val text = f.readText()
            assertTrue("windowOptOutEdgeToEdgeEnforcement" !in text, "${f.name} tries to refuse edge to edge")
        }
        val manifest = moduleFile("src/main/AndroidManifest.xml").readText()
        assertTrue("enableOnBackInvokedCallback=\"false\"" !in manifest, "the manifest turns predictive Back off")
        listOf("screenOrientation", "resizeableActivity", "maxAspectRatio", "minAspectRatio").forEach {
            assertTrue("android:$it" !in manifest, "the manifest fixes $it, which Android 16 ignores on large screens")
        }
    }

    @Test
    fun everyScreenTakesBackThroughTheHandlerThatCountsItAsActivity() {
        val trust = moduleFile("src/main/kotlin/io/silencelen/andvari/app/trust")
        val direct = trust.walkTopDown().filter { it.isFile && it.extension == "kt" }.flatMap { f ->
            f.readLines().withIndex()
                .filter { (_, line) -> Regex("""(?<![A-Za-z])BackHandler\s*[({]""").containsMatchIn(line) }
                .map { (i, _) -> "${f.name}:${i + 1}" }
        }.toList()
        // The one direct use is inside ActiveBackHandler itself.
        assertEquals(listOf("TrustApp.kt"), direct.map { it.substringBefore(':') }, "a screen takes Back directly: $direct")
        val app = File(trust, "TrustApp.kt").readText()
        val body = app.substringAfter("internal fun ActiveBackHandler(").substringBefore("\n}\n")
        assertTrue("model.touched()" in body, "ActiveBackHandler no longer counts Back as activity")
        assertTrue("ActiveBackHandler(" in File(trust, "AccountScreens.kt").readText())
        assertTrue("ActiveBackHandler(" in File(trust, "DevicesScreens.kt").readText())
    }
}
