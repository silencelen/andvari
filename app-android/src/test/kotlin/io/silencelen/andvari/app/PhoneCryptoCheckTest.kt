package io.silencelen.andvari.app

import io.silencelen.andvari.core.crypto.createCryptoProvider
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The test build's check of the phone's crypto. Here it runs on THIS COMPUTER's libsodium (the unit tests load the
 * host's build that lazysodium-java bundles), so it proves the rows and their reading, not the phone's library: only
 * the screen on a phone, or the instrumented test, runs the phone's own copy.
 */
class PhoneCryptoCheckTest {
    private fun moduleFile(relative: String): File =
        listOf(File(relative), File("app-android/$relative")).firstOrNull { it.exists() }
            ?: error("could not locate $relative from ${File(".").absolutePath}")

    private val vectors: File = listOf(File("../spec/test-vectors"), File("spec/test-vectors")).first { it.isDirectory }

    @Test
    fun everyRowPassesOnTheSpecificationsVectors() {
        val o = PhoneCryptoCheck.run(createCryptoProvider()) { File(vectors, it).readText() }
        // What ran it, for the record: the rows, the test JVM, and the class-file version of the phone's crypto library.
        val lib = javaClass.classLoader.getResourceAsStream("com/goterl/lazysodium/LazySodiumAndroid.class")?.use { it.readNBytes(8) }
        val classFile = lib?.let { ((it[6].toInt() and 0xff) shl 8) or (it[7].toInt() and 0xff) }
        println("phone check on the computer: ${o.passed} of ${o.total} rows passed; Java ${System.getProperty("java.version")}; LazySodiumAndroid class file $classFile")
        assertNull(o.firstFailure, "a row failed")
        assertEquals(o.total, o.passed)
        assertTrue(o.total >= 15, "the rows are there: ${o.total}")
    }

    @Test
    fun aWrongVectorIsNamedAndNothingOfItsValuesIsShown() {
        val o = PhoneCryptoCheck.run(createCryptoProvider()) { name ->
            val text = File(vectors, name).readText()
            // The usage key's expected value, changed: exactly one row must fail.
            if (name == "usagekey.json") text.replace(Regex("\"usageKeyB64\"\\s*:\\s*\"(.)")) { m -> m.value.dropLast(1) + (if (m.groupValues[1] == "A") "B" else "A") } else text
        }
        assertEquals(o.total - 1, o.passed)
        val first = assertNotNull(o.firstFailure)
        assertEquals("usage key", first)
    }

    @Test
    fun aReleaseBuildHasNeitherTheScreenNorTheVectors() {
        val release = moduleFile("src/release/kotlin/io/silencelen/andvari/app/PhoneCheck.kt").readText()
        assertTrue("internal val phoneCheck: PhoneCheckEntry? = null" in release)
        assertTrue(!moduleFile("src/release").walkTopDown().any { it.isFile && "PhoneCryptoCheck" in it.readText() })
        moduleFile("src/main").walkTopDown().filter { it.isFile }.forEach { f ->
            assertTrue("PhoneCryptoCheck" !in f.readText() || f.name == "PhoneCheckEntry.kt", "${f.name} reaches the test build's check")
            assertTrue(!f.name.endsWith(".json") || f.parentFile.name != "assets", "a vector file in main's assets: ${f.name}")
        }
        val script = moduleFile("build.gradle.kts").readText()
        assertTrue("getByName(\"debug\") { assets.srcDir(phoneCheckVectorsDir) }" in script)
        assertTrue(!Regex("""getByName\("(main|release)"\)\s*\{[^}]*assets""").containsMatchIn(script), "vectors in a release build's assets")
        PhoneCryptoCheck.FILES.forEach { assertTrue("\"$it\"" in script, "the build copies $it") }
    }
}
