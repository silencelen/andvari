package io.silencelen.andvari.core.crypto

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Audit H89: the 0.26.3 `andvari.native.sodium.path` seam shipped with no test, and its
 * "best-effort, falls back" contract was only true for EXTRACTION failures — a path that did not
 * LOAD threw out of the lazy initializer on every crypto call. [loadSodium] now falls back to
 * lazysodium's bundled loader on a load failure and reports why; this pins both halves on the
 * seam itself (the process-wide lazy reads the property once, so it is exercised through the
 * function it delegates to, not by mutating the property mid-JVM).
 *
 * The explicit-path case extracts the SAME bundled library the desktop's NativeSodium.prepare()
 * extracts, from the same jar resource layout, so a lazysodium bump that moves the resources
 * fails here before it can silently return Windows installs to the broken resource-loader path.
 */
class NativeSodiumPathTest {

    private fun assertWorks(sodium: SodiumJava) {
        val ls = LazySodiumJava(sodium)
        assertEquals(16, ls.randomBytesBuf(16).size)
    }

    /** lazysodium-java's jar-root resource for THIS host, or null on a platform the jar does
     *  not bundle (the desktop's NativeSodium.resourcePath() table, restricted to what CI runs). */
    private fun bundledResourceForThisHost(): String? {
        val os = System.getProperty("os.name").orEmpty().lowercase()
        val arch = System.getProperty("os.arch").orEmpty().lowercase()
        return when {
            os.contains("win") && arch.contains("64") -> "/windows64/libsodium.dll"
            (os.contains("mac") || os.contains("darwin")) && arch.contains("aarch64") -> "/mac/aarch64/libsodium.dylib"
            os.contains("mac") || os.contains("darwin") -> "/mac/intel/libsodium.dylib"
            os.contains("linux") && (arch == "amd64" || arch == "x86_64") -> "/linux64/libsodium.so"
            os.contains("linux") && arch == "aarch64" -> "/arm64/libsodium.so"
            else -> null
        }
    }

    @Test
    fun noPath_usesTheBundledLoader_andNeverReportsAFallback() {
        var fell: Throwable? = null
        assertWorks(loadSodium(null) { fell = it })
        assertNull(fell, "no path ⇒ nothing to fall back from")
    }

    @Test
    fun explicitPath_toTheExtractedBundledLibrary_loadsWithoutFallback() {
        val res = bundledResourceForThisHost() ?: return // platform the jar does not bundle: nothing to pin
        val stream = SodiumJava::class.java.getResourceAsStream(res)
        assertNotNull(stream, "lazysodium jar no longer carries $res — NativeSodium.resourcePath() is now wrong too")
        val out = File.createTempFile("andvari-test-libsodium-", "." + res.substringAfterLast('.')).apply { deleteOnExit() }
        stream.use { input -> out.outputStream().use { input.copyTo(it) } }
        assertTrue(out.length() > 0)

        var fell: Throwable? = null
        assertWorks(loadSodium(out.absolutePath) { fell = it })
        assertNull(fell, "a loadable path must be honoured, not fallen back from: $fell")
    }

    @Test
    fun bogusPath_fallsBackToTheBundledLoader_andReportsTheLoadFailure() {
        val bogus = File(System.getProperty("java.io.tmpdir"), "andvari-no-such-dir-${System.nanoTime()}/libsodium.so").absolutePath
        // Prove the direct load really fails (so the fallback below is exercised, not vacuous).
        assertFailsWith<Throwable> { SodiumJava(bogus) }

        var fell: Throwable? = null
        assertWorks(loadSodium(bogus) { fell = it })
        assertNotNull(fell, "the load failure must be reported to the host, not swallowed")
    }
}
