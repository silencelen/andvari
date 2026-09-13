package io.silencelen.andvari.desktop

import io.silencelen.andvari.core.crypto.NATIVE_SODIUM_PATH_PROPERTY
import io.silencelen.andvari.core.crypto.createCryptoProvider
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Audit H89: 0.26.3's native-loader change — the fix that unblocked every Windows install — shipped
 * with NO test on any of its three seams (`NativeSodium.prepare`, `DesktopDiagnostics`, and core's
 * `andvari.native.sodium.path` property). This file covers the desktop two; core's
 * `NativeSodiumPathTest` covers the property's load/fallback contract, and `DesktopDiagnosticsTest`
 * the log.
 *
 * What is actually at risk without these: [NativeSodium.resourcePath] is a HAND COPY of lazysodium's
 * `LibraryLoader.getSodiumPathInResources()`. A lazysodium bump that renames or moves the bundled
 * libraries turns `getResourceAsStream` into null, `prepare()` into a silent no-op, and every
 * Windows/Program Files install back into the "Sign-in failed" this release fixed — with
 * `scripts/verify.sh` green, because nothing looked. Resolving the path against the real classpath
 * is the one assertion that cannot be fooled by that.
 *
 * Audit H81 is pinned here too: extraction is content-addressed and REUSED, so a second launch
 * writes no second copy (on Windows `deleteOnExit` cannot unlink a mapped DLL, so a per-launch temp
 * copy was a permanent ~300 KB leak per launch).
 */
class NativeSodiumTest {
    private val scratch = Files.createTempDirectory("andvari-native-test").toFile()
    private var savedProperty: String? = null

    @BeforeTest
    fun setUp() {
        // Resolve the process-wide provider FIRST. It reads the property once, inside a `lazy`,
        // so forcing it here means the property this test mutates can never decide how the rest of
        // the suite loads its crypto.
        createCryptoProvider()
        savedProperty = System.getProperty(NATIVE_SODIUM_PATH_PROPERTY)
        System.clearProperty(NATIVE_SODIUM_PATH_PROPERTY)
        NativeSodium.nativeDirOverride = File(scratch, "native")
        DesktopDiagnostics.logFileOverride = File(scratch, "diagnostic.log")
    }

    @AfterTest
    fun tearDown() {
        NativeSodium.nativeDirOverride = null
        DesktopDiagnostics.logFileOverride = null
        savedProperty?.let { System.setProperty(NATIVE_SODIUM_PATH_PROPERTY, it) }
            ?: System.clearProperty(NATIVE_SODIUM_PATH_PROPERTY)
        scratch.deleteRecursively()
    }

    /** The two platforms jpackage actually ships (TargetFormat.Msi + TargetFormat.Deb). Both are
     *  asserted on every host, because the Windows path is the one that broke and no CI box runs
     *  Windows — a Linux gate that only checked its own platform would not have caught the drift. */
    @Test
    fun everyShippedPlatformsResourcePathResolvesInTheBundledJar() {
        for (res in listOf("/windows64/libsodium.dll", "/linux64/libsodium.so")) {
            val stream = NativeSodium::class.java.getResourceAsStream(res)
            assertNotNull(stream, "lazysodium no longer bundles $res — NativeSodium.resourcePath() has drifted from its jar")
            stream.use { assertTrue(it.readBytes().size > 1024, "$res is present but implausibly small") }
        }
    }

    @Test
    fun thisHostsResourcePathResolvesToo() {
        val res = NativeSodium.resourcePath()
        assertNotNull(res, "no bundled library for os.name=${System.getProperty("os.name")} arch=${System.getProperty("os.arch")}")
        assertNotNull(
            NativeSodium::class.java.getResourceAsStream(res),
            "resourcePath() returned $res for this host and the jar has no such entry",
        )
    }

    @Test
    fun prepareSetsThePropertyToAFileThatHoldsExactlyTheBundledLibrary() {
        NativeSodium.prepare()
        val path = System.getProperty(NATIVE_SODIUM_PATH_PROPERTY)
        assertNotNull(path, "prepare() must hand core a path on a platform the jar bundles")
        val file = File(path)
        assertTrue(file.isFile, "the property must name a file that exists: $path")
        val bundled = NativeSodium::class.java.getResourceAsStream(NativeSodium.resourcePath()!!)!!.use { it.readBytes() }
        assertTrue(file.readBytes().contentEquals(bundled), "the extracted file is not the bundled library")
        // It lives under the store directory, not the shared temp dir (H81).
        assertEquals(File(scratch, "native").absolutePath, file.parentFile.absolutePath)
        assertTrue(file.name.startsWith("libsodium-"), "content-addressed name, got ${file.name}")
    }

    @Test
    fun aSecondLaunchReusesTheSameFileInsteadOfLeakingAnother() {
        NativeSodium.prepare()
        val first = File(System.getProperty(NATIVE_SODIUM_PATH_PROPERTY)!!)
        val stamp = first.lastModified()
        // Second launch of the same build: the property starts unset again, the bytes hash the
        // same, so the file must be REUSED — no second copy, no rewrite.
        System.clearProperty(NATIVE_SODIUM_PATH_PROPERTY)
        NativeSodium.prepare()
        val second = File(System.getProperty(NATIVE_SODIUM_PATH_PROPERTY)!!)
        assertEquals(first.absolutePath, second.absolutePath, "a launch must not mint a new path")
        assertEquals(stamp, second.lastModified(), "the file was rewritten — the reuse test failed open")
        assertEquals(
            1,
            File(scratch, "native").listFiles()!!.count { it.name.startsWith("libsodium-") },
            "exactly one extracted library, however many launches",
        )
    }

    @Test
    fun aTruncatedOrTamperedCopyIsRewrittenRatherThanHandedToTheLoader() {
        NativeSodium.prepare()
        val file = File(System.getProperty(NATIVE_SODIUM_PATH_PROPERTY)!!)
        val good = file.readBytes()
        file.writeBytes(good.copyOf(64)) // an interrupted first write / half-restored backup
        System.clearProperty(NATIVE_SODIUM_PATH_PROPERTY)
        NativeSodium.prepare()
        assertTrue(
            File(System.getProperty(NATIVE_SODIUM_PATH_PROPERTY)!!).readBytes().contentEquals(good),
            "reuse must test the CONTENT, not just the name",
        )
    }

    @Test
    fun anUpgradesLibraryReplacesTheOldOneInsteadOfAccumulating() {
        val dir = File(scratch, "native")
        dir.mkdirsOwnerOnly()
        // A previous release's copy, under a different content hash.
        val old = File(dir, "libsodium-deadbeefdeadbeef.so").apply { writeBytes(ByteArray(2048)) }
        NativeSodium.prepare()
        assertFalse(old.exists(), "the superseded copy must be pruned, not left to accumulate per release")
        assertEquals(1, dir.listFiles()!!.count { it.name.startsWith("libsodium-") })
    }

    /** H81's other half: the orphans 0.26.2/0.26.3 already left in %TEMP%/tmp. */
    @Test
    fun theSweepReclaimsStaleTempExtractionsAndSparesTheLiveOne() {
        val tmp = File(System.getProperty("java.io.tmpdir"))
        val stale = File.createTempFile("andvari-libsodium-", ".so", tmp)
        stale.writeBytes(ByteArray(16))
        stale.setLastModified(System.currentTimeMillis() - 24L * 3600 * 1000) // yesterday's launch
        val fresh = File.createTempFile("andvari-libsodium-", ".so", tmp) // a sibling instance, starting now
        val unrelated = File.createTempFile("something-else-", ".so", tmp)
        try {
            // The property names the fresh file: the sweep must never delete the library the
            // launch that just wrote it is about to load.
            System.setProperty(NATIVE_SODIUM_PATH_PROPERTY, fresh.absolutePath)
            NativeSodium.sweepLegacyTempExtractions()
            assertFalse(stale.exists(), "an old orphan must be reclaimed")
            assertTrue(fresh.exists(), "the in-use extraction must survive")
            assertTrue(unrelated.exists(), "the sweep must only ever touch andvari-libsodium-* files")
        } finally {
            stale.delete(); fresh.delete(); unrelated.delete()
            System.clearProperty(NATIVE_SODIUM_PATH_PROPERTY)
        }
    }

    /** H81: every silent exit now leaves a line. The self-check reads this log to explain a
     *  "Sign-in failed" in the field, and "the property is unset" with no reason was the state
     *  that reproduced the 0.26.2 Program Files failure. */
    @Test
    fun prepareRecordsWhereTheLibraryWentInTheDiagnosticLog() {
        NativeSodium.prepare()
        val log = File(scratch, "diagnostic.log").readText()
        assertTrue(log.contains("native libsodium: "), "prepare() must say what it did")
        assertTrue(log.contains(System.getProperty(NATIVE_SODIUM_PATH_PROPERTY)!!), "…naming the path core will load")
    }
}
