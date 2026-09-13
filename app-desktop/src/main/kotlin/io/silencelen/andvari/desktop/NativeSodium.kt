package io.silencelen.andvari.desktop

import io.silencelen.andvari.core.crypto.NATIVE_SODIUM_PATH_PROPERTY
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * Extract the bundled libsodium to a writable file and hand core its absolute path via the
 * [NATIVE_SODIUM_PATH_PROPERTY] system property, BEFORE any crypto touch (call first in main()).
 *
 * lazysodium's resource-loader (2.0.2) fails on a jpackage runtime when the install path contains a
 * space (Windows "Program Files"): `copyToTempDirectory` mis-detects the app jar (`isJarFile` false
 * for the spaced/encoded URL), falls into `getFileFromFileSystem`, and does `Paths.get(jar:…)` on a
 * jar filesystem that was never opened → `FileSystemNotFoundException`, at the first crypto call,
 * before login — the "Sign-in failed" every Windows install hit. Reading the resource through the
 * classloader ([Class.getResourceAsStream], which resolves jar-embedded entries the normal way) has
 * none of that NIO-jar-filesystem fragility, and core then loads it with a plain JNA load-by-path.
 *
 * **What "best-effort" actually covers** (audit H89 — the 0.26.3 KDoc over-promised). Two distinct
 * failures, with two owners:
 *
 *  - **Extraction** (no bundled resource for this platform, an unreadable resource, an unwritable
 *    destination) — handled HERE: the property is left unset and lazysodium's own loader runs, the
 *    path that already works everywhere the install dir has no space, and on Linux/macOS. Every one
 *    of those exits now writes a line to `diagnostic.log` naming which one it was (audit H81: they
 *    were silent, so the silent fallback that 0.26.3 exists to avoid left no trace of WHY).
 *  - **Loading** the file we just wrote (a `noexec` or AV-quarantined directory, a runtime missing
 *    VCRUNTIME/UCRT, a hand-set property pointing nowhere) — NOT handled here, because the property
 *    is set before any load is attempted. Core owns it: `loadSodium` falls back to the bundled
 *    loader and reports the cause ([io.silencelen.andvari.core.crypto.nativeSodiumFallbackCause]).
 *    Until that landed, this KDoc's "on any failure we leave the property unset and core falls
 *    back" was simply untrue of the second half.
 *
 * **Where the file goes** (audit H81). 0.26.3 wrote a fresh `File.createTempFile` per launch with
 * `deleteOnExit()`. On Windows — the only platform this change exists for — JNA's load keeps the
 * DLL mapped for the process lifetime, and `deleteOnExit` runs `File.delete()` in a shutdown hook
 * while it is still mapped: the delete fails, silently, and `%TEMP%` gains a ~300 KB orphan on
 * every single launch, forever. So the destination is now a stable, owner-only, content-addressed
 * file under the store directory — `~/.andvari-desktop/native/libsodium-<sha256-16>.<ext>` — which
 * is written once, reused on every later launch whose bundled bytes hash the same, and replaced
 * (old copies pruned) when an upgrade changes the library. That also takes the load off the
 * world-writable shared temp directory entirely, and makes the path in the diagnostic log
 * deterministic instead of a different random name in every report.
 */
object NativeSodium {
    /** Bytes of the bundled library to hash for the file name. The whole library (~300 KB) is read
     *  anyway — content-addressing is what makes "reuse it" safe across an upgrade. */
    private const val NAME_HASH_CHARS = 16

    /** Test seam (the [DesktopDiagnostics.logFileOverride] idiom): extract into a scratch directory
     *  so the reuse/prune behaviour can be asserted without touching the real
     *  `~/.andvari-desktop/native`. Production never sets it. */
    @Volatile
    internal var nativeDirOverride: File? = null

    fun prepare() {
        // An operator/launcher-set property wins and is honoured as-is (core logs whether it
        // actually loaded). Nothing to extract, nothing to say.
        if (!System.getProperty(NATIVE_SODIUM_PATH_PROPERTY).isNullOrBlank()) return

        val res = resourcePath()
        if (res == null) {
            DesktopDiagnostics.log(
                "native libsodium: no bundled resource for os.name=${System.getProperty("os.name")} " +
                    "os.arch=${System.getProperty("os.arch")} — using lazysodium's own loader",
            )
            return
        }
        val bytes = runCatching { NativeSodium::class.java.getResourceAsStream(res)?.use { it.readBytes() } }
            .onFailure { DesktopDiagnostics.logThrowable("native libsodium: reading bundled $res failed", it) }
            .getOrNull()
        if (bytes == null || bytes.isEmpty()) {
            // The hand-copied resource table drifted from the lazysodium jar (the case
            // NativeSodiumPathTest pins) or the read failed — either way lazysodium's loader,
            // which resolves the same resource its own way, is the better bet than nothing.
            DesktopDiagnostics.log("native libsodium: bundled resource $res is missing or empty — using lazysodium's own loader")
            return
        }

        val ext = res.substringAfterLast('.')
        val digest = sha256Hex(bytes)
        val target = File(nativeDir(), "libsodium-${digest.take(NAME_HASH_CHARS)}.$ext")
        val ready = reuseOrWrite(target, bytes, digest) ?: legacyTempCopy(bytes, ext) ?: return
        System.setProperty(NATIVE_SODIUM_PATH_PROPERTY, ready.absolutePath)
        DesktopDiagnostics.log("native libsodium: ${ready.absolutePath} (${bytes.size} bytes, sha256 ${digest.take(NAME_HASH_CHARS)}…)")
    }

    /** `~/.andvari-desktop/native` — the store's directory, so the F35 owner-only rule covers it
     *  (a shared-temp extraction is readable by every local user; this is not). */
    private fun nativeDir(): File =
        nativeDirOverride ?: File(File(System.getProperty("user.home"), ".andvari-desktop"), "native")

    /**
     * Reuse [target] when it already holds exactly these bytes; otherwise write it and prune the
     * copies of other versions beside it. Returns null when the destination cannot be used at all
     * (a read-only home, or — on Windows — a concurrently-running instance holding the old file
     * mapped so the replace fails), which sends the caller to [legacyTempCopy]: a fallback that
     * leaks is still better than the Program Files sign-in failure this whole file exists to fix.
     *
     * The reuse test is the CONTENT, not the name: the name is derived from the same hash, so a
     * truncated or tampered file (an interrupted first write, a half-restored backup) fails the
     * comparison and is rewritten rather than handed to `dlopen`.
     */
    private fun reuseOrWrite(target: File, bytes: ByteArray, digest: String): File? = runCatching {
        if (target.isFile && target.length() == bytes.size.toLong() && sha256Hex(target.readBytes()) == digest) {
            return@runCatching target
        }
        val dir = target.parentFile
        dir.mkdirsOwnerOnly()
        // Write to a sibling temp then MOVE into place: a launch that dies mid-copy must never
        // leave a partial library at the name a later launch will reuse. Owner-only at create,
        // exactly like every other file this app writes under the store (G50/F35).
        val tmp = Files.createTempFile(dir.toPath(), "libsodium-", ".part", *ownerOnly("rw-------"))
        try {
            Files.newOutputStream(tmp).use { it.write(bytes) }
            Files.move(tmp, target.toPath(), StandardCopyOption.REPLACE_EXISTING)
        } catch (t: Throwable) {
            runCatching { Files.deleteIfExists(tmp) }
            throw t
        }
        pruneOtherVersions(dir, target)
        target
    }.onFailure {
        DesktopDiagnostics.logThrowable("native libsodium: could not stage ${target.absolutePath}", it)
    }.getOrNull()

    /** Delete the other `libsodium-*` files beside [keep] — the previous release's copy after an
     *  upgrade. Best-effort and quiet: on Windows a copy still mapped by another running instance
     *  simply refuses to delete, and the next launch will try again. */
    private fun pruneOtherVersions(dir: File, keep: File) {
        val siblings = dir.listFiles { f: File -> f.isFile && f.name.startsWith("libsodium-") } ?: return
        for (f in siblings) if (f.name != keep.name) runCatching { f.delete() }
    }

    /**
     * The 0.26.3 shape, kept ONLY as a last resort (see [reuseOrWrite]): a per-launch temp copy.
     * `deleteOnExit` is still requested because on Linux/macOS it works, and it is still the reason
     * this path is a fallback rather than the default — on Windows it cannot unlink a mapped DLL.
     */
    private fun legacyTempCopy(bytes: ByteArray, ext: String): File? = runCatching {
        val out = File.createTempFile("andvari-libsodium-", ".$ext").apply { deleteOnExit() }
        out.outputStream().use { it.write(bytes) }
        DesktopDiagnostics.log("native libsodium: store directory unusable — fell back to the temp copy ${out.absolutePath}")
        out
    }.onFailure {
        DesktopDiagnostics.logThrowable("native libsodium: temp extraction failed too — using lazysodium's own loader", it)
    }.getOrNull()

    private fun sha256Hex(bytes: ByteArray): String =
        java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }

    /**
     * The lazysodium bundled-resource path for this platform (paths as they exist at the jar root:
     * windows64/, linux64/, mac/aarch64/, …). Null ⇒ unknown platform, fall back to the default.
     *
     * `internal` for audit H89: this table is a hand copy of lazysodium's own
     * `LibraryLoader.getSodiumPathInResources()`, and nothing pinned that the paths still resolve —
     * a lazysodium bump that moved the resources would silently return every Windows install to the
     * broken resource-loader path, with the gate green. [NativeSodiumTest] resolves it now.
     */
    internal fun resourcePath(): String? {
        val os = System.getProperty("os.name").orEmpty().lowercase()
        val arch = System.getProperty("os.arch").orEmpty().lowercase()
        val is64 = arch.contains("64")
        return when {
            os.contains("win") -> if (is64) "/windows64/libsodium.dll" else "/windows/libsodium.dll"
            os.contains("mac") || os.contains("darwin") ->
                if (arch.contains("aarch64") || arch.contains("arm")) "/mac/aarch64/libsodium.dylib"
                else "/mac/intel/libsodium.dylib"
            arch.contains("aarch64") || arch.contains("arm64") -> "/arm64/libsodium.so"
            arch.startsWith("arm") -> "/armv6/libsodium.so"
            is64 -> "/linux64/libsodium.so"
            else -> "/linux/libsodium.so"
        }
    }

    /**
     * Audit H81: reclaim the orphans 0.26.3 left behind. Every launch of 0.26.2/0.26.3 on Windows
     * wrote `%TEMP%\andvari-libsodium-*.dll` and failed to unlink it at exit, so an install that
     * has been running for months has a pile of them; on Linux the same shape exists whenever the
     * JVM was killed before its shutdown hook ran. This is the JNA idiom (JNA sweeps its own stale
     * `jna*.tmp` files at startup) and is deliberately total: a file another live instance still
     * holds mapped simply refuses to delete, and anything unexpected is swallowed — reclaiming
     * temp space must never be able to keep the app from starting.
     *
     * Called from main() after [prepare], so a failure here cannot delay the crypto path. TWO
     * exclusions keep it from eating a library that is about to be loaded: the file the property
     * currently names (which is exactly this shape when [legacyTempCopy] ran — and which nothing
     * has `dlopen`ed yet, so deleting it would break the very launch that wrote it), and anything
     * touched in the last [SWEEP_MIN_AGE_MS] (a second instance starting alongside this one).
     */
    fun sweepLegacyTempExtractions() {
        runCatching {
            val tmp = File(System.getProperty("java.io.tmpdir") ?: return)
            val inUse = System.getProperty(NATIVE_SODIUM_PATH_PROPERTY)?.let { File(it).absolutePath }
            val cutoff = System.currentTimeMillis() - SWEEP_MIN_AGE_MS
            val stale = tmp.listFiles { f: File ->
                f.isFile && f.name.startsWith("andvari-libsodium-") &&
                    (f.name.endsWith(".dll") || f.name.endsWith(".so") || f.name.endsWith(".dylib")) &&
                    f.absolutePath != inUse && f.lastModified() < cutoff
            } ?: return
            var removed = 0
            // Bounded so a pathological directory cannot turn startup into a stat storm.
            for (f in stale.take(MAX_SWEEP)) if (runCatching { f.delete() }.getOrDefault(false)) removed++
            if (removed > 0) DesktopDiagnostics.log("native libsodium: reclaimed $removed stale temp extraction(s) from ${tmp.absolutePath}")
        }
    }

    private const val MAX_SWEEP = 256
    private const val SWEEP_MIN_AGE_MS = 5L * 60 * 1000
}
