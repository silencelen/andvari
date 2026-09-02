package io.silencelen.andvari.desktop

import java.io.File

/**
 * Extract the bundled libsodium to a writable temp file and point core at it via the
 * `andvari.native.sodium.path` system property, BEFORE any crypto touch (call first in main()).
 *
 * lazysodium's resource-loader (2.0.2) fails on a jpackage runtime when the install path contains a
 * space (Windows "Program Files"): `copyToTempDirectory` mis-detects the app jar (`isJarFile` false
 * for the spaced/encoded URL), falls into `getFileFromFileSystem`, and does `Paths.get(jar:…)` on a
 * jar filesystem that was never opened → `FileSystemNotFoundException`, at the first crypto call,
 * before login — the "Sign-in failed" every Windows install hit. Reading the resource through the
 * classloader ([getResourceAsStream], which resolves jar-embedded entries the normal way) has none
 * of that NIO-jar-filesystem fragility, and core then loads it with a plain JNA load-by-path.
 *
 * Best-effort: on any failure we leave the property unset and core falls back to lazysodium's own
 * loader — the path that already works everywhere the install dir has no space, and on Linux/macOS.
 */
object NativeSodium {
    fun prepare() {
        if (!System.getProperty("andvari.native.sodium.path").isNullOrBlank()) return
        runCatching {
            val res = resourcePath() ?: return
            val ext = res.substringAfterLast('.')
            val out = File.createTempFile("andvari-libsodium-", ".$ext").apply { deleteOnExit() }
            val stream = NativeSodium::class.java.getResourceAsStream(res) ?: return
            stream.use { input -> out.outputStream().use { input.copyTo(it) } }
            System.setProperty("andvari.native.sodium.path", out.absolutePath)
        }
    }

    /** The lazysodium bundled-resource path for this platform (paths as they exist at the jar root:
     *  windows64/, linux64/, mac/aarch64/, …). Null ⇒ unknown platform, fall back to the default. */
    private fun resourcePath(): String? {
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
}
