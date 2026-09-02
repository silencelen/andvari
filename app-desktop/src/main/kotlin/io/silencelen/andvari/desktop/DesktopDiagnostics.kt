package io.silencelen.andvari.desktop

import io.silencelen.andvari.core.crypto.createCryptoProvider
import java.io.File
import java.time.Instant

/**
 * Field diagnostics for failures that the household canon deliberately flattens to a calm,
 * jargon-free line ([HouseholdCopy]) — most of all sign-in, whose "Sign-in failed. Please try
 * again." is the same string for a late crypto throw as for anything else the `else` branch
 * catches ([HouseholdCopy.forSignInError]). The user-facing copy stays calm; this writes the
 * underlying cause where a maintainer can read it, never the user.
 *
 * Log file: `~/.andvari-desktop/diagnostic.log` (the store's own dir). Append-only, best-effort;
 * a diagnostics failure must never affect the app. Contains NO vault material — only exception
 * types/messages, environment facts, and the crypto self-check verdict.
 */
object DesktopDiagnostics {
    private val logFile: File by lazy {
        File(File(System.getProperty("user.home"), ".andvari-desktop"), "diagnostic.log")
    }

    fun log(line: String) {
        val stamped = "${Instant.now()} $line"
        System.err.println("[andvari-diag] $stamped")
        runCatching {
            logFile.parentFile?.mkdirs()
            logFile.appendText(stamped + "\n")
        }
    }

    fun logThrowable(context: String, t: Throwable) {
        val chain = generateSequence(t as Throwable?) { it.cause }
            .joinToString("  <-  ") { "${it::class.qualifiedName}: ${it.message}" }
        log("$context :: $chain")
        runCatching { logFile.appendText(t.stackTraceToString() + "\n") }
    }

    /**
     * Runs once at startup, before the first real crypto touch. Confirms the native libsodium
     * layer actually loads on THIS machine (the one thing that differs across a fresh install and
     * the dev/CI boxes where it always works), and records the environment needed to diagnose a
     * native-load failure — notably which MSVC/UCRT runtime DLLs the bundled JDK runtime ships,
     * since the Windows `libsodium.dll` imports `VCRUNTIME140.dll` + the `api-ms-win-crt-*` UCRT.
     */
    fun runStartupSelfCheck() {
        runCatching {
            log("---- startup self-check ----")
            log("os.name=${System.getProperty("os.name")} os.arch=${System.getProperty("os.arch")} java=${System.getProperty("java.version")}")
            log("java.home=${System.getProperty("java.home")}")
            val runtimeBin = File(System.getProperty("java.home"), "bin")
            val rtDlls = runtimeBin.listFiles { f -> f.name.endsWith(".dll") }
                ?.map { it.name }?.sorted() ?: emptyList()
            val crt = rtDlls.filter {
                it.startsWith("vcruntime", true) || it.startsWith("msvcp", true) ||
                    it.startsWith("ucrtbase", true) || it.startsWith("api-ms-win-crt", true)
            }
            log("runtime/bin CRT dlls: ${if (crt.isEmpty()) "NONE FOUND" else crt.joinToString(",")}")
        }
        try {
            val provider = createCryptoProvider()
            val probe = provider.randomBytes(1)
            log("crypto self-check OK: provider=${provider::class.qualifiedName}, randomBytes=${probe.size}")
        } catch (t: Throwable) {
            logThrowable("crypto self-check FAILED (native libsodium did not load)", t)
        }
    }
}
