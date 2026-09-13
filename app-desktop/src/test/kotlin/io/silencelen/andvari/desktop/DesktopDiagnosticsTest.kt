package io.silencelen.andvari.desktop

import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Audit H11 / H15 / H89: 0.26.3 shipped [DesktopDiagnostics] with no test on any of its seams.
 * The two that bit:
 *
 *  - H11 (a regression of F35): main() runs the self-check BEFORE the store exists, so on a fresh
 *    POSIX install it is the diagnostics that CREATE `~/.andvari-desktop` — and it did so with a
 *    bare `mkdirs()` (0755) and created the log at the umask (0644). The store's own
 *    `mkdirsOwnerOnly` then leaves the existing directory alone forever. OriginNamespaceTest pins
 *    `rwx------` on directories the STORE creates and structurally cannot see main()'s ordering;
 *    this pins the diagnostics' own create-time modes, in the same idiom.
 *  - H15: the self-check computed the verdict and returned Unit. It now returns [SelfCheck].
 *
 * A source-level pin (SurfacePinsTest idiom) guards the one-line regression path: the next
 * diagnostic line someone adds must not reintroduce `mkdirs()` / `appendText(`.
 */
class DesktopDiagnosticsTest {
    private val root = Files.createTempDirectory("andvari-diag-test").toFile()

    @AfterTest
    fun cleanup() {
        DesktopDiagnostics.logFileOverride = null
        root.deleteRecursively()
    }

    private fun mode(f: File): String =
        java.nio.file.attribute.PosixFilePermissions.toString(java.nio.file.Files.getPosixFilePermissions(f.toPath()))

    @Test
    fun aFreshHomeGetsTheStoreDirectoryAndTheLogOwnerOnlyAtCreate() {
        val posix = java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("posix")
        if (!posix) return // Windows uses ACLs; the helper falls back to the best-effort path there
        val home = File(root, "fresh-home") // does NOT exist yet — the fresh-install case
        val dir = File(home, ".andvari-desktop")
        DesktopDiagnostics.logFileOverride = File(dir, "diagnostic.log")
        assertFalse(dir.exists(), "precondition: nothing has created the store directory yet")

        val verdict = DesktopDiagnostics.runStartupSelfCheck()

        assertIs<SelfCheck.Ok>(verdict, "native libsodium loads on the test box — the verdict must say so, not vanish")
        // The load-bearing half (F35): the DIRECTORY, which the store will later find existing
        // and — by design — never re-chmod.
        assertEquals("rwx------", mode(dir), "the diagnostics must create ~/.andvari-desktop the store's way")
        assertEquals("rwx------", mode(home), "…and every parent it had to create")
        // The log holds the home path, every op() exception chain and stack trace — owner-only.
        assertEquals("rw-------", mode(File(dir, "diagnostic.log")))
        assertTrue(File(dir, "diagnostic.log").readText().contains("crypto self-check OK"), "the verdict is also written to the log")
    }

    @Test
    fun appendingToAnExistingLogKeepsWritingAndNeverFallsBackToAUmaskCreate() {
        val dir = File(root, ".andvari-desktop")
        DesktopDiagnostics.logFileOverride = File(dir, "diagnostic.log")
        DesktopDiagnostics.log("first")
        DesktopDiagnostics.logThrowable("second", IllegalStateException("boom"))
        val text = File(dir, "diagnostic.log").readText()
        assertTrue(text.contains(" first\n"), "log() appends a stamped line")
        // H58 moved this pin: the CLASS chain is still written, the message of a
        // non-allowlisted type no longer is (this assertion used to expect ": boom").
        assertTrue(text.contains("second :: java.lang.IllegalStateException"), "logThrowable writes the cause chain")
        assertFalse(text.contains("boom"), "a non-allowlisted type's message must not reach the file")
        assertTrue(text.contains("at io.silencelen.andvari.desktop.DesktopDiagnosticsTest"), "…and the stack trace")
    }

    @Test
    fun theDiagnosticsSourceHasNoBareMkdirsOrAppendText() {
        // H11's regression class: a control written for the set of files that existed at the time,
        // reopened by an addition. The store's helpers exist three lines away; the next diagnostic
        // must go through them too.
        val src = listOf(
            File("src/main/kotlin/io/silencelen/andvari/desktop/DesktopDiagnostics.kt"),
            File("app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/DesktopDiagnostics.kt"),
        ).first { it.isFile }.readText()
        assertFalse(src.contains(".mkdirs()"), "DesktopDiagnostics must create directories via mkdirsOwnerOnly()")
        assertFalse(src.contains("appendText("), "DesktopDiagnostics must create/append the log via Files.newByteChannel + ownerOnly(\"rw-------\")")
        assertTrue(src.contains("mkdirsOwnerOnly()") && src.contains("ownerOnly(\"rw-------\")"))
        // H58's regression class, same shape: `stackTraceToString()` reprints every link's
        // toString() — i.e. the raw messages the allowlist exists to withhold. There is no
        // "just this once" use of it here.
        assertFalse(src.contains("stackTraceToString()"), "the trace must be rebuilt from redacted headers + frames")
        assertFalse(src.contains("it.message}"), "a raw message must never be interpolated into a log line")
    }

    // ---- H58: what may and may not reach a cleartext file in the store directory ----

    /** A REAL kotlinx decode failure over a document shaped like the ones core decodes in the
     *  clear (Account.kt's ItemDoc, Export.kt's BackupPayload, Escrow.kt's EscrowPayload). The
     *  marker stands in for vault plaintext: kotlinx-serialization 1.7.3 appends
     *  `"\nJSON input: <window of the input>"` to the exception message, which is how a window of
     *  a decrypted item doc used to land in the log. */
    @kotlinx.serialization.Serializable
    private data class Doc(val name: String, val count: Int)

    @Test
    fun aJsonDecodeFailureNeverWritesTheInputItFailedOn() {
        val dir = File(root, ".andvari-desktop")
        DesktopDiagnostics.logFileOverride = File(dir, "diagnostic.log")
        val marker = "correct-horse-battery-staple.example"
        val thrown = runCatching {
            kotlinx.serialization.json.Json.decodeFromString(
                Doc.serializer(),
                """{"name":"$marker","count":"not-a-number"}""",
            )
        }.exceptionOrNull()!!
        // Precondition: prove the defect is reachable — this exception really does quote the input,
        // so the assertion below is about the redaction and not about a harmless message.
        assertTrue(thrown.message.orEmpty().contains(marker), "kotlinx no longer quotes its input; re-derive this pin")

        DesktopDiagnostics.logThrowable("op() caught", thrown)
        val text = File(dir, "diagnostic.log").readText()
        assertFalse(text.contains(marker), "a window of decoded plaintext reached the diagnostic log")
        assertFalse(text.contains("JSON input"), "…including through the stack-trace header lines")
        assertTrue(text.contains("kotlinx.serialization"), "the failing CLASS is still recorded — that is the diagnosis")
    }

    @Test
    fun anAppMintedMessageCarryingADecryptedNameNeverReachesTheFile() {
        val dir = File(root, ".andvari-desktop")
        DesktopDiagnostics.logFileOverride = File(dir, "diagnostic.log")
        // The exact sentence DesktopState's backup verify throws — user-facing (exportError's
        // carve-out) and therefore allowed to name the file ON SCREEN, never on disk.
        val ise = IllegalStateException("backup verification failed — attachment \"tax-2025.pdf\" does not round-trip")
        DesktopDiagnostics.logThrowable("op() caught", RuntimeException("wrapper", ise))
        val text = File(dir, "diagnostic.log").readText()
        assertFalse(text.contains("tax-2025.pdf"), "a decrypted attachment name reached the diagnostic log")
        assertTrue(text.contains("java.lang.IllegalStateException"), "the chain still names every link's class")
    }

    @Test
    fun theAllowlistedTypesKeepTheirStructuralDetailAndTheWireTextIsDropped() {
        val dir = File(root, ".andvari-desktop")
        DesktopDiagnostics.logFileOverride = File(dir, "diagnostic.log")
        // A native-load failure is the whole reason this log exists (H15/H81): the JVM loader's
        // own text names the library and the search path and can hold no user data.
        DesktopDiagnostics.logThrowable("self-check", UnsatisfiedLinkError("no libsodium in java.library.path: /usr/lib"))
        // The server's free text is NOT logged — it is attacker-controlled; status+code is.
        DesktopDiagnostics.logThrowable(
            "op() caught",
            io.silencelen.andvari.core.client.ApiException(500, "internal", "SQLITE_CONSTRAINT: UNIQUE failed: sessions.id"),
        )
        DesktopDiagnostics.logThrowable("import", io.silencelen.andvari.core.client.CsvImport.ImportException("too_large"))
        val text = File(dir, "diagnostic.log").readText()
        assertTrue(text.contains("no libsodium in java.library.path"), "the loader's text is the diagnosis — keep it")
        assertTrue(text.contains("status=500 code=internal"), "an ApiException is logged as its structured pair")
        assertFalse(text.contains("SQLITE_CONSTRAINT"), "server-supplied message text must never be written")
        assertTrue(text.contains("code=too_large"), "an import refusal's code is app-minted and safe")
    }

    // ---- H126: bounded, so one offline week cannot grow it without limit ----

    @Test
    fun theLogRotatesAtTheCapAndKeepsExactlyOneGeneration() {
        val dir = File(root, ".andvari-desktop")
        val log = File(dir, "diagnostic.log")
        DesktopDiagnostics.logFileOverride = log
        val line = "x".repeat(4096)
        // Enough to cross 256 KiB twice over — the shape of a laptop that fails a sync per focus.
        repeat(160) { DesktopDiagnostics.log(line) }
        assertTrue(log.length() <= DesktopDiagnostics.MAX_LOG_BYTES, "the live log stayed under the cap: ${log.length()}")
        val rolled = File(dir, "diagnostic.log.1")
        assertTrue(rolled.isFile, "the previous generation is kept as diagnostic.log.1")
        assertTrue(dir.listFiles()!!.none { it.name.startsWith("diagnostic.log.2") }, "exactly ONE generation is kept")
        val total = dir.listFiles()!!.filter { it.name.startsWith("diagnostic.log") }.sumOf { it.length() }
        assertTrue(total <= 2 * DesktopDiagnostics.MAX_LOG_BYTES, "the pair is bounded at twice the cap, got $total")
        // …and the newest lines — the ones a maintainer reads — are the ones that survived.
        assertTrue(log.readText().contains(line), "the live log holds the most recent writes")
    }

    // ---- H15: the failure class the op() belt recognises ----

    @Test
    fun nativeLoadFailuresAreRecognisedThroughTheCauseChainAndNothingElseIs() {
        assertTrue(isNativeCryptoLoadFailure(UnsatisfiedLinkError("no libsodium in java.library.path")))
        assertTrue(isNativeCryptoLoadFailure(RuntimeException("wrapped", UnsatisfiedLinkError("x"))), "JNA/lazysodium wrap the real error")
        assertTrue(isNativeCryptoLoadFailure(NoClassDefFoundError("Could not initialize class com.sun.jna.Native")))
        assertTrue(isNativeCryptoLoadFailure(java.nio.file.FileSystemNotFoundException("Provider \"jar\" not installed")), "the 0.26.3 Program Files shape")
        // The canon's own rows must keep their meaning: network, server refusals, wrong password.
        assertFalse(isNativeCryptoLoadFailure(java.io.IOException("connection reset")))
        assertFalse(isNativeCryptoLoadFailure(io.silencelen.andvari.core.client.ApiException(401, "unauthorized", "no")))
        assertFalse(isNativeCryptoLoadFailure(io.silencelen.andvari.core.crypto.CryptoException("decrypt failed")))
        assertFalse(isNativeCryptoLoadFailure(IllegalStateException("plain")))
    }
}
