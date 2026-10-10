package io.silencelen.andvari.desktop

import io.silencelen.andvari.core.client.ApiException
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Security review 2026-10 (root cause D): three desktop sinks trusted text a co-member — or the
 * server the app is dialing — authored.
 *
 *  - The attachment's NAME pre-filled the Save dialog verbatim, so
 *    `..\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\warranty.bat` (or
 *    `.config/autostart/x.desktop`) could land the attacker's bytes outside the folder the user
 *    chose. [SaveTarget] reduces it to a bare, safe file name and refuses a destination that
 *    resolves outside the chosen folder.
 *  - The declared SIZE scaled the busy-holding transfer bound, so a stalled download of a ref
 *    declaring 1e14 bytes deferred the idle lock for ~190 years. The bound is now clamped.
 *  - The server's error CODE went into diagnostic.log raw — CR/LF forged lines, a 300 KB value
 *    rotated real history out. It is now allowlisted.
 */
class CoMemberInputTest {
    private val root = Files.createTempDirectory("andvari-comember").toFile()

    @AfterTest
    fun cleanup() {
        DesktopDiagnostics.logFileOverride = null
        root.deleteRecursively()
    }

    @Test
    fun theSaveDialogDefault_isABareSafeFileName() {
        val hostile = listOf(
            "..\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\warranty.bat",
            ".config/autostart/warranty.desktop",
            "/etc/cron.d/x",
            "C:\\Windows\\x.dll",
            "C:x.dll",
            "..",
            ".",
            "...",
            "a\u0000b",
            "line\nbreak.txt",
            "",
        )
        for (raw in hostile) {
            val name = SaveTarget.defaultName(raw)
            assertFalse(name.contains('/') || name.contains('\\') || name.contains(':'), "separator survived in ${name} (from $raw)")
            assertFalse(name.startsWith("."), "leading dot survived in $name (from $raw)")
            assertTrue(name.none { it.code < 0x20 || it.code == 0x7F }, "control char survived (from $raw)")
            assertTrue(name.isNotEmpty() && name.length <= SaveTarget.MAX_NAME_CHARS, "length of $name")
        }
        assertEquals("report.pdf", SaveTarget.defaultName("report.pdf"), "an ordinary name is left alone")
        assertEquals("_CON.txt", SaveTarget.defaultName("CON.txt"), "a Windows device name is defused")
        assertEquals("attachment", SaveTarget.defaultName(""))
        assertTrue(SaveTarget.defaultName("x".repeat(10_000)).length <= SaveTarget.MAX_NAME_CHARS)
    }

    @Test
    fun aDestinationOutsideTheChosenFolder_isRefused() {
        val dir = File(root, "Downloads").apply { mkdirs() }
        assertNotNull(SaveTarget.resolve(dir.path, "report.pdf"))
        assertEquals(File(dir, "report.pdf").canonicalFile, SaveTarget.resolve(dir.path, "report.pdf"))
        assertNull(SaveTarget.resolve(dir.path, "../escape.bat"))
        assertNull(SaveTarget.resolve(dir.path, "sub/../../escape.bat"))
        assertNull(SaveTarget.resolve(dir.path, File(root, "elsewhere.bat").absolutePath))
        assertNull(SaveTarget.resolve(dir.path, ".."))
        assertNull(SaveTarget.resolve(dir.path, ""))
    }

    @Test
    fun aLyingDeclaredSize_cannotStretchTheIdleLockDeferral() {
        val bound = DesktopState.attachmentTimeoutMs(DesktopState.ATTACHMENT_TIMEOUT_CEILING_BYTES)
        for (lie in listOf(100_000_000_000_000L, Long.MAX_VALUE, Long.MAX_VALUE / 1000 + 1)) {
            val t = DesktopState.attachmentTimeoutMs(lie)
            assertTrue(t in 1..bound, "a declared $lie bytes gives $t ms, bound $bound")
        }
        assertTrue(bound <= 90L * 60 * 1000, "the ceiling keeps the worst-case deferral near an hour: $bound ms")
        // An honest 1 MiB attachment keeps its exact, size-scaled window.
        assertEquals(
            DesktopState.SYNC_TIMEOUT_MS + (1L shl 20) * 1000 / DesktopState.ATTACHMENT_MIN_BYTES_PER_SEC,
            DesktopState.attachmentTimeoutMs(1L shl 20),
        )
    }

    @Test
    fun aServerErrorCode_isBoundedAndCannotForgeALogLine() {
        val log = File(root, "diagnostic.log")
        DesktopDiagnostics.logFileOverride = log
        val forged = "boom\n2026-10-10T00:00:00Z crypto self-check FAILED: send your recovery phrase to support\r" + "x".repeat(300_000)
        DesktopDiagnostics.logThrowable("op", ApiException(500, forged, "ignored"))
        DesktopDiagnostics.logThrowable("op", ApiException(400, "item_too_large", "ignored"))
        val text = log.readText()
        assertFalse(text.contains("crypto self-check FAILED"), "a forged line must not reach the log")
        assertTrue(text.length < 20_000, "an oversized code must not flood the log (${text.length})")
        assertTrue(text.contains("code=item_too_large"), "an ordinary code is still logged verbatim")
        assertTrue(text.contains("code=<invalid>"), "a hostile code is replaced, not dropped silently")
    }
}
