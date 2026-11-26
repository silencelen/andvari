package io.silencelen.andvari.desktop

import java.io.File
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Audit 2026-09-13 H41: regression pins for the 0.26.2 (2026-08-30 audit) desktop fixes that shipped with no test. A
 * fix nothing pins is a fix nothing keeps — each block names its G-row and FAILS if that fix is reverted.
 *
 * With the onboarding and trust overhaul the old state holder went, and with it G09 (the engine's replay notice, now
 * core's), G37 (the usage ledger, not carried over), G63 and G03 (the old op mapping and teardown). G36 and G50 hold for
 * the new path's file write, `trust/DesktopFiles.kt`'s `writeVerified`, which every export and saved attachment uses.
 */
class RegressionPins0262Test {

    private fun sourceFile(relative: String): File =
        listOf(File(relative), File("app-desktop/$relative")).firstOrNull { it.isFile }
            ?: error("could not locate $relative from ${File(".").absolutePath}")

    private val writer by lazy {
        sourceFile("src/main/kotlin/io/silencelen/andvari/desktop/trust/DesktopFiles.kt").readText()
            .substringAfter("internal fun writeVerified(").substringBefore("\n}")
    }

    private fun assertOrdered(hay: String, first: String, second: String, why: String) {
        val a = hay.indexOf(first)
        val b = hay.indexOf(second)
        assertTrue(a > -1, "$why: missing `$first`")
        assertTrue(b > -1, "$why: missing `$second`")
        assertTrue(a < b, why)
    }

    // ---- G36 / G50: the export temp — created owner-only, and a kept temp that survives exit ----

    /** F35's rule: the permissions are part of the CREATE. The temp holds the full plaintext CSV or a decrypted file. */
    @Test
    fun g50_thePlaintextTempIsCreatedOwnerOnlyNotRepairedAfterwards() {
        assertOrdered(
            writer,
            "PosixFilePermissions.fromString(\"rw-------\")",
            "Files.createTempFile(dir.toPath(), \"andvari-\", \".tmp\", *attrs)",
            "the mode is given to the create itself",
        )
        assertFalse(writer.contains("setReadable("), "no repair after the create")
    }

    /**
     * java.io.File cannot cancel deleteOnExit, so a kept temp would vanish at the next normal exit: the temp goes on the
     * app's own exit list instead, and the kept copy (renamed, or under its temporary name where the rename fails) is
     * taken off it before the result names it. The behaviour is walked in trust/FileWriteTest.
     */
    @Test
    fun g36_theKeptExportIsRenamedToASurvivorBeforeItIsNamed() {
        assertTrue(writer.contains("survivorOf: (File) -> File = { File(it.absoluteFile.parentFile, \"\${it.name}.recovered-\${System.currentTimeMillis()}\") }"))
        val moveFailure = writer.substringAfter("} catch (e: Exception) {")
        assertTrue(moveFailure.contains("val survivor = survivorOf(dest)"))
        assertOrdered(
            moveFailure,
            "val kept = runCatching { Files.move(tmp.toPath(), survivor.toPath()); survivor }.getOrDefault(tmp)",
            "TempsDeletedAtExit.forget(tmp)",
            "the rename happens first",
        )
        assertOrdered(moveFailure, "TempsDeletedAtExit.forget(tmp)", "FileWritten(ExportWrite.NOT_WRITTEN, kept.name)", "off the exit's list BEFORE the result names it")
        assertFalse(writer.contains("deleteOnExit()"), "no deleteOnExit, which cannot be taken back")
        assertTrue(writer.indexOf("TempsDeletedAtExit.add(tmp)") in 0 until writer.indexOf("Files.move(tmp.toPath(), dest.toPath()"))
    }
}
