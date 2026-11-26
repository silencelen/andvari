package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.desktop.SaveTarget
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Files from co-members carry the mark of the web, and a program-like name asks first. */
class SavedFileMarksTest {
    /** Program-like names were kept as they were and nothing looked at their type. */
    @Test
    fun programsShortcutsAndScriptsAreNamed() {
        for ((name, type) in listOf(
            "x.scr" to "scr", "x.lnk" to "lnk", "x.url" to "url", "desktop.ini" to "desktop.ini",
            "router.library-ms" to "library-ms", "run.ps1" to "ps1", "Setup.EXE" to "exe", "invoice.pdf.exe" to "exe",
            "x.exe." to "exe", "x.exe " to "exe", "start.desktop" to "desktop", "go.sh" to "sh", "a.hta" to "hta",
        )) {
            assertEquals(type, SavedFileMarks.riskyType(name), name)
        }
        for (ok in listOf("notes.txt", "scan.pdf", "photo.jpeg", "README", "archive.tar.gz", "x.")) {
            assertNull(SavedFileMarks.riskyType(ok), ok)
        }
    }

    @Test
    fun aRiskySaveWaitsForTheYesAnOrdinaryOneDoesNot() {
        val gate = RiskyTypeGate()
        var saved = 0
        gate.request(File("/tmp/notes.txt")) { saved++ }
        assertEquals(1, saved)
        gate.request(File("/tmp/run.ps1")) { saved++ }
        assertEquals(1, saved, "not before the answer")
        assertEquals("ps1", gate.pending?.second)
        gate.cancel()
        assertNull(gate.pending)
        assertEquals(1, saved, "Cancel saves nothing")
        gate.request(File("/tmp/run.ps1")) { saved++ }
        gate.confirm()
        assertEquals(2, saved)
    }

    @Test
    fun onWindowsTheSavedFileGetsZoneThree() {
        val written = HashMap<String, String>()
        val dest = File("C:\\Users\\me\\Downloads\\x.scr")
        assertTrue(SavedFileMarks.mark(dest, windows = true) { f, b -> written[f.path] = b.decodeToString() })
        assertEquals(mapOf(dest.path + ":Zone.Identifier" to "[ZoneTransfer]\r\nZoneId=3\r\n"), written)
        assertTrue(SavedFileMarks.mark(dest, windows = false) { _, _ -> error("no stream elsewhere") })
        assertFalse(SavedFileMarks.mark(dest, windows = true) { _, _ -> error("FAT has no streams") }, "a failure is reported")
    }

    @Test
    fun aVerifiedWriteStillSavesWhereNoMarkIsWritten() {
        val dir = Files.createTempDirectory("andvari-l7-marks").toFile()
        try {
            val r = writeVerified(File(dir, "x.txt"), "abc".toByteArray())
            assertEquals(ExportWrite.SAVED, r.result)
            assertEquals("abc", File(dir, "x.txt").readText())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun theDeviceNamesThePreviousFilterMissedAreRenamed() {
        for (n in listOf("nul .txt", "COM¹.txt", "CONIN$", "conout$.log", "LPT².x", "clock$")) {
            assertTrue(SaveTarget.defaultName(n).startsWith("_"), n)
        }
        assertEquals("console.txt", SaveTarget.defaultName("console.txt"))
    }
}
