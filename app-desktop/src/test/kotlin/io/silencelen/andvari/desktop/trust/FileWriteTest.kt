package io.silencelen.andvari.desktop.trust

import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * [writeVerified] on this machine's real file system: the replacement of an existing file and the `.recovered-` copy
 * when the move cannot happen. Until now the fallback was pinned only by its source line (RegressionPins0262Test).
 */
class FileWriteTest {
    private val tmp: File = Files.createTempDirectory("andvari-write").toFile()

    @AfterTest
    fun cleanUp() {
        tmp.deleteRecursively()
    }

    private fun leftovers() = tmp.listFiles()!!.filter { it.name.startsWith("andvari-") && it.name.endsWith(".tmp") }

    @Test
    fun anExistingFileIsReplacedOnlyByACheckedCopy() {
        val dest = File(tmp, "export.csv").apply { writeText("old") }
        val r = writeVerified(dest, "new bytes".toByteArray())
        assertEquals(ExportWrite.SAVED, r.result)
        assertEquals("new bytes", dest.readText())
        assertEquals(emptyList(), leftovers())
        if (Files.getFileStore(tmp.toPath()).supportsFileAttributeView("posix")) {
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(dest.toPath())))
        }
    }

    @Test
    fun aMoveThatFailsKeepsTheCheckedCopyBesideIt() {
        // A directory with something in it where the file should go: no move can replace it.
        val dest = File(tmp, "backup.andvari").apply { mkdirs(); File(this, "inside").writeText("x") }
        val r = writeVerified(dest, "the backup".toByteArray())
        assertEquals(ExportWrite.NOT_WRITTEN, r.result)
        val kept = assertNotNull(r.keptAs)
        assertTrue(kept.startsWith("backup.andvari.recovered-"), kept)
        assertEquals("the backup", File(tmp, kept).readText())
        assertEquals("x", File(dest, "inside").readText(), "what was there is untouched")
        assertEquals(emptyList(), leftovers())
    }
}
