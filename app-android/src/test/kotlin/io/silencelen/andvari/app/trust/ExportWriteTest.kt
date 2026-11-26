package io.silencelen.andvari.app.trust

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The export's write, off the main thread: written once, read back and compared, removed if it differs. The order is
 * the one the export was built with; the write itself now runs on the IO dispatcher and finishes even if the screen goes.
 */
class ExportWriteTest {
    private class Place {
        var data = ByteArray(0)
        var writes = 0
        var deleted = false
        var corrupt = false
        var failWrite = false

        fun open(): OutputStream = object : ByteArrayOutputStream() {
            override fun write(b: ByteArray, off: Int, len: Int) {
                if (failWrite) throw IOException("disk full")
                super.write(b, off, len)
            }

            override fun close() {
                writes++
                data = toByteArray().also { if (corrupt && it.isNotEmpty()) it[0] = (it[0] + 1).toByte() }
            }
        }

        fun readBack(): InputStream = ByteArrayInputStream(data)
    }

    private val bytes = "name,url,username,password\nmail,https://mail.example,bo,hunter2\n".encodeToByteArray()

    private fun write(p: Place) = writeAndCheck({ p.open() }, { p.readBack() }, { p.deleted = true }, bytes)

    @Test
    fun aGoodWriteIsWrittenOnceReadBackTheSameAndKept() {
        val p = Place()
        assertEquals(ExportWrite.SAVED, write(p))
        assertEquals(1, p.writes)
        assertTrue(p.data.contentEquals(bytes))
        assertFalse(p.deleted)
    }

    @Test
    fun aCopyThatReadsBackDifferentOrNotAtAllIsRemoved() {
        val p = Place().apply { corrupt = true }
        assertEquals(ExportWrite.DIFFERS, write(p))
        assertTrue(p.deleted)

        val q = Place()
        assertEquals(ExportWrite.DIFFERS, writeAndCheck({ q.open() }, { null }, { q.deleted = true }, bytes))
        assertTrue(q.deleted)

        // A provider that gives back more than was written is refused without reading it all.
        val r = Place()
        val longer = { ByteArrayInputStream(bytes + ByteArray(10_000_000)) }
        assertEquals(ExportWrite.DIFFERS, writeAndCheck({ r.open() }, longer, { r.deleted = true }, bytes))
        assertTrue(r.deleted)
    }

    @Test
    fun aFailedWriteIsRemovedAndAPlaceThatWouldNotOpenIsLeftAlone() {
        val p = Place().apply { failWrite = true }
        assertEquals(ExportWrite.NOT_WRITTEN, write(p))
        assertTrue(p.deleted)

        var deleted = false
        assertEquals(ExportWrite.NOT_OPENED, writeAndCheck({ null }, { null }, { deleted = true }, bytes))
        assertFalse(deleted)
        assertEquals(ExportWrite.NOT_OPENED, writeAndCheck({ throw SecurityException("no") }, { null }, { deleted = true }, bytes))
        assertFalse(deleted)
    }

    @Test
    fun theExportIsWrittenOffTheMainThreadWhileTheScreenSaysItIsWorking() {
        val code = File("src/main/kotlin/io/silencelen/andvari/app/trust/VaultTransferScreens.kt").readText()
        val panel = code.substringAfter("internal fun ExportPanel(").substringBefore("/** What writing an export file came to. */")
        val write = panel.indexOf("withContext(NonCancellable + Dispatchers.IO)")
        assertTrue(write > 0, "written, read back and compared on the IO dispatcher, finished even if the screen goes")
        assertTrue(panel.indexOf("writeAndCheck(", write) > write)
        assertTrue(panel.indexOf("file.bytes.fill(0)", write) > write, "the bytes are zeroed whatever happens")
        // Made only after the place is picked: the file is made inside the picker's answer, never before it.
        val made = panel.indexOf("c.csvFile(ack)")
        assertTrue(made > panel.indexOf("rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument"))
        assertTrue(made < write)
        assertTrue(panel.contains("if (v.busy || writing) Say(Placeholder.WORKING)"))
        // The dialog's main action and its way out wait while a file is being made.
        assertTrue(panel.contains("val idle = !v.busy && !writing") && panel.contains("TextButton(enabled = idle, onClick = {"))
        assertFalse(code.contains("private fun writeExport("), "the main-thread writer is gone")
    }
}
