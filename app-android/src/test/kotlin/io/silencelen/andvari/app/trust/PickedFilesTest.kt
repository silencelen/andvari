package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AttachmentDraftView
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.client.CsvImport
import java.io.ByteArrayInputStream
import java.io.File
import java.io.InputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** A picked file is never read past its limit, whatever its provider says (attachments and the CSV import). */
class PickedFilesTest {
    /** A provider that never ends, counting what was taken from it. */
    private class Endless : InputStream() {
        var taken = 0L
        override fun read(): Int {
            taken++
            return 7
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            b.fill(7, off, off + len)
            taken += len
            return len
        }
    }

    @Test
    fun aDocumentUpToTheLimitIsReadWholeAndOneByteMoreIsRefused() {
        val ten = ByteArray(10) { it.toByte() }
        assertContentEquals(ten, PickedFiles.readAtMost(ByteArrayInputStream(ten), 10))
        assertContentEquals(ten, PickedFiles.readAtMost(ByteArrayInputStream(ten), 11, sizeHint = 10))
        assertNull(PickedFiles.readAtMost(ByteArrayInputStream(ten), 9))
        assertContentEquals(ByteArray(0), PickedFiles.readAtMost(ByteArrayInputStream(ByteArray(0)), 0))
        assertNull(PickedFiles.readAtMost(ByteArrayInputStream(ByteArray(1)), 0))
    }

    @Test
    fun aProviderThatSaysLessOrNothingIsStillStoppedAtTheLimitPlusOne() {
        val limit = 300_000
        for (hint in listOf(null, 10L, limit.toLong(), Long.MAX_VALUE)) {
            val endless = Endless()
            assertNull(PickedFiles.readAtMost(endless, limit, hint), "hint $hint")
            assertEquals(limit + 1L, endless.taken, "never read past the limit plus one (hint $hint)")
        }
        // A provider that says more than it has is read to its end, and no further.
        val five = ByteArray(5) { 1 }
        assertContentEquals(five, PickedFiles.readAtMost(ByteArrayInputStream(five), limit, sizeHint = 4_000))
    }

    @Test
    fun aDocumentLargerThanTheBufferGrowsItAndArrivesWhole() {
        val big = ByteArray(200_000) { (it % 251).toByte() }
        assertContentEquals(big, PickedFiles.readAtMost(ByteArrayInputStream(big), 200_000))
        assertContentEquals(big, PickedFiles.readAtMost(ByteArrayInputStream(big), 1_000_000, sizeHint = 3))
    }

    private fun draft(total: Long, perFile: Long, perItem: Long) =
        AttachmentDraftView(emptyList(), emptyList(), total, AttachmentRules.limits(perFile, perItem))

    @Test
    fun anAttachmentIsReadToTheDraftsLimitsAndRefusedInTheContentsWords() {
        val roomy = draft(total = 0, perFile = 1_000_000, perItem = 5_000_000)
        assertEquals(1_000_000, attachmentRoom(roomy), "the per-file limit")
        val nearlyFull = draft(total = 4_500_000, perFile = 1_000_000, perItem = 5_000_000)
        assertEquals(500_000, attachmentRoom(nearlyFull), "what the item has room for")
        assertEquals(0, attachmentRoom(draft(total = 5_000_000, perFile = 1_000_000, perItem = 5_000_000)))

        assertEquals(AttachmentRules.refusal(1_000_001, 0, roomy.limits), attachmentTooLarge(1_000_001, roomy))
        assertTrue(attachmentTooLarge(1_000_001, roomy).startsWith("This file is larger than"))
        assertTrue(attachmentTooLarge(500_001, nearlyFull).startsWith("This item's files would come to more than"))
    }

    @Test
    fun aCsvIsReadToTheContentsCapAndATooLargeOneSaysSo() {
        assertEquals(10 * 1024 * 1024, CsvImport.MAX_BYTES)
        // Named by its key and filled with the cap, so this holds whatever its words are.
        assertEquals(UiText.ph(Placeholder.IMPORT_TOO_LARGE, "10.0 MB").shown(), csvTooLarge())
        assertTrue(csvTooLarge().contains("10.0 MB"), "the cap is said")
    }

    @Test
    fun noPickIsReadWholeOrOnTheMainThread() {
        val dir = "src/main/kotlin/io/silencelen/andvari/app/trust/"
        for (name in listOf("VaultItemsScreens.kt", "VaultTransferScreens.kt")) {
            val code = File(dir + name).readText()
            val picker = code.substringAfter("rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument())").substringBefore("\n    }\n")
            assertTrue(picker.contains("withContext(Dispatchers.IO) { PickedFiles.read(context, uri, "), "$name reads through PickedFiles, off the main thread")
            assertFalse(picker.contains("readBytes()"), "$name never reads a pick whole before its size is known")
        }
        val items = File(dir + "VaultItemsScreens.kt").readText()
        assertTrue(items.contains("PickedFiles.read(context, uri, room)"))
        val transfer = File(dir + "VaultTransferScreens.kt").readText()
        assertTrue(transfer.contains("PickedFiles.read(context, uri, CsvImport.MAX_BYTES.toLong())"))
    }
}
