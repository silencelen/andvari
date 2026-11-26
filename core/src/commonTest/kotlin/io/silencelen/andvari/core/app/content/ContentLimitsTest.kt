package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The public sentences the screens asked for: the CSV import's size limit, and file names that are safe to offer. */
class ContentLimitsTest {
    @Test
    fun theCsvSizeSentence_isTheOneTheImportAnswers_andAScreenCanCheckBeforeReading() = runBlocking<Unit> {
        assertNull(ContentLimits.csvImportTooLarge(ContentLimits.CSV_IMPORT_MAX_BYTES))
        assertEquals(ContentLimits.CSV_IMPORT_TOO_LARGE, ContentLimits.csvImportTooLarge(ContentLimits.CSV_IMPORT_MAX_BYTES + 1))
        assertEquals(10L * 1024 * 1024, ContentLimits.CSV_IMPORT_MAX_BYTES)
        val c = FakeVaultContent()
        val r = c.importCsv(ByteArray(ContentLimits.CSV_IMPORT_MAX_BYTES.toInt() + 1))
        assertEquals(ContentLimits.CSV_IMPORT_TOO_LARGE, (r as ActionResult.Failed).message)
    }

    @Test
    fun anAttachmentsName_isASafeFileName_inTheDetailTheDraftAndTheOpenedFile() = runBlocking<Unit> {
        val rlo = Char(0x202E)
        val c = FakeVaultContent()
        val item = c.seedNote(FakeVaultContent.PERSONAL_VAULT_ID, "Note", "text")
        val hostile = "..\\..\\etc/passwd/../${rlo}fdp.exe"
        val id = c.seedAttachment(item, hostile, "x".encodeToByteArray())
        val shown = c.itemDetail(item)!!.attachments.single { it.id == id }.name
        fun safe(name: String) {
            assertFalse('/' in name || '\\' in name, name)
            assertFalse(rlo in name, name)
            assertFalse(name.startsWith("."), name)
        }
        safe(shown)
        assertTrue(shown.endsWith("exe"), "the real extension shows: $shown")
        safe(c.readAttachment(item, id).name)

        c.openAttachmentDraft(item)
        safe(c.state.attachmentDraft!!.kept.single().name)
        c.closeAttachmentDraft()
    }
}
