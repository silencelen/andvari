package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupItem
import io.silencelen.andvari.core.client.BackupPayload
import io.silencelen.andvari.core.client.restore.RestoreStop
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The attached files of a restore: those the backup does not hold, and a part of the file that cannot be read. */
internal class RestoreFilesTest : RestoreTestKit() {
    /**
     * An honest backup made without its attached files: 201 items, of which the first and the last each name one file.
     */
    private fun withoutFiles(): ByteArray {
        val items = (1..201).map { n ->
            val refs = if (n == 1 || n == 201) listOf(AttachmentRef(id(), "f$n.pdf", 10, Bytes.toB64(crypto.randomBytes(32)))) else emptyList()
            BackupItem(id(), personal.vaultId, 1, 0, doc("Item $n", refs))
        }
        val payload = BackupPayload(exportedAt = 1_794_484_800_000L, origin = "https://vault.example.org", vaults = listOf(personal), items = items)
        val out = ByteArrayOutputStream()
        Backup.build(crypto, pass, id(), crypto.randomBytes(16), KdfParams(ops = 1, memBytes = 8 * 1024 * 1024), payload) { out.write(it) }
        return out.toByteArray()
    }

    @Test
    fun theFilesTakenOffAreCountedOverEveryRunOfTheRestore() {
        val w = world("files-stripped")
        val bytes = withoutFiles()
        val f = flow(w, bytes)
        open(f)
        val first = page(w, f)
        println("STRIPPED|first preview=$first")
        // Said before anything is sent.
        has(first, ph(Placeholder.RESTORE_FILES_NOT_IN_BACKUP, "2"))
        // The answer to the second batch is lost: the run stops.
        w.server.beforePush = { n -> if (n == 2) w.server.loseNextAnswer = true }
        runBlocking { f.confirm() }
        w.server.beforePush = null
        println("STRIPPED|first run stage=${f.views.value.stage} stop=${f.views.value.stop} account=${personalItems(w)}")
        assertEquals(RestoreFlow.Stage.STOPPED, f.views.value.stage)
        runBlocking { f.tryAgain() }
        val end = page(w, f)
        println("STRIPPED|end=$end account=${personalItems(w)}")
        assertEquals(201, personalItems(w))
        has(end, ph(Placeholder.RESTORE_DONE_STRIPPED, "2"))
        // The same file again: nothing is left, and nothing is counted twice.
        val again = flow(w, bytes)
        open(again)
        has(page(w, again), ph(Placeholder.RESTORE_NOTHING_LEFT))
    }

    @Test
    fun aRunStoppedAfterTheServerTookItsLastBatchOffersNothingMore() {
        val w = world("files-taken-unheard")
        val bytes = withoutFiles()
        val f = flow(w, bytes)
        open(f)
        w.server.beforePush = { n -> if (n == 2) w.server.loseNextAnswer = true }
        runBlocking { f.confirm() }
        w.server.beforePush = null
        assertEquals(RestoreFlow.Stage.STOPPED, f.views.value.stage)
        // A new preview: its sync sends the batch the run left queued, which the server already holds.
        val again = flow(w, bytes)
        open(again)
        val lines = page(w, again)
        println("STRIPPED|taken unheard preview=$lines")
        // Every item is in the account and nothing was refused: the restore is finished, and the record says so now
        // (decided on 23 November 2026; before, the vault stayed "in the account" and never ended).
        val at = kotlin.test.assertNotNull(again.views.value.preview).vaults.first { it.personal }.restoredAt
        has(lines, ph(Placeholder.RESTORE_RESTORED_AT, "Personal vault: 201 items.", RestoreFlow.dayText(kotlin.test.assertNotNull(at))), ph(Placeholder.RESTORE_NOTHING_LEFT))
        assertEquals(201, personalItems(w))
    }

    @Test
    fun aPartOfTheFileThatCannotBeReadStopsTheRestoreWithoutATryAgainThatCannotWork() {
        val w = world("files-damaged")
        val bytes = backup(3)
        // One byte of the attached file's part (the last part of the file) changed.
        bytes[bytes.size - 40] = (bytes[bytes.size - 40].toInt() xor 0x55).toByte()
        val f = flow(w, bytes)
        open(f)
        assertEquals(RestoreFlow.Stage.PREVIEW, f.views.value.stage, "${f.views.value.said?.shown()}")
        runBlocking { f.confirm() }
        val stop = f.views.value.stop
        val lines = page(w, f)
        println("DAMAGED|stop=$stop account=${personalItems(w)} files=${restoreFiles(w).size} drawn=$lines")
        assertTrue(stop is RestoreStop.AttachmentUnreadable, "$stop")
        assertFalse("Try again" in lines, "no Try again that cannot work: $lines")
        has(lines, ph(Placeholder.RESTORE_PART_UNREADABLE, "scan.pdf"))
        val pushes = w.server.pushes
        runBlocking { f.tryAgain() }
        assertEquals(pushes, w.server.pushes, "the flow itself offers no way past it")
    }
}
