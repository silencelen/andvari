package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.BackupAttachmentEntry
import io.silencelen.andvari.core.client.BackupItem
import io.silencelen.andvari.core.client.BackupPayload
import io.silencelen.andvari.core.client.BackupSkipped
import io.silencelen.andvari.core.client.BackupSkippedItem
import io.silencelen.andvari.core.client.BackupVault
import io.silencelen.andvari.core.client.restore.RestoreEvent
import io.silencelen.andvari.core.client.restore.RestoreLeftOut
import io.silencelen.andvari.core.client.restore.RestoreResult
import io.silencelen.andvari.core.crypto.Bytes
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A count of one reads in the singular (the owner's words of 23 November 2026): each line of the restore that names a
 * count says "1 item", "1 attached file", "1 vault" where the count is one, and keeps its words for more than one. The
 * lines for none stay as built: the greyed "Restore 0 items" and the line of a vault that holds no item.
 */
internal class RestoreCountOfOneTest : RestoreTestKit() {
    private val work = BackupVault("33333333-3333-4333-8333-333333333333", "shared", "Work", "writer")

    /**
     * One of everything: "A" in the personal vault with one attached file (70 000 bytes), one item in "Family" (owned)
     * and one in "Work" (a member's), one item the device that made it could not read, one attached file too large.
     */
    private fun oneOfEach(): ByteArray {
        val fileKey = crypto.randomBytes(32)
        val attachmentId = id()
        val plain = ByteArray(70_000) { (it % 251).toByte() }
        val first = BackupItem(id(), personal.vaultId, 1, 0, doc("A", listOf(AttachmentRef(attachmentId, "scan.pdf", plain.size.toLong(), Bytes.toB64(fileKey)))))
        return build(
            BackupPayload(
                exportedAt = 1_794_484_800_000L, origin = "https://vault.example.org", vaults = listOf(personal, family, work),
                items = listOf(first, BackupItem(id(), family.vaultId, 1, 0, doc("Family 1")), BackupItem(id(), work.vaultId, 1, 0, doc("Work 1"))),
                attachments = listOf(BackupAttachmentEntry(1, attachmentId, first.itemId, "scan.pdf", plain.size.toLong(), Bytes.toB64(fileKey))),
                skipped = BackupSkipped(listOf(BackupSkippedItem(id(), personal.vaultId, 1)), listOf("big.mov"), emptyList()),
            ),
            listOf(fileKey to plain),
        )
    }

    @Test
    fun aBackupOfOneOfEachReadsInTheSingularOnThePreviewInTheRunAndAtItsEnd() {
        val w = world("one-of-each")
        val c = assertNotNull(w.m.content.value)
        // The account already holds one item of its own.
        runBlocking { assertEquals(ActionResult.Ok, c.saveLogin(null, LoginInput("Mine 1", "me", "pw-1", listOf("https://one.test"), "", "", false), null)) }
        val bytes = oneOfEach()
        val f = flow(w, bytes)
        open(f)
        val preview = page(w, f)
        has(
            preview,
            "Personal vault: 1 item",
            "Family: 1 item. You owned it.",
            "Work: 1 item. You were a member.",
            // Stays as it is.
            "Attached files: 1 (${sizeText(70_000)}).",
            "1 attached file was too large for the backup. Attach it again by hand.",
            "1 item could not be read by the device that made the backup.",
            "This account already holds 1 item. Restoring adds the backup's items beside it. Nothing is replaced, and an item you have in both will be there twice.",
            "Restore 1 item",
        )
        // The page while the run goes on, as each line of the run leaves it.
        val running = ArrayList<List<String>>()
        runBlocking {
            val watch = launch(Dispatchers.Unconfined) {
                f.views.collect { v -> if (v.stage == RestoreFlow.Stage.RUNNING && v.progress != null) running += f.page(v).texts }
            }
            f.confirm()
            watch.cancel()
        }
        assertTrue(running.any { "Restoring: 1 of 1 item." in it }, "$running")
        assertEquals(RestoreFlow.Stage.ENDED, f.views.value.stage)
        has(page(w, f), "1 item restored into 1 vault.", "1 attached file restored.")
        // The same file again: the personal vault's line inside the longer line, in the singular too.
        val again = flow(w, bytes)
        open(again)
        val at = assertNotNull(assertNotNull(again.views.value.preview).vaults.first { it.personal }.restoredAt)
        has(
            page(w, again),
            ph(Placeholder.RESTORE_RESTORED_AT, "Personal vault: 1 item.", RestoreFlow.dayText(at)),
            "Family: 1 item. You owned it.",
            "This account already holds 1 item. Restoring adds the backup's items beside it. Nothing is replaced, and an item you have in both will be there twice.",
        )
    }

    @Test
    fun theProgressLineReadsInTheSingularWhereTheRunHasOneItemAndAsApprovedForMore() {
        // A run of one item that has stored none yet, and one stopped: the kit's server reaches neither, so the page is
        // made from the state that holds them.
        val w = world("one-progress")
        val f = flow(w, backup(1))
        fun drawn(stage: RestoreFlow.Stage, done: Int, total: Int) = f.page(RestoreFlow.View(stage, busy = stage == RestoreFlow.Stage.RUNNING, progress = RestoreEvent.Progress(done, total))).texts
        has(drawn(RestoreFlow.Stage.RUNNING, 0, 1), "Restoring: 0 of 1 item.")
        has(drawn(RestoreFlow.Stage.RUNNING, 1, 1), "Restoring: 1 of 1 item.")
        has(drawn(RestoreFlow.Stage.STOPPED, 1, 1), "Restoring: 1 of 1 item.")
        has(drawn(RestoreFlow.Stage.RUNNING, 0, 2), "Restoring: 0 of 2 items.")
        has(drawn(RestoreFlow.Stage.RUNNING, 1, 2), "Restoring: 1 of 2 items.")
        has(drawn(RestoreFlow.Stage.RUNNING, 200, 412), "Restoring: 200 of 412 items.")
    }

    @Test
    fun theEndReadsInTheSingularForOneItemInOneVaultAndForOneAttachedFile() {
        val w = world("one-end")
        val f = flow(w, backup(1))
        fun end(stored: Int, vaults: Int, carried: Int = 0) = f.page(RestoreFlow.View(RestoreFlow.Stage.ENDED, done = RestoreResult.Done(stored, vaults, emptyList(), carried, 0, RestoreLeftOut()))).texts
        has(end(1, 1, carried = 1), "1 item restored into 1 vault.", "1 attached file restored.")
        // Every other pair the run draws keeps the words approved for it.
        has(end(0, 1), "0 items restored into 1 vault.")
        has(end(2, 1, carried = 2), "2 items restored into 1 vault.", "2 attached files restored.")
        has(end(0, 2), "0 items restored into 2 vaults.")
        has(end(412, 2), "412 items restored into 2 vaults.")
        has(end(0, 0), ph(Placeholder.RESTORE_DONE_NOTHING_LEFT))
    }

    @Test
    fun theLinesForNoneStayAsBuilt() {
        val w = world("one-none")
        val f = flow(w, backup(3, familyItems = 0))
        open(f)
        f.choose(personal.vaultId, false)
        onScreen(w, f) { d ->
            val lines = d.lines()
            has(lines, "Family: 0 items. You owned it.", "Restore 0 items")
            assertEquals(null, d.ticked("Family: 0 items. You owned it."), "a vault with no item has no box")
            assertEquals(true, d.disabled("Restore 0 items"), "greyed")
        }
    }
}
