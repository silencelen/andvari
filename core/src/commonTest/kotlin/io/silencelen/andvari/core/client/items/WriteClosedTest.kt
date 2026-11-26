package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.CsvImport
import io.silencelen.andvari.core.crypto.Bytes
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A vault the app interface closed for writing (its deletion signed and waiting) takes nothing new on this device:
 * every road that would put something into it or change something in it is refused before anything is sealed or sent,
 * a copy out stays allowed, and the mark outlives a restart until it is cleared.
 */
class WriteClosedTest {
    private val closed = ItemFailure.NotAllowed(ItemRefusal.VAULT_CLOSED_FOR_WRITING)

    /** The shared vault, writable here, with one item and one tombstoned item; then closed for writing. */
    private fun rig(): Triple<ItemRig, String, String> {
        val r = ItemRig()
        val id = r.id()
        val gone = r.id()
        r.openShared(items = listOf(r.itemRow(id, r.shared, r.sharedKey, rev = 6), r.itemRow(gone, r.shared, r.sharedKey, rev = 7)))
        r.server.itemRows[id] = r.itemRow(id, r.shared, r.sharedKey, rev = 6)
        r.server.itemRows[gone] = r.tombstone(gone, r.shared, 8)
        r.server.queue.add(r.response(8, items = listOf(r.tombstone(gone, r.shared, 8))))
        runBlocking { r.engine.sync().ok() }
        r.engine.markClosedForWriting(r.shared, VaultClosedReason.DELETION_WAITING)
        return Triple(r, id, gone)
    }

    /** [road] is refused as closed, and sends nothing at all. */
    private suspend fun refusedAndNothingSent(r: ItemRig, what: String, road: suspend () -> ItemResult<*>) {
        val calls = r.server.calls
        assertEquals(closed, road().failure(), what)
        assertEquals(calls, r.server.calls, "$what: nothing was sent")
    }

    @Test
    fun everyRoadIntoOrOutOfAClosedVaultIsRefusedBeforeAnythingIsSealed_andACopyOutIsAllowed() = runBlocking<Unit> {
        val (r, id, gone) = rig()
        val e = r.engine
        assertEquals(VaultClosedReason.DELETION_WAITING, e.closedForWriting(r.shared))
        val view = e.vaults().single { it.vaultId == r.shared }
        assertEquals(listOf(false, VaultClosedReason.DELETION_WAITING), listOf(view.writable, view.closedFor))

        refusedAndNothingSent(r, "a new item") { e.save(null, r.doc.copy(name = "New"), r.shared) }
        refusedAndNothingSent(r, "an edit") { e.save(id, r.doc.copy(name = "Edited"), r.shared) }
        refusedAndNothingSent(r, "a delete") { e.remove(id) }
        refusedAndNothingSent(r, "a restore") { e.restoreDeleted(gone, r.shared, r.doc) }
        refusedAndNothingSent(r, "a delete for good") { e.purgeDeleted(gone, r.shared) }
        refusedAndNothingSent(r, "an import") { e.importAll(listOf(CsvImport.PlannedItem(r.id(), r.doc.copy(name = "Imported"))), vaultId = r.shared) }
        val data = ByteArray(10) { 1 }
        val ref = AttachmentRef(r.id(), "f.txt", data.size.toLong(), Bytes.toB64(r.crypto.randomBytes(32)))
        refusedAndNothingSent(r, "an item with a file") { e.save(id, r.doc.copy(attachments = listOf(ref)), r.shared, uploads = listOf(NewAttachment(ref, data))) }
        refusedAndNothingSent(r, "a file uploaded on its own") { e.uploadEncryptedAttachment(r.id(), id, r.shared, ByteArray(40)) }
        refusedAndNothingSent(r, "a rename") { e.renameVault(r.shared, "Other") }

        // A move or a copy into it, from the personal vault.
        val mine = r.id()
        r.serve(r.itemRow(mine, r.personal, r.personalKey, rev = 9))
        e.sync().ok()
        refusedAndNothingSent(r, "a move into it") { e.runMove(e.planMove(mine, r.shared, deleteSource = true).ok()) }
        refusedAndNothingSent(r, "a copy into it") { e.runMove(e.planMove(mine, r.shared, deleteSource = false).ok()) }
        // A move out of it deletes there: refused. A copy out changes nothing there: allowed.
        refusedAndNothingSent(r, "a move out of it") { e.runMove(e.planMove(id, r.personal, deleteSource = true).ok()) }
        val copyOut = e.planMove(id, r.personal, deleteSource = false).ok()
        e.runMove(copyOut, finalSync = false).ok()
        assertNotNull(e.item(copyOut.targetItemId), "the copy is in the personal vault")
        assertNotNull(e.item(id), "and the source stays")

        // The personal vault is not touched by the mark.
        e.save(null, r.doc.copy(name = "Still fine"), r.personal).ok()
    }

    @Test
    fun theMarkOutlivesARestartUntilItIsCleared() = runBlocking<Unit> {
        val (r, id, _) = rig()
        r.engine.close()
        val after = r.restarted()
        assertEquals(VaultClosedReason.DELETION_WAITING, after.closedForWriting(r.shared), "kept in the account's cache")
        assertEquals(closed, after.save(id, r.doc.copy(name = "Edited"), r.shared).failure())

        after.markClosedForWriting(r.shared, null)
        assertNull(after.closedForWriting(r.shared))
        assertTrue(after.vaults().single { it.vaultId == r.shared }.writable)
        after.save(id, r.doc.copy(name = "Edited"), r.shared).ok()
        assertNull(r.restarted().closedForWriting(r.shared), "and cleared for good")
    }
}
