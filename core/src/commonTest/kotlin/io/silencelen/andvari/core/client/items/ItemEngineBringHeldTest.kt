package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KeysGoneException
import io.silencelen.andvari.core.model.wire.MutationOp
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A vault deleted behind a move's back: the device holds its copy, and brings the items added or changed since into
 * the move's new vault, each with its files ([ItemEngine.bringHeldInto]).
 */
class ItemEngineBringHeldTest {
    private val into = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    private val intoKey = ByteArray(32) { 11 }

    /** The shared vault with one item carrying two files, and the move's new vault, writable here. */
    private fun rig(): Pair<ItemRig, String> {
        val r = ItemRig()
        val id = r.id()
        val refs = (1..2).map { n ->
            val key = r.crypto.randomBytes(32)
            val enc = Attachments.encrypt(r.crypto, key, ByteArray(10) { n.toByte() })
            val fileId = r.id()
            r.server.attachments[fileId] = enc.header + enc.ciphertext
            AttachmentRef(fileId, "f$n.txt", 10, Bytes.toB64(key))
        }
        r.openShared(items = listOf(r.itemRow(id, r.shared, r.sharedKey, r.doc.copy(attachments = refs))))
        r.keys.put(into, intoKey)
        r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(r.vaultRow(into, intoKey, "shared", "Family (new)")), grants = listOf(r.grantRow(into, "owner"))))
        runBlocking { r.engine.sync().ok() }
        return r to id
    }

    /** The old vault deleted on the server behind the move's back: held on this device. */
    private fun deleteBehindTheMove(r: ItemRig) {
        r.keys.onServed = { report -> if (r.shared in report.lostAccess) r.keys.depart(r.shared, VaultDeparture.DELETED, keepKey = true) }
        r.server.queue.add(r.response(r.server.rev + 1, removed = listOf(r.shared)))
        runBlocking { r.engine.sync().ok() }
        assertEquals(1, r.engine.heldVaults().single().itemCount)
    }

    private fun puts(r: ItemRig, vaultId: String) = r.server.pushes.flatten().filter { it.op == MutationOp.PUT && it.vaultId == vaultId }

    @Test
    fun aHeldItemWithTwoFilesLandsWholeInTheChosenVault_andOpens() = runBlocking<Unit> {
        val (r, id) = rig()
        deleteBehindTheMove(r)
        val said = ArrayList<HeldCopied>()
        val made = r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, null)), { said += it }).ok().single()
        assertEquals(listOf(made.madeItemId), said.map { it.madeItemId }, "each copy is said as it is made")
        assertEquals(id to 0, made.itemId to made.filesLeftOut)
        assertFalse(made.earlierKept)
        val copy = assertNotNull(r.engine.item(made.madeItemId))
        assertEquals(into, copy.vaultId)
        assertEquals("Router", copy.doc.name)
        assertEquals(listOf("f1.txt", "f2.txt"), copy.doc.attachments.map { it.name })
        for ((n, ref) in copy.doc.attachments.withIndex()) {
            assertContentEquals(ByteArray(10) { (n + 1).toByte() }, r.engine.downloadAttachment(ref).ok(), "a file of the copy opens")
        }
        assertEquals(r.doc.name, r.pushedDoc(puts(r, into).single(), intoKey).name, "sealed under the chosen vault's key")
        assertTrue(r.engine.heldItems(r.shared).isNotEmpty(), "nothing of the held copy changes")
    }

    @Test
    fun aChangedItemReplacesItsEarlierCopy_newCopyFirst_andTheEarlierCopyIsDeleted() = runBlocking<Unit> {
        val (r, id) = rig()
        // The move copied the item while its vault was open; the vault's own copy is read from its live rows.
        val first = r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, null))).ok().single()
        // Changed after that copy, then the vault was deleted behind the move.
        r.serve(r.itemRow(id, r.shared, r.sharedKey, r.doc.copy(name = "Router (changed)"), rev = r.server.rev + 1))
        r.engine.sync().ok()
        deleteBehindTheMove(r)
        val pushesBefore = r.server.pushes.size
        val second = r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, first.madeItemId, first.madeRev))).ok().single()
        assertNotEquals(first.madeItemId, second.madeItemId, "a newer rev is a new copy")
        assertFalse(second.earlierKept)
        val sent = r.server.pushes.drop(pushesBefore).flatten()
        assertEquals(listOf(MutationOp.PUT to second.madeItemId, MutationOp.DELETE to first.madeItemId), sent.map { it.op to it.itemId }, "the new copy first, then the earlier one")
        assertNull(r.engine.item(first.madeItemId))
        assertEquals("Router (changed)", r.engine.item(second.madeItemId)?.doc?.name)
        assertEquals(1, r.engine.items().count { it.vaultId == into }, "it replaced the earlier copy instead of standing beside it")
    }

    @Test
    fun anEarlierCopySomeoneChangedSinceIsKept_neverDeletedForACopy() = runBlocking<Unit> {
        val (r, id) = rig()
        val first = r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, null))).ok().single()
        r.serve(r.itemRow(id, r.shared, r.sharedKey, r.doc.copy(name = "Router (changed)"), rev = r.server.rev + 1))
        r.engine.sync().ok()
        deleteBehindTheMove(r)
        // Another member edited the earlier copy in the new vault; this device has not seen it yet.
        val row = r.server.itemRows.getValue(first.madeItemId)
        r.server.itemRows[first.madeItemId] = row.copy(rev = row.rev + 10)
        val second = r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, first.madeItemId, first.madeRev))).ok().single()
        assertTrue(second.earlierKept)
        assertFalse(r.server.itemRows.getValue(first.madeItemId).deleted)
    }

    @Test
    fun aSecondRunCopiesNothing_evenAfterARestart() = runBlocking<Unit> {
        val (r, id) = rig()
        deleteBehindTheMove(r)
        val first = r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, null))).ok().single()
        val puts = puts(r, into).size
        val uploads = r.server.attachments.size
        val again = r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, first.madeItemId, first.madeRev))).ok().single()
        assertEquals(first.madeItemId, again.madeItemId)
        assertFalse(again.earlierKept)
        val restarted = r.restarted()
        assertEquals(emptyList(), restarted.heldDocsToBring(r.shared, into, listOf(HeldPick(id, null))), "nothing is left to copy")
        val afterRestart = restarted.bringHeldInto(r.shared, into, listOf(HeldPick(id, null))).ok().single()
        assertEquals(first.madeItemId, afterRestart.madeItemId)
        assertEquals(puts, puts(r, into).size, "no second copy was sent")
        assertEquals(uploads, r.server.attachments.size, "no file was sent again")
        assertTrue(r.server.pushes.flatten().none { it.op == MutationOp.DELETE }, "the copy is never taken for its own earlier copy")
        assertEquals(1, restarted.items().count { it.vaultId == into })
    }

    @Test
    fun aLockDuringAFilesCopyMakesNothing_andTheNextRunLandsTheItemWhole() = runBlocking<Unit> {
        val (r, id) = rig()
        val first = r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, null))).ok().single()
        r.serve(r.itemRow(id, r.shared, r.sharedKey, r.doc.copy(name = "Router (changed)", attachments = r.engine.item(id)!!.doc.attachments), rev = r.server.rev + 1))
        r.engine.sync().ok()
        deleteBehindTheMove(r)
        var downloads = 0
        r.server.hold = { route -> if (route == "download" && ++downloads == 2) r.keys.locked = true }
        val said = ArrayList<HeldCopied>()
        val pushesBefore = r.server.pushes.size
        assertFailsWith<KeysGoneException> { r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, first.madeItemId, first.madeRev)), { said += it }) }
        assertEquals(emptyList(), said)
        assertEquals(pushesBefore, r.server.pushes.size, "no item was sealed or sent, and the earlier copy was not deleted")
        assertNotNull(r.engine.item(first.madeItemId))

        r.server.hold = null
        r.keys.locked = false
        val made = r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, first.madeItemId, first.madeRev))).ok().single()
        assertEquals(listOf("f1.txt", "f2.txt"), r.engine.item(made.madeItemId)?.doc?.attachments?.map { it.name })
        assertNull(r.engine.item(first.madeItemId))
    }

    @Test
    fun everyPickIsCheckedBeforeAnythingIsSent() = runBlocking<Unit> {
        val (r, id) = rig()
        deleteBehindTheMove(r)
        val pushes = r.server.pushes.size
        assertEquals(ItemFailure.NotAllowed(ItemRefusal.ITEM_GONE), r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, null), HeldPick(r.id(), null))).failure())
        assertEquals(pushes, r.server.pushes.size)
        val personalItem = r.engine.save(null, r.doc.copy(name = "Mine"), r.personal).ok().itemId
        val sent = r.server.pushes.size
        assertEquals(ItemFailure.NotAllowed(ItemRefusal.ITEM_CHANGED_VAULTS), r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, personalItem))).failure(), "nothing outside the target is deleted")
        r.engine.markClosedForWriting(into, VaultClosedReason.DELETION_WAITING)
        assertEquals(ItemFailure.NotAllowed(ItemRefusal.VAULT_CLOSED_FOR_WRITING), r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, null))).failure())
        assertEquals(sent, r.server.pushes.size, "nothing was sent, so nothing was deleted")
    }
}
