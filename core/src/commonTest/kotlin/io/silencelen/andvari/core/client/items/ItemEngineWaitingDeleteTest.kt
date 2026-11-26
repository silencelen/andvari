package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.model.wire.MutationOp
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A deletion the person made on this device that was still waiting when its vault closed for writing (queued, held
 * back, then parked with the held copy when the vault went) is carried by [ItemEngine.bringHeldInto]: the item they
 * deleted is not copied into the new vault, and the earlier copy a pick names goes as a replaced copy goes. A deletion
 * the server would refuse (made on an older revision than this device holds) carries the item as it is now.
 */
class ItemEngineWaitingDeleteTest {
    private val into = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    private val intoKey = ByteArray(32) { 11 }

    /** The shared vault with one item, as the server stores it too, and the move's new vault; the queue is durable. */
    private fun rig(): Pair<ItemRig, String> {
        val r = ItemRig(DurableCache())
        val id = r.id()
        val row = r.itemRow(id, r.shared, r.sharedKey)
        r.server.itemRows[id] = row
        r.openShared(items = listOf(row))
        r.keys.put(into, intoKey)
        r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(r.vaultRow(into, intoKey, "shared", "Family (new)")), grants = listOf(r.grantRow(into, "owner"))))
        runBlocking { r.engine.sync().ok() }
        return r to id
    }

    /** The person deletes [id] offline, then the vault is closed for writing; back online, the deletion is held back. */
    private fun deleteThenClose(r: ItemRig, id: String) = runBlocking {
        r.server.offline = true
        assertEquals(Written.QUEUED, r.engine.remove(id).ok())
        r.engine.markClosedForWriting(r.shared, VaultClosedReason.DELETION_WAITING)
        r.server.offline = false
        r.engine.sync().ok()
    }

    private fun goes(r: ItemRig) = runBlocking {
        r.keys.onServed = { report -> if (r.shared in report.lostAccess) r.keys.depart(r.shared, VaultDeparture.DELETED, keepKey = true) }
        r.server.queue.add(r.response(r.server.rev + 1, removed = listOf(r.shared)))
        r.engine.sync().ok()
    }

    private fun intoNew(r: ItemRig, from: Int) = r.server.pushes.drop(from).flatten().filter { it.vaultId == into }

    @Test
    fun anItemDeletedWhileItsVaultClosedIsNotCopied_andItsEarlierCopyIsDeletedIntoTheTrash_once() = runBlocking<Unit> {
        val (r, id) = rig()
        // The move copied the item while its vault was open.
        val first = r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, null))).ok().single()
        deleteThenClose(r, id)
        assertEquals(setOf(id), r.engine.waitingChanges(r.shared))
        assertEquals(setOf(id), r.engine.waitingDeletions(r.shared))
        assertEquals(emptyList(), r.engine.heldDocsToBring(r.shared, into, listOf(HeldPick(id, first.madeItemId, first.madeRev))), "nothing to copy, so no room to check")

        val pushes = r.server.pushes.size
        val said = ArrayList<HeldDeleted>()
        val made = r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, first.madeItemId, first.madeRev)), onDeleted = { said += it }).ok()
        assertEquals(emptyList(), made, "the item the person deleted is not copied")
        val d = said.single()
        assertEquals(Triple(id, first.madeItemId, false), Triple(d.itemId, d.earlier, d.earlierKept))
        assertNull(d.keptBecause)
        assertEquals(listOf(MutationOp.DELETE to first.madeItemId), intoNew(r, pushes).map { it.op to it.itemId }, "only the earlier copy's deletion is sent")
        assertTrue(r.server.itemRows.getValue(first.madeItemId).deleted)
        assertNull(r.engine.item(first.madeItemId))
        assertTrue(r.engine.items().none { it.vaultId == into }, "the new vault does not have the item the person deleted")
        assertNotNull(r.cache.clientState(ItemStore.TRASH_PREFIX + first.madeItemId), "the earlier copy's envelope is kept, so it is in the trash")
        assertTrue(r.server.pushes.drop(pushes).flatten().none { it.vaultId == r.shared }, "nothing is sent into the closed vault")

        // Once the vault went, the deletion is parked with the held copy and still carried; a second run sends nothing.
        goes(r)
        assertEquals(1, r.engine.heldVaults().single().parkedCount)
        assertEquals(setOf(id), r.engine.waitingDeletions(r.shared), "parked, not lost")
        val before = r.server.pushes.size
        assertEquals(emptyList(), r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, first.madeItemId, first.madeRev)), onDeleted = { said += it }).ok())
        assertEquals(before, r.server.pushes.size, "nothing more is deleted or copied")
        assertEquals(2, said.size)
        assertFalse(said.last().earlierKept)
    }

    @Test
    fun aHeldItemDeletedWithNoEarlierCopy_isNeitherCopiedNorDoesAnythingReachTheNewVault() = runBlocking<Unit> {
        val (r, id) = rig()
        deleteThenClose(r, id)
        goes(r)
        val pushes = r.server.pushes.size
        val said = ArrayList<HeldDeleted>()
        assertEquals(emptyList(), r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, null)), onDeleted = { said += it }).ok())
        assertEquals(id to null, said.single().itemId to said.single().earlier)
        assertEquals(emptyList(), intoNew(r, pushes))
        assertTrue(r.engine.heldItems(r.shared).any { it.itemId == id }, "the held copy itself is unchanged")
    }

    @Test
    fun anEarlierCopySomeoneChangedSinceIsKept_whenTheItemWasDeletedHere() = runBlocking<Unit> {
        val (r, id) = rig()
        val first = r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, null))).ok().single()
        deleteThenClose(r, id)
        // Another member edited the earlier copy in the new vault; this device has not seen it yet.
        val row = r.server.itemRows.getValue(first.madeItemId)
        r.server.itemRows[first.madeItemId] = row.copy(rev = row.rev + 10)
        val said = ArrayList<HeldDeleted>()
        assertEquals(emptyList(), r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, first.madeItemId, first.madeRev)), onDeleted = { said += it }).ok())
        assertTrue(said.single().earlierKept, "someone's change is never deleted for a copy")
        assertEquals(HeldDeleted.KEPT_CHANGED, said.single().keptBecause, "changed there since: a sentence of its own")
        assertFalse(r.server.itemRows.getValue(first.madeItemId).deleted)
    }

    @Test
    fun anEarlierCopyWhoseDeletionTheServerRefuses_isKept_andSaysItWasRefused() = runBlocking<Unit> {
        val (r, id) = rig()
        val first = r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, null))).ok().single()
        deleteThenClose(r, id)
        r.server.denyVaults.add(into)
        val said = ArrayList<HeldDeleted>()
        assertEquals(emptyList(), r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, first.madeItemId, first.madeRev)), onDeleted = { said += it }).ok())
        assertTrue(said.single().earlierKept)
        assertEquals(HeldDeleted.KEPT_REFUSED, said.single().keptBecause, "refused by the server: a sentence of its own")
        assertFalse(r.server.itemRows.getValue(first.madeItemId).deleted)
    }

    @Test
    fun aDeletionMadeOnAnOlderRevisionThanThisDeviceHolds_carriesTheItemAsItIsNow() = runBlocking<Unit> {
        val (r, id) = rig()
        deleteThenClose(r, id)
        // Someone else changed the item after the person's deletion was made: the server would refuse that deletion.
        r.serve(r.itemRow(id, r.shared, r.sharedKey, r.doc.copy(name = "Router (changed by someone)"), rev = r.server.rev + 1))
        r.engine.sync().ok()
        assertEquals(setOf(id), r.engine.waitingChanges(r.shared))
        assertEquals(emptySet(), r.engine.waitingDeletions(r.shared))
        val said = ArrayList<HeldDeleted>()
        val made = r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, null)), onDeleted = { said += it }).ok().single()
        assertEquals("Router (changed by someone)", r.engine.item(made.madeItemId)?.doc?.name)
        assertEquals(emptyList(), said)
    }
}
