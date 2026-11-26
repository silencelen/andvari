package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.model.wire.MutationOp
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * An earlier copy a move made in its new vault is deleted by [ItemEngine.bringHeldInto] only at the revision the pick
 * names (the one the move made it at), as it stands when the deletion is sent: a copy another member changed since, or
 * one with a change of this device's since (sent or still waiting), stays live and is said as kept. Both of the move's
 * roads are here: "copy what is late" (a changed item replaces its earlier copy) and the carry of the person's own
 * waiting deletion (the earlier copy goes to the trash).
 */
class EarlierCopyAtRevTest {
    private val into = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    private val intoKey = ByteArray(32) { 11 }

    /**
     * The shared vault with one item, as the server stores it too, and the move's new vault, writable here; the queue is
     * durable. The move copies the item: the copy and the revision the server gave it.
     */
    private fun moved(): Triple<ItemRig, String, Pair<String, Long>> {
        val r = ItemRig(DurableCache())
        val id = r.id()
        val row = r.itemRow(id, r.shared, r.sharedKey)
        r.server.itemRows[id] = row
        r.openShared(items = listOf(row))
        r.keys.put(into, intoKey)
        r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(r.vaultRow(into, intoKey, "shared", "Family (new)")), grants = listOf(r.grantRow(into, "owner"))))
        runBlocking { r.engine.sync().ok() }
        val first = runBlocking { r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, null))).ok().single() }
        val atRev = assertNotNull(r.engine.item(first.madeItemId)).rev
        // From here a pull answers every stored row newer than its cursor, as the real server does: a change this device
        // sent comes back with the revision the server gave it.
        r.server.echo = true
        return Triple(r, id, first.madeItemId to atRev)
    }

    /** Another member changes [id] in the old vault after its copy; this device receives it. */
    private fun changedAfterTheCopy(r: ItemRig, id: String) = runBlocking {
        r.serve(r.itemRow(id, r.shared, r.sharedKey, r.doc.copy(name = "Router (changed)"), rev = r.server.rev + 1))
        r.engine.sync().ok()
    }

    /** The old vault deleted on the server behind the move's back: held on this device. */
    private fun deleteBehindTheMove(r: ItemRig) = runBlocking {
        r.keys.onServed = { report -> if (r.shared in report.lostAccess) r.keys.depart(r.shared, VaultDeparture.DELETED, keepKey = true) }
        r.server.queue.add(r.response(r.server.rev + 1, removed = listOf(r.shared)))
        r.engine.sync().ok()
    }

    /** The person deletes [id] offline, then the old vault is closed for writing; back online, the deletion is held back. */
    private fun deletedHereThenClosed(r: ItemRig, id: String) = runBlocking {
        r.server.offline = true
        assertEquals(Written.QUEUED, r.engine.remove(id).ok())
        r.engine.markClosedForWriting(r.shared, VaultClosedReason.DELETION_WAITING)
        r.server.offline = false
        r.engine.sync().ok()
    }

    /** Another member changes the copy [copyId] in the new vault; this device's sync before the copy brings it in. */
    private fun anotherMemberChangesTheCopy(r: ItemRig, copyId: String) = runBlocking {
        r.serve(r.itemRow(copyId, into, intoKey, r.doc.copy(name = "Router (Bo's)"), rev = r.server.rev + 1))
        r.engine.sync().ok()
    }

    private fun deletes(r: ItemRig, from: Int) = r.server.pushes.drop(from).flatten().filter { it.op == MutationOp.DELETE }

    @Test
    fun copyWhatIsLate_overACopyAnotherMemberChangedSince_keepsTheirVersionLive_andTheLateItemArrivesAsACopyOfItsOwn() = runBlocking<Unit> {
        val (r, id, made) = moved()
        val (copyId, atRev) = made
        changedAfterTheCopy(r, id)
        deleteBehindTheMove(r)
        anotherMemberChangesTheCopy(r, copyId)
        assertNotEquals(atRev, r.engine.item(copyId)?.rev, "this device holds the other member's revision")
        val pushes = r.server.pushes.size

        val late = r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, copyId, atRev))).ok().single()
        assertTrue(late.earlierKept, "kept, as on a conflict")
        assertEquals(HeldDeleted.KEPT_CHANGED, late.keptBecause)
        assertEquals(emptyList(), deletes(r, pushes), "no deletion is sent for a copy that changed since")
        assertFalse(r.server.itemRows.getValue(copyId).deleted, "their version stays live at the server")
        assertEquals("Router (Bo's)", r.engine.item(copyId)?.doc?.name, "and on this device")
        assertNull(r.cache.clientState(ItemStore.TRASH_PREFIX + copyId), "nothing went to the trash")
        assertNotEquals(copyId, late.madeItemId)
        assertEquals("Router (changed)", r.engine.item(late.madeItemId)?.doc?.name, "the late item arrives as a copy of its own")
        assertEquals(setOf("Router (Bo's)", "Router (changed)"), r.engine.items().filter { it.vaultId == into }.map { it.doc.name }.toSet())
    }

    @Test
    fun copyWhatIsLate_overACopyWithAChangeStillWaitingOnThisDevice_keepsIt_andTheChangeLandsLater() = runBlocking<Unit> {
        val (r, id, made) = moved()
        val (copyId, atRev) = made
        changedAfterTheCopy(r, id)
        deleteBehindTheMove(r)
        // The person changes the copy here while the server does not answer: the change waits in the queue.
        r.server.offline = true
        r.engine.save(copyId, r.doc.copy(name = "Router (mine)"), into).ok()
        r.server.offline = false
        assertTrue(r.engine.hasPendingSync(copyId))
        assertEquals(atRev, r.cache.getItem(copyId)?.rev, "the server's revision is still the one the move made")
        val pushes = r.server.pushes.size

        val late = r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, copyId, atRev))).ok().single()
        assertTrue(late.earlierKept)
        assertEquals(HeldDeleted.KEPT_CHANGED, late.keptBecause)
        assertEquals(emptyList(), deletes(r, pushes), "a copy with a change waiting here is never deleted")
        r.engine.sync().ok()
        assertFalse(r.engine.hasPendingSync(copyId), "the waiting change was sent")
        val stored = r.server.itemRows.getValue(copyId)
        assertFalse(stored.deleted)
        assertEquals("Router (mine)", r.engine.item(copyId)?.doc?.name, "the person's change stands")
        assertNull(r.cache.clientState(ItemStore.TRASH_PREFIX + copyId), "nothing went to the trash")
    }

    @Test
    fun copyWhatIsLate_overACopyWhoseChangeTheSyncBeforeItSent_keepsIt() = runBlocking<Unit> {
        val (r, id, made) = moved()
        val (copyId, atRev) = made
        changedAfterTheCopy(r, id)
        deleteBehindTheMove(r)
        r.server.offline = true
        r.engine.save(copyId, r.doc.copy(name = "Router (mine)"), into).ok()
        r.server.offline = false
        // The sync the copy makes first sends the change: the copy moves past the revision the move made it at.
        r.engine.sync().ok()
        assertFalse(r.engine.hasPendingSync(copyId))
        val pushes = r.server.pushes.size

        val late = r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, copyId, atRev))).ok().single()
        assertTrue(late.earlierKept)
        assertEquals(emptyList(), deletes(r, pushes))
        assertFalse(r.server.itemRows.getValue(copyId).deleted)
        assertEquals("Router (mine)", r.engine.item(copyId)?.doc?.name)
    }

    @Test
    fun copyWhatIsLate_overAnUntouchedCopy_replacesItAsBefore_deletingItAtTheNamedRevision() = runBlocking<Unit> {
        val (r, id, made) = moved()
        val (copyId, atRev) = made
        changedAfterTheCopy(r, id)
        deleteBehindTheMove(r)
        val pushes = r.server.pushes.size

        val late = r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, copyId, atRev))).ok().single()
        assertFalse(late.earlierKept)
        assertNull(late.keptBecause)
        assertEquals(listOf(copyId to atRev), deletes(r, pushes).map { it.itemId to it.baseItemRev }, "deleted at the revision named")
        assertTrue(r.server.itemRows.getValue(copyId).deleted)
        assertNull(r.engine.item(copyId))
        assertNotNull(r.cache.clientState(ItemStore.TRASH_PREFIX + copyId), "in the new vault's trash")
        assertEquals(listOf("Router (changed)"), r.engine.items().filter { it.vaultId == into }.map { it.doc.name })
        assertEquals(late.madeRev, r.engine.item(late.madeItemId)?.rev, "the copy's own revision, for the next pick to name")
    }

    @Test
    fun aCopyChangedAtTheServerAfterTheLastPull_isAnsweredConflictAtTheNamedRevision_andKept() = runBlocking<Unit> {
        val (r, id, made) = moved()
        val (copyId, atRev) = made
        changedAfterTheCopy(r, id)
        deleteBehindTheMove(r)
        // Another member's change reaches the server after this device's last pull: only the server can tell.
        val row = r.server.itemRows.getValue(copyId)
        r.server.itemRows[copyId] = row.copy(rev = r.server.rev + 1)
        val pushes = r.server.pushes.size

        val late = r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, copyId, atRev))).ok().single()
        assertEquals(listOf(copyId to atRev), deletes(r, pushes).map { it.itemId to it.baseItemRev }, "sent at the revision named")
        assertTrue(late.earlierKept, "the server's conflict is kept, never done")
        assertEquals(HeldDeleted.KEPT_CHANGED, late.keptBecause)
        assertFalse(r.server.itemRows.getValue(copyId).deleted)
        assertNotNull(r.engine.item(copyId))
    }

    @Test
    fun aPickThatNamesNoRevision_deletesNothing() = runBlocking<Unit> {
        val (r, id, made) = moved()
        val (copyId, _) = made
        changedAfterTheCopy(r, id)
        deleteBehindTheMove(r)
        val pushes = r.server.pushes.size

        val late = r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, copyId))).ok().single()
        assertTrue(late.earlierKept)
        assertEquals(HeldDeleted.KEPT_NO_REVISION, late.keptBecause)
        assertEquals(emptyList(), deletes(r, pushes))
        assertFalse(r.server.itemRows.getValue(copyId).deleted)
        assertNotNull(r.engine.item(copyId))
    }

    @Test
    fun theCarryOfAWaitingDeletion_overACopyAnotherMemberChangedSince_keepsTheirVersionLive() = runBlocking<Unit> {
        val (r, id, made) = moved()
        val (copyId, atRev) = made
        deletedHereThenClosed(r, id)
        anotherMemberChangesTheCopy(r, copyId)
        val pushes = r.server.pushes.size
        val said = ArrayList<HeldDeleted>()

        assertEquals(emptyList(), r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, copyId, atRev)), onDeleted = { said += it }).ok())
        assertTrue(said.single().earlierKept)
        assertEquals(HeldDeleted.KEPT_CHANGED, said.single().keptBecause)
        assertEquals(emptyList(), deletes(r, pushes).filter { it.vaultId == into })
        assertFalse(r.server.itemRows.getValue(copyId).deleted)
        assertEquals("Router (Bo's)", r.engine.item(copyId)?.doc?.name)
    }

    @Test
    fun theCarryOfAWaitingDeletion_overACopyWithAChangeWaitingHere_keepsIt() = runBlocking<Unit> {
        val (r, id, made) = moved()
        val (copyId, atRev) = made
        deletedHereThenClosed(r, id)
        r.server.offline = true
        r.engine.save(copyId, r.doc.copy(name = "Router (mine)"), into).ok()
        r.server.offline = false
        val pushes = r.server.pushes.size
        val said = ArrayList<HeldDeleted>()

        assertEquals(emptyList(), r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, copyId, atRev)), onDeleted = { said += it }).ok())
        assertTrue(said.single().earlierKept)
        assertEquals(emptyList(), deletes(r, pushes).filter { it.vaultId == into })
        r.engine.sync().ok()
        assertFalse(r.server.itemRows.getValue(copyId).deleted)
        assertEquals("Router (mine)", r.engine.item(copyId)?.doc?.name)
    }

    @Test
    fun theCarryOfAWaitingDeletion_overAnUntouchedCopy_deletesItIntoTheTrashAtTheNamedRevision() = runBlocking<Unit> {
        val (r, id, made) = moved()
        val (copyId, atRev) = made
        deletedHereThenClosed(r, id)
        val pushes = r.server.pushes.size
        val said = ArrayList<HeldDeleted>()

        assertEquals(emptyList(), r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, copyId, atRev)), onDeleted = { said += it }).ok())
        assertFalse(said.single().earlierKept)
        assertEquals(listOf(copyId to atRev), deletes(r, pushes).filter { it.vaultId == into }.map { it.itemId to it.baseItemRev })
        assertTrue(r.server.itemRows.getValue(copyId).deleted)
        assertNotNull(r.cache.clientState(ItemStore.TRASH_PREFIX + copyId))
    }
}
