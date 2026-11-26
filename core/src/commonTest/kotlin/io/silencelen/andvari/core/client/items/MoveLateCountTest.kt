package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.VaultItem
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * What the notice of a move whose deletion the server stored before it finished ("added since", "changed since") counts
 * today, when one of the late changes is the person's own deletion that waited when the vault closed for writing.
 *
 * The notice is the app interface's: it counts, from this engine, the items of the old vault this device holds (held, or
 * still open), and takes as late those whose revision is not the one the move copied or that have a change waiting
 * ([ItemEngine.waitingChanges]); of those, an item the move never copied is "added" and one it copied is "changed". That
 * reading is private to the app interface, and the move's own rig is private to its tests, so this small rig reads the
 * same engine calls in the same way ([lateCounts]) over the item engine alone.
 *
 * The rule of 2026-11-17 says such a deletion is carried by the run that finishes the move, without a question, and
 * counts neither as added nor as changed; the notice says how many deletions were carried. Today it counts as changed:
 * this test records that, so the difference is on record for whoever moves the notice to the rule.
 */
class MoveLateCountTest {
    private val into = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    private val intoKey = ByteArray(32) { 11 }

    /** The shared vault with [names] as items (the server stores them too), and the move's new vault; the queue is durable. */
    private fun rig(vararg names: String): Pair<ItemRig, List<String>> {
        val r = ItemRig(DurableCache())
        val rows = names.map { r.itemRow(r.id(), r.shared, r.sharedKey, r.doc.copy(name = it)) }
        rows.forEach { r.server.itemRows[it.itemId] = it }
        r.openShared(items = rows)
        r.keys.put(into, intoKey)
        r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(r.vaultRow(into, intoKey, "shared", "Family (new)")), grants = listOf(r.grantRow(into, "owner"))))
        runBlocking { r.engine.sync().ok() }
        return r to rows.map { it.itemId }
    }

    /** The counts as the notice reads them: (added, changed), from what this device holds and what the move copied. */
    private fun lateCounts(engine: ItemEngine, oldId: String, copied: Map<String, Long>): Pair<Int, Int> {
        val heldNow: List<VaultItem> = engine.heldItems(oldId).ifEmpty { engine.items().filter { it.vaultId == oldId } }
        val waiting = engine.waitingChanges(oldId)
        val late = heldNow.filter { copied[it.itemId] != it.rev || it.itemId in waiting }
        return late.count { it.itemId !in copied } to late.count { it.itemId in copied }
    }

    @Test
    fun aPersonsOwnDeletionThatWaitedWhenTheVaultClosed_countsAsChangedToday_andNotAsADeletionCarried() = runBlocking<Unit> {
        val (r, ids) = rig("Bank", "Old")
        val (bank, old) = ids
        // The move copied both items while the vault was open.
        val copied = r.engine.bringHeldInto(r.shared, into, ids.map { HeldPick(it, null) }).ok().associate { it.itemId to it.rev }
        assertEquals(setOf(bank, old), copied.keys)
        assertEquals(0 to 0, lateCounts(r.engine, r.shared, copied), "nothing is late yet")

        // The person deletes Old offline; the vault is closed for writing, so the deletion waits; then the vault goes.
        r.server.offline = true
        assertEquals(Written.QUEUED, r.engine.remove(old).ok())
        r.engine.markClosedForWriting(r.shared, VaultClosedReason.DELETION_WAITING)
        r.server.offline = false
        r.engine.sync().ok()
        r.keys.onServed = { report -> if (r.shared in report.lostAccess) r.keys.depart(r.shared, VaultDeparture.DELETED, keepKey = true) }
        r.server.queue.add(r.response(r.server.rev + 1, removed = listOf(r.shared)))
        r.engine.sync().ok()
        assertEquals(1, r.engine.heldVaults().single().parkedCount, "the deletion is parked with the held copy")

        // What the engine offers the notice: the held copy still holds Old, and Old has a change waiting, its deletion.
        assertEquals(setOf(bank, old), r.engine.heldItems(r.shared).map { it.itemId }.toSet())
        assertEquals(setOf(old), r.engine.waitingChanges(r.shared))
        assertEquals(setOf(old), r.engine.waitingDeletions(r.shared), "the engine can tell it is a deletion")

        // Today: the person's own deletion is counted as one item changed since its copy. The rule counts it as neither
        // added nor changed (0 to 0 here), and as one deletion carried ([ItemEngine.waitingDeletions]).
        assertEquals(0 to 1, lateCounts(r.engine, r.shared, copied))
    }
}
