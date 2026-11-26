package io.silencelen.andvari.core.client.items

import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * What a move leaves on the device, and what happens to changes sealed and waiting when their vault is closed for
 * writing: they are held back (sent now, they would land in a vault whose deletion is signed), and copied by
 * [ItemEngine.bringHeldInto] from the queue or, once the vault went, from the held copy.
 */
class ItemEngineMoveLeavesTest {
    private fun kept(r: ItemRig, itemId: String): String? = r.cache.clientState(ItemStore.TRASH_PREFIX + itemId)

    /** The shared vault with one item, as the server stores it too, over a cache whose queue is durable (as SQLite's is). */
    private fun rig(): Pair<ItemRig, String> {
        val r = ItemRig(DurableCache())
        val id = r.id()
        val row = r.itemRow(id, r.shared, r.sharedKey)
        r.server.itemRows[id] = row
        r.openShared(items = listOf(row))
        return r to id
    }

    @Test
    fun aMovedItemsSourceKeepsItsEnvelope_soItsTrashRowShowsItsNameWithNoCall() = runBlocking<Unit> {
        val (r, id) = rig()
        val plan = r.engine.planMove(id, r.personal, deleteSource = true).ok()
        r.engine.runMove(plan).ok()
        assertNotNull(kept(r, id), "the source's envelope is kept for the trash")
        val row = r.engine.deletedItems().ok().single { it.itemId == id }
        assertFalse(row.notRead)
        assertEquals("Router", row.doc?.name)
        assertTrue(id !in r.server.versionsRead, "no call for its name")
    }

    @Test
    fun aChangeSealedBeforeTheVaultClosedForWritingWaits_isCopiedFromTheQueue_andDrainsWhenTheMarkGoes() = runBlocking<Unit> {
        val (r, id) = rig()
        r.server.offline = true
        assertEquals(Written.QUEUED, r.engine.save(id, r.doc.copy(name = "Router (edited offline)"), r.shared).ok().outcome)
        r.engine.markClosedForWriting(r.shared, VaultClosedReason.DELETION_WAITING)
        r.server.offline = false
        val pushes = r.server.pushes.size
        r.engine.sync().ok()
        assertEquals(pushes, r.server.pushes.size, "nothing is sent into a vault whose deletion waits")
        assertEquals(setOf(id), r.engine.waitingChanges(r.shared))

        val made = r.engine.bringHeldInto(r.shared, r.personal, listOf(HeldPick(id, null))).ok().single()
        assertEquals("Router (edited offline)", r.engine.item(made.madeItemId)?.doc?.name, "the waiting change is what is copied")

        r.engine.markClosedForWriting(r.shared, null)
        r.engine.sync().ok()
        assertTrue(r.server.pushes.drop(pushes).flatten().any { it.itemId == id && it.vaultId == r.shared }, "the mark gone, it drains")
        assertEquals(emptySet(), r.engine.waitingChanges(r.shared))
    }

    @Test
    fun aWaitingChangeIsParkedWithTheHeldCopyWhenTheVaultGoes_andStillCopied_once() = runBlocking<Unit> {
        val (r, id) = rig()
        r.server.offline = true
        r.engine.save(id, r.doc.copy(name = "Router (edited offline)"), r.shared).ok()
        r.engine.markClosedForWriting(r.shared, VaultClosedReason.DELETION_WAITING)
        r.server.offline = false
        val first = r.engine.bringHeldInto(r.shared, r.personal, listOf(HeldPick(id, null))).ok().single()

        r.keys.onServed = { report -> if (r.shared in report.lostAccess) r.keys.depart(r.shared, VaultDeparture.DELETED, keepKey = true) }
        r.server.queue.add(r.response(r.server.rev + 1, removed = listOf(r.shared)))
        r.engine.sync().ok()
        assertEquals(1, r.engine.heldVaults().single().parkedCount)
        assertEquals(setOf(id), r.engine.waitingChanges(r.shared), "parked, not lost")

        val puts = r.server.pushes.size
        val again = r.engine.bringHeldInto(r.shared, r.personal, listOf(HeldPick(id, first.madeItemId))).ok().single()
        assertEquals(first.madeItemId, again.madeItemId, "the same change, so the same copy")
        assertEquals(puts, r.server.pushes.size)

        // Without the earlier copy, a fresh device run from the held copy still carries the change.
        val restarted = r.restarted()
        assertEquals(emptyList(), restarted.heldDocsToBring(r.shared, r.personal, listOf(HeldPick(id, null))))
    }
}
