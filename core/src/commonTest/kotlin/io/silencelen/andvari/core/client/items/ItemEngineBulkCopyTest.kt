package io.silencelen.andvari.core.client.items

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The four item-plane tests the old `SyncEngineLifecycleTest` had and the item engine's first port left out:
 * the bulk copy's remembered plans, a malformed push answer, and a save that waits out a sync already pulling.
 */
class ItemEngineBulkCopyTest {
    private fun puts(r: ItemRig, from: Int, vaultId: String) = r.server.pushes.drop(from).flatten().filter { it.op == "put" && it.vaultId == vaultId }.map { it.mutationId }

    @Test
    fun bulkCopyRemembersPlansPerSourceItem_retryConverges() = runBlocking<Unit> {
        val r = ItemRig()
        r.openShared(items = listOf(r.itemRow(r.id(), r.shared, r.sharedKey)))
        // The first try's copy gets a malformed answer: not confirmed, and the retry sends the same mutation.
        r.server.emptyResultsVaults.add(r.personal)
        assertTrue(r.engine.rescueToPersonal(r.shared) is ItemResult.Failed)
        val first = puts(r, 0, r.personal)
        r.server.emptyResultsVaults.clear()
        val before = r.server.pushes.size
        assertEquals(1, (r.engine.rescueToPersonal(r.shared) as ItemResult.Ok).value) // a retry of the same rescue
        assertEquals(first, puts(r, before, r.personal), "remembered plans: the same mutation ids, deduplicated, not duplicated")
        // A copy that was confirmed is not remembered: a third run makes a new copy, under fresh ids.
        val made = r.server.pushes.size
        assertEquals(1, (r.engine.rescueToPersonal(r.shared) as ItemResult.Ok).value)
        val third = puts(r, made, r.personal)
        assertTrue(third.isNotEmpty() && third.intersect(first.toSet()).isEmpty(), "a new copy, never a replay")
    }

    /** The device shows in the personal vault exactly the live copies the server holds there: no more, no fewer. */
    private fun shownAreHeld(r: ItemRig, e: ItemEngine, why: String) {
        val onServer = r.server.itemRows.values.filter { it.vaultId == r.personal && !it.deleted }.map { it.itemId }.toSet()
        assertEquals(onServer, e.items().filter { it.vaultId == r.personal }.map { it.itemId }.toSet(), why)
    }

    /**
     * The check's probe P2c: a copy into the personal vault that the person deleted, copied again (in the same unlock,
     * and on a new engine after a restart), is a new copy the server holds; never the old copy shown again on this device
     * while the server holds it deleted (a replay of the first copy's mutation, which the server answers from its journal
     * as applied and stores nothing). For an open vault and for one in the holding area.
     */
    @Test
    fun aCopyThePersonDeleted_copiedAgain_isANewCopyTheServerHolds_neverOneOnlyThisDeviceShows() = runBlocking<Unit> {
        val r = ItemRig()
        r.server.journal = true
        r.server.echo = true
        r.openShared(items = listOf(r.itemRow(r.id(), r.shared, r.sharedKey)))
        fun liveCopy() = r.server.itemRows.values.single { it.vaultId == r.personal && !it.deleted }.itemId
        assertEquals(1, (r.engine.rescueToPersonal(r.shared) as ItemResult.Ok).value)
        val a = liveCopy()
        r.engine.remove(a).ok()
        assertTrue(r.server.itemRows.getValue(a).deleted)

        // Again, in the same unlock.
        assertEquals(1, (r.engine.rescueToPersonal(r.shared) as ItemResult.Ok).value)
        r.engine.sync().ok()
        shownAreHeld(r, r.engine, "the same engine")
        val b = liveCopy()
        assertTrue(b != a)
        r.engine.remove(b).ok()

        // Again, after a restart.
        val next = r.restarted()
        next.sync().ok()
        assertEquals(1, (next.rescueToPersonal(r.shared) as ItemResult.Ok).value)
        next.sync().ok()
        shownAreHeld(r, next, "a new engine")
        assertTrue(liveCopy() !in setOf(a, b))
        val later = r.restarted()
        later.sync().ok()
        shownAreHeld(r, later, "and after a further restart")

        // A held vault: its item copied out, the copy deleted, then copied out again on the next engine.
        val h = ItemRig()
        h.server.journal = true
        h.server.echo = true
        h.openShared(items = listOf(h.itemRow(h.id(), h.shared, h.sharedKey)))
        h.keys.onServed = { report -> if (h.shared in report.lostAccess) h.keys.depart(h.shared, VaultDeparture.DELETED, true) }
        h.server.queue.add(h.response(h.server.rev + 1, removed = listOf(h.shared)))
        h.engine.sync().ok()
        assertEquals(1, h.engine.rescueHeldToPersonal(h.shared).ok().copied)
        val first = h.server.itemRows.values.single { it.vaultId == h.personal && !it.deleted }.itemId
        h.engine.remove(first).ok()
        val again = h.restarted()
        again.sync().ok()
        assertEquals(1, again.rescueHeldToPersonal(h.shared).ok().copied)
        again.sync().ok()
        shownAreHeld(h, again, "the held vault, copied out again")
        assertEquals(1, h.server.itemRows.values.count { it.vaultId == h.personal && !it.deleted })
    }

    /**
     * The check's probe P2d: a source item changed between two runs. Copying again copies everything again, as the line
     * after a lock now says: two copies of the item, both on the server and both shown, never one the server lacks.
     */
    @Test
    fun aSourceChangedBetweenTwoRuns_copiedAgain_showsOnlyCopiesTheServerHolds() = runBlocking<Unit> {
        val r = ItemRig()
        r.server.journal = true
        val id = r.id()
        r.openShared(items = listOf(r.itemRow(id, r.shared, r.sharedKey)))
        assertEquals(1, (r.engine.rescueToPersonal(r.shared) as ItemResult.Ok).value)
        r.server.queue.add(r.response(r.server.rev + 1, items = listOf(r.itemRow(id, r.shared, r.sharedKey, r.doc.copy(name = "A edited"), rev = 40))))
        r.engine.sync().ok()
        r.server.echo = true
        val next = r.restarted()
        next.sync().ok()
        assertEquals(1, (next.rescueToPersonal(r.shared) as ItemResult.Ok).value)
        next.sync().ok()
        shownAreHeld(r, next, "after the source changed")
        assertEquals(2, r.server.itemRows.values.count { it.vaultId == r.personal && !it.deleted }, "everything copied again")
    }

    @Test
    fun bulkCopyPlansAfreshWhenTheSourceRevChanges() = runBlocking<Unit> {
        val r = ItemRig()
        val id = r.id()
        r.openShared(items = listOf(r.itemRow(id, r.shared, r.sharedKey)))
        r.engine.rescueToPersonal(r.shared)
        val first = puts(r, 0, r.personal).toSet()
        // The source changes on another device: a plan is only good for unchanged content.
        r.server.queue.add(r.response(r.server.rev + 1, items = listOf(r.itemRow(id, r.shared, r.sharedKey, r.doc.copy(name = "changed upstream"), rev = 40))))
        assertTrue(r.engine.sync() is ItemResult.Ok)
        val before = r.server.pushes.size
        r.engine.rescueToPersonal(r.shared)
        val retry = puts(r, before, r.personal).toSet()
        assertTrue(retry.isNotEmpty() && first.intersect(retry).isEmpty(), "a changed source gets a new plan, under new mutation ids")
    }

    @Test
    fun aCopyAnsweredWithNoResult_stopsTheMove_andTheSourceIsUntouched() = runBlocking<Unit> {
        val r = ItemRig()
        val id = r.id()
        r.openShared(items = listOf(r.itemRow(id, r.shared, r.sharedKey)))
        r.server.emptyResultsVaults.add(r.personal) // a malformed reply: no per-mutation result at all
        val plan = (r.engine.planMove(id, r.personal, deleteSource = true) as ItemResult.Ok).value
        val before = r.server.pushes.size
        val result = r.engine.runMove(plan)
        assertEquals(ItemFailure.NotAllowed(ItemRefusal.COPY_UNCONFIRMED), (result as ItemResult.Failed).why)
        assertEquals(before + 1, r.server.pushes.size, "the copy leg only: no delete is sent")
        assertNotNull(r.engine.item(id))
        assertEquals(r.shared, r.engine.item(id)!!.vaultId)
    }

    @Test
    fun aSaveWaitsOutASyncAlreadyPulling_andAStalePullNeverUndoesIt() = runBlocking<Unit> {
        val r = ItemRig()
        val id = r.id()
        r.openShared(items = listOf(r.itemRow(id, r.shared, r.sharedKey, rev = 6)))
        r.server.echo = true // the reconcile pull after the save serves the stored row, as the real server does
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        r.server.pullEntered = entered
        r.server.pullRelease = release
        // Sync A's answer predates the edit: the item as it was.
        r.server.queue.add(r.response(r.server.rev + 1, items = listOf(r.itemRow(id, r.shared, r.sharedKey, rev = 6))))
        val a = async { r.engine.sync() }
        entered.await() // A is mid-pull, holding the sync's serialization
        val pushed = r.server.pushes.size
        val b = async { r.engine.save(id, r.doc.copy(name = "mid-flight edit"), r.shared, emptyList(), null, null, null) }
        delay(50) // every chance to misbehave, were the save not serialized with the sync
        assertEquals(pushed, r.server.pushes.size, "the save waits for the pull in flight")
        release.complete(Unit)
        assertTrue(a.await() is ItemResult.Ok)
        assertTrue(b.await() is ItemResult.Ok)
        assertEquals("mid-flight edit", r.engine.item(id)!!.doc.name, "the stale pull did not put the old item back over the edit")
        assertEquals(pushed + 1, r.server.pushes.size)
    }
}
