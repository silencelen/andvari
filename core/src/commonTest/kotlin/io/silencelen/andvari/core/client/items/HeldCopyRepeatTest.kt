package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.model.wire.MutationOp
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The copy of held items into a vault ([ItemEngine.bringHeldInto], the move's own road) run a second time over the same
 * items, in the same unlock and after a restart, with the server's journal of mutation ids on as the real server keeps
 * it: over a first copy the person edited since, one the person deleted since, and a source that changed between the two
 * runs. A second run names no earlier copy here: it is the run a lock cut short before the first copy was recorded.
 */
class HeldCopyRepeatTest {
    private val into = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    private val intoKey = ByteArray(32) { 11 }

    /** The shared vault, still open here, with one item as the server stores it, and the move's new vault; journal on. */
    private fun rig(): Pair<ItemRig, String> {
        val r = ItemRig(DurableCache())
        val id = r.id()
        val row = r.itemRow(id, r.shared, r.sharedKey)
        r.server.itemRows[id] = row
        r.openShared(items = listOf(row))
        r.keys.put(into, intoKey)
        r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(r.vaultRow(into, intoKey, "shared", "Family (new)")), grants = listOf(r.grantRow(into, "owner"))))
        runBlocking { r.engine.sync().ok() }
        r.server.journal = true
        r.server.echo = true
        return r to id
    }

    /** What this device shows in the new vault, each with whether the server holds it live. */
    private fun shown(e: ItemEngine, r: ItemRig) = e.items().filter { it.vaultId == into }.map { it.itemId to (r.server.itemRows[it.itemId]?.deleted == false) }

    private fun liveOnServer(r: ItemRig) = r.server.itemRows.values.filter { it.vaultId == into && !it.deleted }

    private fun putsInto(r: ItemRig) = r.server.pushes.flatten().count { it.op == MutationOp.PUT && it.vaultId == into }

    @Test
    fun aRepeatOverAFirstCopyThePersonEdited_keepsTheEdit_andSendsNothing() = runBlocking<Unit> {
        val (r, id) = rig()
        val first = r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, null))).ok().single()
        r.engine.save(first.madeItemId, r.doc.copy(name = "Router (mine)"), into).ok()
        r.engine.sync().ok()
        val puts = putsInto(r)
        for ((road, e) in listOf("same unlock" to r.engine, "after a restart" to r.restarted())) {
            e.sync().ok()
            val again = e.bringHeldInto(r.shared, into, listOf(HeldPick(id, null))).ok().single()
            assertEquals(first.madeItemId, again.madeItemId, road)
            assertEquals(puts, putsInto(r), "nothing is sent ($road)")
            assertEquals("Router (mine)", e.item(first.madeItemId)?.doc?.name, "the edit stays ($road)")
            assertEquals(listOf(first.madeItemId to true), shown(e, r), road)
        }
    }

    /**
     * Before, the same unlock replayed the first copy's confirmed plan: the server's journal answered the replay as
     * applied and stored nothing, and this device showed a copy the server holds as deleted, which no sync corrected.
     * Forgetting the plan alone was not enough: a fresh put over the deleted row brings it back as a conflict, beside a
     * conflict copy of the version that was deleted (the item twice).
     */
    @Test
    fun aRepeatOverAFirstCopyThePersonDeleted_showsOnlyWhatTheServerHolds() = runBlocking<Unit> {
        val (r, id) = rig()
        val first = r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, null))).ok().single()
        assertEquals(Written.APPLIED, r.engine.remove(first.madeItemId).ok())
        assertTrue(r.server.itemRows.getValue(first.madeItemId).deleted)
        val puts = putsInto(r)
        for ((road, e) in listOf("same unlock" to r.engine, "after a restart" to r.restarted())) {
            e.sync().ok()
            e.bringHeldInto(r.shared, into, listOf(HeldPick(id, null))).ok()
            e.sync().ok()
            val s = shown(e, r)
            assertTrue(s.all { it.second }, "every copy shown is one the server holds ($road): $s")
            assertEquals(liveOnServer(r).map { it.itemId }.toSet(), s.map { it.first }.toSet(), road)
            // The person's deletion is the answer: nothing is sent, nothing comes back, and the item is never there twice.
            assertEquals(emptyList(), s, road)
            assertEquals(puts, putsInto(r), "nothing is sent ($road)")
        }
    }

    /**
     * A count never says more than is so: a repeat whose copy was deleted in the target since is answered as such, by a
     * field of its own, and the content's result counts it by itself, never as a copy made. Before, the engine's answer
     * said it only by the absence of a revision, and the content's result listed it among the copies with nothing to tell.
     */
    @Test
    fun aRepeatOverACopyDeletedThereIsToldApartAndNeverCountedAsCopied() = runBlocking<Unit> {
        val (r, id) = rig()
        val content = io.silencelen.andvari.core.app.content.EngineVaultContent(r.engine, r.crypto, Host(r))
        val first = content.bringHeldItemsInto(r.shared, into, listOf(HeldPick(id, null)))
        assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok, first.result)
        val made = first.made.single()
        assertFalse(made.deletedThere, "a copy made now")
        assertEquals(0, first.deletedThere)
        assertEquals(Written.APPLIED, r.engine.remove(made.madeItemId).ok())
        r.engine.sync().ok()
        val again = content.bringHeldItemsInto(r.shared, into, listOf(HeldPick(id, null)))
        assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok, again.result)
        assertTrue(again.made.single().deletedThere, "found deleted in the target since")
        assertEquals(null, again.made.single().madeRev)
        assertEquals(1, again.deletedThere, "counted by itself")
        assertEquals(emptyList(), liveOnServer(r), "not copied again")
    }

    private class Host(val r: ItemRig) : io.silencelen.andvari.core.app.content.ContentHost {
        override fun wallMs(): Long = r.now
        override fun attachmentLimits() = io.silencelen.andvari.core.app.AttachmentRules.limits(null, null)
        override fun origin(): String = "https://vault.example.com"
        override fun userId(): String = r.userId
        override fun accountId(): String = "0123456789abcdef0123456789abcdef"
        override fun backupKdfParams(): io.silencelen.andvari.core.crypto.KdfParams? = null
    }

    @Test
    fun aSourceChangedBetweenTwoRuns_whatEachRunMakes() = runBlocking<Unit> {
        val (r, id) = rig()
        val first = r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, null))).ok().single()
        r.serve(r.itemRow(id, r.shared, r.sharedKey, r.doc.copy(name = "Router (changed)"), rev = r.server.rev + 1))
        r.engine.sync().ok()
        // Naming the earlier copy and the revision it was made at, as the move's record does: the earlier copy is replaced.
        val named = r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, first.madeItemId, first.madeRev))).ok().single()
        assertFalse(named.earlierKept)
        assertEquals(listOf(named.madeItemId to true), shown(r.engine, r), "one copy, the newer one")
        assertEquals("Router (changed)", r.engine.item(named.madeItemId)?.doc?.name)
        assertNotNull(r.server.itemRows[first.madeItemId]?.takeIf { it.deleted }, "the earlier copy is in the trash")
    }

    @Test
    fun aSourceChangedBetweenTwoRuns_aRunThatNamesNoEarlierCopy_makesASecondCopy() = runBlocking<Unit> {
        val (r, id) = rig()
        val first = r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, null))).ok().single()
        r.serve(r.itemRow(id, r.shared, r.sharedKey, r.doc.copy(name = "Router (changed)"), rev = r.server.rev + 1))
        r.engine.sync().ok()
        val second = r.engine.bringHeldInto(r.shared, into, listOf(HeldPick(id, null))).ok().single()
        val s = shown(r.engine, r)
        assertTrue(s.all { it.second }, "both are held by the server: $s")
        assertEquals(setOf(first.madeItemId, second.madeItemId), s.map { it.first }.toSet(), "a second copy beside the first")
    }
}
