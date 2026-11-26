package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.items.TrustBed.Companion.DAY
import io.silencelen.andvari.core.client.log.Adoption
import io.silencelen.andvari.core.client.log.AppendOutcome
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.model.wire.SyncItem
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * What accepting does with a kept copy (spec 02 §10.6, decided on 24 November 2026). Until its person accepts, the copy
 * is whole: nothing the server serves about the vault's items changes it. A deletion the server serves for an item the
 * copy holds is recorded beside the copy, until a live row of the item is served, and the record goes with the copy. At
 * the acceptance, what the server served since rules: the copy puts back only an item of which this device holds no
 * served row, readable or not, and no recorded deletion.
 *
 * The course most cases share: a vault with x, y and z; the person is removed and keeps the copy; a member changes x and
 * deletes y; the person is added again, and the answer that brings the re-add (the earlier answer) serves x as changed,
 * y's deletion and z; the person accepts; the answer of the acceptance serves the vault and the grant and no item. The
 * stand-in item server answers only what a test queues, so no later answer brings the vault's items again.
 *
 * Real: the item engine and its store, and the trust engine over a stand-in log server ([TrustBed]).
 */
class KeptCopyAcceptTest {
    private class Kept(val bed: TrustBed, val s: TrustBed.Shared, val x: String, val y: String, val z: String, val rows: List<SyncItem>, val day: Long) {
        val r: ItemRig get() = bed.rig
        val v: String get() = s.vaultId
        lateinit var x2: SyncItem
        lateinit var yGone: SyncItem

        fun held(e: ItemEngine = r.engine): HeldVaultView? = e.heldVaults().singleOrNull { it.vaultId == v }
        fun names(e: ItemEngine = r.engine): List<String> = e.items().filter { it.vaultId == v }.map { it.doc.name }.sorted()
        fun heldNames(e: ItemEngine = r.engine): List<String> = e.heldItems(v).map { it.doc.name }.sorted()
        fun intoV(from: Int) = r.server.pushes.drop(from).flatten().filter { it.vaultId == v }

        /** The served deletions recorded beside this vault's kept copy, read from the store's client state. */
        fun record(): Set<String> = r.cache.clientState(RECORD + v)?.split(',')?.filter { it.isNotEmpty() }?.toSet().orEmpty()

        fun ask(): Adoption.AskAccept = runBlocking { bed.logs.adoption(v) as Adoption.AskAccept }
    }

    /** A cache whose next removal of a kept copy fails once, as a write the disk refused does. */
    private class RefusesOneRemoval(private val d: InMemoryVaultCache = InMemoryVaultCache()) : VaultCache by d {
        var refuseNext = false

        override fun removeHeld(vaultId: String) {
            if (refuseNext) {
                refuseNext = false
                throw IllegalStateException("the disk refused the write")
            }
            d.removeHeld(vaultId)
        }
    }

    /**
     * Shared with x, y, z (rev 7); with [parkedOn], an edit of that item waiting (parked at the removal); removed; kept.
     * The engine's store is [cache].
     */
    private fun kept(parkedOn: Char? = null, leftOver: Boolean = false, cache: VaultCache = InMemoryVaultCache()): Kept = runBlocking {
        val bed = TrustBed(cache)
        val r = bed.rig
        val x = r.id()
        val y = r.id()
        val z = r.id()
        lateinit var rows: List<SyncItem>
        val s = bed.share { rows = listOf(bed.row(it, x, "x", 7), bed.row(it, y, "y", 7), bed.row(it, z, "z", 7)); rows }
        rows.forEach { r.server.itemRows[it.itemId] = it }
        r.server.rev = maxOf(r.server.rev, 7)
        if (parkedOn != null) {
            val id = if (parkedOn == 'x') x else z
            r.server.emptyResultsVaults += s.vaultId
            r.engine.save(id, r.doc.copy(name = "$parkedOn edited by the person"), s.vaultId)
        }
        // A record of y's deletion with no copy beside it (from a write of an earlier copy that never went).
        if (leftOver) r.cache.setClientState(RECORD + s.vaultId, y)
        bed.removeMe(s)
        r.engine.sync()
        r.server.emptyResultsVaults -= s.vaultId
        val h = r.engine.heldVaults().single { it.vaultId == s.vaultId }
        if (parkedOn != null) check(h.parkedCount == 1) { "the edit is parked: ${h.parkedCount}" }
        Kept(bed, s, x, y, z, rows, h.expungeAt).also { k ->
            // Meanwhile a member changes x and deletes y.
            r.server.rev += 1
            k.x2 = bed.row(s, x, "x changed by the owner", r.server.rev)
            r.server.itemRows[x] = k.x2
            r.server.rev += 1
            k.yGone = bed.row(s, y, "y", r.server.rev).copy(deleted = true, blob = null)
            r.server.itemRows[y] = k.yGone
        }
    }

    /** The owner adds the person again; the earlier answer serves the vault, the grant and [items]. The copy is closed. */
    private fun Kept.addAgain(items: List<SyncItem>) = runBlocking {
        r.now += 3 * DAY
        // The owner's device reads the log first: after a decline it holds the person's own leave.
        bed.owner.refresh(v, null, null, force = true)
        check(bed.owner.append(v, LogAction.Add(r.userId, "writer")) is AppendOutcome.Appended) { "the owner adds the person again" }
        bed.logs.refresh(v, null, null, force = true)
        r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(bed.vaultRow(s)), grants = listOf(bed.grantRow(s)), items = items))
        r.engine.sync()
        check(held()?.let { !it.readable && it.addedAgain } == true) { "closed after the re-add: ${held()?.readable} ${held()?.addedAgain}" }
    }

    /** The earlier answer of the course: x as changed, y's deletion, z. */
    private fun Kept.earlier(): List<SyncItem> = listOf(x2, yGone, rows[2])

    /** The person accepts; the answer of the acceptance serves the vault, the grant and [items]; one sync of [e]. */
    private fun Kept.accept(e: ItemEngine = r.engine, items: List<SyncItem> = emptyList()) = runBlocking {
        check(bed.logs.answerIncoming(ask(), accept = true) is Adoption.Adopted) { "the acceptance is taken" }
        r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(bed.vaultRow(s)), grants = listOf(bed.grantRow(s)), items = items))
        e.sync()
    }

    private fun Kept.vaultBack(e: ItemEngine = r.engine) = check(e.vaults().any { it.vaultId == v } && held(e) == null) { "the vault is back and the copy taken" }

    // ---- 1 to 3: the course ----

    @Test
    fun aDeletionServedInAnEarlierAnswerDoesNotComeBackAtTheAcceptance() {
        val k = kept()
        k.addAgain(k.earlier())
        k.accept()
        k.vaultBack()
        assertTrue("y" !in k.names(), "y, deleted in the earlier answer, came back: ${k.names()}")
    }

    @Test
    fun aChangeServedInAnEarlierAnswerStaysAndOpensAtOnce() {
        val k = kept()
        k.addAgain(k.earlier())
        k.accept()
        k.vaultBack()
        assertEquals("x changed by the owner", k.r.engine.item(k.x)?.doc?.name, "x as the member changed it, open after the acceptance's one sync: ${k.names()}")
        assertTrue("x" !in k.names(), "the kept copy's older x is not put over the newer one: ${k.names()}")
    }

    @Test
    fun anItemServedInAnEarlierAnswerOpensAtOnceAndSoDoesOneTheCopyNeverHeld() {
        val k = kept()
        val w = k.r.id()
        k.r.server.rev += 1
        val wRow = k.bed.row(k.s, w, "w made while the person was out", k.r.server.rev)
        k.addAgain(k.earlier() + wRow)
        k.accept()
        k.vaultBack()
        assertEquals("z", k.r.engine.item(k.z)?.doc?.name, "z opens after the acceptance's one sync")
        assertEquals("w made while the person was out", k.r.engine.item(w)?.doc?.name, "an item the copy never held opens too")
    }

    // ---- 4 and 5: across a restart and a resync ----

    @Test
    fun aDeletionServedEarlierDoesNotComeBackAfterARestartBeforeTheAcceptance() = runBlocking<Unit> {
        val k = kept()
        k.addAgain(k.earlier())
        val e = k.r.restarted()
        e.hydrate()
        k.accept(e)
        k.vaultBack(e)
        assertTrue("y" !in k.names(e), "after a restart, y came back: ${k.names(e)}")
        assertEquals("x changed by the owner", e.item(k.x)?.doc?.name, "x as changed")
    }

    /** A resync serves every row of the vault again, deletions included (the server's pull from 0 has no filter on them). */
    @Test
    fun aDeletionServedEarlierDoesNotComeBackAfterAResyncThatServesItAgain() {
        val k = kept()
        k.addAgain(k.earlier())
        k.resync(k.earlier())
        k.accept()
        k.vaultBack()
        assertTrue("y" !in k.names(), "after a resync, y came back: ${k.names()}")
        assertEquals("x changed by the owner", k.r.engine.item(k.x)?.doc?.name, "x as changed")
    }

    /** A resync that no longer serves y's deletion (the server dropped the row): the record outlives the resync's clear. */
    @Test
    fun aDeletionServedEarlierDoesNotComeBackAfterAResyncThatLeavesItOut() {
        val k = kept()
        k.addAgain(k.earlier())
        k.resync(listOf(k.x2, k.rows[2]))
        k.accept()
        k.vaultBack()
        assertTrue("y" !in k.names(), "after a resync without the deletion, y came back: ${k.names()}")
    }

    private fun Kept.resync(items: List<SyncItem>) = runBlocking {
        r.server.goneOnce = true
        r.server.queue.add(
            r.response(
                r.server.rev + 1, full = true,
                vaults = listOf(r.vaultRow(r.personal, r.personalKey, "personal", "Personal"), bed.vaultRow(s)),
                grants = listOf(r.personalGrant, bed.grantRow(s)), items = items,
            ),
        )
        check(r.engine.sync() is ItemResult.Ok) { "the resync" }
        check(held()?.let { !it.readable && it.addedAgain } == true) { "still closed after the resync" }
    }

    // ---- 6: the copy is whole until the person accepts ----

    @Test
    fun afterADeclineTheCopyIsWholeAndANewAddAndAcceptanceStillLeaveYOut() = runBlocking<Unit> {
        val k = kept()
        val r = k.r
        k.addAgain(k.earlier())
        check(k.bed.logs.answerIncoming(k.ask(), accept = false) is Adoption.Declined)
        r.server.queue.add(r.response(r.server.rev + 1, removed = listOf(k.v)))
        r.engine.sync()
        assertTrue(k.held()!!.readable, "after a decline the copy opens")
        assertEquals(listOf("x", "y", "z"), k.heldNames(), "the copy lists x as it was at the removal, y and z")
        assertEquals(3, r.engine.rescueHeldToPersonal(k.v).ok().copied, "copying out copies three items")
        k.addAgain(emptyList())
        k.accept()
        k.vaultBack()
        assertTrue("y" !in k.names(), "after a decline, a new add and an acceptance, y came back: ${k.names()}")
        assertTrue("x" in k.names() && "z" in k.names(), "the rest of the copy is put back: ${k.names()}")
    }

    @Test
    fun afterTheInvitationIsWithdrawnTheCopyIsWhole() = runBlocking<Unit> {
        val k = kept()
        val r = k.r
        k.addAgain(k.earlier())
        r.now += 1000
        check(k.bed.owner.append(k.v, LogAction.Remove(r.userId)) is AppendOutcome.Appended)
        k.bed.logs.refresh(k.v, null, null, force = true)
        r.server.queue.add(r.response(r.server.rev + 1, removed = listOf(k.v)))
        r.engine.sync()
        assertTrue(k.held()!!.readable, "withdrawn: the copy opens")
        assertEquals(listOf("x", "y", "z"), k.heldNames(), "the copy lists x as it was at the removal, y and z")
        assertEquals(3, r.engine.rescueHeldToPersonal(k.v).ok().copied, "copying out copies three items")
        assertEquals(k.day, k.held()!!.expungeAt, "its day")
    }

    /** A server that serves a vault's deletions to a person whom no owner added again: the copy stays whole, until its day. */
    @Test
    fun deletionsServedWithNoAddLeaveTheCopyWholeUntilItsDay() = runBlocking<Unit> {
        val k = kept()
        val r = k.r
        r.server.queue.add(r.response(r.server.rev + 1, items = listOf(k.yGone, k.r.tombstone(k.x, k.v, r.server.rev + 1))))
        r.engine.sync()
        assertTrue(k.held()!!.readable, "removed and not added again: the copy opens")
        assertEquals(listOf("x", "y", "z"), k.heldNames(), "the copy keeps every item")
        assertEquals(3, r.engine.rescueHeldToPersonal(k.v).ok().copied, "copying out copies three items")
        r.now = k.day
        r.engine.sync()
        assertEquals(null, k.held(), "on its day the copy goes")
        assertEquals(emptySet(), k.record(), "and its record with it")
    }

    // ---- 7 and 8: what the record holds ----

    @Test
    fun aDeletionThenALiveRowOfTheSameItemLeavesTheItemAsServed() = runBlocking<Unit> {
        val k = kept()
        val r = k.r
        k.addAgain(k.earlier())
        r.server.rev += 1
        val yBack = k.bed.row(k.s, k.y, "y restored by the owner", r.server.rev)
        r.server.itemRows[k.y] = yBack
        r.server.queue.add(r.response(r.server.rev + 1, items = listOf(yBack)))
        r.engine.sync()
        assertTrue(k.y !in k.record(), "a live row of y takes its deletion out of the record: ${k.record()}")
        k.accept()
        k.vaultBack()
        assertEquals("y restored by the owner", r.engine.item(k.y)?.doc?.name, "y as served, open at once: ${k.names()}")
        assertTrue("y" !in k.names(), "the kept copy's y is not put over it: ${k.names()}")
        assertEquals(emptySet(), k.record(), "the record holds nothing")
    }

    @Test
    fun aDeletionServedUnderAnotherVaultsIdIsNotRecordedForThisCopy() {
        val k = kept()
        val other = k.r.id()
        k.addAgain(listOf(k.x2, k.rows[2], k.yGone.copy(vaultId = other)))
        assertEquals(emptySet(), k.record(), "nothing recorded for this copy")
        k.accept()
        k.vaultBack()
        assertTrue("y" in k.names(), "y comes back from the copy: ${k.names()}")
    }

    // ---- 9: a served row that does not open ----

    @Test
    fun aServedRowThatDoesNotOpenIsNotOverwrittenByTheKeptCopy() {
        val k = kept()
        val r = k.r
        r.server.rev += 1
        val xBad = r.itemRow(k.x, k.v, ByteArray(32) { 4 }, r.doc.copy(name = "x sealed under another key"), r.server.rev)
        k.addAgain(listOf(xBad, k.yGone, k.rows[2]))
        k.accept()
        k.vaultBack()
        assertTrue("x" !in k.names(), "the kept copy's x was put over the served row: ${k.names()}")
        assertEquals(null, r.engine.item(k.x), "x does not open")
        assertEquals(xBad.blob, r.engine.envelopes().single { it.itemId == k.x }.blob, "the served row of x is kept as served")
    }

    // ---- 10: the record goes with the copy ----

    @Test
    fun theRecordGoesWithRemoveFromThisDevice() {
        val k = kept()
        k.addAgain(k.earlier())
        assertEquals(setOf(k.y), k.record(), "y's deletion is recorded beside the copy")
        k.r.engine.removeFromDevice(k.v).ok()
        assertEquals(null, k.held())
        assertEquals(emptySet(), k.record(), "the record went with the copy")
    }

    @Test
    fun theRecordGoesOnTheCopysDay() = runBlocking<Unit> {
        val k = kept()
        k.addAgain(k.earlier())
        assertEquals(setOf(k.y), k.record(), "y's deletion is recorded beside the copy")
        k.r.now = k.day
        k.r.engine.sync()
        assertEquals(null, k.held(), "the copy went on its day")
        assertEquals(emptySet(), k.record(), "the record went with it")
    }

    @Test
    fun theRecordGoesAtTheAcceptanceAndALaterRemovalStartsEmpty() = runBlocking<Unit> {
        val k = kept()
        val r = k.r
        k.addAgain(k.earlier())
        assertEquals(setOf(k.y), k.record(), "y's deletion is recorded beside the copy")
        k.accept()
        k.vaultBack()
        assertEquals(emptySet(), k.record(), "the record went at the acceptance")
        k.bed.removeMe(k.s)
        r.engine.sync()
        assertTrue(k.held() != null, "removed again: a new copy is kept")
        assertEquals(emptySet(), k.record(), "the new copy starts with an empty record")
    }

    @Test
    fun aRecordLeftWithNoCopyDoesNotApplyToANewCopy() {
        val k = kept(leftOver = true)
        assertEquals(emptySet(), k.record(), "the new copy starts with an empty record")
        k.addAgain(emptyList())
        k.accept()
        k.vaultBack()
        assertEquals(listOf("x", "y", "z"), k.names(), "nothing served was deleted: the whole copy is put back")
    }

    // ---- 11: what is green today stays green ----

    @Test
    fun aDeletionInTheAnswerOfTheAcceptanceDoesNotComeBack() {
        val k = kept()
        k.addAgain(emptyList())
        k.accept(items = k.earlier())
        k.vaultBack()
        assertEquals(listOf("x changed by the owner", "z"), k.names())
    }

    @Test
    fun aDeletionOfAnItemServedLiveAfterTheReAddDoesNotComeBack() = runBlocking<Unit> {
        val k = kept()
        val r = k.r
        k.addAgain(k.rows)
        r.server.queue.add(r.response(r.server.rev + 1, items = listOf(k.yGone)))
        r.engine.sync()
        k.accept()
        k.vaultBack()
        assertTrue("y" !in k.names(), "y came back: ${k.names()}")
    }

    /** The server withholds the change and the deletion: never served, the device does not know them, and the copy is put back. */
    @Test
    fun whatTheServerNeverServedIsPutBackFromTheCopy() {
        val k = kept()
        k.addAgain(emptyList())
        k.accept()
        k.vaultBack()
        assertEquals(listOf("x", "y", "z"), k.names())
    }

    // ---- the item home, and the parked changes ----

    @Test
    fun aKeptItemWhoseHomeIsAnotherVaultIsNotPutBack() {
        val k = kept()
        k.addAgain(emptyList())
        k.r.cache.setItemHome(k.x, k.r.personal)
        check(k.r.cache.itemHome(k.x) == k.r.personal) { "the home is written" }
        k.accept()
        k.vaultBack()
        assertTrue("x" !in k.names() && k.r.engine.items().none { it.itemId == k.x }, "x is not put back under another vault than its home: ${k.names()}")
    }

    /**
     * The same, when the acceptance's sync fails on one write after the trust step adopted the key: the failed pull
     * opens the vault in memory, so the next sync, which puts the copy back, does not read the vault's items again
     * after it. Only the put-back itself can keep x out.
     */
    @Test
    fun aKeptItemWhoseHomeIsAnotherVaultIsNotPutBackAfterAFailedAcceptanceSync() = runBlocking<Unit> {
        val cache = RefusesOneRemoval()
        val k = kept(cache = cache)
        val r = k.r
        k.addAgain(emptyList())
        r.cache.setItemHome(k.x, r.personal)
        check(r.cache.itemHome(k.x) == r.personal) { "the home is written" }
        check(k.bed.logs.answerIncoming(k.ask(), accept = true) is Adoption.Adopted) { "the acceptance is taken" }
        cache.refuseNext = true
        r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(k.bed.vaultRow(k.s)), grants = listOf(k.bed.grantRow(k.s))))
        val first = runCatching { r.engine.sync() }
        check(first.isFailure || first.getOrNull() !is ItemResult.Ok) { "the acceptance's sync fails: $first" }
        check(!cache.refuseNext) { "it failed on the removal of the copy" }
        r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(k.bed.vaultRow(k.s)), grants = listOf(k.bed.grantRow(k.s))))
        r.engine.sync()
        k.vaultBack()
        assertTrue("x" !in k.names() && r.engine.items().none { it.itemId == k.x }, "x is not put back under another vault than its home: ${k.names()}")
        assertTrue("y" in k.names() && "z" in k.names(), "the rest of the copy is put back: ${k.names()}")
    }

    @Test
    fun theChangesParkedWithTheCopyAreSentAtTheAcceptance() = runBlocking<Unit> {
        val k = kept(parkedOn = 'z')
        val r = k.r
        k.addAgain(k.earlier())
        val p0 = r.server.pushes.size
        k.accept()
        k.vaultBack()
        r.engine.sync()
        assertEquals(listOf("put ${k.z}"), k.intoV(p0).map { "${it.op} ${it.itemId}" }, "the parked edit of z is sent")
        assertTrue("y" !in k.names(), "y stays out: ${k.names()}")
    }

    private companion object {
        /** The client-state key prefix under which a kept copy's record of served deletions is kept, per vault. */
        const val RECORD = "held.deleted."
    }
}
