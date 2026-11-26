package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.items.TrustBed.Companion.DAY
import io.silencelen.andvari.core.client.log.Adoption
import io.silencelen.andvari.core.client.log.AppendOutcome
import io.silencelen.andvari.core.client.log.LogAction
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Removed from a shared vault, then added again before the held copy's day, and not yet answered (decided on 22
 * November 2026: for 1.0.0 the copy stays closed for that stretch, and its entry says so). The copy is still held with
 * its first day; it does not open, nothing of it can be copied out, nothing is written or sent into the vault, and the
 * view says the account was added again. Beside it, what a decline does: the copy opens again until its first day.
 *
 * Real: the item engine and its store, and the trust engine ([io.silencelen.andvari.core.client.log.StoredVaultLogs]
 * behind [SessionVaultKeys]) on a stand-in log server, with the clock the test drives. Stand-in: the item server
 * ([FakeItemServer]).
 */
class HeldCopyAddedAgainTest {
    private class AddedAgain(val s: TrustBed.Shared, val t0: Long)

    /** Shared with `wifi`, removed (verified: the copy is held from t0), added again on day 15, served again. */
    private fun TrustBed.addedAgainOnDay15(): AddedAgain = runBlocking {
        val r = rig
        val s = share { listOf(row(it, r.id(), "wifi", 7)) }
        removeMe(s)
        val t0 = r.now
        r.engine.sync().ok()
        check(r.engine.heldVaults().single { it.vaultId == s.vaultId }.readable)
        r.now = t0 + 15 * DAY
        check(owner.append(s.vaultId, LogAction.Add(r.userId, "writer")) is AppendOutcome.Appended)
        logs.refresh(s.vaultId, null, null, force = true)
        r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(vaultRow(s)), grants = listOf(grantRow(s))))
        r.engine.sync()
        AddedAgain(s, t0)
    }

    @Test
    fun addedAgainOnDay15AndNotAnsweredTheKeptCopyStaysClosedWithItsDayAndTheViewSaysAddedAgain() = runBlocking<Unit> {
        val bed = TrustBed()
        val r = bed.rig
        val a = bed.addedAgainOnDay15()
        val held = r.engine.heldVaults().singleOrNull { it.vaultId == a.s.vaultId }
        assertEquals(a.t0 + ItemEngine.HOLDING_MS, held?.expungeAt, "the kept copy is still under Recently removed, with its first day")
        assertTrue(!held!!.readable, "it does not open")
        assertTrue(held.addedAgain, "the view says the account was added again")
        assertEquals(emptyList(), r.engine.heldItems(a.s.vaultId).map { it.doc.name }, "no items are listed")
        val pushes = r.server.pushes.size
        assertEquals(ItemFailure.NotAllowed(ItemRefusal.VAULT_NOT_OPEN), r.engine.rescueHeldToPersonal(a.s.vaultId).failure(), "nothing can be copied out")
        assertTrue(r.engine.save(null, r.doc.copy(name = "new"), a.s.vaultId) is ItemResult.Failed, "a save into the vault fails")
        r.engine.sync()
        assertTrue(r.server.pushes.drop(pushes).flatten().none { it.vaultId == a.s.vaultId }, "nothing is sent into that vault")
        assertEquals(a.t0 + ItemEngine.HOLDING_MS, r.engine.heldVaults().single { it.vaultId == a.s.vaultId }.expungeAt)
    }

    /**
     * Removed with an edit of `z` waiting (it is parked with the kept copy); meanwhile the owner changes `x` and deletes
     * `y`, adds the person again, and the person accepts. The vault comes back as the server has it: `x` as changed and no
     * `y` (it does not come back from the kept copy), and the person's own parked edit is sent, as decided.
     */
    @Test
    fun acceptedAgainAnItemTheOwnerDeletedMeanwhileDoesNotComeBackFromTheKeptCopy() = runBlocking<Unit> {
        val bed = TrustBed()
        val r = bed.rig
        val x = r.id()
        val y = r.id()
        val z = r.id()
        lateinit var rows: List<io.silencelen.andvari.core.model.wire.SyncItem>
        val s = bed.share { rows = listOf(bed.row(it, x, "x", 7), bed.row(it, y, "y", 7), bed.row(it, z, "z", 7)); rows }
        rows.forEach { r.server.itemRows[it.itemId] = it }
        r.server.rev = maxOf(r.server.rev, 7)
        r.server.emptyResultsVaults += s.vaultId
        r.engine.save(z, r.doc.copy(name = "z edited by the person"), s.vaultId)
        bed.removeMe(s)
        r.engine.sync()
        r.server.emptyResultsVaults -= s.vaultId
        check(r.engine.heldVaults().single { it.vaultId == s.vaultId }.parkedCount == 1) { "the edit is parked with the kept copy" }
        // Meanwhile the owner changes x and deletes y.
        r.server.rev += 1
        val x2 = bed.row(s, x, "x changed by the owner", r.server.rev)
        r.server.itemRows[x] = x2
        r.server.rev += 1
        val yGone = bed.row(s, y, "y", r.server.rev).copy(deleted = true, blob = null)
        r.server.itemRows[y] = yGone
        r.now += 10 * DAY
        check(bed.owner.append(s.vaultId, LogAction.Add(r.userId, "writer")) is AppendOutcome.Appended)
        bed.logs.refresh(s.vaultId, null, null, force = true)
        val ask = bed.logs.adoption(s.vaultId) as Adoption.AskAccept
        bed.logs.answerIncoming(ask, accept = true)
        val pushes = r.server.pushes.size
        r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(bed.vaultRow(s)), grants = listOf(bed.grantRow(s)), items = listOf(x2, yGone, rows[2])))
        r.engine.sync()
        r.engine.sync()
        val names = r.engine.items().filter { it.vaultId == s.vaultId }.map { it.doc.name }.sorted()
        assertTrue("x changed by the owner" in names && "y" !in names, "x as changed and no y: $names")
        assertTrue(r.server.pushes.drop(pushes).flatten().any { it.itemId == z && it.vaultId == s.vaultId }, "the person's parked edit is sent")
    }

    /**
     * The same start, then the person declines (the product's own answer to the invitation, which signs a leave): the
     * copy opens again until its first day, its items can be copied out, nothing is written or sent into the vault, the
     * entry keeps the reason of the removal, and on its first day the copy goes.
     */
    @Test
    fun aDeclineAfterBeingAddedAgainKeepsTheDayAndSendsNothingIntoTheVault() = runBlocking<Unit> {
        val bed = TrustBed()
        val r = bed.rig
        val a = bed.addedAgainOnDay15()
        val ask = bed.logs.adoption(a.s.vaultId)
        check(ask is Adoption.AskAccept) { "the person is asked: ${ask::class.simpleName}" }
        bed.logs.answerIncoming(ask, accept = false)
        val pushes = r.server.pushes.size
        r.server.queue.add(r.response(r.server.rev + 1, removed = listOf(a.s.vaultId)))
        r.engine.sync()
        val held = r.engine.heldVaults().singleOrNull { it.vaultId == a.s.vaultId }
        assertEquals(a.t0 + ItemEngine.HOLDING_MS, held?.expungeAt, "a decline does not move the day: ${r.engine.heldVaults().map { "${it.reason} ${it.expungeAt}" }}")
        assertEquals(ItemNotice.REMOVED, held!!.reason, "the entry keeps the reason of the removal")
        assertTrue(!held.addedAgain, "no longer said to be closed")
        assertTrue(held.readable, "after a decline the copy opens again until its day")
        assertEquals(listOf("wifi"), r.engine.heldItems(a.s.vaultId).map { it.doc.name })
        assertEquals(1, r.engine.rescueHeldToPersonal(a.s.vaultId).ok().copied, "its items can be copied out")
        assertTrue(r.engine.save(null, r.doc.copy(name = "new"), a.s.vaultId) is ItemResult.Failed, "a save into the vault fails")
        r.engine.sync()
        assertTrue(r.server.pushes.drop(pushes).flatten().none { it.vaultId == a.s.vaultId }, "nothing is sent into that vault")
        r.now = a.t0 + ItemEngine.HOLDING_MS
        r.engine.sync()
        assertTrue(r.engine.heldVaults().none { it.vaultId == a.s.vaultId }, "on its first day the copy goes")
    }
}
