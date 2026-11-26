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
 * What the rule of the kept copy while its person is added again (closed only while this device holds an invitation its
 * person can answer, decided on 22 and 23 November 2026) leaves as it was: the copy still goes on its day, also while it
 * is closed; an invitation the owner withdraws opens it again until its first day; "Remove from this device" works in
 * every state; and the closed state lives in memory only, so a new start of the trust engine (a start of the app, or the
 * next unlock) opens the copy until its adoption rules ask again.
 *
 * Real: the item engine and its store, and the trust engine behind [SessionVaultKeys] on a stand-in log server, with the
 * clock the test drives. Stand-in: the item server ([FakeItemServer]).
 */
class KeptCopyAddedAgainStaysTest {
    private class AddedAgain(val bed: TrustBed, val s: TrustBed.Shared, val day: Long) {
        val r: ItemRig get() = bed.rig
        val v: String get() = s.vaultId
        fun held(): HeldVaultView? = r.engine.heldVaults().singleOrNull { it.vaultId == v }
    }

    /** Shared with `wifi`, removed (the copy kept), added again on day 15 and served again: asked, the copy closed. */
    private fun addedAgain(): AddedAgain = runBlocking {
        val bed = TrustBed()
        val r = bed.rig
        val s = bed.share { listOf(bed.row(it, r.id(), "wifi", 7)) }
        bed.removeMe(s)
        r.engine.sync().ok()
        val day = r.engine.heldVaults().single { it.vaultId == s.vaultId }.expungeAt
        r.now += 15 * DAY
        check(bed.owner.append(s.vaultId, LogAction.Add(r.userId, "writer")) is AppendOutcome.Appended)
        bed.logs.refresh(s.vaultId, null, null, force = true)
        r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(bed.vaultRow(s)), grants = listOf(bed.grantRow(s))))
        r.engine.sync().ok()
        val a = AddedAgain(bed, s, day)
        check(a.held()!!.addedAgain && !a.held()!!.readable) { "asked: the copy is closed" }
        a
    }

    /**
     * The two ends of thirty days: the copy's day ([HeldVaultView.expungeAt], set when the item engine moved the copy aside)
     * and the end of the held key (set when the trust engine verified the removal). Both are taken in the same sync; with
     * one clock reading for that sync they are the same instant, so the line names the day on which both end.
     */
    @Test
    fun theCopysDayAndTheHeldKeysEndAreTakenInTheSameSync() = runBlocking<Unit> {
        val a = addedAgain()
        val keyEnd = a.bed.device.get(io.silencelen.andvari.core.client.log.StoredVaultLogs.recordKey(a.r.userId, a.v, "held"))!!.substringBefore(':').toLong()
        assertEquals(a.day, keyEnd, "the copy's day and the held key's end")
    }

    @Test
    fun aClosedCopyGoesOnItsDay() = runBlocking<Unit> {
        val a = addedAgain()
        a.r.now = a.day - 1
        a.r.engine.sync()
        assertTrue(a.held() != null && !a.held()!!.readable, "the day before: still kept, still closed")
        a.r.now = a.day
        a.r.engine.sync()
        assertEquals(null, a.held(), "on its day the closed copy goes")
        assertTrue(a.r.engine.vaults().none { it.vaultId == a.v }, "and the vault is not this person's")
    }

    @Test
    fun anInvitationTheOwnerWithdrawsOpensTheCopyAgainUntilItsFirstDay() = runBlocking<Unit> {
        val a = addedAgain()
        a.r.now += 1000
        check(a.bed.owner.append(a.v, LogAction.Remove(a.r.userId)) is AppendOutcome.Appended)
        a.bed.logs.refresh(a.v, null, null, force = true)
        a.r.server.queue.add(a.r.response(a.r.server.rev + 1, removed = listOf(a.v)))
        a.r.engine.sync()
        val h = a.held()!!
        assertTrue(h.readable && !h.addedAgain, "withdrawn: an ordinary kept copy again")
        assertEquals(a.day, h.expungeAt, "with its first day")
        assertEquals(ItemNotice.REMOVED, h.reason)
        assertEquals(listOf("wifi"), a.r.engine.heldItems(a.v).map { it.doc.name })
        assertEquals(1, a.r.engine.rescueHeldToPersonal(a.v).ok().copied, "copying out works")
        a.r.now = a.day
        a.r.engine.sync()
        assertEquals(null, a.held(), "on its first day the copy goes")
    }

    @Test
    fun removeFromThisDeviceWorksWhileTheCopyIsClosed() = runBlocking<Unit> {
        val a = addedAgain()
        a.r.engine.removeFromDevice(a.v).ok()
        assertEquals(null, a.held(), "the closed copy is removed from this device")
    }

    @Test
    fun removeFromThisDeviceWorksAfterADecline() = runBlocking<Unit> {
        val a = addedAgain()
        a.bed.logs.answerIncoming(a.bed.logs.adoption(a.v) as Adoption.AskAccept, accept = false)
        a.r.server.queue.add(a.r.response(a.r.server.rev + 1, removed = listOf(a.v)))
        a.r.engine.sync()
        check(a.held()!!.readable) { "declined: open" }
        a.r.engine.removeFromDevice(a.v).ok()
        assertEquals(null, a.held(), "the open copy is removed from this device")
    }

    @Test
    fun removeFromThisDeviceWorksWhileAnAddThatCannotBeAnsweredKeepsTheCopyOpen() = runBlocking<Unit> {
        val bed = TrustBed()
        val r = bed.rig
        val s = bed.share { listOf(bed.row(it, r.id(), "wifi", 7)) }
        bed.removeMe(s)
        r.engine.sync().ok()
        r.now += 3 * DAY
        check(bed.owner.append(s.vaultId, LogAction.Add(r.userId, "writer")) is AppendOutcome.Appended)
        bed.logServer.grants.remove(s.vaultId to r.userId)
        bed.logs.refresh(s.vaultId, null, null, force = true)
        r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(bed.vaultRow(s))))
        r.engine.sync().ok()
        check(r.engine.heldVaults().single { it.vaultId == s.vaultId }.readable) { "nothing to answer: open" }
        r.engine.removeFromDevice(s.vaultId).ok()
        assertTrue(r.engine.heldVaults().none { it.vaultId == s.vaultId }, "removed from this device")
    }

    /**
     * The closed state is kept in memory: a trust engine started afresh over the same device state (a start of the app,
     * or the next unlock) offers the kept copy's key until its adoption rules run online and ask again; reopening only
     * what is adopted, as a start without a connection does, keeps it open; the first adoption closes it again.
     */
    @Test
    fun afterARestartTheCopyIsOpenUntilTheAdoptionRulesAskAgain() = runBlocking<Unit> {
        val a = addedAgain()
        val fresh = a.bed.logsAfterRestart()
        assertTrue(fresh.copyOutAllowed(a.v), "after a start, before any adoption: the held key is offered (the copy opens)")
        assertTrue(!fresh.heldWhileMemberAgain(a.v), "and it is not said to be closed")
        assertTrue(!fresh.adoptionSettled(a.v), "the held key still gives no access")
        fresh.reopenAdopted(a.v)
        assertTrue(fresh.copyOutAllowed(a.v), "a start without a connection reopens only what is adopted: still open")
        assertTrue(fresh.adoption(a.v) is Adoption.AskAccept, "online, the adoption rules ask again")
        assertTrue(!fresh.copyOutAllowed(a.v) && fresh.heldWhileMemberAgain(a.v), "and the copy is closed again")
    }
}
