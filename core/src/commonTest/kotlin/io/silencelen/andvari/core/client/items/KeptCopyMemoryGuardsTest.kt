package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.items.TrustBed.Companion.DAY
import io.silencelen.andvari.core.client.log.Adoption
import io.silencelen.andvari.core.client.log.AppendOutcome
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.state.AccountStateWrite
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The places where the trust engine reads and writes what it remembers of an invitation to a kept copy's vault, each held
 * by a case: an answer whose outcome the device did not learn ends the invitation it answered, so the copy opens until
 * the next adoption pass; an invitation withdrawn opens the copy as soon as the removal is verified, before any
 * adoption pass, also when the decline record for the removal is refused; a verdict that does not ask ends the
 * invitation; an adoption ends both the invitation and a refused answer remembered for it; and a person removed and not
 * added again keeps an ordinary kept copy until its day. In none of them is the vault one the account may use unless it
 * was adopted.
 *
 * Real: the item engine and its store, and the trust engine behind [SessionVaultKeys] on a stand-in log server and a
 * stand-in account state, with the clock the test drives. Stand-in: the item server ([FakeItemServer]).
 */
class KeptCopyMemoryGuardsTest {
    private class Kept(val bed: TrustBed, val s: TrustBed.Shared, val day: Long) {
        val r: ItemRig get() = bed.rig
        val v: String get() = s.vaultId
        fun held(): HeldVaultView? = r.engine.heldVaults().singleOrNull { it.vaultId == v }
        fun verdict(): Adoption = runBlocking { bed.logs.adoption(v) }

        fun assertNotLive(what: String) {
            assertTrue(r.engine.vaults().none { it.vaultId == v }, "$what: not a vault the account may use")
            assertTrue(r.engine.items().none { it.vaultId == v }, "$what: no item of it among the account's items")
        }

        fun assertOpen(what: String) {
            val h = held()!!
            assertTrue(h.readable && !h.addedAgain, "$what: open (readable ${h.readable}, addedAgain ${h.addedAgain})")
            assertEquals(day, h.expungeAt, "$what: its day")
            assertEquals(listOf("wifi"), r.engine.heldItems(v).map { it.doc.name }, "$what: its items read")
            assertNotLive(what)
        }

        fun assertClosed(what: String) {
            val h = held()!!
            assertTrue(!h.readable && h.addedAgain, "$what: closed (readable ${h.readable}, addedAgain ${h.addedAgain})")
            assertEquals(day, h.expungeAt, "$what: its day")
            assertNotLive(what)
        }

        /** The server serves the vault's row and this account's grant, and the engine syncs (the adoption rules run). */
        fun syncWithGrant() = runBlocking {
            r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(bed.vaultRow(s)), grants = listOf(bed.grantRow(s))))
            r.engine.sync()
        }

        /** The server serves the vault's row, and the engine syncs (the adoption rules run in it). */
        fun sync() = runBlocking {
            r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(bed.vaultRow(s))))
            r.engine.sync()
        }
    }

    /** Shared with `wifi`; the person is removed: the copy is kept with its day. */
    private fun removed(): Kept = runBlocking {
        val bed = TrustBed()
        val r = bed.rig
        val s = bed.share { listOf(bed.row(it, r.id(), "wifi", 7)) }
        bed.removeMe(s)
        r.engine.sync().ok()
        val day = r.engine.heldVaults().single { it.vaultId == s.vaultId }.expungeAt
        Kept(bed, s, day)
    }

    /** Three days on the owner adds the person again; the device verifies the log and syncs: asked, closed. */
    private fun asked(): Kept = removed().also { k ->
        runBlocking {
            k.r.now += 3 * DAY
            check(k.bed.owner.append(k.v, LogAction.Add(k.r.userId, "writer")) is AppendOutcome.Appended)
            k.bed.logs.refresh(k.v, null, null, force = true)
            k.syncWithGrant()
        }
        assertTrue(k.verdict() is Adoption.AskAccept, "asked")
        k.assertClosed("asked")
    }

    /**
     * An acceptance whose outcome the device did not learn: the answer's own verdict ends the invitation, so the copy is
     * open until the next adoption pass, which finds nothing stored, asks again and closes it.
     */
    @Test
    fun anAcceptanceWhoseOutcomeIsNotKnownOpensTheCopyUntilTheNextAdoptionPass() = runBlocking<Unit> {
        val k = asked()
        k.bed.accountState.failNext += AccountStateWrite.Unknown
        val r = k.bed.logs.answerIncoming(k.verdict() as Adoption.AskAccept, accept = true)
        assertTrue(r is Adoption.AnswerNotKnown, "not known: $r")
        k.assertOpen("an acceptance not known, before the next adoption pass")
        k.syncWithGrant()
        assertTrue(k.verdict() is Adoption.AskAccept, "nothing was stored: asked again")
        k.assertClosed("an acceptance not known, after the next adoption pass")
    }

    /** A decline whose outcome the device did not learn (its leave unanswered): the copy is open, and not live. */
    @Test
    fun aDeclineWhoseOutcomeIsNotKnownOpensTheCopy() = runBlocking<Unit> {
        val k = asked()
        k.bed.accountState.failNext += AccountStateWrite.Unknown
        k.bed.logServer.appendsUnanswered += k.v
        val r = k.bed.logs.answerIncoming(k.verdict() as Adoption.AskAccept, accept = false)
        assertTrue(r is Adoption.AnswerNotKnown, "not known: $r")
        k.assertOpen("a decline not known")
    }

    /** A withdrawn invitation, read after the log engine verified the removal and before any adoption pass: open. */
    @Test
    fun aWithdrawnInvitationOpensTheCopyAsSoonAsTheRemovalIsVerified() = runBlocking<Unit> {
        val k = asked()
        k.r.now += 1000
        check(k.bed.owner.append(k.v, LogAction.Remove(k.r.userId)) is AppendOutcome.Appended)
        k.bed.logs.refresh(k.v, null, null, force = true)
        k.assertOpen("withdrawn, before any adoption pass")
    }

    /**
     * A withdrawn invitation while the account state refuses the decline record this device writes for its own removal:
     * no answer to the withdrawn add is recorded, so only the question "is this account a member" ends the invitation.
     * The person is no member and nothing can be answered, so the copy is an ordinary kept copy (open, not "added
     * again"), before any adoption pass and after the next sync.
     */
    @Test
    fun aWithdrawnInvitationWhoseDeclineRecordIsRefusedLeavesAnOrdinaryKeptCopy() = runBlocking<Unit> {
        val k = asked()
        val addSeq = (k.verdict() as Adoption.AskAccept).addSeq
        repeat(3) { k.bed.accountState.failNext += AccountStateWrite.Refused("forbidden") }
        k.r.now += 1000
        check(k.bed.owner.append(k.v, LogAction.Remove(k.r.userId)) is AppendOutcome.Appended)
        k.bed.logs.refresh(k.v, null, null, force = true)
        k.bed.accountState.failNext.clear()
        assertTrue(k.bed.accountState.doc.accepted[k.v]?.addSeq != addSeq, "no answer to the withdrawn add is recorded: ${k.bed.accountState.doc.accepted[k.v]}")
        k.assertOpen("withdrawn, its decline record refused, before any adoption pass")
        k.sync()
        k.assertOpen("withdrawn, its decline record refused, after the next sync")
    }

    /**
     * No refused answer: asked, then one sync whose verdict does not ask (the grant left out; later, the owner no current
     * contact, so connect first). That verdict ends the invitation: nothing can be answered, so the copy opens; each time
     * the same add is asked again it closes.
     */
    @Test
    fun aVerdictThatDoesNotAskOpensTheCopyUntilTheSameAddIsAskedAgain() = runBlocking<Unit> {
        val k = asked()
        val grant = k.bed.logServer.grants.remove(k.v to k.r.userId)!!
        k.sync()
        assertTrue(k.verdict() is Adoption.Refused, "the grant left out: ${k.verdict()}")
        k.assertOpen("the grant left out, nothing to answer")
        k.bed.logServer.grants[k.v to k.r.userId] = grant
        k.sync()
        assertTrue(k.verdict() is Adoption.AskAccept, "the grant served again: asked")
        k.assertClosed("asked again")
        val key = k.bed.contacts.remove(k.bed.ownerId)!!
        k.sync()
        assertTrue(k.verdict() is Adoption.ConnectFirst, "connect first: ${k.verdict()}")
        k.assertOpen("connect first, nothing to answer")
        k.bed.contacts[k.bed.ownerId] = key
        k.sync()
        k.assertClosed("asked once more")
    }

    /**
     * An adoption ends what the engine remembers of the invitation. The account's answers are then served without the
     * acceptance: an engine that still remembered the invitation would call the adopted vault a kept copy closed for it.
     * The measure is a trust engine started afresh over the same state, which remembers nothing.
     */
    @Test
    fun afterAnAdoptionNoInvitationIsRememberedWhenTheAcceptanceIsServedAway() = runBlocking<Unit> {
        val k = asked()
        assertTrue(k.bed.logs.answerIncoming(k.verdict() as Adoption.AskAccept, accept = true) is Adoption.Adopted, "taken")
        k.sync()
        val doc = k.bed.accountState.doc
        k.bed.accountState.doc = doc.copy(seq = doc.seq + 1, accepted = doc.accepted - k.v)
        k.sync()
        val fresh = k.bed.logsAfterRestart()
        assertEquals(fresh.heldWhileMemberAgain(k.v), k.bed.logs.heldWhileMemberAgain(k.v), "the adopted vault: as an engine that remembers nothing")
        assertTrue(!k.bed.logs.heldWhileMemberAgain(k.v), "the adopted vault is no kept copy closed for an invitation")
    }

    /**
     * An adoption ends what the engine remembers of a refused answer. Refused, then answered again and taken (adopted);
     * the acceptance is then served away and the adoption rules are asked again directly, as the command line's accept
     * does: the engine answers as one that never saw the refusal, that is, as a trust engine started afresh over the same
     * state and asked the same.
     */
    @Test
    fun afterAnAdoptionNoRefusalIsRememberedWhenTheAcceptanceIsServedAway() = runBlocking<Unit> {
        val k = asked()
        k.bed.accountState.failNext += AccountStateWrite.Refused("forbidden")
        val refused = k.bed.logs.answerIncoming(k.verdict() as Adoption.AskAccept, accept = true)
        assertTrue(refused is Adoption.AskAccept, "refused: the question stands: $refused")
        assertTrue(k.bed.logs.answerIncoming(k.verdict() as Adoption.AskAccept, accept = true) is Adoption.Adopted, "taken")
        k.sync()
        val doc = k.bed.accountState.doc
        k.bed.accountState.doc = doc.copy(seq = doc.seq + 1, accepted = doc.accepted - k.v)
        val here = k.verdict()
        val fresh = k.bed.logsAfterRestart()
        val there = fresh.adoption(k.v)
        assertEquals(there::class, here::class, "the same verdict here and in a fresh engine")
        assertEquals(fresh.heldWhileMemberAgain(k.v), k.bed.logs.heldWhileMemberAgain(k.v), "after an adoption: as an engine that never saw the refusal ($here)")
    }

    /**
     * A person removed and not added again: the kept copy opens, lists and copies out as it always did, until its day; on
     * its day it goes from the device.
     */
    @Test
    fun removedAndNotAddedAgainTheCopyOpensListsCopiesOutAndGoesOnItsDay() = runBlocking<Unit> {
        val k = removed()
        k.assertOpen("removed")
        k.r.now = k.day - 1
        k.r.engine.sync()
        k.assertOpen("the day before its day")
        assertEquals(1, k.r.engine.rescueHeldToPersonal(k.v).ok().copied, "copying out works")
        k.r.now = k.day
        k.r.engine.sync()
        assertEquals(null, k.held(), "on its day the copy goes")
        k.assertNotLive("on its day")
    }

    /** "Remove from this device" works for a person removed and not added again. */
    @Test
    fun removedAndNotAddedAgainRemoveFromThisDeviceWorks() = runBlocking<Unit> {
        val k = removed()
        k.r.engine.removeFromDevice(k.v).ok()
        assertEquals(null, k.held(), "removed from this device")
    }
}
