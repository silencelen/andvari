package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.items.TrustBed.Companion.DAY
import io.silencelen.andvari.core.client.log.Adoption
import io.silencelen.andvari.core.client.log.AdoptionRefusal
import io.silencelen.andvari.core.client.log.AppendOutcome
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.state.AccountStateWrite
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.SyncGrant
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * What this device remembers of a decline given to an invitation to a vault whose kept copy it holds (decided on
 * 24 November 2026): the decline keeps the copy open for the add it answered, as an answer the server refused does, and
 * the memory ends as that one's ends. An accept whose outcome is not known keeps the copy closed after the next sync,
 * and a decline after it opens the copy; whatever the syncs after a decline bring, the copy stays open for its add; a
 * later add is asked afresh and closes the copy; a trust engine started afresh remembers nothing; and an adoption ends
 * the memory. Each decline here is one whose record and leave are not known, so nothing but the memory opens the copy.
 *
 * Real: the item engine and its store, and the trust engine behind [SessionVaultKeys] on a stand-in log server and a
 * stand-in account state, with the clock the test drives. Stand-in: the item server ([FakeItemServer]).
 */
class KeptCopyDeclineMemoryTest {
    private class Asked(val bed: TrustBed, val s: TrustBed.Shared, val day: Long) {
        val r: ItemRig get() = bed.rig
        val v: String get() = s.vaultId
        var addSeq = -1L
        fun held(): HeldVaultView = assertNotNull(r.engine.heldVaults().singleOrNull { it.vaultId == v }, "the kept copy is there")
        fun verdict(): Adoption = runBlocking { bed.logs.adoption(v) }

        /** The server serves the vault's row, and the engine syncs (the adoption rules run in it). */
        fun sync() = runBlocking {
            r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(bed.vaultRow(s))))
            r.engine.sync()
        }

        fun assertNotLive(what: String) {
            assertTrue(r.engine.vaults().none { it.vaultId == v }, "$what: not a vault the account may use")
            assertTrue(r.engine.items().none { it.vaultId == v }, "$what: no item of it among the account's items")
        }

        /** An ordinary kept copy: it opens with its day, its items read, the engine's gate allows a copy-out. */
        fun assertOpen(what: String) {
            val h = held()
            assertTrue(h.readable && !h.addedAgain, "$what: open (readable ${h.readable}, addedAgain ${h.addedAgain})")
            assertEquals(day, h.expungeAt, "$what: its day")
            assertEquals(listOf("wifi"), r.engine.heldItems(v).map { it.doc.name }, "$what: its items read")
            assertTrue(bed.logs.copyOutAllowed(v), "$what: the engine's gate allows a copy-out")
            assertNotLive(what)
        }

        fun assertClosed(what: String) {
            val h = held()
            assertTrue(!h.readable && h.addedAgain, "$what: closed (readable ${h.readable}, addedAgain ${h.addedAgain})")
            assertEquals(day, h.expungeAt, "$what: its day")
            assertTrue(!bed.logs.copyOutAllowed(v), "$what: the engine's gate refuses a copy-out")
            assertNotLive(what)
        }

        fun assertAskedAgain(what: String) {
            val again = verdict()
            assertTrue(again is Adoption.AskAccept && again.addSeq == addSeq, "$what: asked again for the same add: $again")
        }

        /** A decline whose record's outcome is not known and whose leave the log server does not answer. */
        fun declineNotKnown(what: String) = runBlocking {
            bed.accountState.failNext += AccountStateWrite.Unknown
            bed.logServer.appendsUnanswered += v
            val res = bed.logs.answerIncoming(verdict() as Adoption.AskAccept, accept = false)
            assertEquals(Adoption.AnswerNotKnown(v, accepted = false, adopted = false), res, "$what: not known")
        }

        /** An accept whose record's outcome is not known. */
        fun acceptNotKnown(what: String) = runBlocking {
            bed.accountState.failNext += AccountStateWrite.Unknown
            val res = bed.logs.answerIncoming(verdict() as Adoption.AskAccept, accept = true)
            assertEquals(Adoption.AnswerNotKnown(v, accepted = true, adopted = false), res, "$what: not known")
        }

        fun serveGrant(grant: SyncGrant?) {
            if (grant == null) bed.logServer.grants.remove(v to r.userId) else bed.logServer.grants[v to r.userId] = grant
        }
    }

    private fun SyncGrant.thatDoesNotVerify(): SyncGrant = copy(signedGrant = Bytes.toB64(ByteArray(96) { 1 }))

    /**
     * Shared with `wifi`; the person is removed: the copy is kept, open, and the engine's gate allows a copy-out. Three
     * days on the owner adds them again: asked, closed.
     */
    private fun asked(): Asked = runBlocking {
        val bed = TrustBed()
        val r = bed.rig
        val s = bed.share { listOf(bed.row(it, r.id(), "wifi", 7)) }
        bed.removeMe(s)
        r.engine.sync().ok()
        val a = Asked(bed, s, r.engine.heldVaults().single { it.vaultId == s.vaultId }.expungeAt)
        a.assertOpen("removed")
        r.now += 3 * DAY
        check(bed.owner.append(s.vaultId, LogAction.Add(r.userId, "writer")) is AppendOutcome.Appended)
        bed.logs.refresh(s.vaultId, null, null, force = true)
        r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(bed.vaultRow(s)), grants = listOf(bed.grantRow(s))))
        r.engine.sync().ok()
        a.assertClosed("asked")
        a.addSeq = (a.verdict() as Adoption.AskAccept).addSeq
        a
    }

    /**
     * An accept whose outcome is not known keeps the copy closed after the next sync (decided on 24 November 2026: whether
     * it should open the copy is not built); a decline after it, whose record and leave are not known, opens the copy, and
     * three syncs later it is still open and the same add is still there to be answered.
     */
    @Test
    fun anAcceptNotKnownStaysClosedAndADeclineNotKnownAfterItOpensTheCopy() = runBlocking<Unit> {
        val a = asked()
        a.acceptNotKnown("the accept")
        a.assertOpen("the accept not known, before the next sync")
        a.sync()
        a.assertClosed("the accept not known, after the next sync")
        a.assertAskedAgain("the accept not known, after the next sync")
        a.declineNotKnown("the decline")
        a.assertOpen("the decline not known")
        repeat(3) { i ->
            a.sync()
            a.assertAskedAgain("the decline not known, sync ${i + 1}")
            a.assertOpen("the decline not known, sync ${i + 1}")
        }
    }

    /**
     * After a decline whose record and leave are not known, the copy stays open for that add whatever the syncs after it
     * bring: three rounds of an answer without the person's grant, an answer with a grant that does not verify, and an
     * answer that asks again; then the owner no current contact and a contact again; then an accept whose outcome is not
     * known. At the end an honest decline is taken.
     */
    @Test
    fun aDeclineNotKnownKeepsTheCopyOpenForItsAddWhateverTheSyncsAfterItBring() = runBlocking<Unit> {
        val a = asked()
        a.declineNotKnown("the decline")
        a.assertOpen("after the decline")
        val grant = a.bed.grantRow(a.s)
        repeat(3) { i ->
            val round = "round ${i + 1}"
            a.serveGrant(null)
            a.sync()
            assertTrue(a.verdict() is Adoption.Refused, "$round, the grant left out: a verdict that does not ask: ${a.verdict()}")
            a.assertOpen("$round, the grant left out")
            a.serveGrant(grant.thatDoesNotVerify())
            a.sync()
            assertEquals(Adoption.Refused(a.v, AdoptionRefusal.GRANT_REFUSED), a.verdict(), "$round, a grant that does not verify")
            a.assertOpen("$round, a grant that does not verify")
            a.serveGrant(grant)
            a.sync()
            a.assertAskedAgain("$round, the grant served again")
            a.assertOpen("$round, the same add asked again")
        }
        val key = a.bed.contacts.remove(a.bed.ownerId)!!
        a.sync()
        assertTrue(a.verdict() is Adoption.ConnectFirst, "connect first: ${a.verdict()}")
        a.assertOpen("connect first")
        a.bed.contacts[a.bed.ownerId] = key
        a.sync()
        a.assertAskedAgain("a contact again")
        a.assertOpen("a contact again")
        a.acceptNotKnown("an accept after the decline")
        a.assertOpen("an accept not known after the decline")
        a.sync()
        a.assertOpen("an accept not known after the decline, after a sync")
        a.bed.logServer.appendsUnanswered.clear()
        val answered = a.bed.logs.answerIncoming(a.verdict() as Adoption.AskAccept, accept = false)
        assertEquals(Adoption.Declined(a.v), answered, "an honest decline is taken")
        a.assertOpen("declined")
    }

    /**
     * A decline remembered for one add opens nothing for a later one: a decline not known, then the person removed and
     * added again with an invitation they can answer. The new add is asked, and the copy is closed.
     */
    @Test
    fun aDeclineRememberedForOneAddOpensNothingForALaterOne() = runBlocking<Unit> {
        val a = asked()
        a.declineNotKnown("the decline")
        a.assertOpen("the decline not known")
        a.bed.logServer.appendsUnanswered.clear()
        a.r.now += 1000
        check(a.bed.owner.append(a.v, LogAction.Remove(a.r.userId)) is AppendOutcome.Appended)
        a.bed.logs.refresh(a.v, null, null, force = true)
        a.sync()
        a.assertOpen("removed")
        a.r.now += 1000
        check(a.bed.owner.append(a.v, LogAction.Add(a.r.userId, "writer")) is AppendOutcome.Appended)
        a.bed.logs.refresh(a.v, null, null, force = true)
        a.r.server.queue.add(a.r.response(a.r.server.rev + 1, vaults = listOf(a.bed.vaultRow(a.s)), grants = listOf(a.bed.grantRow(a.s))))
        a.r.engine.sync()
        val again = a.verdict()
        assertTrue(again is Adoption.AskAccept && again.addSeq > a.addSeq, "the new add is asked: $again")
        a.assertClosed("a new add after a decline not known")
    }

    /** The memory of a decline ends with the program: a trust engine started afresh closes the copy again once it asks. */
    @Test
    fun aDeclineIsForgottenWithTheProgram() = runBlocking<Unit> {
        val a = asked()
        a.declineNotKnown("the decline")
        a.assertOpen("the decline not known")
        val fresh = a.bed.logsAfterRestart()
        assertTrue(fresh.adoption(a.v) is Adoption.AskAccept, "after a start, online, the adoption rules ask again")
        assertTrue(!fresh.copyOutAllowed(a.v) && fresh.heldWhileMemberAgain(a.v), "and the copy is closed again")
        assertTrue(!fresh.adoptionSettled(a.v), "the held key gives no access")
    }

    /**
     * An adoption ends what the engine remembers of a decline. A decline not known, then an accept with the server
     * honest, taken (adopted); the acceptance is then served away and the adoption rules are asked again directly: the
     * engine answers as a trust engine started afresh over the same state and asked the same, which closes the copy.
     */
    @Test
    fun afterAnAdoptionNoDeclineIsRememberedWhenTheAcceptanceIsServedAway() = runBlocking<Unit> {
        val a = asked()
        a.declineNotKnown("the decline")
        a.assertOpen("the decline not known")
        a.bed.logServer.appendsUnanswered.clear()
        val taken = a.bed.logs.answerIncoming(a.verdict() as Adoption.AskAccept, accept = true)
        assertTrue(taken is Adoption.Adopted, "the accept is taken: $taken")
        a.sync()
        val doc = a.bed.accountState.doc
        a.bed.accountState.doc = doc.copy(seq = doc.seq + 1, accepted = doc.accepted - a.v)
        val here = a.verdict()
        val fresh = a.bed.logsAfterRestart()
        val there = fresh.adoption(a.v)
        assertEquals(there::class, here::class, "the same verdict here and in a fresh engine")
        assertTrue(fresh.heldWhileMemberAgain(a.v), "a fresh engine asked so holds the copy closed ($there)")
        assertEquals(fresh.heldWhileMemberAgain(a.v), a.bed.logs.heldWhileMemberAgain(a.v), "after an adoption: as an engine that never saw the decline ($here)")
    }
}
