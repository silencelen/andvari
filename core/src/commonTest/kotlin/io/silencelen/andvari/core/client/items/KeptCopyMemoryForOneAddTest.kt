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
import kotlin.test.assertTrue

/**
 * What this device remembers of an invitation to a vault whose kept copy it holds (decided on 24 November 2026): that it
 * shows the invitation, and that the server refused the answer to it, is remembered for ONE add of this account, named by
 * that add's place in the vault's log, and counts only while that add is the account's latest add in the verified log.
 * So a refused answer keeps the copy open for its add whatever the syncs after it bring; an invitation shown for an
 * earlier add closes nothing for a later one; and a refusal remembered for one add opens nothing for a later one.
 *
 * Real: the item engine and its store, and the trust engine behind [SessionVaultKeys] on a stand-in log server and a
 * stand-in account state, with the clock the test drives. Stand-in: the item server ([FakeItemServer]).
 */
class KeptCopyMemoryForOneAddTest {
    private class Asked(val bed: TrustBed, val s: TrustBed.Shared, val day: Long, val addSeq: Long) {
        val r: ItemRig get() = bed.rig
        val v: String get() = s.vaultId
        fun held(): HeldVaultView = r.engine.heldVaults().single { it.vaultId == v }
        fun verdict(): Adoption = runBlocking { bed.logs.adoption(v) }

        /** The server serves the vault's row, and the engine syncs (the adoption rules run in it). */
        fun sync() = runBlocking {
            r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(bed.vaultRow(s))))
            r.engine.sync()
        }

        /** An ordinary kept copy: it opens, with the ordinary line and its day, and it is no vault the account may use. */
        fun assertOpen(what: String) {
            val h = held()
            assertTrue(h.readable && !h.addedAgain, "$what: open (readable ${h.readable}, addedAgain ${h.addedAgain})")
            assertEquals(day, h.expungeAt, "$what: its day")
            assertEquals(listOf("wifi"), r.engine.heldItems(v).map { it.doc.name }, "$what: its items read")
            assertTrue(r.engine.vaults().none { it.vaultId == v }, "$what: not a vault the account may use")
            assertTrue(r.engine.items().none { it.vaultId == v }, "$what: no item of it among the account's items")
        }

        fun assertClosed(what: String) {
            val h = held()
            assertTrue(!h.readable && h.addedAgain, "$what: closed (readable ${h.readable}, addedAgain ${h.addedAgain})")
            assertEquals(day, h.expungeAt, "$what: its day")
            assertTrue(r.engine.vaults().none { it.vaultId == v }, "$what: not a vault the account may use")
        }
    }

    /** Shared with `wifi`; the person is removed (the copy kept); three days on the owner adds them again: asked, closed. */
    private fun asked(): Asked = runBlocking {
        val bed = TrustBed()
        val r = bed.rig
        val s = bed.share { listOf(bed.row(it, r.id(), "wifi", 7)) }
        bed.removeMe(s)
        r.engine.sync().ok()
        val day = r.engine.heldVaults().single { it.vaultId == s.vaultId }.expungeAt
        r.now += 3 * DAY
        check(bed.owner.append(s.vaultId, LogAction.Add(r.userId, "writer")) is AppendOutcome.Appended)
        bed.logs.refresh(s.vaultId, null, null, force = true)
        r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(bed.vaultRow(s)), grants = listOf(bed.grantRow(s))))
        r.engine.sync().ok()
        val ask = bed.logs.adoption(s.vaultId) as Adoption.AskAccept
        Asked(bed, s, day, ask.addSeq).also { it.assertClosed("asked") }
    }

    private fun Asked.refuseTheAnswer(accept: Boolean) = runBlocking {
        bed.accountState.failNext += AccountStateWrite.Refused("forbidden")
        val r = bed.logs.answerIncoming(verdict() as Adoption.AskAccept, accept)
        assertTrue(r is Adoption.AskAccept, "refused: the question stands: $r")
    }

    private fun Asked.serveGrant(grant: SyncGrant?) {
        if (grant == null) bed.logServer.grants.remove(v to r.userId) else bed.logServer.grants[v to r.userId] = grant
    }

    private fun SyncGrant.thatDoesNotVerify(): SyncGrant = copy(signedGrant = Bytes.toB64(ByteArray(96) { 1 }))

    /**
     * After an answer that the server refused, the copy stays open for that add, whatever the syncs after it bring: an
     * answer without the person's grant, an answer with a grant that does not verify, an answer that asks again. Three
     * rounds of that: the copy is never closed again, and the invitation is still there to be answered.
     */
    @Test
    fun aRefusedAnswerKeepsTheCopyOpenForItsAddWhateverTheSyncsAfterItBring() = runBlocking<Unit> {
        val a = asked()
        a.refuseTheAnswer(accept = true)
        a.assertOpen("after the refused answer")
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
            val again = a.verdict()
            assertTrue(again is Adoption.AskAccept && again.addSeq == a.addSeq, "$round, the grant served again: the same add is asked: $again")
            a.assertOpen("$round, the same add asked again")
        }
        val answered = a.bed.logs.answerIncoming(a.verdict() as Adoption.AskAccept, accept = false)
        assertTrue(answered is Adoption.Declined, "the invitation is still there to be answered: $answered")
        a.assertOpen("declined")
    }

    /**
     * An invitation shown for an earlier add closes nothing for a later one: asked, then withdrawn, then added once more
     * with a grant that this device cannot use. The copy is open when the log's news arrives (before any adoption pass
     * has looked at the new add), and stays open after the next adoption pass.
     */
    @Test
    fun anInvitationShownForAnEarlierAddClosesNothingForALaterOne() = runBlocking<Unit> {
        val a = asked()
        a.r.now += 1000
        check(a.bed.owner.append(a.v, LogAction.Remove(a.r.userId)) is AppendOutcome.Appended)
        a.bed.logs.refresh(a.v, null, null, force = true)
        a.sync()
        a.assertOpen("withdrawn")
        a.r.now += 1000
        check(a.bed.owner.append(a.v, LogAction.Add(a.r.userId, "writer")) is AppendOutcome.Appended)
        a.serveGrant(a.bed.grantRow(a.s).thatDoesNotVerify())
        a.bed.logs.refresh(a.v, null, null, force = true)
        a.assertOpen("added once more, when the log's news arrives")
        a.sync()
        assertEquals(Adoption.Refused(a.v, AdoptionRefusal.GRANT_REFUSED), a.verdict(), "the later add cannot be answered here")
        a.assertOpen("added once more, after the next adoption pass")
    }

    /**
     * A refusal remembered for one add opens nothing for a later one: the answer refused, then the person removed and
     * added again with an invitation they can answer. The new add is asked, and the copy is closed.
     */
    @Test
    fun aRefusalRememberedForOneAddOpensNothingForALaterOne() = runBlocking<Unit> {
        val a = asked()
        a.refuseTheAnswer(accept = false)
        a.assertOpen("refused")
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
        a.assertClosed("a new add after a refused answer")
    }

    /** The memory of a refusal ends when its vault is adopted: a refused answer given again and taken adopts the vault. */
    @Test
    fun aRefusedAnswerGivenAgainAndTakenAdoptsTheVault() = runBlocking<Unit> {
        val a = asked()
        a.refuseTheAnswer(accept = true)
        a.assertOpen("refused")
        a.sync()
        a.assertOpen("refused, after a sync")
        val taken = a.bed.logs.answerIncoming(a.verdict() as Adoption.AskAccept, accept = true)
        assertTrue(taken is Adoption.Adopted, "the second answer is taken: $taken")
        a.r.server.queue.add(a.r.response(a.r.server.rev + 1, vaults = listOf(a.bed.vaultRow(a.s)), grants = listOf(a.bed.grantRow(a.s)),
            items = listOf(a.bed.row(a.s, a.r.id(), "served after the acceptance", a.r.server.rev + 1))))
        a.r.engine.sync().ok()
        assertTrue(a.r.engine.vaults().any { it.vaultId == a.v }, "the vault is the account's again")
        assertTrue(a.r.engine.heldVaults().none { it.vaultId == a.v }, "the kept copy went with the acceptance")
        assertTrue(a.r.engine.items().any { it.vaultId == a.v && it.doc.name == "served after the acceptance" }, "with its items")
    }

    /** The memory of a refusal ends with the program: a trust engine started afresh closes the copy again once it asks. */
    @Test
    fun aRefusalIsForgottenWithTheProgram() = runBlocking<Unit> {
        val a = asked()
        a.refuseTheAnswer(accept = true)
        a.assertOpen("refused")
        val fresh = a.bed.logsAfterRestart()
        assertTrue(fresh.adoption(a.v) is Adoption.AskAccept, "after a start, online, the adoption rules ask again")
        assertTrue(!fresh.copyOutAllowed(a.v) && fresh.heldWhileMemberAgain(a.v), "and the copy is closed again")
        assertTrue(!fresh.adoptionSettled(a.v), "the held key gives no access")
    }
}
