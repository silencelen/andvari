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
 * Orders of answers a server can give around an invitation to a vault whose kept copy this device holds. After a refused
 * answer, no order closes the copy again for the same add: an answer whose outcome is not known, adoption passes with no
 * sync between, connect first, the log served behind. A refusal remembered for one add opens nothing for a later add, and
 * neither does an adoption: each new add is asked afresh and closes the copy. In every state the vault is no vault the
 * account may use unless it was adopted.
 *
 * Real: the item engine and its store, and the trust engine behind [SessionVaultKeys] on a stand-in log server and a
 * stand-in account state, with the clock the test drives. Stand-in: the item server ([FakeItemServer]).
 */
class KeptCopyOrdersOfAnswersTest {
    private class Asked(val bed: TrustBed, val s: TrustBed.Shared, val day: Long) {
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
            assertNotLive(what)
        }

        fun assertClosed(what: String) {
            val h = held()
            assertTrue(!h.readable && h.addedAgain, "$what: closed (readable ${h.readable}, addedAgain ${h.addedAgain})")
            assertEquals(day, h.expungeAt, "$what: its day")
            assertNotLive(what)
        }

        fun assertNotLive(what: String) {
            assertTrue(r.engine.vaults().none { it.vaultId == v }, "$what: not a vault the account may use")
            assertTrue(r.engine.items().none { it.vaultId == v }, "$what: no item of it among the account's items")
        }

        /** The person answers; the account state refuses the write: the question stands. */
        fun refuseTheAnswer(accept: Boolean) = runBlocking {
            bed.accountState.failNext += AccountStateWrite.Refused("forbidden")
            val res = bed.logs.answerIncoming(verdict() as Adoption.AskAccept, accept)
            assertTrue(res is Adoption.AskAccept, "refused: the question stands: $res")
        }

        /** The owner removes the person; the device verifies the removal and syncs. */
        fun removeAndVerify() = runBlocking {
            r.now += 1000
            check(bed.owner.append(v, LogAction.Remove(r.userId)) is AppendOutcome.Appended)
            bed.logs.refresh(v, null, null, force = true)
            sync()
        }

        /** The owner adds the person again; the device verifies the add and syncs. */
        fun addAndVerify() = runBlocking {
            r.now += 1000
            check(bed.owner.append(v, LogAction.Add(r.userId, "writer")) is AppendOutcome.Appended)
            bed.logs.refresh(v, null, null, force = true)
            sync()
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
        Asked(bed, s, day).also {
            assertTrue(it.verdict() is Adoption.AskAccept, "asked")
            it.assertClosed("asked")
        }
    }

    /** Refused, then answered again with an outcome not known, then the same add asked again: open throughout. */
    @Test
    fun aRefusedAnswerThenAnAnswerNotKnownThenTheSameAddAskedAgainKeepsTheCopyOpen() = runBlocking<Unit> {
        val a = asked()
        val addSeq = (a.verdict() as Adoption.AskAccept).addSeq
        a.refuseTheAnswer(accept = true)
        a.assertOpen("refused")
        a.bed.accountState.failNext += AccountStateWrite.Unknown
        val r = a.bed.logs.answerIncoming(a.verdict() as Adoption.AskAccept, accept = true)
        assertTrue(r is Adoption.AnswerNotKnown, "answered again, not known: $r")
        a.assertOpen("answered again, not known")
        a.sync()
        val again = a.verdict()
        assertTrue(again is Adoption.AskAccept && again.addSeq == addSeq, "the same add asked again: $again")
        a.assertOpen("asked again after an answer not known")
    }

    /** Refused, then two adoption passes with no sync between: open. */
    @Test
    fun aRefusedAnswerThenTwoAdoptionPassesWithoutASyncKeepsTheCopyOpen() = runBlocking<Unit> {
        val a = asked()
        a.refuseTheAnswer(accept = false)
        repeat(2) { assertTrue(a.verdict() is Adoption.AskAccept, "pass ${it + 1}: asked") }
        a.assertOpen("two passes after a refusal")
    }

    /** Refused, then the owner not a current contact (connect first), then a contact again: open throughout. */
    @Test
    fun aRefusedAnswerThenConnectFirstThenAContactAgainKeepsTheCopyOpen() = runBlocking<Unit> {
        val a = asked()
        a.refuseTheAnswer(accept = true)
        val key = a.bed.contacts.remove(a.bed.ownerId)!!
        a.sync()
        assertTrue(a.verdict() is Adoption.ConnectFirst, "connect first: ${a.verdict()}")
        a.assertOpen("connect first after a refusal")
        a.bed.contacts[a.bed.ownerId] = key
        a.sync()
        assertTrue(a.verdict() is Adoption.AskAccept, "a contact again: asked")
        a.assertOpen("a contact again after a refusal")
    }

    /** Refused, then the log served one entry behind, then served whole again: open throughout. */
    @Test
    fun aRefusedAnswerThenTheLogServedBehindThenWholeKeepsTheCopyOpen() = runBlocking<Unit> {
        val a = asked()
        a.refuseTheAnswer(accept = true)
        val log = a.bed.logServer.logs.getValue(a.v)
        val full = log.toList()
        log.removeAt(log.size - 1)
        a.bed.logs.refresh(a.v, null, null, force = true)
        a.sync()
        a.assertOpen("the log served behind (${a.bed.logs.status(a.v)}, ${a.verdict()})")
        log.clear()
        log.addAll(full)
        a.bed.logs.refresh(a.v, null, null, force = true)
        a.sync()
        assertTrue(a.verdict() is Adoption.AskAccept, "whole again: asked")
        a.assertOpen("the log whole again")
    }

    /** Two adds, each refused in turn, then a third: each new add closes, each refusal opens for its own add only. */
    @Test
    fun refusalsForTwoAddsInTurnThenAThirdAddEachNewAddIsAskedAfresh() = runBlocking<Unit> {
        val a = asked()
        a.refuseTheAnswer(accept = true)
        a.assertOpen("first add refused")
        a.removeAndVerify()
        a.assertOpen("removed")
        a.addAndVerify()
        a.assertClosed("second add asked")
        a.refuseTheAnswer(accept = false)
        a.assertOpen("second add refused")
        a.removeAndVerify()
        a.addAndVerify()
        a.assertClosed("third add asked")
    }

    /** Asked, the answer taken, removed again and added again: the new add is asked and closes the new kept copy. */
    @Test
    fun adoptedThenRemovedAndAddedAgainTheNewAddClosesTheNewKeptCopy() = runBlocking<Unit> {
        val a = asked()
        a.refuseTheAnswer(accept = true)
        assertTrue(a.bed.logs.answerIncoming(a.verdict() as Adoption.AskAccept, accept = true) is Adoption.Adopted, "taken")
        a.r.server.queue.add(a.r.response(a.r.server.rev + 1, vaults = listOf(a.bed.vaultRow(a.s)), grants = listOf(a.bed.grantRow(a.s)),
            items = listOf(a.bed.row(a.s, a.r.id(), "served after the acceptance", a.r.server.rev + 1))))
        a.r.engine.sync().ok()
        check(a.r.engine.vaults().any { it.vaultId == a.v }) { "adopted" }
        a.bed.removeMe(a.s)
        a.r.engine.sync().ok()
        val second = Asked(a.bed, a.s, a.r.engine.heldVaults().single { it.vaultId == a.v }.expungeAt)
        val h1 = second.held()
        assertTrue(h1.readable && !h1.addedAgain, "removed after the adoption: open (readable ${h1.readable}, addedAgain ${h1.addedAgain})")
        second.assertNotLive("removed after the adoption")
        second.addAndVerify()
        assertTrue(second.verdict() is Adoption.AskAccept, "the new add is asked")
        second.assertClosed("the new add after an adoption")
    }
}
