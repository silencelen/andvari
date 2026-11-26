package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.items.TrustBed.Companion.DAY
import io.silencelen.andvari.core.client.log.Adoption
import io.silencelen.andvari.core.client.log.AppendOutcome
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.state.AccountStateWrite
import io.silencelen.andvari.core.model.wire.SyncItem
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A server that refuses the answer cannot keep the kept copy closed (decided on 23 November 2026). The copy of a vault its
 * person was removed from is closed while this device holds an invitation to it that the person can answer now. An
 * answer whose write the server refuses (or keeps meeting newer writes) does not close it: from that answer on, in this
 * run of the program, the copy is open as in any other state, with its ordinary line and its day, and copying out works.
 * The invitation stays to be answered again, and a second answer that the server takes brings the vault back as before.
 *
 * Real: the item engine and its store, and the trust engine ([io.silencelen.andvari.core.client.log.StoredVaultLogs]
 * behind [SessionVaultKeys]) on a stand-in log server and a stand-in account state, with the clock the test drives.
 */
class RefusedAnswerOpensKeptCopyTest {
    private class Asked(val bed: TrustBed, val s: TrustBed.Shared, val day: Long, val rows: List<SyncItem>)

    /** Shared with `wifi`; the person is removed (the copy kept); three days on the owner adds them again: closed. */
    private fun asked(): Asked = runBlocking {
        val bed = TrustBed()
        val r = bed.rig
        lateinit var rows: List<SyncItem>
        val s = bed.share { rows = listOf(bed.row(it, r.id(), "wifi", 7)); rows }
        bed.removeMe(s)
        r.engine.sync().ok()
        val day = r.engine.heldVaults().single { it.vaultId == s.vaultId }.expungeAt
        r.now += 3 * DAY
        check(bed.owner.append(s.vaultId, LogAction.Add(r.userId, "writer")) is AppendOutcome.Appended)
        bed.logs.refresh(s.vaultId, null, null, force = true)
        r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(bed.vaultRow(s)), grants = listOf(bed.grantRow(s))))
        r.engine.sync().ok()
        val h = r.engine.heldVaults().single { it.vaultId == s.vaultId }
        check(h.addedAgain && !h.readable) { "asked: the copy is closed" }
        Asked(bed, s, day, rows)
    }

    private fun Asked.ask(): Adoption.AskAccept = runBlocking { bed.logs.adoption(s.vaultId) as Adoption.AskAccept }

    /** Open, with the ordinary line (not "added again"), the same day, and copying out works. */
    private fun Asked.openAsAnyKeptCopy(what: String) = runBlocking {
        val r = bed.rig
        val h = r.engine.heldVaults().single { it.vaultId == s.vaultId }
        assertTrue(h.readable && !h.addedAgain, "$what: open, with the ordinary line (readable ${h.readable}, added again ${h.addedAgain})")
        assertEquals(day, h.expungeAt, "$what: the same day")
        assertEquals(listOf("wifi"), r.engine.heldItems(s.vaultId).map { it.doc.name }, "$what: its items read")
        assertEquals(1, r.engine.rescueHeldToPersonal(s.vaultId).ok().copied, "$what: copying out works")
        assertTrue(r.engine.vaults().none { it.vaultId == s.vaultId }, "$what: the held key gives no access to the vault")
    }

    /** The server takes the answer: the vault comes back with its rows. */
    private fun Asked.adoptedWithItsRows() = runBlocking {
        val r = bed.rig
        r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(bed.vaultRow(s)), grants = listOf(bed.grantRow(s)), items = rows))
        r.engine.sync().ok()
        assertTrue(r.engine.vaults().any { it.vaultId == s.vaultId }, "the vault is this person's again")
        assertTrue(r.engine.items().any { it.vaultId == s.vaultId && it.doc.name == "wifi" }, "with its items")
    }

    @Test
    fun anAcceptanceTheServerRefusesOpensTheCopyAndASecondOneThatItTakesAdoptsTheVault() = runBlocking<Unit> {
        val a = asked()
        a.bed.accountState.failNext += AccountStateWrite.Refused("forbidden")
        val first = a.bed.logs.answerIncoming(a.ask(), accept = true)
        assertTrue(first is Adoption.AskAccept, "the question stands: $first")
        a.openAsAnyKeptCopy("after a refused acceptance")
        val again = a.bed.logs.answerIncoming(a.ask(), accept = true)
        assertTrue(again is Adoption.Adopted, "the second acceptance is taken: $again")
        a.adoptedWithItsRows()
    }

    @Test
    fun aDeclineTheServerRefusesOpensTheCopyAndASecondOneThatItTakesIsADecline() = runBlocking<Unit> {
        val a = asked()
        a.bed.accountState.failNext += AccountStateWrite.Refused("forbidden")
        val first = a.bed.logs.answerIncoming(a.ask(), accept = false)
        assertTrue(first is Adoption.AskAccept, "the question stands: $first")
        a.openAsAnyKeptCopy("after a refused decline")
        val again = a.bed.logs.answerIncoming(a.ask(), accept = false)
        assertTrue(again is Adoption.Declined, "the second decline is taken: $again")
        a.openAsAnyKeptCopy("after the decline")
    }

    @Test
    fun anAcceptanceThatMeetsNewerWritesOnceOpensTheCopyAndIsTakenTheSecondTime() = runBlocking<Unit> {
        val a = asked()
        a.bed.accountState.failNext += AccountStateWrite.Contended
        val first = a.bed.logs.answerIncoming(a.ask(), accept = true)
        assertTrue(first is Adoption.AskAccept, "the question stands: $first")
        a.openAsAnyKeptCopy("after a contended acceptance")
        val again = a.bed.logs.answerIncoming(a.ask(), accept = true)
        assertTrue(again is Adoption.Adopted, "taken the second time: $again")
        a.adoptedWithItsRows()
    }

    /** A refused answer stays open across the sync after it: the adoption rules run again and ask again, the copy stays open. */
    @Test
    fun aRefusedAnswerKeepsTheCopyOpenAcrossTheNextSync() = runBlocking<Unit> {
        val a = asked()
        val r = a.bed.rig
        a.bed.accountState.failNext += AccountStateWrite.Refused("forbidden")
        a.bed.logs.answerIncoming(a.ask(), accept = true)
        r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(a.bed.vaultRow(a.s)), grants = listOf(a.bed.grantRow(a.s))))
        r.engine.sync().ok()
        assertTrue(a.bed.logs.adoption(a.s.vaultId) is Adoption.AskAccept, "the invitation stays to be answered")
        a.openAsAnyKeptCopy("after the next sync")
    }

    /**
     * A server that withholds this account's new grant row while the log names it a member again: nothing can be answered
     * here, so the copy stays open with its day; served, the invitation closes it.
     */
    @Test
    fun aGrantRowWithheldDoesNotCloseTheCopy() = runBlocking<Unit> {
        val bed = TrustBed()
        val r = bed.rig
        val s = bed.share { listOf(bed.row(it, r.id(), "wifi", 7)) }
        bed.removeMe(s)
        r.engine.sync().ok()
        val day = r.engine.heldVaults().single { it.vaultId == s.vaultId }.expungeAt
        r.now += 3 * DAY
        check(bed.owner.append(s.vaultId, LogAction.Add(r.userId, "writer")) is AppendOutcome.Appended)
        val grant = bed.logServer.grants.remove(s.vaultId to r.userId)!!
        bed.logs.refresh(s.vaultId, null, null, force = true)
        r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(bed.vaultRow(s))))
        r.engine.sync().ok()
        val withheld = r.engine.heldVaults().single { it.vaultId == s.vaultId }
        assertTrue(withheld.readable && !withheld.addedAgain && withheld.expungeAt == day, "grant withheld: an ordinary kept copy with its day")
        bed.logServer.grants[s.vaultId to r.userId] = grant
        r.server.queue.add(r.response(r.server.rev + 1, grants = listOf(grant)))
        r.engine.sync().ok()
        val asked = r.engine.heldVaults().single { it.vaultId == s.vaultId }
        assertTrue(asked.addedAgain && !asked.readable && asked.expungeAt == day, "grant served: asked, closed, the same day")
    }

    /** Before any answer the copy is closed, as decided; an answer the server takes adopts at once, as before. */
    @Test
    fun withoutARefusalTheCopyIsClosedUntilTheAnswerAsBefore() = runBlocking<Unit> {
        val a = asked()
        val h = a.bed.rig.engine.heldVaults().single { it.vaultId == a.s.vaultId }
        assertTrue(h.addedAgain && !h.readable && h.expungeAt == a.day)
        assertTrue(a.bed.logs.answerIncoming(a.ask(), accept = true) is Adoption.Adopted)
        a.adoptedWithItsRows()
    }
}
