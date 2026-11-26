package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.client.items.ItemEngine
import io.silencelen.andvari.core.client.items.ItemNotice
import io.silencelen.andvari.core.client.items.ItemResult
import io.silencelen.andvari.core.client.items.ItemRig
import io.silencelen.andvari.core.client.items.TrustBed
import io.silencelen.andvari.core.client.items.TrustBed.Companion.DAY
import io.silencelen.andvari.core.client.items.ok
import io.silencelen.andvari.core.client.log.Adoption
import io.silencelen.andvari.core.client.log.AdoptionRefusal
import io.silencelen.andvari.core.client.log.AppendOutcome
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.log.VaultLogStatus
import io.silencelen.andvari.core.client.state.AcceptedRecord
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A kept copy of a vault the person was removed from, added again before its day: the copy is closed exactly while this
 * device holds an invitation its person can answer now (decided on 23 November 2026). In every other state of being
 * added again it stays an ordinary kept copy: it opens, its ordinary line shows with its day, copying out works, and
 * nothing is written or sent into the vault. Two attacks it closes: a hostile owner who adds a removed person again with
 * a grant that does not open, and a server that withholds the grant row of an honest add, could each close a copy that
 * lies on the device until its day. The other direction counts as much: with an answerable invitation the copy is
 * closed.
 *
 * Real: the content layer over the item engine and the trust engine on a stand-in log server ([TrustBed]), with the
 * clock the test drives. Stand-in: the item server, and the session host.
 */
class KeptCopyClosedWhileAskedTest {
    private class Host(val r: ItemRig, val invitation: (String) -> String?) : ContentHost {
        override fun timeZone(): kotlinx.datetime.TimeZone = kotlinx.datetime.TimeZone.UTC
        override fun wallMs(): Long = r.now
        override fun attachmentLimits() = AttachmentRules.limits(null, null)
        override fun origin(): String = "https://vault.example.com"
        override fun userId(): String = r.userId
        override fun accountId(): String = "0123456789abcdef0123456789abcdef"
        override fun backupKdfParams(): KdfParams? = null
        override fun openInvitationName(vaultId: String): String? = invitation(vaultId)
    }

    /** The open invitation as the trust engine answers it, the way the shared vaults' part keeps it. */
    private fun TrustBed.askedName(vaultId: String): String? = runBlocking { (logs.adoption(vaultId) as? Adoption.AskAccept)?.vaultName }

    private class Bed(val bed: TrustBed, val c: EngineVaultContent, val s: TrustBed.Shared, val t0: Long) {
        val r: ItemRig get() = bed.rig
        val v: String get() = s.vaultId
    }

    /**
     * Shared with `wifi`, removed (the copy is held from t0); on day 15 [beforeAdd] runs, the owner adds the person again,
     * [afterAdd] runs, and the server serves the vault and the grant again at the content's refresh.
     */
    private fun addedAgain(beforeAdd: TrustBed.() -> Unit = {}, afterAdd: TrustBed.(TrustBed.Shared) -> Unit = {}): Bed = runBlocking {
        val bed = TrustBed()
        val r = bed.rig
        val c = EngineVaultContent(r.engine, r.crypto, Host(r) { id -> bed.askedName(id) })
        val s = bed.share { listOf(bed.row(it, r.id(), "wifi", 7)) }
        bed.removeMe(s)
        val t0 = r.now
        r.engine.sync().ok()
        c.refresh()
        r.now = t0 + 15 * DAY
        bed.beforeAdd()
        check(bed.owner.append(s.vaultId, LogAction.Add(r.userId, "writer")) is AppendOutcome.Appended)
        bed.afterAdd(s)
        bed.logs.refresh(s.vaultId, null, null, force = true)
        r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(bed.vaultRow(s)), grants = listOf(bed.grantRow(s))))
        c.refresh()
        Bed(bed, c, s, t0)
    }

    /** The ordinary kept copy: the entry, the engine, copying out, and nothing written or sent into the vault. */
    private fun Bed.assertOrdinary(state: String) = runBlocking {
        val row = c.state.held.single()
        assertEquals(ContentCopy.heldLine(ItemNotice.REMOVED, t0 + ItemEngine.HOLDING_MS), row.line, "$state: the ordinary line with its day")
        assertTrue(row.readable, "$state: the copy opens")
        assertEquals("Family", row.name, "$state: the kept copy's own name")
        val held = r.engine.heldVaults().single { it.vaultId == v }
        assertTrue(held.readable && !held.addedAgain, "$state: the engine's view is an ordinary kept copy")
        assertEquals(t0 + ItemEngine.HOLDING_MS, held.expungeAt, "$state: its day")
        assertEquals(listOf("wifi"), r.engine.heldItems(v).map { it.doc.name }, "$state: its items")
        val pushes = r.server.pushes.size
        assertTrue(r.engine.save(null, r.doc.copy(name = "new"), v) is ItemResult.Failed, "$state: a save into the vault fails")
        assertEquals(1, r.engine.rescueHeldToPersonal(v).ok().copied, "$state: copying out works")
        r.engine.sync()
        assertTrue(r.server.pushes.drop(pushes).flatten().none { it.vaultId == v }, "$state: nothing is sent into the vault")
        assertTrue(r.engine.vaults().none { it.vaultId == v }, "$state: the held key gives no access to the vault")
    }

    private fun Bed.verdict(): Adoption = runBlocking { bed.logs.adoption(v) }

    @Test
    fun aGrantThatDoesNotOpenLeavesTheKeptCopyOpen() {
        val b = addedAgain(afterAdd = { s ->
            val g = logServer.grants.getValue(s.vaultId to rig.userId)
            logServer.grants[s.vaultId to rig.userId] = g.copy(signedGrant = Bytes.toB64(ByteArray(96) { 1 }))
        })
        assertEquals(Adoption.Refused(b.v, AdoptionRefusal.GRANT_REFUSED), b.verdict())
        b.assertOrdinary("grant refused")
    }

    @Test
    fun anAddByAnOwnerWhoIsNotACurrentContactLeavesTheKeptCopyOpen() {
        val b = addedAgain(beforeAdd = { contacts.remove(ownerId) })
        assertTrue(b.verdict() is Adoption.ConnectFirst, "connect first: ${b.verdict()}")
        b.assertOrdinary("connect first")
    }

    @Test
    fun aDeclineWhoseLeaveIsNotInTheLogYetLeavesTheKeptCopyOpen() = runBlocking<Unit> {
        val b = addedAgain()
        val ask = b.verdict() as Adoption.AskAccept
        b.bed.logServer.appendsUnanswered += b.v
        assertTrue(b.bed.logs.answerIncoming(ask, accept = false) is Adoption.Declined)
        b.r.server.queue.add(b.r.response(b.r.server.rev + 1, vaults = listOf(b.bed.vaultRow(b.s)), grants = listOf(b.bed.grantRow(b.s))))
        b.c.refresh()
        assertTrue(b.bed.logs.status(b.v).let { it is VaultLogStatus.Verified && b.r.userId in it.state.members }, "the leave is not in the log")
        b.assertOrdinary("declined, leave not in the log")
    }

    @Test
    fun acceptedOnAnotherDeviceAndNotYetTakenHereTheKeptCopyIsOpen() = runBlocking<Unit> {
        val b = addedAgain()
        check(b.c.state.held.single().line.startsWith("You were added to")) { "asked first: ${b.c.state.held.single().line}" }
        val addSeq = (b.bed.logs.status(b.v) as VaultLogStatus.Verified).state.members.getValue(b.r.userId).addSeq ?: error("the add's position")
        b.bed.accountState.update { it.copy(accepted = it.accepted + (b.v to AcceptedRecord(b.v, b.bed.ownerId, addSeq, b.r.now, AcceptedRecord.ACCEPT))) }
        b.c.refreshHealth()
        val row = b.c.state.held.single()
        assertEquals(ContentCopy.heldLine(ItemNotice.REMOVED, b.t0 + ItemEngine.HOLDING_MS), row.line, "the ordinary line with its day")
        assertTrue(row.readable, "the copy opens")
        assertEquals(listOf("wifi"), b.r.engine.heldItems(b.v).map { it.doc.name }, "its items")
        assertEquals(1, b.r.engine.rescueHeldToPersonal(b.v).ok().copied, "copying out works")
    }

    @Test
    fun anotherRefusalLeavesTheKeptCopyOpen() {
        val b = addedAgain(afterAdd = { s ->
            val g = logServer.grants.getValue(s.vaultId to rig.userId)
            logServer.grants[s.vaultId to rig.userId] = g.copy(signedGrant = null)
        })
        assertTrue(b.verdict() is Adoption.Refused, "another refusal: ${b.verdict()}")
        b.assertOrdinary("another refusal")
    }

    /** With an invitation its person can answer now the copy is closed, and the entry says so with the owner's sentence. */
    @Test
    fun withAnInvitationThatCanBeAnsweredTheKeptCopyIsClosedWithItsLine() = runBlocking<Unit> {
        val b = addedAgain()
        assertTrue(b.verdict() is Adoption.AskAccept)
        val row = b.c.state.held.single()
        assertEquals(addedAgainSentence("Family", ContentCopy.day(b.t0 + ItemEngine.HOLDING_MS)), row.line)
        assertEquals("Family", row.name, "the open invitation's name")
        assertTrue(!row.readable, "the copy does not open")
        assertTrue(b.r.engine.heldVaults().single { it.vaultId == b.v }.addedAgain, "the engine's view says added again")
        assertEquals(b.t0 + ItemEngine.HOLDING_MS, b.r.engine.heldVaults().single { it.vaultId == b.v }.expungeAt, "its day")
        assertEquals(emptyList(), b.r.engine.heldItems(b.v).map { it.doc.name })
        val pushes = b.r.server.pushes.size
        assertTrue(b.r.engine.rescueHeldToPersonal(b.v) is ItemResult.Failed, "nothing can be copied out")
        assertEquals(pushes, b.r.server.pushes.size)
        assertTrue(b.r.engine.vaults().none { it.vaultId == b.v }, "the vault is not this person's until they accept")
    }
}
