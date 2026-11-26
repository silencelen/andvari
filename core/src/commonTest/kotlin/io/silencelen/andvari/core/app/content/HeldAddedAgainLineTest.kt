package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.client.items.ItemEngine
import io.silencelen.andvari.core.client.items.ItemRig
import io.silencelen.andvari.core.client.items.TrustBed
import io.silencelen.andvari.core.client.items.TrustBed.Companion.DAY
import io.silencelen.andvari.core.client.items.ok
import io.silencelen.andvari.core.client.log.Adoption
import io.silencelen.andvari.core.client.log.AppendOutcome
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.crypto.KdfParams
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The approved sentence of a kept copy closed because its person was added again (decided on 22 November 2026), as a
 * person reads it: {0} the vault's name in its quotes, or the plain words "a vault" without them where no name is
 * known; {1} the day the copy goes.
 */
internal fun addedAgainSentence(vaultName: String?, day: String): String {
    val sentence = "You were added to “{0}” again. Until you accept, this device can't open the copy it kept. Accept before {1} to get it back. On that day it goes from this device."
    val named = if (vaultName == null) sentence.replace("“{0}”", "a vault") else sentence.replace("{0}", vaultName)
    return named.replace("{1}", day)
}

/**
 * The entry of a held vault on the "Recently removed" surface while the account was added to it again and has not
 * answered (decided on 22 November 2026): the approved sentence, with the vault's name and the day the copy goes, in
 * place of the reason and the kept-until sentence. The copy cannot read its own name then, so the name is the open
 * invitation's, as its prompt on this device shows it; where no open invitation is known, the plain words stand. After a
 * decline the entry has its kept copy's own name and its earlier line again.
 *
 * Real: the content layer over the item engine and the trust engine on a stand-in log server ([TrustBed]), with the
 * clock the test drives, and the invitation as the trust engine answers it. Stand-in: the item server, and the session
 * host, which hands the content the open invitation's name as the shared vaults' part keeps it.
 */
class HeldAddedAgainLineTest {
    private class Host(val r: ItemRig, val zone: kotlinx.datetime.TimeZone = kotlinx.datetime.TimeZone.UTC, val invitation: (String) -> String?) : ContentHost {
        override fun timeZone(): kotlinx.datetime.TimeZone = zone
        override fun wallMs(): Long = r.now
        override fun attachmentLimits() = AttachmentRules.limits(null, null)
        override fun origin(): String = "https://vault.example.com"
        override fun userId(): String = r.userId
        override fun accountId(): String = "0123456789abcdef0123456789abcdef"
        override fun backupKdfParams(): KdfParams? = null
        override fun openInvitationName(vaultId: String): String? = invitation(vaultId)
    }

    private class Bed(val bed: TrustBed, val c: EngineVaultContent, val s: TrustBed.Shared, val t0: Long)

    /** The open invitation as the trust engine answers it, the way the shared vaults' part keeps it. */
    private fun TrustBed.askedName(vaultId: String): String? = runBlocking { (logs.adoption(vaultId) as? Adoption.AskAccept)?.vaultName }

    /**
     * Shared, removed (the copy is held from t0; with [removedAt], the removal is verified at that instant), added again
     * on day 15 and served again; the content refreshed, its host in [zone]. [heldLine] gets the held copy's line as it
     * read before the adding.
     */
    private fun addedAgain(
        knowsInvitation: Boolean, zone: kotlinx.datetime.TimeZone = kotlinx.datetime.TimeZone.UTC, removedAt: Long? = null,
        heldLine: (String) -> Unit = {},
    ): Bed = runBlocking {
        val bed = TrustBed()
        val r = bed.rig
        val c = EngineVaultContent(r.engine, r.crypto, Host(r, zone) { id -> if (knowsInvitation) bed.askedName(id) else null })
        val s = bed.share { listOf(bed.row(it, r.id(), "wifi", 7)) }
        if (removedAt != null) r.now = removedAt - 1000
        bed.removeMe(s)
        val t0 = r.now
        r.engine.sync().ok()
        c.refresh()
        val before = c.state.held.single().line
        assertTrue(before.startsWith(CopyKey.HELD_ACCESS_REMOVED.english.substringBefore("{0}")), before)
        heldLine(before)
        r.now = t0 + 15 * DAY
        check(bed.owner.append(s.vaultId, LogAction.Add(r.userId, "writer")) is AppendOutcome.Appended)
        bed.logs.refresh(s.vaultId, null, null, force = true)
        r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(bed.vaultRow(s)), grants = listOf(bed.grantRow(s))))
        c.refresh()
        Bed(bed, c, s, t0)
    }

    @Test
    fun withAnOpenInvitationTheEntryCarriesItsNameAndTheLineQuotesIt() {
        val b = addedAgain(knowsInvitation = true)
        val row = b.c.state.held.single()
        assertEquals("Family", row.name, "the open invitation's name")
        assertEquals(addedAgainSentence("Family", ContentCopy.day(b.t0 + ItemEngine.HOLDING_MS)), row.line)
        assertTrue("“Family”" in row.line, row.line)
        assertTrue(!row.readable)
    }

    /**
     * A removal verified at 20:00 Pacific time on 22 November 2026 (04:00 on 23 November in UTC): the copy goes at 20:00
     * Pacific time on 22 December, so on a device in that zone every line names December 22, never the UTC day.
     */
    @Test
    fun theDayALineNamesIsTheDevicesDayOnWhichTheCopyGoes() {
        val la = kotlinx.datetime.TimeZone.of("America/Los_Angeles")
        var held = ""
        val b = addedAgain(knowsInvitation = true, zone = la, removedAt = 1_795_406_400_000L) { held = it }
        assertTrue("December 22" in held && "December 23" !in held, "the held copy's line: $held")
        val row = b.c.state.held.single()
        assertTrue("December 22" in row.line && "December 23" !in row.line, "the closed copy's entry: ${row.line}")
    }

    /** Accepted, and no sync yet: the copy opens with the vault's own key, and the entry no longer says it can't. */
    @Test
    fun acceptedAndNotYetSyncedTheEntryNoLongerSaysTheCopyCantOpenAndItsItemsShow() = runBlocking<Unit> {
        val b = addedAgain(knowsInvitation = true)
        val r = b.bed.rig
        val ask = b.bed.logs.adoption(b.s.vaultId) as Adoption.AskAccept
        b.bed.logs.answerIncoming(ask, accept = true)
        b.c.refreshHealth()
        val row = b.c.state.held.single()
        assertTrue(!row.line.startsWith("You were added to"), "no longer \"can't open\": ${row.line}")
        assertTrue(row.readable, "the copy opens")
        assertEquals(listOf("wifi"), r.engine.heldItems(b.s.vaultId).map { it.doc.name }, "its items show")
    }

    @Test
    fun withNoOpenInvitationKnownThePlainWordsStand() {
        val b = addedAgain(knowsInvitation = false)
        val row = b.c.state.held.single()
        assertEquals("", row.name)
        assertEquals(addedAgainSentence(null, ContentCopy.day(b.t0 + ItemEngine.HOLDING_MS)), row.line)
        assertTrue(ContentCopy.day(b.t0 + ItemEngine.HOLDING_MS) in row.line, "the day the copy goes: ${row.line}")
    }

    @Test
    fun afterADeclineTheEntryHasItsKeptCopysNameAndItsEarlierLine() = runBlocking<Unit> {
        val b = addedAgain(knowsInvitation = true)
        val r = b.bed.rig
        val ask = b.bed.logs.adoption(b.s.vaultId) as Adoption.AskAccept
        b.bed.logs.answerIncoming(ask, accept = false)
        r.server.queue.add(r.response(r.server.rev + 1, removed = listOf(b.s.vaultId)))
        b.c.refresh()
        val row = b.c.state.held.single()
        assertEquals("Family", row.name, "the kept copy's own name, as it opens again")
        assertEquals(ContentCopy.heldLine(io.silencelen.andvari.core.client.items.ItemNotice.REMOVED, b.t0 + ItemEngine.HOLDING_MS), row.line)
        assertTrue(row.readable)
    }
}
