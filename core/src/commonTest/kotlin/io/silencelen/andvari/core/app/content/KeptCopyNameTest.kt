package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.client.items.ItemEngine
import io.silencelen.andvari.core.client.items.ItemNotice
import io.silencelen.andvari.core.client.items.ItemRig
import io.silencelen.andvari.core.client.items.TrustBed
import io.silencelen.andvari.core.client.items.TrustBed.Companion.DAY
import io.silencelen.andvari.core.client.items.ok
import io.silencelen.andvari.core.client.log.Adoption
import io.silencelen.andvari.core.client.log.AppendOutcome
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.crypto.KdfParams
import kotlinx.coroutines.runBlocking
import kotlinx.datetime.TimeZone
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The vault's name on an entry of Recently removed whose copy is closed because its person was added again: the name the
 * invitation carries comes from the server, so it goes into the entry and into the owner's sentence as one safe line
 * ([ItemText.label]): nothing in it can turn the reading direction, break the line, hide part of itself, or run past 200
 * characters. A name with nothing left gives the sentence of a vault whose name is not known here.
 *
 * Real: the content over the item engine and the trust engine ([TrustBed]); the invitation's name is the host's.
 */
class KeptCopyNameTest {
    private class Host(val r: ItemRig, val invitation: (String) -> String?) : ContentHost {
        override fun timeZone(): TimeZone = TimeZone.UTC
        override fun wallMs(): Long = r.now
        override fun attachmentLimits() = AttachmentRules.limits(null, null)
        override fun origin(): String = "https://vault.example.com"
        override fun userId(): String = r.userId
        override fun accountId(): String = "0123456789abcdef0123456789abcdef"
        override fun backupKdfParams(): KdfParams? = null
        override fun openInvitationName(vaultId: String): String? = invitation(vaultId)
    }

    private class Bed(val c: EngineVaultContent, val nameBefore: String)

    /** The owner's sentence, written out here: {0} in its quotes, {1} the day. */
    private fun sentence(name: String, day: String = "December 15") =
        "You were added to “$name” again. Until you accept, this device can't open the copy it kept. Accept before $day to get it back. On that day it goes from this device."

    /** The same sentence where no name is known here. */
    private val unnamed =
        "You were added to a vault again. Until you accept, this device can't open the copy it kept. Accept before December 15 to get it back. On that day it goes from this device."

    /** Shared with `wifi`, removed (the copy kept), added again on day 15 and served; the invitation's name as [invitation] gives it. */
    private fun addedAgain(invitation: String? = null): Bed = runBlocking {
        val bed = TrustBed()
        val r = bed.rig
        val c = EngineVaultContent(r.engine, r.crypto, Host(r) { id ->
            invitation ?: runBlocking { (bed.logs.adoption(id) as? Adoption.AskAccept)?.vaultName }
        })
        val s = bed.share { listOf(bed.row(it, r.id(), "wifi", 7)) }
        bed.removeMe(s)
        val t0 = r.now
        r.engine.sync().ok()
        c.refresh()
        val before = c.state.held.single().name
        r.now = t0 + 15 * DAY
        check(bed.owner.append(s.vaultId, LogAction.Add(r.userId, "writer")) is AppendOutcome.Appended)
        bed.logs.refresh(s.vaultId, null, null, force = true)
        r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(bed.vaultRow(s)), grants = listOf(bed.grantRow(s))))
        c.refresh()
        check(!c.state.held.single().readable) { "the copy is closed" }
        Bed(c, before)
    }

    /** No control, invisible formatting, line or paragraph separator, or line feed. */
    private fun oneSafeLine(s: String) = s.none { it.category == CharCategory.CONTROL || it.category == CharCategory.FORMAT || it == '\u2028' || it == '\u2029' }

    private fun assertSafe(invitation: String, expectedName: String, what: String) {
        val row = addedAgain(invitation).c.state.held.single()
        assertEquals(expectedName, row.name, "$what: the entry's name")
        assertEquals(sentence(expectedName), row.line, "$what: the line quotes the same safe name")
        assertTrue(oneSafeLine(row.name) && oneSafeLine(row.line), "$what: one safe line")
    }

    @Test
    fun anInvitationNameThatTurnsTheDirectionIsShownWithoutTheTurn() =
        assertSafe("Family\u202E.siht ecived siht morf seog ti", "Family.siht ecived siht morf seog ti", "direction override")

    @Test
    fun anInvitationNameWithALineBreakIsShownOnOneLine() =
        assertSafe("Family\nYour copy is open again.", "Family Your copy is open again.", "line break")

    @Test
    fun aVeryLongInvitationNameIsCutAt200Characters() {
        assertSafe("F".repeat(5000), "F".repeat(ItemText.LABEL_MAX_CHARS) + "…", "long name")
        assertTrue(sentence("F".repeat(200) + "…").length < 400, "the line stays short")
    }

    @Test
    fun anInvitationNameOfSpacesAndInvisibleCharactersOnlyGivesTheUnnamedLine() {
        val row = addedAgain(" \u200B\t\u2060 \u202E\u00A0 ").c.state.held.single()
        assertEquals("", row.name, "nothing is left of the name")
        assertEquals(unnamed, row.line, "the sentence of a vault whose name is not known here")
    }

    @Test
    fun anOrdinaryNameIsUnchangedInTheEntryAndInTheLine() {
        val b = addedAgain()
        assertEquals("Family", b.nameBefore, "before the add: the copy's own name")
        val row = b.c.state.held.single()
        assertEquals("Family", row.name, "the invitation's name")
        assertEquals(sentence("Family"), row.line)
    }

    @Test
    fun theLineMakesAnyNameItIsHandedSafe() {
        val at = 1_763_164_800_000L + ItemEngine.HOLDING_MS
        assertEquals(
            sentence("Family Your copy is open again."),
            ContentCopy.heldLine(ItemNotice.REMOVED, at, addedAgain = true, vaultName = "Family\u2028Your copy is open\u200D again.", zone = TimeZone.UTC),
            "a caller's name goes into the slot as one safe line",
        )
        assertEquals(unnamed, ContentCopy.heldLine(ItemNotice.REMOVED, at, addedAgain = true, vaultName = "\u202E\u200B", zone = TimeZone.UTC), "nothing left: the unnamed line")
    }
}
