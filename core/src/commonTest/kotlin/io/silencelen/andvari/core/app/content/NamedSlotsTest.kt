package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.CopyKey
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * A sentence that has its words quotes a name's slot itself (“{0}”). The content's lines about what a lock cut short
 * and about the trash used to quote the name before filling it in, so a name stood in doubled quotes once its
 * sentence had its words; and the plain words that stand where no name is known ("an item with no name") must not
 * stand in quotes at all. Every check here holds whether a key still shows its gloss or already has its words.
 */
class NamedSlotsTest {
    private fun cut(kind: LockCutKind, name: String, target: String = "") = LockCut(kind, name, target, 1, 3).line

    private val cuts = listOf(
        LockCutKind.VAULT_COPY, LockCutKind.MOVE, LockCutKind.ITEM_COPY, LockCutKind.ITEM_DELETE, LockCutKind.FILE,
        LockCutKind.RESTORE, LockCutKind.VERSION, LockCutKind.PERSONAL_COPY,
    )

    @Test
    fun aSentenceThatQuotesItsSlotQuotesANameOnce() {
        // A key whose words quote a slot: the name goes in as it is, inside the sentence's own quotes.
        assertEquals("Bo wants to share “Family” with you", ContentCopy.fillNames(CopyKey.INCOMING_VAULT, ContentCopy.Slot("Bo", true), ContentCopy.Slot("Family", true)))
        // Where no name is known, the plain words stand there and the sentence's quotes around that slot go.
        assertEquals("Bo wants to share a vault with you", ContentCopy.fillNames(CopyKey.INCOMING_VAULT, ContentCopy.Slot("Bo", true), ContentCopy.Slot("a vault", false)))
        // A name that itself reads like a slot is copied, never filled in again.
        assertEquals("{1} wants to share “{0}” with you", ContentCopy.fillNames(CopyKey.INCOMING_VAULT, ContentCopy.Slot("{1}", true), ContentCopy.Slot("{0}", true)))
        // A slot the caller gives nothing for stays as it stands.
        assertEquals("Bo wants to share “{1}” with you", ContentCopy.fillNames(CopyKey.INCOMING_VAULT, ContentCopy.Slot("Bo", true)))
    }

    @Test
    fun aNameInALineAboutALockOrTheTrashIsNeverQuotedTwice() {
        val lines = cuts.map { cut(it, "Bin me", "Family") } +
            ContentCopy.trashNotDone(listOf(true to "Bin me", false to "Bin me")) + ContentCopy.trashInAgain(listOf("Bin me"))
        for (line in lines) {
            assertTrue("Bin me" in line, line)
            assertFalse("““" in line || "””" in line, line)
            assertFalse("{0}" in line || "{1}" in line, line)
        }
    }

    @Test
    fun whereNoNameIsKnownThePlainWordsStandWithoutQuotes() {
        val lines = cuts.map { cut(it, "", "") } +
            ContentCopy.trashNotDone(listOf(true to null, false to "  ")) + ContentCopy.trashInAgain(listOf(null, ""))
        for (line in lines) {
            assertFalse("“an item with no name”" in line || "“an item”" in line || "“a vault”" in line || "“a file with no name”" in line, line)
            assertFalse("““" in line || "””" in line || "“”" in line, line)
            assertFalse("{0}" in line || "{1}" in line, line)
        }
        assertTrue("an item with no name" in cut(LockCutKind.ITEM_DELETE, ""))
        assertTrue("a vault" in cut(LockCutKind.MOVE, "Bin me", ""))
        assertTrue("an item" in ContentCopy.trashNotDone(listOf(true to null)))
    }

    private fun notice(kind: String, vaultName: String, count: Int? = null) =
        ContentCopy.notice(io.silencelen.andvari.core.client.items.ItemNotice("n1", "00000000-0000-4000-8000-0000000000aa", vaultName, kind, count)).first

    private val noticeKinds = listOf(
        io.silencelen.andvari.core.client.items.ItemNotice.DELETED, io.silencelen.andvari.core.client.items.ItemNotice.PURGED,
        io.silencelen.andvari.core.client.items.ItemNotice.REMOVED, io.silencelen.andvari.core.client.items.ItemNotice.LEFT,
        io.silencelen.andvari.core.client.items.ItemNotice.RESTORED, io.silencelen.andvari.core.client.items.ItemNotice.WITHHELD,
        io.silencelen.andvari.core.client.items.ItemNotice.REPLAY_DENIED, io.silencelen.andvari.core.client.items.ItemNotice.WRITE_REJECTED, "something-new",
    )

    @Test
    fun theContentsOtherLinesThatNameSomethingAreSaidByTheirKeys_andQuoteANameOnce() {
        assertEquals(ContentCopy.fillNames(CopyKey.ITEM_MOVED_TO, ContentCopy.Slot("Family", true)), ContentCopy.moved("Family"))
        assertEquals(ContentCopy.fillNames(CopyKey.ITEM_COPIED_TO, ContentCopy.Slot("Family", true)), ContentCopy.copied("Family"))
        assertEquals(ContentCopy.fillNames(CopyKey.KEPT_SAVE_LATER, ContentCopy.Slot("Passport", true)), ContentCopy.savedLater("Passport"))
        assertEquals(
            ContentCopy.fillNames(CopyKey.NOTICE_VAULT_DELETED, ContentCopy.Slot("Family", true)) + " " +
                ContentCopy.fillNames(CopyKey.NOTICE_EDITS_KEPT_MANY, ContentCopy.Slot("2", true)),
            notice(io.silencelen.andvari.core.client.items.ItemNotice.DELETED, "Family", 2),
        )
        assertEquals(ContentCopy.fillNames(CopyKey.NOTICE_WRITE_REJECTED_MANY, ContentCopy.Slot("2", true), ContentCopy.Slot("Family", true)), notice(io.silencelen.andvari.core.client.items.ItemNotice.WRITE_REJECTED, "Family", 2))
        assertEquals(ContentCopy.fillNames(CopyKey.HELD_LEFT, ContentCopy.Slot(ContentCopy.fillNames(CopyKey.HELD_KEPT_UNTIL, ContentCopy.Slot("November 19", true)), true)), ContentCopy.heldLine(io.silencelen.andvari.core.client.items.ItemNotice.LEFT, 1_763_510_400_000L))
        val lines = noticeKinds.map { notice(it, "Bin me", 1) } + noticeKinds.map { notice(it, "Bin me", 3) } + listOf(
            ContentCopy.moved("Bin me"), ContentCopy.copied("Bin me"), ContentCopy.alreadyCopied("Bin me", "Bin me", true),
            ContentCopy.alreadyCopied("Bin me", "Bin me", false), ContentCopy.inBothVaults("Bin me", "Bin me", "Bin me"),
            ContentCopy.savedWithoutFiles("Bin me", "Try again."), ContentCopy.savedLater("Bin me"),
            ContentCopy.filesOnly("Bin me", true), ContentCopy.filesOnly("Bin me", false),
        )
        for (line in lines) {
            assertTrue("Bin me" in line, line)
            assertFalse("““" in line || "””" in line, line)
            assertFalse("{0}" in line || "{1}" in line || "{2}" in line, line)
        }
    }

    @Test
    fun aNoticeAboutAVaultWithNoNameKnownSaysThePlainWordsUnquoted() {
        for (kind in noticeKinds) {
            val line = notice(kind, "", 2)
            assertTrue("a vault" in line, line)
            assertFalse("“a vault”" in line || "“”" in line, line)
            assertFalse("{0}" in line || "{1}" in line, line)
        }
    }
}
