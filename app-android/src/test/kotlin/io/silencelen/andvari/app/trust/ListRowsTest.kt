package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.content.ContentNoticeKind
import io.silencelen.andvari.core.app.content.FakeVaultContent
import io.silencelen.andvari.core.client.items.VaultAccess
import io.silencelen.andvari.core.client.items.VaultStanding
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The vault's list as the current app has it, over the fields the shared code puts on a row: the sort by the last
 * change, the filters by type and by vault, the shared vault's mark, a card's second line, no Edit where an item may
 * only be viewed; the trash's rows not read yet and "view only"; a notice that something was not done is a warning.
 */
class ListRowsTest {
    private val personal = FakeVaultContent.PERSONAL_VAULT_ID
    private val family = "00000000-0000-4000-8000-0000000fa111"

    private class Seeded(val c: FakeVaultContent, val bank: String, val diary: String, val visa: String, val bare: String, val wifi: String)

    private fun seeded(): Seeded {
        val c = FakeVaultContent()
        c.addSharedVault(family, "Family", VaultAccess.ROLE_READER, VaultStanding.VERIFIED)
        val bank = c.seedLogin(personal, "Bank", "me@example.com", "pw", "https://bank.example")
        val diary = c.seedNote(personal, "Diary", "text")
        val visa = c.seedCard(personal, "Travel card", "4242424242424242", "07", "2031")
        val bare = c.seedCard(personal, "Card with no number", "", "", "")
        val wifi = c.seedLogin(family, "Wifi", "", "pw3", "https://router.example")
        c.setUpdatedAt(bank, 1_000L)
        c.setUpdatedAt(diary, 4_000L)
        c.setUpdatedAt(visa, 2_000L)
        c.setUpdatedAt(bare, 3_000L)
        c.setUpdatedAt(wifi, 5_000L)
        return Seeded(c, bank, diary, visa, bare, wifi)
    }

    @Test
    fun theSortAndBothFiltersFollowTheCurrentApp() {
        val s = seeded()
        val st = s.c.state
        val byName = st.items.map { it.itemId }
        // By name is the content's own order, untouched.
        assertEquals(byName, listView(st.items, ListControls(), st.vaults).map { it.itemId })
        // Recently updated: the newest change first.
        assertEquals(listOf(s.wifi, s.diary, s.bare, s.visa, s.bank), listView(st.items, ListControls(recent = true), st.vaults).map { it.itemId })
        // By type.
        assertEquals(setOf(s.visa, s.bare), listView(st.items, ListControls(type = "card"), st.vaults).map { it.itemId }.toSet())
        assertEquals(listOf(s.diary), listView(st.items, ListControls(type = "note"), st.vaults).map { it.itemId })
        // By vault: its choices are the content's own vaults, personal first.
        assertEquals(listOf(personal, family), st.vaults.map { it.vaultId })
        assertEquals(listOf(s.wifi), listView(st.items, ListControls(vaultId = family), st.vaults).map { it.itemId })
        assertEquals("Family", vaultFilterWords(ListControls(vaultId = family), st.vaults).shown())
        // Both filters and the sort together.
        assertEquals(listOf(s.bare, s.visa), listView(st.items, ListControls(recent = true, type = "card", vaultId = personal), st.vaults).map { it.itemId })
        // A filter naming a vault the content no longer lists is every vault, never a silent empty list.
        val gone = ListControls(vaultId = "00000000-0000-4000-8000-00000000dead")
        assertEquals(byName, listView(st.items, gone, st.vaults).map { it.itemId })
        assertEquals(UiText.ph(Placeholder.LIST_ALL_VAULTS).shown(), vaultFilterWords(gone, st.vaults).shown())
        // A filter that leaves nothing says "nothing matches", not "no items".
        val emptyOnly = FakeVaultContent().also { it.seedNote(personal, "N", "t") }.state
        assertEquals(Placeholder.VAULT_NO_MATCH, emptyListWords(emptyOnly, ListControls(type = "card")))
        assertEquals(Placeholder.VAULT_EMPTY, emptyListWords(FakeVaultContent().state, ListControls(type = "card")))
    }

    @Test
    fun aRowSaysItsSecondLineAndItsSharedVaultAsTheCurrentAppDoes() {
        val s = seeded()
        val rows = s.c.state.items.associateBy { it.itemId }
        assertEquals("me@example.com", rowSecondLine(rows.getValue(s.bank)))
        // A login with no user name: its address, as the new app showed before.
        assertEquals("router.example", rowSecondLine(rows.getValue(s.wifi)))
        // A card: its brand and its last four digits, never more of the number.
        assertEquals("Visa ••4242", rowSecondLine(rows.getValue(s.visa)))
        assertFalse(rowSecondLine(rows.getValue(s.visa)).contains("424242"))
        // A card with no number is its kind; a note is its kind.
        assertEquals(kindWords("card").shown(), rowSecondLine(rows.getValue(s.bare)))
        assertEquals(kindWords("note").shown(), rowSecondLine(rows.getValue(s.diary)))
        // The shared vault's mark names the vault; the personal vault's rows carry none.
        assertEquals("Family", sharedVaultMark(rows.getValue(s.wifi)))
        assertNull(sharedVaultMark(rows.getValue(s.bank)))
    }

    @Test
    fun anItemThatMayOnlyBeViewedOffersNoEditAndSaysViewOnly() {
        val s = seeded()
        val rows = s.c.state.items.associateBy { it.itemId }
        assertFalse(rows.getValue(s.wifi).editable, "a reader's row")
        assertTrue(rows.getValue(s.bank).editable)
        val detail = assertNotNull(s.c.itemDetail(s.wifi))
        assertFalse(detail.editable)
        // The detail's Edit is behind the item's own editable, and its line says "view only" when it is not.
        val src = File("src/main/kotlin/io/silencelen/andvari/app/trust/VaultItemsScreens.kt").readText()
        assertTrue(src.contains("Placeholder.ITEM_VIEW_ONLY).shown().takeIf { !d.editable }"))
        assertTrue(src.contains("d.editable && !state.serverStopped"))
    }

    @Test
    fun aTrashRowNotReadYetSaysSoAndStillOffersRestore() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.addSharedVault(family, "Family", VaultAccess.ROLE_READER, VaultStanding.VERIFIED)
        val id = c.seedDeleted(personal, "Old bank", "ana", 3, notReadYet = true)
        c.seedDeleted(family, "Their router", "", 2)
        assertEquals(ActionResult.Ok, c.openTrash())
        val rows = assertNotNull(c.state.trash).associateBy { it.itemId }
        val row = rows.getValue(id)
        assertTrue(row.notReadYet)
        assertEquals(UiText.ph(Placeholder.TRASH_NOT_READ_YET).shown(), trashRowName(row).shown())
        assertEquals(Placeholder.TRASH_NOT_READ_YET, (trashRowName(row) as UiText.Ph).placeholder)
        assertTrue(row.canRestore, "a row not read yet can still be restored")
        assertFalse(trashRowLine(row).contains(UiText.ph(Placeholder.ITEM_VIEW_ONLY).shown()))
        // A row of a vault this account only reads: "view only", and neither action.
        val theirs = rows.values.single { it.itemId != id }
        assertFalse(theirs.canPurge)
        assertTrue(trashRowLine(theirs).endsWith(UiText.ph(Placeholder.ITEM_VIEW_ONLY).shown()), trashRowLine(theirs))
        assertEquals("Their router", trashRowName(theirs).shown())
        // The day it was deleted, as the phone's language writes a date: never a machine's timestamp.
        assertTrue(trashRowLine(theirs).contains(Dates.date(theirs.deletedAtMs)), trashRowLine(theirs))
        assertFalse(Regex("""\d{4}-\d{2}-\d{2}""").containsMatchIn(trashRowLine(theirs)), trashRowLine(theirs))
        // Restore reads the row first, then the item is back.
        assertEquals(ActionResult.Ok, c.restoreFromTrash(id))
        assertEquals("Old bank", c.state.items.single().name)
    }

    @Test
    fun aNoticeThatTheServerDidNotDoItIsAWarningNeverASuccess() = runBlocking<Unit> {
        val c = FakeVaultContent()
        val id = c.seedDeleted(personal, "Old bank", "ana", 2)
        c.trashActionsStoreNothing(true)
        assertEquals(ActionResult.Ok, c.openTrash())
        assertEquals(ActionResult.Ok, c.restoreFromTrash(id))
        assertFalse(noticeWarns(c.state.noticeKind), "the server's answer was a success, and said as one")
        c.dismissNotice()
        assertEquals(ActionResult.Ok, c.openTrash())
        assertEquals(ContentNoticeKind.NOT_DONE_ON_SERVER, c.state.noticeKind)
        assertTrue(noticeWarns(c.state.noticeKind))
        assertEquals(listOf(c.state.notice), noticeLines(c.state).map { it.shown() })
        // Every kind: only what went well, waits, or is plain information (an item in the trash again after a later
        // deletion elsewhere, which accuses nobody) is drawn as the notice bar.
        assertFalse(noticeWarns(ContentNoticeKind.IN_TRASH_AGAIN), "in the trash again is information, not a warning about the server")
        assertEquals(
            setOf(ContentNoticeKind.DONE, ContentNoticeKind.QUEUED, ContentNoticeKind.KEPT_SAVE, ContentNoticeKind.IN_TRASH_AGAIN),
            ContentNoticeKind.entries.filterNot { noticeWarns(it) }.toSet(),
        )
        assertTrue(noticeWarns(null))
    }
}
