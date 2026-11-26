package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.layout.Column
import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.unit.Density
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.content.ContentNoticeKind
import io.silencelen.andvari.core.app.content.FakeVaultContent
import io.silencelen.andvari.core.client.CardData
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.items.VaultAccess
import io.silencelen.andvari.core.client.items.VaultStanding
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The vault's list as the current desktop app has it, on the fields the shared code now puts on a row: the sort with
 * "recently updated", the filter by vault, a shared vault's mark, a card's second line, no Edit on an item that may only
 * be viewed; in the trash, a row not read yet; a notice that the server did not do something is a warning.
 */
class ListRowsTest {
    private val personal = FakeVaultContent.PERSONAL_VAULT_ID
    private val family = "00000000-0000-4000-8000-0000000000aa"
    private val work = "00000000-0000-4000-8000-0000000000bb"
    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/$name").readText()
    private fun body(text: String, head: String) = text.substringAfter(head).substringBefore("\n}\n")

    private fun content() = FakeVaultContent().also { c ->
        c.addSharedVault(family, "Family", VaultAccess.ROLE_READER, VaultStanding.VERIFIED)
        c.addSharedVault(work, "Work", VaultAccess.ROLE_WRITER, VaultStanding.VERIFIED)
        c.seedLogin(personal, "Bank", "ana", "made-up-1", "https://bank.test")
        c.seedLogin(family, "Wifi", "home", "made-up-2", "")
        c.seedLogin(work, "Wiki", "ana", "made-up-3", "")
        c.seed(personal, ItemDoc(type = "card", name = "Visa card", card = CardData(number = "4242 4242 4242 4242")))
        c.seedCard(family, "Odd card", "9999123", "01", "2031")
        c.seed(personal, ItemDoc(type = "card", name = "Blank card", card = CardData()))
    }

    private fun FakeVaultContent.id(name: String) = state.items.single { it.name == name }.itemId
    private fun FakeVaultContent.row(name: String) = state.items.single { it.name == name }

    @Test
    fun theSortIsByNameAsTheContentGivesItOrRecentlyUpdatedFirst() {
        val c = content()
        assertEquals(c.state.items.map { it.itemId }, listRows(c.state, null, null, ListSort.NAME).map { it.itemId }, "by name: the content's order")
        val latest = c.state.items.maxOf { it.updatedAt }
        c.setUpdatedAt(c.id("Wiki"), latest + 9_000)
        c.setUpdatedAt(c.id("Bank"), latest + 5_000)
        val recent = listRows(c.state, null, null, ListSort.RECENT).map { it.name }
        assertEquals(listOf("Wiki", "Bank"), recent.take(2))
        assertEquals(c.state.items.size, recent.size, "nothing is dropped by the order")
        assertEquals(listOf(ListSort.NAME, ListSort.RECENT), ListSort.entries.toList())
        assertEquals(Placeholder.SORT_RECENT, ListSort.RECENT.label)
        // The chip sits with the type and vault chips under the search box, as the current app's row.
        val list = body(src("VaultItemsScreens.kt"), "private fun VaultItemsList(")
        assertTrue(list.contains("SortChoice(sort) { sort = it }") && list.contains("TypeFilter(typeFilter) { typeFilter = it }") && list.contains("VaultFilter(state, vaultFilter) { vaultFilter = it }"))
        assertTrue(list.contains("val shown = listRows(state, typeFilter, vaultFilter, sort)"))
    }

    @Test
    fun theVaultFilterTakesItsChoicesFromTheContentsOwnVaultsAndAGoneVaultIsAll() {
        val c = content()
        assertEquals(c.state.vaults.map { it.vaultId }, vaultChoices(c.state).map { it.vaultId })
        assertTrue(vaultChoices(c.state).map { it.vaultId }.containsAll(listOf(personal, family, work)))
        assertEquals(setOf("Wifi", "Odd card"), listRows(c.state, null, family, ListSort.NAME).map { it.name }.toSet())
        assertEquals(listOf("Odd card"), listRows(c.state, "card", family, ListSort.NAME).map { it.name }, "type and vault together")
        assertNull(effectiveVaultFilter(c.state, "00000000-0000-4000-8000-0000000000ff"), "a vault no longer listed falls back to all")
        assertEquals(c.state.items.size, listRows(c.state, null, "00000000-0000-4000-8000-0000000000ff", ListSort.NAME).size)
        // Offered only when there is a choice.
        assertTrue(body(src("VaultItemsScreens.kt"), "private fun VaultFilter(").contains("if (vaults.size < 2) return"))
    }

    @Test
    fun aRowOfASharedVaultIsMarkedWithThatVaultsName() {
        val c = content()
        assertNull(sharedMark(c.row("Bank")), "the personal vault has no mark")
        assertEquals("Family", assertIs<UiText.Plain>(sharedMark(c.row("Wifi"))).text)
        assertEquals("Work", assertNotNull(sharedMark(c.row("Wiki"))).shown())
        val unnamed = c.row("Wiki").copy(vaultName = null)
        assertEquals(Placeholder.ROW_SHARED_VAULT, assertIs<UiText.Ph>(sharedMark(unnamed)).placeholder, "shared, its name unknown here: still marked")
        assertTrue(body(src("VaultItemsScreens.kt"), "private fun ItemRow(").contains("color = MaterialTheme.colorScheme.primary, maxLines = 1"), "the current app's gold tag")
    }

    @Test
    fun aCardsSecondLineIsItsBrandAndLastFourDigits() {
        val c = content()
        assertEquals("Visa ••4242", rowSecondLine(c.row("Visa card"))?.shown())
        assertEquals("Card ••9123", rowSecondLine(c.row("Odd card"))?.shown(), "a brand not known")
        assertEquals("card", rowSecondLine(c.row("Blank card"))?.shown(), "no number")
        // The same words as the item's own view (the shared code's summary).
        assertEquals(assertNotNull(c.itemDetail(c.id("Visa card"))?.card).summary, rowSecondLine(c.row("Visa card"))?.shown())
    }

    @Test
    fun anItemThatMayOnlyBeViewedOffersNoEditAndSaysSo() {
        val c = content()
        val reader = assertNotNull(c.itemDetail(c.id("Wifi")))
        assertFalse(reader.editable)
        assertFalse(c.row("Wifi").editable, "the row agrees")
        assertFalse(canDeleteState(reader, c.state), "no Edit and no Delete")
        assertTrue(canDeleteState(assertNotNull(c.itemDetail(c.id("Wiki"))), c.state), "a writer has both")
        val detail = body(src("VaultItemsScreens.kt"), "private fun ItemDetailView(")
        assertTrue(detail.contains("if (!d.editable) Say(UiText.ph(Placeholder.VIEW_ONLY)"))
        assertTrue(detail.contains("val canEdit = canDelete(d, state) && d.type in EDITOR_KINDS"))
    }

    @Test
    fun aTrashRowNotReadYetSaysSoAndStillOffersRestore() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.seedDeleted(personal, "Old bank", "ana", 2)
        val unread = c.seedDeleted(personal, "Never held", "bo", 3, notReadYet = true)
        assertEquals(ActionResult.Ok, c.openTrash())
        val row = assertNotNull(c.state.trash).single { it.itemId == unread }
        assertTrue(row.notReadYet && row.canRestore)
        assertEquals(Placeholder.TRASH_NOT_READ, assertIs<UiText.Ph>(trashRowName(row)).placeholder)
        assertEquals("Old bank", trashRowName(assertNotNull(c.state.trash).single { it.itemId != unread }).shown())
        val trash = body(src("VaultItemsScreens.kt"), "private fun TrashView(")
        assertTrue(trash.contains("trashRowName(t)") && trash.contains("if (t.canRestore) Quieter(UiText.ph(Placeholder.TRASH_RESTORE)"))
        // Restore reads it first, then it is back.
        assertEquals(ActionResult.Ok, c.restoreFromTrash(unread))
        assertTrue(c.state.items.any { it.itemId == unread })
    }

    @Test
    fun aNoticeThatTheServerDidNotDoItIsAWarningNeverASuccess() = runBlocking<Unit> {
        val c = FakeVaultContent()
        val id = c.seedDeleted(personal, "Old bank", "ana", 2)
        c.trashActionsStoreNothing(true)
        assertEquals(ActionResult.Ok, c.openTrash())
        assertEquals(ActionResult.Ok, c.restoreFromTrash(id))
        c.dismissNotice()
        assertEquals(ActionResult.Ok, c.openTrash())
        assertEquals(ContentNoticeKind.NOT_DONE_ON_SERVER, c.state.noticeKind)
        assertTrue(noticeIsWarning(c.state.noticeKind))
        assertFalse(noticeIsWarning(ContentNoticeKind.DONE))
        assertFalse(noticeIsWarning(ContentNoticeKind.QUEUED))
        assertFalse(noticeIsWarning(null))
        // An item in the trash again is plain information (it blames nobody); every other kind is the warning.
        assertFalse(noticeIsWarning(ContentNoticeKind.IN_TRASH_AGAIN))
        for (kind in ContentNoticeKind.entries.filter { it != ContentNoticeKind.DONE && it != ContentNoticeKind.QUEUED && it != ContentNoticeKind.IN_TRASH_AGAIN }) assertTrue(noticeIsWarning(kind), "$kind")
        val said = body(src("VaultItemsScreens.kt"), "internal fun ContentSaid(")
        assertTrue(said.contains("if (noticeIsWarning(state.noticeKind)) ErrorBar(UiText.Plain(it)) { c.dismissNotice() }"))
        assertTrue(said.contains("else NoticeBar(UiText.Plain(it)) { c.dismissNotice() }"))
        // Said in the trash, where the next read finds it, and in the list.
        assertTrue(body(src("VaultItemsScreens.kt"), "private fun TrashView(").contains("ContentSaid(c, state)"))
        assertTrue(body(src("VaultItemsScreens.kt"), "private fun VaultItemsList(").contains("ContentSaid(c, state)"))
        // Both bars draw.
        val scene = ImageComposeScene(480, 300, Density(1f)) {
            MaterialTheme { Column { ContentSaid(c, c.state) } }
        }
        try {
            scene.render()
        } finally {
            scene.close()
        }
    }
}
