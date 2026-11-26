package io.silencelen.andvari.desktop.trust

import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.unit.Density
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.ItemSummary
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The signed-in screens follow the current desktop app's structure (decided on 2026-11-16): the vault's toolbar and
 * list, an item's view and its editors, Settings and Sharing as pages of their own with a card per section. Over the
 * fake, and pinned against the source where the structure itself is the point.
 */
class CurrentAppStructureTest {
    private fun unlocked(): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(FakeScene.LOCKED)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        m.onSnapshot(api.snapshot)
        return api to m
    }

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/$name").readText()

    private fun summary(type: String, username: String? = null, host: String? = null) =
        ItemSummary("id-$type", "Name", type, username, host, favorite = false, hasTotp = false, pendingSync = false)

    @Test
    fun theTypeFilterLetsThroughOneKindOrAllInTheContentsOrder() {
        val (_, m) = unlocked()
        val items = assertNotNull(m.content.value).state.items + listOf(summary("login"), summary("note"), summary("card"), summary("login", "b"))
        assertEquals(items, itemsOfType(items, null))
        val kinds = TYPE_FILTERS.mapNotNull { it.first }
        assertEquals(EDITOR_KINDS.toSet(), kinds.toSet(), "a filter for each kind an editor makes")
        for (k in kinds) assertTrue(itemsOfType(items, k).all { it.type == k })
        assertEquals(items.size, kinds.sumOf { itemsOfType(items, it).size }, "the kinds together are the whole list")
        assertEquals(items.filter { it.type == "login" }.map { it.itemId }, itemsOfType(items, "login").map { it.itemId })
    }

    @Test
    fun aRowsSecondLineIsTheUserNameOrTheSiteOrSecureNote() {
        assertEquals("ada", rowSecondLine(summary("login", "ada", "example.org"))?.shown())
        assertEquals("example.org", rowSecondLine(summary("login", "", "example.org"))?.shown())
        assertNull(rowSecondLine(summary("login")))
        assertEquals(Placeholder.ROW_NOTE, (rowSecondLine(summary("note")) as UiText.Ph).placeholder)
        // A card with no number in the row is "card", as the item's view says (its brand and last four: ListRowsTest).
        assertEquals("card", rowSecondLine(summary("card"))?.shown())
        assertEquals(Placeholder.KIND_LOGIN, kindWord("login"))
        assertEquals(Placeholder.KIND_CARD, kindWord("card"))
        assertEquals(Placeholder.KIND_NOTE, kindWord("note"))
    }

    @Test
    fun theVaultPageIsTheToolbarOverARuleThenTheListAndTheOtherPagesHaveBackAndATitle() {
        val shell = src("AccountScreens.kt")
        val vault = shell.substringAfter("SignedInPage.VAULT -> {").substringBefore("else -> Box(Modifier.fillMaxSize()) {")
        assertTrue(vault.indexOf("SignedInTopBar(") in 0 until vault.indexOf("HorizontalDivider()"))
        assertTrue(vault.indexOf("HorizontalDivider()") < vault.indexOf("VaultItemsSection(model)"))
        val page = shell.substringAfter("else -> Box(Modifier.fillMaxSize()) {").substringAfter("PageColumn {").substringBefore("/** The room left under")
        assertTrue(page.indexOf("PageHeader(") in 0 until page.indexOf("AttentionArea("))
        for (p in SignedInPage.entries) assertTrue(pageTitle(p).gloss.isNotEmpty())
        // The current app's toolbar order: import, sharing, trash, (health), settings, (console), sync, lock.
        val bar = shell.substringAfter("private fun SignedInTopBar(").substringBefore("/** A toolbar icon")
        val order = listOf("Icons.Default.FileUpload", "Icons.Default.Group", "Icons.Default.Delete", "Icons.Default.HealthAndSafety",
            "Icons.Default.Settings", "Icons.Default.AdminPanelSettings", "Icons.Default.Refresh", "Icons.Default.Lock")
        val at = order.map { bar.indexOf(it) }
        assertTrue(at.all { it >= 0 } && at == at.sorted(), "toolbar order: $at")
    }

    @Test
    fun settingsAndSharingAreACardPerSection() {
        val settings = src("SettingsScreens.kt").substringAfter("internal fun SettingsSections(").substringBefore("\n}\n")
        for (s in listOf("TwoStepSection(", "DevicesSection(", "RecoverySection(", "ChangePasswordSection(", "PolicySection(", "DeleteAccountSection(")) {
            assertTrue(settings.contains("SectionCard { $s"), s)
        }
        val shell = src("AccountScreens.kt")
        for (s in listOf("SharedVaultsSection(", "PeopleSection(", "LinksSection(")) assertTrue(shell.contains("SectionCard { $s"), s)
        assertTrue(shell.contains("BackupSection(model)"), "the backup and the exports are a Settings card, as the current app's")
        // No card marks a state at its edge.
        assertTrue(!src("TrustUi.kt").substringAfter("internal fun SectionCard(").substringBefore("\n}\n").contains("border"))
    }

    @Test
    fun anItemsViewEndsWithEditBesideDeleteAndDeleteAndCancelAskInADialogWhoseWayOutComesFirst() {
        val items = src("VaultItemsScreens.kt")
        val view = items.substringAfter("private fun ItemDetailView(").substringBefore("\n}\n")
        assertTrue(view.contains("headlineMedium"), "the name is a large heading")
        assertTrue(view.indexOf("Placeholder.ITEM_EDIT_BUTTON") in 0 until view.indexOf("DeleteItem(c, state, d, onBack)"))
        val delete = items.substringAfter("private fun DeleteItem(").substringBefore("\n}\n")
        assertTrue(delete.contains("AlertDialog("))
        assertTrue(delete.indexOf("dismissButton") in 0 until delete.indexOf("confirmButton"), "Keep before Delete")
        val editor = items.substringAfter("private fun ItemEditor(").substringBefore("\n}\n")
        assertTrue(editor.indexOf("Placeholder.EDITOR_CANCEL") in 0 until editor.indexOf("Placeholder.ITEM_NAME"))
        assertTrue(editor.indexOf("dismissButton") in 0 until editor.indexOf("confirmButton"), "keep editing before discard")
        assertTrue(editor.indexOf("VaultChoice(choices, vaultId)") in 0 until editor.indexOf("Placeholder.ITEM_NAME"), "the vault under the heading")
    }

    @Test
    fun theTrashHistoryHealthImportAndExportOpenWithBackAndALargeTitle() {
        val items = src("VaultItemsScreens.kt")
        assertTrue(items.contains("PageHeader(UiText.ph(Placeholder.TRASH)) { c.closeTrash() }"))
        assertTrue(items.contains("PageHeader(UiText.ph(Placeholder.HISTORY)) { c.closeItemHistory() }"))
        assertTrue(src("VaultHealthScreens.kt").contains("PageHeader(UiText.ph(Placeholder.HEALTH)) { c.closeHealth() }"))
        val transfer = src("VaultTransferScreens.kt")
        assertTrue(transfer.contains("PageHeader(UiText.ph(Placeholder.IMPORT_CSV), enabled = !v.busy) { c.closeImport() }"))
        assertTrue(transfer.contains("enabled = !v.busy && !writing) { c.closeExport() }"), "no way back while the file is written")
        val header = src("TrustUi.kt").substringAfter("internal fun PageHeader(").substringBefore("\n}\n")
        assertTrue(header.indexOf("ArrowBack") in 0 until header.indexOf("headlineMedium"))
    }

    @Test
    fun theSignedInShellDrawsAtTheNarrowestAndAWideWindowWithTheListInIt() {
        val (api, m) = unlocked()
        val s = api.snapshot
        val account = assertNotNull(s.account)
        for (width in listOf(480, 1000)) {
            val scene = ImageComposeScene(width, 720, Density(1f)) { MaterialTheme { AccountShell(m, s, account) } }
            try {
                scene.render()
            } finally {
                scene.close()
            }
        }
    }
}
