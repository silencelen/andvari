package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.content.FakeVaultContent
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The vault's home, an item's view and the editors, drawn beside what the current (0.30.0) app builds for the same
 * screens: each place where they did not follow it is pinned here. The images are vault-list, item-login, item-card,
 * editor-edit-login, editor-discard, vault-search-none, vault-backup, export-backup and deleted-vaults.
 */
class FollowsCurrentAppTest {
    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    private fun body(text: String, fn: String): String {
        val start = text.indexOf(fn)
        assertTrue(start >= 0, "$fn is gone")
        val end = Regex("""\n(@Composable|internal fun|private fun|fun |/\*\*)""").find(text, start + fn.length)?.range?.first ?: text.length
        return text.substring(start, end)
    }

    private fun unlocked(): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.LOCKED)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(api.snapshot)
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        m.onSnapshot(api.snapshot)
        return api to m
    }

    /** vault-list: the current app's bar has five icons and no menu; with a sixth the name broke over two lines. */
    @Test
    fun theVaultsBarHasTheCurrentAppsFiveActionsAndNoMenu() {
        val bar = body(src("VaultHome.kt"), "internal fun VaultTopBar(")
        assertEquals(5, Regex("""IconButton\(""").findAll(bar).count(), "import, health, sharing, trash, settings")
        assertTrue("DropdownMenu" !in bar && "MoreVert" !in bar, "no menu in the vault's bar")
        assertTrue("maxLines = 1" in bar, "the name stays on one line")
        val order = listOf("Icons.Default.FileUpload", "Icons.Default.Favorite", "Icons.Default.Group", "Icons.Default.Delete", "Icons.Default.Settings")
        assertEquals(order, order.sortedBy { bar.indexOf(it) }, "in the current app's order")
    }

    /** vault-backup, export-backup, deleted-vaults: the backups in Settings, the deleted shared vaults in Sharing. */
    @Test
    fun backupsAreInSettingsAndDeletedVaultsInSharing() {
        val settings = body(src("SettingsScreens.kt"), "internal fun SettingsSections(")
        assertTrue(settings.indexOf("VaultBackupSection(model)") in 0 until settings.indexOf("QuickUnlockSection("), "before quick unlock")
        val backup = body(src("VaultHome.kt"), "internal fun VaultBackupSection(")
        assertTrue(backup.indexOf("ExportKind.BACKUP") < backup.indexOf("ExportKind.CSV"), "the encrypted backup is the main button")
        assertTrue("ExportPanel(c, exporting)" in backup, "the export opens in place")
        val shell = body(src("AccountScreens.kt"), "internal fun AccountShell(")
        val sharing = shell.substringAfter("SignedInPage.SHARING ->").substringBefore("SignedInPage.SETTINGS ->")
        assertTrue("RecentlyDeletedVaultsSection(model)" in sharing)
        assertTrue("RecentlyDeletedVaultsSection" !in shell.substringAfter("SignedInPage.SETTINGS ->"))
    }

    /** vault-search-none: a search that finds nothing says so, not that the vault is empty. */
    @Test
    fun anEmptySearchIsNotAnEmptyVault() {
        val (api, m) = unlocked()
        val c = assertNotNull(m.content.value)
        assertEquals(Placeholder.VAULT_EMPTY, emptyListWords(c.state))
        assertNotNull(api.fakeContent).seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "pw", "https://bank.example")
        c.setQuery("zzz")
        assertTrue(c.state.items.isEmpty())
        assertEquals(Placeholder.VAULT_NO_MATCH, emptyListWords(c.state))
    }

    /** item-login, item-card: copy says so, the code is large and tapped to copy, the postal code shows, view only is said. */
    @Test
    fun theDetailFollowsTheCurrentAppsRows() {
        val text = src("VaultItemsScreens.kt")
        val detail = body(text, "private fun ItemDetailView(")
        assertTrue("Placeholder.ITEM_POSTAL_CODE" in detail, "the card's postal code is shown")
        assertTrue(detail.indexOf("Placeholder.ITEM_CARD_CODE") < detail.indexOf("Placeholder.ITEM_POSTAL_CODE"), "after the security code")
        assertTrue("Placeholder.ITEM_VIEW_ONLY" in detail && "!d.editable" in detail, "an item this account cannot change says so")
        for (row in listOf("private fun PlainCopyRow(", "private fun SecretRow(", "private fun OneTimeCodeRow(")) {
            assertTrue("CopiedLine(clearSeconds)" in body(text, row), "$row says a copy was made")
        }
        val code = body(text, "private fun OneTimeCodeRow(")
        assertTrue("groupedCode(otp.code)" in code && "headlineMedium" in code && "clearAndSetSemantics" in code)
        assertEquals("309 848", groupedCode("309848"))
        assertEquals("123 456 78", groupedCode("12345678"))
        assertTrue("maxLines = 1" in body(text, "private fun SecretRow("), "the mask stays on one line")
        assertEquals(3500L, COPIED_LINE_MS)
    }

    /** editor-edit-login, editor-discard: Cancel and Back ask first; the vault comes first; Generate asks over a typed password. */
    @Test
    fun theEditorFollowsTheCurrentApp() {
        val editor = body(src("VaultItemsScreens.kt"), "private fun ItemEditor(")
        assertTrue("ActiveBackHandler(model) { confirmDiscard = true }" in editor, "Back asks before throwing typed work away")
        assertTrue("TextButton(onClick = { confirmDiscard = true }) { Text(UiText.ph(Placeholder.ITEM_CANCEL)" in editor, "so does Cancel")
        assertTrue("onClick = onDone) { Text(UiText.ph(Placeholder.ITEM_BACK)" !in editor, "no way out without asking")
        assertTrue(editor.indexOf("Placeholder.ITEM_VAULT") < editor.indexOf("Placeholder.ITEM_NAME"), "the vault picker comes first")
        assertTrue("Icons.Default.Refresh" in editor && "confirmGenerate = true" in editor, "Generate has its icon and asks over a typed password")
        assertTrue(editor.indexOf("Placeholder.ITEM_DISCARD") < editor.indexOf("Placeholder.ITEM_KEEP_EDITING"))
    }
}
