package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.CardInput
import io.silencelen.andvari.core.app.GeneratorSettings
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.NoteInput
import io.silencelen.andvari.core.app.SecretField
import io.silencelen.andvari.core.app.TrashItemView
import io.silencelen.andvari.core.app.content.FakeVaultContent
import io.silencelen.andvari.core.app.content.VaultSyncState
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** The vault's items on the desktop's new path, over the fake's content. */
class VaultContentWiringTest {
    private fun at(scene: FakeScene): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(scene)
        return api to TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
    }

    private val src = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/VaultItemsScreens.kt").readText()

    private fun unlocked(): Pair<FakeDesktopAppApi, TrustModel> {
        val (api, m) = at(FakeScene.LOCKED)
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        m.onSnapshot(api.snapshot)
        return api to m
    }

    @Test
    fun theContentIsReadAtEveryUnlockAndDroppedAtEveryLock() {
        val (api, m) = unlocked()
        val first = assertNotNull(m.content.value)
        assertSame(api.content, first)
        m.lockNow()
        m.onSnapshot(api.snapshot)
        assertNull(m.content.value, "a lock drops the content")
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        m.onSnapshot(api.snapshot)
        assertTrue(assertNotNull(m.content.value) !== first, "a new instance per unlock, the old one is never kept")
        assertTrue(src.contains("remember(unlocks) { mutableStateOf<String?>(null) }"), "a new unlock starts on the list")
    }

    @Test
    fun theListShowsWhatTheContentHoldsAndItsSearch() {
        val (api, m) = unlocked()
        val fake = assertNotNull(api.fakeContent)
        fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "pw", "https://bank.example")
        fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Mail", "me@example.com", "pw2", "")
        val c = assertNotNull(m.content.value)
        assertEquals(listOf("Bank", "Mail"), c.state.items.map { it.name })
        c.setQuery("ban")
        assertEquals(listOf("Bank"), c.state.items.map { it.name })
    }

    @Test
    fun aRevealedSecretComesFromTheContentAndACopyIsAlwaysCleared() {
        val (api, m) = unlocked()
        val id = assertNotNull(api.fakeContent).seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "pw", "https://bank.example")
        val c = assertNotNull(m.content.value)
        assertTrue(assertNotNull(c.itemDetail(id)).hasPassword)
        assertEquals("pw", c.revealSecret(id, SecretField.PASSWORD))
        // Copy goes through the desktop's sensitive clipboard with the policy's window, never 0, and a failure is said.
        assertEquals(30, clipboardSeconds(m))
        assertTrue(src.contains("copyWithAutoClear(value, clipboardSeconds(model))"))
        assertFalse(src.contains("copyPlain("), "no copy without a clear")
        assertTrue(src.contains("CLIPBOARD_COPY_FAILED"))
        val root = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/TrustApp.kt").readText()
        assertTrue(root.contains("if (s.phase != AppPhase.UNLOCKED) clearVaultClipboard()"), "a lock clears what the vault copied")
    }

    @Test
    fun theSyncAndFailureStatesEachHaveALine() {
        val (api, m) = unlocked()
        val fake = assertNotNull(api.fakeContent)
        val c = assertNotNull(m.content.value)
        fake.setOffline(true)
        runBlocking { c.refresh() }
        assertEquals(VaultSyncState.OFFLINE, c.state.sync)
        assertEquals(Placeholder.SYNC_OFFLINE, (syncLine(c.state) as UiText.Ph).placeholder)
        fake.setOffline(false)
        fake.rollbackNextSync()
        runBlocking { c.refresh() }
        assertEquals(Placeholder.SYNC_ROLLBACK, (syncLine(c.state) as UiText.Ph).placeholder)
        fake.stopServer()
        assertEquals(Placeholder.SYNC_STOPPED, (syncLine(c.state) as UiText.Ph).placeholder)
    }

    /** A fork stops traffic, not reading (§4.4): under a stopped server the items stay readable and nothing is offered that saves. */
    @Test
    fun aStoppedServerKeepsTheItemsReadableAndOffersNothingThatSaves() {
        val (api, m) = unlocked()
        val fake = assertNotNull(api.fakeContent)
        val id = fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "pw", "")
        val c = assertNotNull(m.content.value)
        assertTrue(canDeleteState(assertNotNull(c.itemDetail(id)), c.state))
        fake.stopServer()
        assertEquals("pw", c.revealSecret(id, SecretField.PASSWORD), "still readable")
        assertFalse(canSaveState(c.state))
        assertFalse(canDeleteState(assertNotNull(c.itemDetail(id)), c.state))
        val adds = src.substringAfter("val adds = @Composable {").substringBefore("BoxWithConstraints(")
        assertTrue(adds.indexOf("if (canSave(state)) {") in 0 until adds.indexOf("onNew(kind)"), "no Add while stopped")
        assertTrue(src.contains("enabled = canSave(state) && !state.busy && name.isNotBlank()"), "no Save while stopped")
    }

    @Test
    fun theEditorsSaveEachKindAndAnEditKeepsEveryWebAddress() {
        val (api, m) = unlocked()
        val c = assertNotNull(m.content.value)
        val personal = assertNotNull(c.vaultsForNewItems().firstOrNull { it.personal })
        val input = LoginInput("Bank", "me", c.generatePassword(GeneratorSettings.standard), listOf("https://bank.example"), "", "", false)
        assertEquals(ActionResult.Ok, runBlocking { c.saveLogin(null, input, personal.vaultId) })
        assertEquals(ActionResult.Ok, runBlocking { c.saveCard(null, CardInput("Visa", "Me", "4242424242424242", "07", "2031", "123", "", "", false), personal.vaultId) })
        assertEquals(ActionResult.Ok, runBlocking { c.saveNote(null, NoteInput("Wifi", "the code", false), personal.vaultId) })
        assertEquals(EDITOR_KINDS.toSet(), c.state.items.map { it.type }.toSet())
        assertTrue(src.contains("moreUris = d?.uris?.drop(1) ?: emptyList()") && src.contains("listOf(uri) + draft.moreUris"), "an edit keeps the addresses it does not show")
        assertNotNull(api.fakeContent)
    }

    @Test
    fun deleteAsksFirstAndTheTrashBringsItBack() {
        val (api, m) = unlocked()
        val id = assertNotNull(api.fakeContent).seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "pw", "")
        val c = assertNotNull(m.content.value)
        val delete = src.substringAfter("private fun DeleteItem(").substringBefore("\n@Composable")
        assertTrue(delete.indexOf("Placeholder.BACK") < delete.indexOf("c.deleteItem("), "the way out comes first")
        assertEquals(ActionResult.Ok, runBlocking { c.deleteItem(id) })
        assertTrue(c.state.items.none { it.itemId == id })
        assertEquals(ActionResult.Ok, runBlocking { c.openTrash() })
        val rows: List<TrashItemView> = assertNotNull(c.state.trash)
        assertTrue(rows.single { it.itemId == id }.canRestore)
        assertEquals(ActionResult.Ok, runBlocking { c.restoreFromTrash(id) })
        assertTrue(c.state.items.any { it.itemId == id })
        c.closeTrash()
        assertNull(c.state.trash)
    }
}
