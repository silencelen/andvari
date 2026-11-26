package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.content.FakeVaultContent
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.CardInput
import io.silencelen.andvari.core.app.ExportKind
import io.silencelen.andvari.core.app.GeneratorSettings
import io.silencelen.andvari.core.app.NoteInput
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.SecretField
import io.silencelen.andvari.core.app.TrashItemView
import io.silencelen.andvari.core.app.ItemHistoryView
import io.silencelen.andvari.core.client.items.ItemNotice
import io.silencelen.andvari.core.client.items.VaultAccess
import io.silencelen.andvari.core.client.items.VaultStanding
import io.silencelen.andvari.core.app.content.VaultSyncState
import io.silencelen.andvari.core.app.content.emptyLine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** The vault's content on the new path: read at every unlock, never kept across a lock, and the shell shows it. */
class VaultContentWiringTest {
    private fun at(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(api.snapshot)
        return api to m
    }

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    private fun unlock(api: FakeAppApi, m: TrustModel) {
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        m.onSnapshot(api.snapshot)
    }

    @Test
    fun theContentIsReadAtEveryUnlockAndDroppedAtEveryLock() {
        val (api, m) = at(FakeScene.LOCKED)
        assertNull(m.content.value, "no content while locked")
        unlock(api, m)
        val first = assertNotNull(m.content.value)
        // The screens reach it through the containing wrapper, over this very instance.
        assertSame(api.content, assertIs<GuardedContent>(first).inner)
        api.lock()
        m.onSnapshot(api.snapshot)
        assertNull(m.content.value, "a lock drops the content")
        unlock(api, m)
        val second = assertNotNull(m.content.value)
        assertTrue(second !== first, "a new instance per unlock, the old one is never kept")
    }

    @Test
    fun theListShowsWhatTheContentHoldsAndItsSearch() {
        val (api, m) = at(FakeScene.LOCKED)
        unlock(api, m)
        val fake = assertNotNull(api.fakeContent)
        fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "pw", "https://bank.example")
        fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Mail", "me@example.com", "pw2", "")
        val c = assertNotNull(m.content.value)
        assertEquals(listOf("Bank", "Mail"), c.state.items.map { it.name })
        c.setQuery("ban")
        assertEquals(listOf("Bank"), c.state.items.map { it.name })
    }

    @Test
    fun theDetailRevealsWhatTheContentHoldsAndTheCodeIsLive() {
        val (api, m) = at(FakeScene.LOCKED)
        unlock(api, m)
        val id = assertNotNull(api.fakeContent).seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "pw", "https://bank.example")
        val c = assertNotNull(m.content.value)
        val d = assertNotNull(c.itemDetail(id))
        assertTrue(d.hasPassword)
        assertEquals("pw", c.revealSecret(id, SecretField.PASSWORD))
        val src = src("VaultItemsScreens.kt")
        // Copy goes through the old app's sensitive, generation-guarded clipboard with the policy's window, never 0.
        assertTrue(src.contains("maxOf(1, (model.clipboardClearMs() / 1000).toInt())"))
        assertFalse(src.contains(", 0)"), "no copy without a clear")
        // A new unlock starts on the list: the open item is keyed by the content instance.
        assertTrue(src.contains("remember(c) { mutableStateOf<String?>(null) }"))
    }

    @Test
    fun theSyncAndFailureStatesEachHaveALine() {
        val (api, m) = at(FakeScene.LOCKED)
        unlock(api, m)
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

    @Test
    fun deleteIsOfferedOnlyWhileSomethingCanBeSavedAndRemovesTheItem() {
        val (api, m) = at(FakeScene.LOCKED)
        unlock(api, m)
        val fake = assertNotNull(api.fakeContent)
        val id = fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "pw", "")
        val c = assertNotNull(m.content.value)
        val d = assertNotNull(c.itemDetail(id))
        assertTrue(canDelete(d, c.state))
        assertEquals(ActionResult.Ok, runBlocking { c.deleteItem(id) })
        assertTrue(c.state.items.none { it.itemId == id })
        val other = fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Mail", "me", "pw", "")
        fake.stopServer()
        assertFalse(canDelete(assertNotNull(c.itemDetail(other)), c.state), "server stopped: nothing can be saved")
    }

    @Test
    fun theLoginEditorsCallsSaveANewLoginAndKeepEveryWebAddressOnAnEdit() {
        val (api, m) = at(FakeScene.LOCKED)
        unlock(api, m)
        val c = assertNotNull(m.content.value)
        val personal = assertNotNull(c.vaultsForNewItems().firstOrNull { it.personal })
        val input = LoginInput("Bank", "me", c.generatePassword(GeneratorSettings.standard), listOf("https://bank.example"), "", "", false)
        assertEquals(ActionResult.Ok, runBlocking { c.saveLogin(null, input, personal.vaultId) })
        val id = c.state.items.single().itemId
        assertTrue(canSave(c.state))
        val src = src("VaultItemsScreens.kt")
        assertTrue(src.contains("listOf(uri) + (d?.uris?.drop(1) ?: emptyList())"), "an edit keeps the addresses it does not show")
        assertTrue(src.contains("c.saveCard(itemId, CardInput(name, holder, number, expMonth, expYear, code, postal, notes, fav), into)"))
        assertTrue(src.contains("c.saveNote(itemId, NoteInput(name, notes, fav), into)"))
        assertNotNull(c.itemDetail(id))
        val card = CardInput("Visa", "Me", "4242424242424242", "07", "2031", "123", "", "", false)
        assertEquals(ActionResult.Ok, runBlocking { c.saveCard(null, card, personal.vaultId) })
        assertEquals(ActionResult.Ok, runBlocking { c.saveNote(null, NoteInput("Wifi", "the code", false), personal.vaultId) })
        assertEquals(setOf("login", "card", "note"), c.state.items.map { it.type }.toSet())
        assertEquals(EDITOR_KINDS.toSet(), c.state.items.map { it.type }.toSet())
        assertNotNull(api.fakeContent).stopServer()
        assertFalse(canSave(c.state))
    }

    @Test
    fun theTrashShowsADeletedItemAndRestoreBringsItBack() {
        val (api, m) = at(FakeScene.LOCKED)
        unlock(api, m)
        val id = assertNotNull(api.fakeContent).seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "pw", "")
        val c = assertNotNull(m.content.value)
        assertEquals(ActionResult.Ok, runBlocking { c.deleteItem(id) })
        assertEquals(ActionResult.Ok, runBlocking { c.openTrash() })
        val rows: List<TrashItemView> = assertNotNull(c.state.trash)
        val row = rows.single { it.itemId == id }
        assertTrue(row.canRestore)
        assertEquals(ActionResult.Ok, runBlocking { c.restoreFromTrash(id) })
        assertTrue(c.state.items.any { it.itemId == id })
        c.closeTrash()
        val closed: List<TrashItemView>? = c.state.trash
        assertNull(closed)
    }

    @Test
    fun anEditedLoginsHistoryHoldsTheEarlierPassword() {
        val (api, m) = at(FakeScene.LOCKED)
        unlock(api, m)
        val c = assertNotNull(m.content.value)
        val personal = assertNotNull(c.vaultsForNewItems().firstOrNull { it.personal }).vaultId
        assertEquals(ActionResult.Ok, runBlocking { c.saveLogin(null, LoginInput("Bank", "me", "old-pw", emptyList(), "", "", false), personal) })
        val id = c.state.items.single().itemId
        assertEquals(ActionResult.Ok, runBlocking { c.saveLogin(id, LoginInput("Bank", "me", "new-pw", emptyList(), "", "", false), personal) })
        assertEquals(ActionResult.Ok, runBlocking { c.openItemHistory(id) })
        val h: ItemHistoryView = assertNotNull(c.state.history)
        val v = h.versions.first()
        assertTrue(v.hasPassword)
        assertEquals("old-pw", c.historyPassword(id, v.rev))
        c.closeItemHistory()
    }

    /** An item never edited has no earlier versions: its history says so in a line of its own, never "Nothing here yet.". */
    @Test
    fun anItemWithNoEarlierVersionsHasItsOwnLine() {
        val (api, m) = at(FakeScene.LOCKED)
        unlock(api, m)
        val c = assertNotNull(m.content.value)
        val personal = assertNotNull(c.vaultsForNewItems().firstOrNull { it.personal }).vaultId
        assertEquals(ActionResult.Ok, runBlocking { c.saveLogin(null, LoginInput("Bank", "me", "pw", emptyList(), "", "", false), personal) })
        val id = c.state.items.single().itemId
        assertEquals(ActionResult.Ok, runBlocking { c.openItemHistory(id) })
        val h: ItemHistoryView = assertNotNull(c.state.history)
        assertTrue(h.versions.isEmpty())
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ITEM_HISTORY_EMPTY, h.emptyLine)
        val view = java.io.File("src/main/kotlin/io/silencelen/andvari/app/trust/VaultItemsScreens.kt").readText()
            .substringAfter("private fun HistoryView(").substringBefore("\n}\n")
        assertTrue(view.contains("h.emptyLine?.let { Quiet(UiText.of(it)) }"))
        assertFalse(view.contains("Placeholder.VAULT_EMPTY"), "the empty vault's line is not the history's")
        c.closeItemHistory()
    }

    @Test
    fun anItemMovesToASharedVaultAndARemovedVaultCanBeCopiedOutOrDropped() {
        val (api, m) = at(FakeScene.LOCKED)
        unlock(api, m)
        val fake = assertNotNull(api.fakeContent)
        fake.addSharedVault("shared-1", "Family", VaultAccess.ROLE_WRITER, VaultStanding.VERIFIED)
        val id = fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "pw", "")
        val c = assertNotNull(m.content.value)
        val target = c.moveTargets(id).single { it.vaultId == "shared-1" }
        assertTrue(c.canMoveOut(id))
        assertEquals(ActionResult.Ok, runBlocking { c.moveOrCopyItem(id, target.vaultId, move = true) })
        assertEquals("shared-1", assertNotNull(c.state.items.single { it.name == "Bank" }.let { c.itemDetail(it.itemId) }).vaultId)

        fake.holdVault("shared-1", ItemNotice.DELETED, readable = true)
        val held = c.state.held.single()
        assertTrue(held.readable)
        assertEquals(ActionResult.Ok, runBlocking { c.saveVaultItemsToPersonal(held.vaultId) })
        assertTrue(c.state.items.any { it.name == "Bank" }, "the copy is in the personal vault")
        assertEquals(ActionResult.Ok, c.removeFromDevice(held.vaultId))
        assertTrue(c.state.held.isEmpty())
        // The copy out of a removed vault always shows the content's check-what-you-copy warning first.
        assertTrue(src("VaultItemsScreens.kt").contains("if (ask.second) Say(CopyKey.CHECK_WHAT_YOU_COPY)"))
    }

    @Test
    fun filesAreListedReadAndAddedThroughTheEditorsDraft() {
        val (api, m) = at(FakeScene.LOCKED)
        unlock(api, m)
        val fake = assertNotNull(api.fakeContent)
        val id = fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "pw", "")
        val fileId = fake.seedAttachment(id, "statement.pdf", byteArrayOf(1, 2, 3))
        val c = assertNotNull(m.content.value)
        val d = assertNotNull(c.itemDetail(id))
        assertEquals(listOf("statement.pdf"), d.attachments.map { it.name })
        assertEquals(listOf<Byte>(1, 2, 3), assertNotNull(runBlocking { c.readAttachment(id, fileId) }.bytes).toList())

        c.openAttachmentDraft(id)
        val added = byteArrayOf(9, 9)
        assertEquals(ActionResult.Ok, runBlocking { c.addAttachment("key.txt", added) })
        assertTrue(added.all { it == 0.toByte() }, "the content zeroes what it was handed")
        assertEquals(ActionResult.Ok, runBlocking { c.saveLogin(id, LoginInput("Bank", "me", "pw", emptyList(), "", "", false), d.vaultId) })
        c.closeAttachmentDraft()
        assertEquals(setOf("statement.pdf", "key.txt"), assertNotNull(c.itemDetail(id)).attachments.map { it.name }.toSet())
        assertEquals("3 B", sizeText(3))
        assertEquals("2 KB", sizeText(1025))
        val src = src("VaultItemsScreens.kt")
        assertTrue(src.contains("bytes.fill(0)"), "the decrypted bytes are zeroed after the write")
        assertTrue(src.contains("onDispose { c.closeAttachmentDraft() }"))
        assertEquals(2, Regex("ExternalExcursion.begin\\(\\)").findAll(src).count(), "both pickers arm the excursion")
    }

    @Test
    fun aCsvImportsAndTheVaultExportsAsCsv() {
        val (api, m) = at(FakeScene.LOCKED)
        unlock(api, m)
        val c = assertNotNull(m.content.value)
        val csv = "name,url,username,password\nBank,https://bank.example,me,pw\n".toByteArray()
        assertEquals(ActionResult.Ok, runBlocking { c.importCsv(csv) })
        assertTrue(csv.all { it == 0.toByte() }, "the content zeroes the file it read")
        val plan = assertNotNull(c.state.csvImport)
        assertEquals(1, plan.toImport)
        assertEquals(ActionResult.Ok, runBlocking { c.confirmImport() })
        c.closeImport()
        assertEquals(listOf("Bank"), c.state.items.map { it.name })

        assertEquals(ActionResult.Ok, runBlocking { c.openExport(ExportKind.CSV) })
        assertNotNull(c.state.exporting)
        val file = assertNotNull(c.csvFile(acknowledged = true))
        assertTrue(String(file.bytes).contains("bank.example"))
        val src = src("VaultTransferScreens.kt")
        assertTrue(src.contains("back.contentEquals(bytes)"), "an export is read back and compared")
        assertTrue(src.contains("bytes.fill(0)"))
        c.closeExport()
    }

    @Test
    fun healthOpensWithReusedPasswordsAndCloses() {
        val (api, m) = at(FakeScene.LOCKED)
        unlock(api, m)
        val fake = assertNotNull(api.fakeContent)
        fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "same-password-1", "https://bank.example")
        fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Mail", "me", "same-password-1", "https://mail.example")
        val c = assertNotNull(m.content.value)
        c.openHealth()
        val h = assertNotNull(c.state.health)
        assertEquals(2, h.tiles.logins)
        assertTrue(h.passwords.all { it.reused == 1 }, "each shares its password with one other login")
        // The reuse mark shows from one other login on (the count is of the others).
        assertTrue(src("VaultHealthScreens.kt").contains(".takeIf { p.reused > 0 }"))
        c.closeHealth()
        val closed: io.silencelen.andvari.core.app.HealthView? = c.state.health
        assertNull(closed)
    }

    @Test
    fun theShellRendersTheItemsAndTheEngineGetsACacheDirectory() {
        val shell = src("AccountScreens.kt")
        // The vault page: the live-updates line, then the items.
        assertTrue(shell.contains("SignedInPage.VAULT -> VaultItemsSection(model, header = {"))
        // The vault is home: a session starts there and Back from any other page returns to it.
        assertEquals(SignedInPage.VAULT, SignedInPage.entries.first())
        // ...unless a two-step set-up waits on its confirm step (AppInterfaceGainsOnScreensTest): then Settings.
        assertTrue(shell.contains("rememberSaveable(account.accountId) { mutableStateOf(firstPage ?: landingPage(account)) }"))
        // The screen images' way in is provided nowhere in the app's own code.
        val app = File("src/main/kotlin").walkTopDown().filter { it.isFile && it.extension == "kt" }.map { it.readText() }
        assertTrue(app.none { it.contains("LocalFirstPage provides") || it.contains("LocalFirstVaultView provides") || it.contains("LocalFirstSharingVault provides") })
        assertTrue(src("SettingsScreens.kt").contains("if (account.twoStep?.enrolment != null) SignedInPage.SETTINGS else SignedInPage.VAULT"))
        // Back returns to the vault from any other page; from a shared vault's own page it returns to Sharing's list first.
        assertTrue(shell.contains("ActiveBackHandler(model, enabled = page != SignedInPage.VAULT) {\n        if (page == SignedInPage.SHARING && sharingVault != null) sharingVaultId = null else page = SignedInPage.VAULT"))
        assertFalse(src("UiText.kt").contains("VAULT_NOT_HERE_YET"))
        assertTrue(src("TrustSeam.kt").contains("cacheFiles = SqliteVaultCacheFiles("))
    }
}
