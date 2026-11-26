package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.CardInput
import io.silencelen.andvari.core.app.GeneratorSettings
import io.silencelen.andvari.core.app.HealthView
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.NoteInput
import io.silencelen.andvari.core.app.SecretField
import io.silencelen.andvari.core.app.TrashItemView
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.PasswordHistoryEntry
import io.silencelen.andvari.core.client.items.ItemFailure
import io.silencelen.andvari.core.client.items.ItemNotice
import io.silencelen.andvari.core.client.items.VaultAccess
import io.silencelen.andvari.core.client.items.VaultStanding
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The rules of [VaultContent] as a screen meets them, through the fake (one controller serves both implementations). */
class FakeVaultContentTest {
    private val personal = FakeVaultContent.PERSONAL_VAULT_ID
    private val shared = "00000000-0000-4000-8000-0000000000aa"
    private val readOnly = "00000000-0000-4000-8000-0000000000bb"

    private fun login(name: String, password: String = "pw", totp: String = "") = LoginInput(name, "me", password, listOf(" https://a.example.com/x ", ""), "", totp, false)

    /** Typed on purpose: the test compiler has read a just-added state property as `Nothing?` when it was not annotated. */
    private fun healthOf(c: FakeVaultContent): HealthView? = c.state.health

    private fun ActionResult.message(): String =(this as? ActionResult.Failed)?.message ?: error("expected Failed, got $this")

    @Test
    fun theFakeRunsOnTheCryptoProviderItIsHanded() = runBlocking<Unit> {
        val real = io.silencelen.andvari.core.crypto.createCryptoProvider()
        var drawn = 0
        val counting = object : io.silencelen.andvari.core.crypto.CryptoProvider by real {
            override fun randomBytes(n: Int): ByteArray {
                drawn++
                return real.randomBytes(n)
            }
        }
        val c = FakeVaultContent(counting)
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("Router"), null))
        c.openAttachmentDraft(null)
        val before = drawn
        assertEquals(ActionResult.Ok, c.addAttachment("a.txt", "x".encodeToByteArray()))
        assertTrue(drawn > before, "the file's key and id came from the provider the test handed over")
        val text = c.readAttachment(c.state.items.single().itemId, "none").error
        assertNotNull(text)
    }

    @Test
    fun theListIsByName_searchedOnNameUsernameAddressesAndNotes_andCarriesNoSecret() {
        val c = FakeVaultContent()
        c.seedLogin(personal, "zeta", "zed", "s3cret", "https://user@Login.Example.com:8443/p")
        c.seedNote(personal, "Alpha", "the door code is 4411")
        assertEquals(listOf("Alpha", "zeta"), c.state.items.map { it.name })
        assertEquals("login.example.com", c.state.items[1].host)
        c.setQuery("ZED")
        assertEquals(listOf("zeta"), c.state.items.map { it.name })
        c.setQuery("door code")
        assertEquals(listOf("Alpha"), c.state.items.map { it.name }, "notes are searched")
        c.setQuery("s3cret")
        assertTrue(c.state.items.isEmpty(), "a password is never searched")
    }

    @Test
    fun detailAndSecrets_areReadOnRequest() {
        val c = FakeVaultContent()
        val id = c.seed(
            personal,
            ItemDoc(
                type = "login", name = "Bank",
                login = LoginData(username = "me", password = "now", totp = "JBSWY3DPEHPK3PXP", passwordHistory = listOf(PasswordHistoryEntry("first", 10), PasswordHistoryEntry("second", 20))),
            ),
        )
        val d = c.itemDetail(id)!!
        assertTrue(d.hasPassword && d.hasTotp && d.editable)
        assertEquals(2, d.previousPasswords)
        assertEquals("now", c.revealSecret(id, SecretField.PASSWORD))
        assertNull(c.revealSecret(id, SecretField.NOTES))
        assertEquals(listOf(20L, 10L), c.passwordHistory(id), "newest first")
        assertEquals("second", c.previousPassword(id, 0))
        assertNull(c.previousPassword(id, 2))
        val code = c.oneTimeCode(id)!!
        assertEquals(6, code.code.length)
        assertEquals(30, code.periodSeconds)
        assertNull(c.itemDetail("00000000-0000-4000-8000-00000000ffff"))
    }

    @Test
    fun theGenerator_givesWhatWasAskedFor_andFallsBackWhenNothingCanSatisfyIt() {
        val c = FakeVaultContent()
        assertEquals(24, c.generatePassword(GeneratorSettings(24, true, false, false, false, false)).length)
        assertEquals(12, c.generatePassword(GeneratorSettings(12, false, false, false, false, false)).length)
    }

    @Test
    fun aNewLogin_isValidated_trimmed_andGoesToThePersonalVault() = runBlocking<Unit> {
        val c = FakeVaultContent()
        assertEquals(ContentCopy.NAME_REQUIRED, c.saveLogin(null, login("  "), null).message())
        assertEquals(ContentCopy.TOTP_INVALID, c.saveLogin(null, login("A", totp = "not base32 !!"), null).message())
        assertEquals(ActionResult.Ok, c.saveLogin(null, login(" Mail "), null))
        val row = c.state.items.single()
        assertEquals("Mail", row.name)
        assertEquals(personal, c.itemDetail(row.itemId)!!.vaultId)
        assertEquals(listOf("https://a.example.com/x"), c.itemDetail(row.itemId)!!.uris)
        assertFalse(c.state.busy)
    }

    @Test
    fun anEdit_keepsWhatTheEditorDoesNotShow() = runBlocking<Unit> {
        val c = FakeVaultContent()
        val id = c.seed(personal, ItemDoc(type = "login", name = "Old", favorite = true, login = LoginData(password = "a", passwordHistory = listOf(PasswordHistoryEntry("z", 1)))))
        assertEquals(ActionResult.Ok, c.saveLogin(id, LoginInput("New", "u", "b", emptyList(), "", "", true), null))
        val doc = c.serverDoc(id)!!
        assertEquals("New", doc.name)
        assertEquals(1, doc.login!!.passwordHistory.size, "the history survives the edit")
    }

    @Test
    fun cards_areNormalised_andAnUnreadableExpiryIsRefused() = runBlocking<Unit> {
        val c = FakeVaultContent()
        fun card(month: String, year: String, number: String = "4242 4242 4242 4242") = CardInput("Visa", " Me ", number, month, year, "12 3", "", "", false)
        assertEquals(ContentCopy.CARD_EXPIRY_INVALID, c.saveCard(null, card("13", ""), null).message())
        assertEquals(ContentCopy.CARD_NUMBER_TOO_LONG, c.saveCard(null, card("07", "31", "4".repeat(20)), null).message())
        assertEquals(ActionResult.Ok, c.saveCard(null, card("07/31", ""), null))
        val id = c.state.items.single().itemId
        val d = c.itemDetail(id)!!.card!!
        assertEquals("07", d.expMonth)
        assertEquals("2031", d.expYear)
        assertEquals("4242424242424242", c.revealSecret(id, SecretField.CARD_NUMBER))
        assertEquals("123", c.revealSecret(id, SecretField.CARD_CODE))
        assertEquals(ContentCopy.CARD_NUMBER_UNUSUAL, c.cardNumberWarning("4242 4242 4242 4241"))
        assertNull(c.cardNumberWarning("4242 4242 4242 4242"))
    }

    @Test
    fun aNote_needsAName_andItsTextIsASecret() = runBlocking<Unit> {
        val c = FakeVaultContent()
        assertEquals(ContentCopy.NOTE_NAME_REQUIRED, c.saveNote(null, NoteInput("", "x", false), null).message())
        assertEquals(ActionResult.Ok, c.saveNote(null, NoteInput("Wifi", "pass", false), null))
        val id = c.state.items.single().itemId
        assertEquals("pass", c.revealSecret(id, SecretField.NOTES))
        assertEquals(ContentCopy.ITEM_GONE, c.saveCard(id, CardInput("x", "", "", "", "", "", "", "", false), null).message(), "a note is not edited as a card")
    }

    @Test
    fun whereANewItemMayGo_personalFirst_thenWritableSharedVaults() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.addSharedVault(shared, "Family", VaultAccess.ROLE_WRITER, VaultStanding.VERIFIED)
        c.addSharedVault(readOnly, "Archive", VaultAccess.ROLE_READER, VaultStanding.VERIFIED)
        assertEquals(listOf(personal, shared), c.vaultsForNewItems().map { it.vaultId })
        assertTrue(c.vaultsForNewItems().first().personal)
        assertEquals(ContentVaultState.READER, c.state.vaults.single { it.vaultId == readOnly }.access)
        assertEquals(ContentCopy.VAULT_NOT_WRITABLE, c.saveLogin(null, login("A"), readOnly).message())
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("B"), shared))
        assertEquals("Family", c.vaultName(shared))
        val inArchive = c.seedLogin(readOnly, "Kept", "", "", "")
        assertFalse(c.itemDetail(inArchive)!!.editable)
        assertEquals(ContentCopy.READ_ONLY, c.deleteItem(inArchive).message())
    }

    @Test
    fun aFrozenOrWithheldVault_isReadOnly() {
        val c = FakeVaultContent()
        c.addSharedVault(shared, "Family", VaultAccess.ROLE_OWNER, VaultStanding.FROZEN)
        c.addSharedVault(readOnly, "Club", VaultAccess.ROLE_WRITER, VaultStanding.WITHHELD)
        assertEquals(listOf(personal), c.vaultsForNewItems().map { it.vaultId })
        assertEquals(ContentVaultState.FROZEN, c.state.vaults.single { it.vaultId == shared }.access)
        assertEquals(ContentVaultState.WITHHELD, c.state.vaults.single { it.vaultId == readOnly }.access)
    }

    @Test
    fun withNoPersonalVault_aNewItemNeedsAChosenVault() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.dropPersonalVault()
        assertEquals(ContentCopy.NO_PERSONAL_VAULT, c.saveLogin(null, login("A"), null).message())
    }

    @Test
    fun anEditBoundToAnotherVault_isRefused_neverReTargeted() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.addSharedVault(shared, "Family", VaultAccess.ROLE_WRITER, VaultStanding.VERIFIED)
        val id = c.seedLogin(shared, "A", "", "", "")
        assertEquals(ContentCopy.ITEM_CHANGED_VAULTS, c.saveLogin(id, login("A2"), personal).message())
        assertEquals("A", c.serverDoc(id)!!.name)
        assertEquals(ActionResult.Ok, c.saveLogin(id, login("A2"), null), "no vault named: the vault it is in now")
        assertEquals(shared, c.itemDetail(id)!!.vaultId)
    }

    @Test
    fun offline_aSaveIsQueued_shownMarked_andSentByTheNextSync() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.setOffline(true)
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("Queued"), null))
        assertEquals(ContentCopy.SAVE_OFFLINE, c.state.notice)
        assertEquals(1, c.state.queued)
        assertTrue(c.state.items.single().pendingSync)
        assertEquals(ContentCopy.SYNC_OFFLINE, c.refresh().message())
        assertEquals(VaultSyncState.OFFLINE, c.state.sync)
        c.setOffline(false)
        assertEquals(ActionResult.Ok, c.refresh())
        assertEquals(VaultSyncState.SYNCED, c.state.sync)
        assertEquals(ContentCopy.SYNCED, c.state.notice)
        assertEquals(0, c.state.queued)
        assertFalse(c.state.items.single().pendingSync)
        val id = c.state.items.single().itemId
        assertEquals("Queued", c.serverDoc(id)!!.name)
        c.setOffline(true)
        assertEquals(ActionResult.Ok, c.deleteItem(id))
        assertTrue(c.state.items.isEmpty(), "a queued delete hides the item")
        assertNotNull(c.serverDoc(id))
    }

    /** The fake counts what waits as the engine does over the real server (`ContentQueueCountTest` in the command-line tool). */
    @Test
    fun whatWaits_isCountedAsTheEngineCountsIt() = runBlocking<Unit> {
        val c = FakeVaultContent()
        // A new item made offline and deleted before it was sent: nothing is left to send.
        c.setOffline(true)
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("Draft"), null))
        assertEquals(1, c.state.queued)
        assertEquals(ActionResult.Ok, c.deleteItem(c.state.items.single().itemId))
        assertEquals(0, c.state.queued)
        assertTrue(c.state.items.isEmpty())
        // An edit made offline, then a delete: one change waits, and the delete is what the server ends with.
        c.setOffline(false)
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("Vpn"), null))
        val vpn = c.state.items.single().itemId
        c.setOffline(true)
        assertEquals(ActionResult.Ok, c.saveLogin(vpn, login("Vpn 2"), FakeVaultContent.PERSONAL_VAULT_ID))
        assertEquals(ActionResult.Ok, c.deleteItem(vpn))
        assertEquals(1, c.state.queued)
        c.setOffline(false)
        assertEquals(ActionResult.Ok, c.syncQuietly())
        assertEquals(0, c.state.queued)
        assertNull(c.serverDoc(vpn))
        // A change that waited goes with the next write that gets through, as the engine sends its whole queue.
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("Router"), null))
        val router = c.state.items.single().itemId
        c.setOffline(true)
        assertEquals(ActionResult.Ok, c.saveLogin(router, login("Router 2"), FakeVaultContent.PERSONAL_VAULT_ID))
        c.setOffline(false)
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("Nas"), null))
        assertEquals(0, c.state.queued, "nothing waits behind a write that got through")
        assertEquals("Router 2", c.serverDoc(router)!!.name)
    }

    @Test
    fun aFailureIsASentence_neverAnException() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.failNextWith(ItemFailure.Refused("rate_limited", 429))
        assertEquals(ContentCopy.TOO_MANY_REQUESTS, c.saveLogin(null, login("A"), null).message())
        c.failNextWith(ItemFailure.Refused("x", 503))
        assertEquals(ContentCopy.SYNC_FAILED, c.refresh().message())
        assertEquals(VaultSyncState.REFUSED, c.state.sync)
        c.failNextWith(ItemFailure.Refused("x", 401))
        assertEquals(ContentCopy.SESSION_EXPIRED, c.refresh().message())
    }

    @Test
    fun underAStoppedServer_theCopyIsReadable_andNothingCanBeSaved() = runBlocking<Unit> {
        val c = FakeVaultContent()
        val id = c.seedLogin(personal, "Kept", "me", "pw", "")
        c.stopServer()
        assertTrue(c.state.serverStopped)
        assertEquals(VaultSyncState.STOPPED, c.state.sync)
        assertEquals("pw", c.revealSecret(id, SecretField.PASSWORD))
        assertFalse(c.itemDetail(id)!!.editable)
        assertTrue(c.vaultsForNewItems().isEmpty())
        assertTrue(c.state.vaults.all { it.access == ContentVaultState.STOPPED })
        assertEquals(ContentCopy.SERVER_STOPPED, c.saveLogin(null, login("A"), null).message())
        assertEquals(ContentCopy.SERVER_STOPPED, c.saveLogin(id, login("A"), null).message())
        assertEquals(ContentCopy.SERVER_STOPPED, c.deleteItem(id).message())
        assertEquals(ContentCopy.SERVER_STOPPED, c.refresh().message())
        assertEquals(0, c.syncCount, "nothing reached the server")
        assertEquals("Kept", c.serverDoc(id)!!.name)
    }

    @Test
    fun aServerThatWentBackwards_isShown_andItsNoticeIsAWarning() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.rollbackNextSync()
        assertEquals(ContentCopy.ROLLBACK, c.refresh().message())
        assertEquals(VaultSyncState.ROLLBACK, c.state.sync)
        val n = c.state.vaultNotices.single()
        assertTrue(n.warning)
        c.dismissVaultNotice(n.id)
        assertTrue(c.state.vaultNotices.isEmpty())
    }

    @Test
    fun aQuietSyncWhoseWritesWereDenied_saysSo() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.failNextWith(ItemFailure.Denied(2))
        assertTrue(c.syncQuietly() is ActionResult.Failed)
        assertEquals(ContentCopy.denied(2), c.state.error)
        assertEquals(VaultSyncState.SYNCED, c.state.sync, "the cycle completed")
        c.dismissError()
        assertNull(c.state.error)
        c.setOffline(true)
        c.syncQuietly()
        assertNull(c.state.error, "being offline is the sync state, not an error")
        assertFalse(c.state.busy)
    }

    @Test
    fun notices_haveTheirSentences() {
        val c = FakeVaultContent()
        c.raiseNotice(shared, "Family", ItemNotice.WRITE_REJECTED, 2)
        c.raiseNotice(shared, "Family", ItemNotice.WITHHELD, 0)
        c.raiseNotice(shared, "", ItemNotice.LEFT, 0)
        val texts = c.state.vaultNotices
        assertEquals("2 offline changes to “Family” couldn't be applied — the server refused them.", texts[0].text)
        assertTrue(texts[1].warning)
        // A vault with no name known: the plain words stand in the sentence, unquoted (it is not a name).
        assertEquals(ContentCopy.fillNames(io.silencelen.andvari.core.app.CopyKey.NOTICE_LEFT, ContentCopy.Slot("a vault", named = false)), texts[2].text)
        assertTrue("a vault" in texts[2].text && "“a vault”" !in texts[2].text, texts[2].text)
    }

    @Test
    fun aClosedContent_doesNothing_andPublishesNothing() = runBlocking<Unit> {
        val c = FakeVaultContent()
        val id = c.seedLogin(personal, "A", "", "pw", "")
        var seen = 0
        c.observe { seen++ }
        assertEquals(1, seen, "the current state at once")
        val before = c.state.revision
        c.close()
        assertTrue(c.saveLogin(null, login("B"), null) is ActionResult.NotDone)
        assertTrue(c.refresh() is ActionResult.NotDone)
        assertNull(c.revealSecret(id, SecretField.PASSWORD))
        assertNull(c.itemDetail(id))
        assertEquals(before, c.state.revision)
        assertEquals(1, seen)
    }

    @Test
    fun theEditorsFiles_areHeldToTheLimits_andSentWithTheSave() = runBlocking<Unit> {
        val c = FakeVaultContent()
        val id = c.seedLogin(personal, "Bank", "", "", "")
        val kept = c.seedAttachment(id, "statement.pdf", ByteArray(8) { 1 })
        c.setAttachmentLimits(10, 20)
        assertTrue(c.addAttachment("x", ByteArray(3)) is ActionResult.NotDone, "no editor is open")
        c.openAttachmentDraft(id)
        assertEquals(listOf("statement.pdf"), c.state.attachmentDraft!!.kept.map { it.name })
        assertTrue(c.addAttachment("big", ByteArray(11)).message().startsWith("This file is larger than"))
        assertEquals(ActionResult.Ok, c.addAttachment("a.txt", ByteArray(4) { 2 }))
        assertEquals(ActionResult.Ok, c.addAttachment("b.txt", ByteArray(4) { 3 }))
        assertTrue(c.addAttachment("sum", ByteArray(10)).message().startsWith("This item's files would come to more than"))
        val b = c.state.attachmentDraft!!.added.single { it.name == "b.txt" }.id
        c.removeAttachment(b)
        c.removeAttachment(kept)
        assertEquals(4L, c.state.attachmentDraft!!.totalBytes)
        assertEquals(ActionResult.Ok, c.saveLogin(id, LoginInput("Bank", "", "", emptyList(), "", "", false), null))
        val files = c.itemDetail(id)!!.attachments
        assertEquals(listOf("a.txt"), files.map { it.name })
        assertEquals(listOf<Byte>(2, 2, 2, 2), c.readAttachment(id, files.single().id).bytes!!.toList())
        assertEquals(setOf(kept, files.single().id), c.uploadedFiles, "the removed file is the server's to drop; the added one is up")
        assertEquals(ContentCopy.FILE_GONE, c.readAttachment(id, b).error)
    }

    @Test
    fun aSaveWhoseUploadFailed_triesAgainUnderTheSameIds() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.openAttachmentDraft(null)
        c.addAttachment("a.txt", ByteArray(4))
        c.failNextWith(ItemFailure.Unreachable(io.silencelen.andvari.core.client.net.NoAnswerKind.TIMEOUT))
        assertEquals(ContentCopy.SAVE_FAILED_OFFLINE, c.saveNote(null, NoteInput("N", "t", false), null).message())
        assertTrue(c.state.items.isEmpty())
        assertEquals(ActionResult.Ok, c.saveNote(null, NoteInput("N", "t", false), null))
        assertEquals(1, c.uploadedFiles.size)
        assertEquals(c.uploadedFiles, c.itemDetail(c.state.items.single().itemId)!!.attachments.map { it.id }.toSet())
        assertNull(c.state.upload)
    }

    @Test
    fun theTrash_restoresWithoutFiles_andPurges() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.addSharedVault(readOnly, "Archive", VaultAccess.ROLE_READER, VaultStanding.VERIFIED)
        val old = c.seedDeleted(personal, "Old mail", "me", 3)
        val theirs = c.seedDeleted(readOnly, "Theirs", "", 1)
        assertNull(c.state.trash)
        assertEquals(ActionResult.Ok, c.openTrash())
        val rows: List<TrashItemView> = c.state.trash!!
        assertEquals(listOf(theirs, old), rows.map { it.itemId }, "newest first")
        assertFalse(rows[0].canRestore || rows[0].canPurge, "a reader cannot")
        assertEquals("me", rows[1].detail)
        assertEquals(ContentCopy.READ_ONLY, c.restoreFromTrash(theirs).message())
        assertEquals(ActionResult.Ok, c.restoreFromTrash(old))
        assertEquals(ContentCopy.TRASH_RESTORED, c.state.notice)
        assertEquals(listOf("Old mail"), c.state.items.map { it.name })
        assertEquals(ContentCopy.TRASH_GONE, c.purgeFromTrash(old).message())
        val gone = c.seedLogin(personal, "Gone", "", "", "")
        c.deleteItem(gone)
        c.openTrash()
        assertEquals(ActionResult.Ok, c.purgeFromTrash(gone))
        assertFalse(gone in c.trashedItems)
        c.closeTrash()
        assertNull(c.state.trash)
    }

    @Test
    fun anItemsHistory_showsPasswordsOnRequest_andRestoresAVersion() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.saveLogin(null, login("Site", password = "one"), null)
        val id = c.state.items.single().itemId
        c.saveLogin(id, login("Site", password = "two"), null)
        assertNull(c.historyPassword(id, 1), "not open")
        assertEquals(ActionResult.Ok, c.openItemHistory(id))
        val h = c.state.history!!
        assertTrue(h.canRestore)
        val v = h.versions.single()
        assertEquals("one", c.historyPassword(id, v.rev))
        assertEquals(ActionResult.Ok, c.restoreItemVersion(id, v.rev))
        assertEquals(ContentCopy.VERSION_RESTORED, c.state.notice)
        assertEquals("one", c.revealSecret(id, SecretField.PASSWORD))
        assertEquals(2, c.state.history!!.versions.size, "the version it replaced is in the history")
        assertEquals(ContentCopy.HISTORY_GONE, c.restoreItemVersion(id, 999).message())
        c.closeItemHistory()
        assertNull(c.state.history)
    }

    @Test
    fun moveAndCopy_betweenVaults_withTheirFiles() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.addSharedVault(shared, "Family", VaultAccess.ROLE_WRITER, VaultStanding.VERIFIED)
        val id = c.seedLogin(personal, "Wifi", "", "pw", "")
        c.seedAttachment(id, "router.jpg", ByteArray(5) { 7 })
        assertEquals(listOf(shared), c.moveTargets(id).map { it.vaultId })
        assertTrue(c.canMoveOut(id))
        assertEquals(ActionResult.Ok, c.moveOrCopyItem(id, shared, false))
        assertEquals(ContentCopy.copied("Family"), c.state.notice)
        assertEquals(2, c.state.items.size)
        assertEquals(ActionResult.Ok, c.moveOrCopyItem(id, shared, true))
        assertEquals(ContentCopy.moved("Family"), c.state.notice)
        assertEquals(listOf(shared, shared), c.state.items.map { c.itemDetail(it.itemId)!!.vaultId })
        val copy = c.state.items.first()
        assertEquals(listOf<Byte>(7, 7, 7, 7, 7), c.readAttachment(copy.itemId, c.itemDetail(copy.itemId)!!.attachments.single().id).bytes!!.toList())
        assertEquals(ContentCopy.VAULT_NOT_WRITABLE, c.moveOrCopyItem(copy.itemId, readOnly, false).message())
    }

    @Test
    fun aMoveThatGotNoAnswer_isTriedAgainWithoutADuplicate() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.addSharedVault(shared, "Family", VaultAccess.ROLE_WRITER, VaultStanding.VERIFIED)
        val id = c.seedLogin(personal, "Wifi", "", "pw", "")
        c.failNextWith(ItemFailure.Unreachable(io.silencelen.andvari.core.client.net.NoAnswerKind.TIMEOUT))
        assertEquals(ContentCopy.MOVE_RETRY, c.moveOrCopyItem(id, shared, false).message())
        assertEquals(ActionResult.Ok, c.moveOrCopyItem(id, shared, false))
        assertEquals(2, c.state.items.size)
    }

    @Test
    fun aFrozenVault_canOnlyBeCopiedOutOf() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.addSharedVault(shared, "Family", VaultAccess.ROLE_OWNER, VaultStanding.FROZEN)
        val a = c.seedLogin(shared, "A", "", "", "")
        c.seedNote(shared, "B", "")
        assertFalse(c.canMoveOut(a))
        assertEquals(listOf(personal), c.moveTargets(a).map { it.vaultId })
        assertEquals(ContentCopy.READ_ONLY, c.moveOrCopyItem(a, personal, true).message())
        assertEquals(ActionResult.Ok, c.saveVaultItemsToPersonal(shared))
        assertEquals(ContentCopy.copiedToPersonal(2), c.state.notice)
        assertNull(c.state.copying)
        assertEquals(2, c.state.items.count { c.itemDetail(it.itemId)!!.vaultId == personal })
        assertEquals(ActionResult.Ok, c.saveVaultItemsToPersonal(shared), "a second run converges")
        assertEquals(4, c.state.items.size)
        assertEquals(ContentCopy.STILL_YOURS, c.removeFromDevice(personal).message())
        assertEquals(ActionResult.Ok, c.removeFromDevice(shared), "a vault that is no longer verified can be dropped here")
        assertEquals(2, c.state.items.size)
    }

    @Test
    fun recentlyRemoved_isReadable_copiedOut_andRemovedFromThisDevice() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.addSharedVault(shared, "Family", VaultAccess.ROLE_WRITER, VaultStanding.VERIFIED)
        c.addSharedVault(readOnly, "Club", VaultAccess.ROLE_WRITER, VaultStanding.VERIFIED)
        val id = c.seedLogin(shared, "Door", "", "1234", "")
        c.seedLogin(readOnly, "Gym", "", "", "")
        c.holdVault(shared, ItemNotice.DELETED, readable = true)
        c.holdVault(readOnly, ItemNotice.REMOVED, readable = false)
        assertTrue(c.state.items.isEmpty())
        val rows = c.state.held
        assertEquals(listOf("Family", ""), rows.map { it.name })
        val kept = io.silencelen.andvari.core.app.CopyKey.HELD_KEPT_UNTIL.english.substringBefore("{0}")
        assertTrue(rows[0].line.startsWith(io.silencelen.andvari.core.app.CopyKey.HELD_DELETED_BY_OWNER.english.substringBefore("{0}") + kept), rows[0].line)
        assertTrue(rows[1].line.startsWith(io.silencelen.andvari.core.app.CopyKey.HELD_ACCESS_REMOVED.english.substringBefore("{0}") + kept), rows[1].line)
        assertEquals(listOf("Door"), c.heldItems(shared).map { it.name })
        assertTrue(c.heldItems(readOnly).isEmpty())
        assertEquals("1234", c.revealSecret(id, SecretField.PASSWORD), "a held copy can still be read")
        assertFalse(c.itemDetail(id)!!.editable)
        assertEquals(ContentCopy.ITEM_GONE, c.saveLogin(id, login("Door2"), null).message())
        assertEquals(ContentCopy.VAULT_NOT_OPEN, c.saveVaultItemsToPersonal(readOnly).message())
        assertEquals(ActionResult.Ok, c.saveVaultItemsToPersonal(shared))
        assertEquals(ContentCopy.copiedOutOfHeld(1, 0), c.state.notice)
        assertEquals(listOf("Door"), c.state.items.map { it.name })
        assertEquals(ActionResult.Ok, c.removeFromDevice(shared))
        assertEquals(1, c.state.held.size)
    }

    @Test
    fun onlyTheOwnerRenamesASharedVault() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.addSharedVault(shared, "Family", VaultAccess.ROLE_OWNER, VaultStanding.VERIFIED)
        c.addSharedVault(readOnly, "Club", VaultAccess.ROLE_WRITER, VaultStanding.VERIFIED)
        assertEquals(ContentCopy.VAULT_NAME_REQUIRED, c.renameSharedVault(shared, "  ").message())
        assertEquals(ContentCopy.NOT_VAULT_OWNER, c.renameSharedVault(readOnly, "Mine").message())
        assertEquals(ContentCopy.VAULT_NOT_OPEN, c.renameSharedVault(personal, "Mine").message(), "the personal vault is not renamed here")
        assertEquals(ActionResult.Ok, c.renameSharedVault(shared, " Home "))
        assertEquals("Home", c.vaultName(shared))
    }

    @Test
    fun aCsvImport_isPlannedAgainstTheVault_retriedWithoutDuplicates_andSentToTheChosenVault() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.addSharedVault(shared, "Family", VaultAccess.ROLE_WRITER, VaultStanding.VERIFIED)
        c.seedLogin(personal, "GH", "jordan", "pw", "https://gh.test")
        val csv = "name,url,username,password,note\nGH,https://gh.test,jordan,pw,hi\nNT,https://n.test,ana,pw2,\n".encodeToByteArray()
        assertEquals(ActionResult.Ok, c.importCsv(csv))
        assertTrue(csv.all { it == 0.toByte() }, "the file's bytes are zeroed once read")
        val view = c.state.csvImport!!
        assertEquals("Chrome or another Chromium browser", view.source)
        assertEquals(1, view.toImport, "the login already in the vault is not imported again")
        assertEquals(listOf(personal, shared), view.vaultChoices.map { it.vaultId })
        assertEquals(ActionResult.Ok, c.setImportVault(shared))
        assertEquals(2, c.state.csvImport!!.toImport, "planned again against the other vault")
        c.failNextWith(ItemFailure.Unreachable(io.silencelen.andvari.core.client.net.NoAnswerKind.TRANSPORT))
        c.confirmImport()
        assertEquals("The import was interrupted. Retry finishes it without making duplicates.", c.state.csvImport!!.error)
        assertEquals(ActionResult.Ok, c.confirmImport())
        assertNotNull(c.state.csvImport!!.done)
        assertEquals(2, c.state.items.count { c.itemDetail(it.itemId)!!.vaultId == shared })
        c.closeImport()
        assertNull(c.state.csvImport)
        assertEquals("That file is larger than 10 MiB, far bigger than any real password export.", c.importCsv(ByteArray(10 * 1024 * 1024 + 1)).message())
        assertTrue(c.importCsv("not,a,known,header\n1,2,3,4\n".encodeToByteArray()).message().startsWith("This file isn't a password export"))
    }

    @Test
    fun aCsvExport_waitsForTheFormulaTick_andSaysWhatItSaved() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.seedLogin(personal, "Calc", "=1+1", "pw", "https://calc.test")
        c.seedNote(personal, "A note", "x")
        assertEquals(ActionResult.Ok, c.openExport(io.silencelen.andvari.core.app.ExportKind.CSV))
        val view = c.state.exporting!!
        assertEquals(1, view.count)
        assertEquals(1, view.formulaCells.size)
        assertNull(c.csvFile(false))
        assertEquals(io.silencelen.andvari.core.app.ExportCopy.FORMULA_ACK_NEEDED, c.state.exporting!!.error)
        val file = c.csvFile(true)!!
        assertTrue(file.bytes.decodeToString().contains("Calc"))
        c.exportSaved(file.fileName, "Downloads")
        assertTrue(c.state.exporting!!.done!!.contains("1 login"))
        c.setOffline(true)
        c.openExport(io.silencelen.andvari.core.app.ExportKind.CSV)
        assertTrue(c.state.exporting!!.offlineNote!!.startsWith("This device couldn't reach your server"))
        c.closeExport()
        assertNull(c.state.exporting)
    }

    @Test
    fun aBackup_needsAGoodPassphraseTypedTwice() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.seedLogin(personal, "Bank", "me", "pw", "")
        c.openExport(io.silencelen.andvari.core.app.ExportKind.BACKUP)
        assertNull(c.backupFile("abc", "abc"))
        assertEquals(io.silencelen.andvari.core.app.ExportCopy.PASSPHRASE_WEAK, c.state.exporting!!.error)
        assertNull(c.backupFile("correct horse battery staple", "correct horse battery stapler"))
        assertEquals(io.silencelen.andvari.core.app.ExportCopy.PASSPHRASES_DIFFER, c.state.exporting!!.error)
        assertNotNull(c.backupFile("correct horse battery staple", "correct horse battery staple"))
        assertFalse(c.state.exporting!!.busy)
    }

    @Test
    fun aBackupFromCharArrays_wipesThem_andASaveWithNoFolderReadsWell() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.seedLogin(personal, "Bank", "me", "pw", "")
        c.openExport(io.silencelen.andvari.core.app.ExportKind.BACKUP)
        val typed = "correct horse battery staple".toCharArray()
        val again = "correct horse battery staple".toCharArray()
        val file = assertNotNull(c.backupFileChars(typed, again))
        assertTrue(typed.all { it == 0.toChar() } && again.all { it == 0.toChar() }, "the screen's copies are zeroed")
        val weak = "abc".toCharArray()
        assertNull(c.backupFileChars(weak, "abc".toCharArray()))
        assertTrue(weak.all { it == 0.toChar() }, "zeroed on a refusal too")
        c.backupFileChars("correct horse battery staple".toCharArray(), "correct horse battery staple".toCharArray())
        c.exportSaved(file.fileName, "")
        assertEquals("Saved “${file.fileName}”: 1 item from 1 vault.", c.state.exporting!!.done)
        c.backupFileChars("correct horse battery staple".toCharArray(), "correct horse battery staple".toCharArray())
        c.exportSaved(file.fileName, "Downloads")
        assertEquals(io.silencelen.andvari.core.app.ExportCopy.backupSaved(file.fileName, "Downloads", 1, 1, 0), c.state.exporting!!.done, "word for word with a folder")
    }

    @Test
    fun vaultHealth_findsBreachedAndReusedPasswords_andMergesDuplicates() = runBlocking<Unit> {
        val c = FakeVaultContent()
        val a = c.seedLogin(personal, "Mail", "me", "hunter2", "https://mail.test")
        val b = c.seedLogin(personal, "Mail copy", "me", "hunter2", "https://mail.test")
        c.seedLogin(personal, "Bank", "me", "Very-long and unusual 9 passphrase!", "https://bank.test")
        c.addBreachedPassword("hunter2")
        assertNull(healthOf(c))
        c.openHealth()
        val h = healthOf(c)!!
        assertEquals(3, h.tiles.logins)
        assertEquals(2, h.passwords.count { it.reused > 0 })
        assertEquals(ActionResult.Ok, c.checkBreaches())
        val checked = healthOf(c)!!
        assertEquals(FakeContentSource.BREACH_COUNT, checked.passwords.single { it.itemId == a }.breaches)
        assertEquals(0L, checked.passwords.single { it.name == "Bank" }.breaches)
        assertEquals(2, checked.tiles.breached)
        val cluster = checked.duplicates.single()
        assertEquals(setOf(a, b), cluster.members.map { it.itemId }.toSet())
        assertEquals(ActionResult.Ok, c.mergeDuplicates(cluster.signature))
        assertEquals(2, c.state.items.size, "one copy went to the trash")
        assertEquals(1, c.trashedItems.size)
        c.closeHealth()
        assertNull(healthOf(c))
    }

    @Test
    fun aCheckRun_recordsVerdicts_andOffersTheTrashForAGoneLogin() = runBlocking<Unit> {
        val c = FakeVaultContent()
        val a = c.seedLogin(personal, "Old forum", "me", "pw1", "https://forum.test")
        c.seedLogin(personal, "Shop", "me", "pw2", "https://shop.test")
        c.openHealth()
        c.startCheckRun(neverCheckedOnly = true)
        assertNotNull(healthOf(c)!!.run)
        assertEquals(ContentCopy.SERVER_STOPPED, run {
            val s = FakeVaultContent()
            s.stopServer()
            s.openHealth()
            s.checkBreaches().message()
        })
        assertTrue(c.recordCheck(a, "maybe").message().isNotEmpty(), "a verdict must be one of the four")
        assertEquals(ActionResult.Ok, c.recordCheck(a, "gone"))
        assertEquals(a, healthOf(c)!!.offerDelete!!.itemId)
        assertEquals("gone", c.serverDoc(a)!!.check!!.result)
        assertEquals(ActionResult.Ok, c.trashGoneLogin())
        assertNull(c.itemDetail(a))
        c.stopCheckRun()
        assertNull(healthOf(c)!!.run)
    }

    @Test
    fun everyChangeIsANewRevision_andListenersHearIt() = runBlocking<Unit> {
        val c = FakeVaultContent()
        val seen = ArrayList<Long>()
        val sub = c.observe { seen += it.revision }
        c.setQuery("x")
        c.saveLogin(null, login("A"), null)
        assertTrue(seen.zipWithNext().all { (a, b) -> b > a })
        assertTrue(seen.size >= 4, "busy, then done")
        sub.close()
        val n = seen.size
        c.setQuery("")
        assertEquals(n, seen.size)
    }
}
