package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.ExportKind
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.SecretField
import io.silencelen.andvari.core.client.items.ItemRig
import io.silencelen.andvari.core.client.items.VaultAccess
import io.silencelen.andvari.core.client.items.VaultDeparture
import io.silencelen.andvari.core.model.wire.MutationOp
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** [EngineVaultContent] over the real item engine and a fake server: what a screen sees is what the engine did. */
class EngineVaultContentTest {
    private fun content(r: ItemRig): EngineVaultContent {
        r.server.echo = true
        return EngineVaultContent(r.engine, r.crypto, TestHost(r))
    }

    private class TestHost(val r: ItemRig) : ContentHost {
        override fun wallMs(): Long = r.now
        override fun attachmentLimits() = AttachmentRules.limits(null, null)
        override fun origin(): String = "https://vault.example.com"
        override fun userId(): String = r.userId
        override fun accountId(): String = "0123456789abcdef0123456789abcdef"
        override fun backupKdfParams(): KdfParams? = null
    }

    /** An answer that claims the personal vault away changes nothing, and the screen says so in its own words. */
    @Test
    fun anAnswerTakingThePersonalVaultAway_isRefusedAndSaid() = runBlocking<Unit> {
        val r = ItemRig()
        val c = content(r)
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("Bank"), null))
        r.server.queue.add(r.response(r.server.rev + 1, removed = listOf(r.personal)))
        assertEquals(ActionResult.Ok, c.refresh())
        assertEquals(listOf("Bank"), c.state.items.map { it.name })
        assertTrue(c.state.vaults.any { it.vaultId == r.personal }, "the vault stays")
        val said = c.state.vaultNotices.single()
        assertEquals(ContentCopy.PERSONAL_KEPT, said.text)
        assertTrue(said.warning)
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("Shop"), null), "saves go on")
        assertEquals(listOf("Bank", "Shop"), c.state.items.map { it.name })
    }

    @Test
    fun anImportLandsInTheVault_andABackupOpensAgain() = runBlocking<Unit> {
        val r = ItemRig()
        val c = content(r)
        val csv = "name,url,username,password,note\nGH,https://gh.test,jordan,pw,hi\nNT,https://n.test,ana,pw2,\n".encodeToByteArray()
        assertEquals(ActionResult.Ok, c.importCsv(csv))
        assertEquals(2, c.state.csvImport!!.toImport)
        assertEquals(ActionResult.Ok, c.confirmImport())
        assertTrue(c.state.csvImport!!.done != null)
        assertEquals(listOf("GH", "NT"), c.state.items.map { it.name })
        c.closeImport()
        assertEquals(ActionResult.Ok, c.openExport(ExportKind.BACKUP))
        assertEquals(2, c.state.exporting!!.count)
        val file = c.backupFile("correct horse battery staple", "correct horse battery staple")!!
        val opened = io.silencelen.andvari.core.client.Backup.open(r.crypto, "correct horse battery staple", file.bytes)
        assertEquals(listOf("GH", "NT"), opened.payload.items.map { it.doc.name }.sorted())
        c.exportSaved(file.fileName, "Downloads")
        assertTrue(c.state.exporting!!.done!!.startsWith("Saved “andvari-backup-"))
    }

    @Test
    fun aFileAddedInTheEditor_goesUpBeforeItsItem_andReadsBack() = runBlocking<Unit> {
        val r = ItemRig()
        val c = content(r)
        c.openAttachmentDraft(null)
        val bytes = "hello file".encodeToByteArray()
        assertEquals(ActionResult.Ok, c.addAttachment("dir/notes.txt", bytes))
        assertTrue(bytes.all { it == 0.toByte() }, "the plaintext is zeroed once encrypted")
        assertEquals(listOf("notes.txt"), c.state.attachmentDraft!!.added.map { it.name })
        r.server.offline = true
        assertEquals(ContentCopy.SAVE_FAILED_OFFLINE, c.saveLogin(null, login("Doc"), null).message())
        r.server.offline = false
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("Doc"), null), "the same editor tries again")
        assertEquals(1, r.server.attachments.size, "one file, under the id minted once")
        assertNull(c.state.attachmentDraft, "the editor's files went with its save")
        val item = c.state.items.single()
        val file = c.itemDetail(item.itemId)!!.attachments.single()
        assertEquals(r.server.attachments.keys.single(), file.id)
        val read = c.readAttachment(item.itemId, file.id)
        assertNull(read.error)
        assertEquals("hello file", read.bytes!!.decodeToString())
    }

    @Test
    fun aMove_copiesIntoTheSharedVault_thenDeletesTheOriginal() = runBlocking<Unit> {
        val r = ItemRig()
        r.openShared()
        val c = content(r)
        c.saveLogin(null, login("Wifi"), null)
        val id = c.state.items.single().itemId
        assertEquals(listOf(r.shared), c.moveTargets(id).map { it.vaultId })
        assertEquals(ActionResult.Ok, c.moveOrCopyItem(id, r.shared, true))
        assertEquals(ContentCopy.moved("Family"), c.state.notice)
        val last = r.server.pushes.takeLast(2).map { it.single() }
        assertEquals(listOf(MutationOp.PUT to r.shared, MutationOp.DELETE to r.personal), last.map { it.op to it.vaultId })
        assertEquals(r.shared, c.itemDetail(c.state.items.single().itemId)!!.vaultId)
    }

    @Test
    fun aDeletedVaultsHeldCopy_isCopiedOutThroughTheEngine() = runBlocking<Unit> {
        val r = ItemRig()
        val id = r.id()
        r.openShared(items = listOf(r.itemRow(id, r.shared, r.sharedKey)))
        val c = content(r)
        r.keys.onServed = { report -> if (r.shared in report.lostAccess) r.keys.depart(r.shared, VaultDeparture.DELETED) }
        r.server.queue.add(r.response(r.server.rev + 1, removed = listOf(r.shared)))
        c.refresh()
        val row = c.state.held.single()
        assertEquals("Family", row.name)
        assertTrue(row.readable)
        assertEquals(listOf("Router"), c.heldItems(r.shared).map { it.name })
        assertEquals(ActionResult.Ok, c.saveVaultItemsToPersonal(r.shared))
        val put = r.server.pushes.last().single()
        assertEquals(r.personal, put.vaultId)
        assertEquals("Router", r.pushedDoc(put).name)
        assertEquals(ActionResult.Ok, c.removeFromDevice(r.shared))
        assertTrue(c.state.held.isEmpty())
    }

    @Test
    fun theTrash_listsRestoresAndPurges_throughTheEngine() = runBlocking<Unit> {
        val r = ItemRig()
        val c = content(r)
        c.saveLogin(null, login("Gone"), null)
        val id = c.state.items.single().itemId
        c.saveLogin(id, LoginInput("Gone", "me", "pw2", emptyList(), "", "", false), null)
        assertEquals(ActionResult.Ok, c.openItemHistory(id))
        val v = c.state.history!!.versions.single()
        assertEquals("pw", c.historyPassword(id, v.rev))
        assertEquals(ActionResult.Ok, c.restoreItemVersion(id, v.rev))
        assertEquals(ContentCopy.VERSION_RESTORED, c.state.notice)
        assertEquals("pw", c.revealSecret(id, SecretField.PASSWORD))
        c.closeItemHistory()
        c.deleteItem(id)
        assertEquals(ActionResult.Ok, c.openTrash())
        val row = c.state.trash!!.single()
        assertEquals("Gone", row.name)
        assertTrue(row.canRestore && row.canPurge)
        assertEquals(ActionResult.Ok, c.restoreFromTrash(id))
        assertEquals(listOf("Gone"), c.state.items.map { it.name })
        c.deleteItem(id)
        c.openTrash()
        assertEquals(ActionResult.Ok, c.purgeFromTrash(id))
        assertEquals(listOf(id), r.server.purged)
        assertTrue(c.state.trash!!.isEmpty())
    }

    private fun login(name: String) = LoginInput(name, "me", "pw", listOf("https://example.com"), "", "", false)

    private fun ActionResult.message(): String = (this as? ActionResult.Failed)?.message ?: error("expected Failed, got $this")

    @Test
    fun aSavedLogin_isSealedIntoThePersonalVault_andListed() = runBlocking<Unit> {
        val r = ItemRig()
        val c = content(r)
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("Mail"), null))
        val put = r.server.pushes.flatten().single()
        assertEquals(MutationOp.PUT, put.op)
        assertEquals(r.personal, put.vaultId)
        assertEquals("Mail", r.pushedDoc(put).name)
        val row = c.state.items.single()
        assertEquals("Mail", row.name)
        assertFalse(row.pendingSync)
        assertEquals("pw", c.revealSecret(row.itemId, SecretField.PASSWORD))
        assertEquals(listOf(r.personal), c.vaultsForNewItems().map { it.vaultId })
        assertEquals(ActionResult.Ok, c.deleteItem(row.itemId))
        assertEquals(MutationOp.DELETE, r.server.pushes.flatten().last().op)
        assertTrue(c.state.items.isEmpty())
    }

    /**
     * The desktop's first run against a real server: a delete left "changes waiting to send: 1" and no notice until Sync.
     * The item leaves the detail the moment its delete is queued, so the detail view left composition and its scope, the
     * one running the delete, was cancelled while the push was on the wire. The intent now runs to its end: the delete is
     * sent and settled, nothing waits, and an offline one says so.
     */
    @Test
    fun aDeleteWhoseScreenLeavesWhileItIsOnTheWire_isSentAndSettled_orSaidQueued() = runBlocking<Unit> {
        for (offline in listOf(false, true)) {
            val r = ItemRig(io.silencelen.andvari.core.client.items.DurableCache())
            val c = content(r)
            c.saveLogin(null, login("Mail"), null)
            val id = c.state.items.single().itemId
            val entered = kotlinx.coroutines.CompletableDeferred<Unit>()
            val release = kotlinx.coroutines.CompletableDeferred<Unit>()
            r.server.pushEntered = entered
            r.server.pushRelease = release
            val job = launch { c.deleteItem(id) }
            entered.await()
            assertNull(c.itemDetail(id), "queued, the item is gone from its detail: the screen showing it leaves")
            job.cancel()
            r.server.offline = offline
            release.complete(Unit)
            job.join()
            assertTrue(c.state.items.isEmpty())
            if (offline) {
                assertEquals(1, c.state.queued)
                assertEquals(ContentCopy.SAVE_OFFLINE, c.state.notice, "a delete that waits says so")
            } else {
                assertEquals(MutationOp.DELETE, r.server.pushes.flatten().last().op, "the delete went")
                assertEquals(true, r.server.itemRows[id]?.deleted)
                assertEquals(0, c.state.queued, "nothing waits to be sent")
                assertTrue(r.engine.pendingSyncItemIds().isEmpty())
            }
        }
    }

    /**
     * A write runs to its end after its screen left, and its answer then reaches nobody: a refusal it carries is the
     * notice the next screen shows. Before, the save the server refused and the delete it denied were said to no one.
     */
    @Test
    fun aRefusalWhoseScreenLeftWhileItWasOnTheWire_isTheNoticeTheNextScreenShows() = runBlocking<Unit> {
        val r = ItemRig()
        val c = content(r)
        c.saveLogin(null, login("Mail"), null)
        val id = c.state.items.single().itemId
        r.server.rejectItems[id] = "item_too_large"
        val said = (c.saveLogin(id, login("Mail 2"), null) as ActionResult.Failed).message
        assertTrue(c.state.notice != said, "attended, the editor says it itself")

        suspend fun leaving(write: suspend () -> ActionResult) {
            c.dismissNotice()
            val entered = kotlinx.coroutines.CompletableDeferred<Unit>()
            val release = kotlinx.coroutines.CompletableDeferred<Unit>()
            r.server.pushEntered = entered
            r.server.pushRelease = release
            val job = launch { write() }
            entered.await()
            job.cancel()
            release.complete(Unit)
            job.join()
        }

        leaving { c.saveLogin(id, login("Mail 3"), null) }
        assertEquals(said, c.state.notice, "the refused save is said at the next screen")

        r.server.rejectItems.remove(id)
        r.server.denyVaults += r.personal
        val denied = (c.deleteItem(id) as ActionResult.Failed).message
        c.syncQuietly()
        leaving { c.deleteItem(id) }
        assertEquals(denied, c.state.notice, "the denied delete is said at the next screen")
        assertEquals(1, c.state.items.size, "and the item is still there")
    }

    @Test
    fun offlineOnACacheThatDiesWithTheSession_theSaveFailsHonestly() = runBlocking<Unit> {
        val r = ItemRig()
        val c = content(r)
        r.server.offline = true
        assertEquals(ContentCopy.SAVE_FAILED_OFFLINE, c.saveLogin(null, login("Lost"), null).message())
        assertEquals(0, c.state.queued, "nothing claims to be queued over a queue that will not survive")
        assertTrue(c.state.items.isEmpty())
        assertEquals(VaultSyncState.OFFLINE, c.state.sync)
    }

    @Test
    fun theFirstSyncShowsThisDevicesCopy_evenWithNoServer() = runBlocking<Unit> {
        val r = ItemRig()
        content(r).saveLogin(null, login("Cached"), null)
        r.server.offline = true
        val c = EngineVaultContent(r.restarted(), r.crypto, TestHost(r))
        assertEquals(ContentCopy.SYNC_OFFLINE, c.refresh().message())
        assertEquals(listOf("Cached"), c.state.items.map { it.name })
        assertEquals(VaultSyncState.OFFLINE, c.state.sync)
    }

    @Test
    fun aReaderSeesTheSharedVault_andCannotChangeIt() = runBlocking<Unit> {
        val r = ItemRig()
        val id = r.id()
        r.openShared(role = VaultAccess.ROLE_READER, items = listOf(r.itemRow(id, r.shared, r.sharedKey)))
        val c = content(r)
        assertEquals(listOf(r.personal), c.vaultsForNewItems().map { it.vaultId })
        assertEquals("Family", c.vaultName(r.shared))
        assertEquals(ContentVaultState.READER, c.state.vaults.single { it.vaultId == r.shared }.access)
        assertFalse(c.itemDetail(id)!!.editable)
        assertEquals(ContentCopy.VAULT_NOT_WRITABLE, c.saveLogin(null, login("X"), r.shared).message())
        assertEquals(ContentCopy.READ_ONLY, c.deleteItem(id).message())
        assertTrue(r.server.pushes.isEmpty())
    }

    @Test
    fun underAForkedPin_theCopyIsReadable_andNothingIsSent() = runBlocking<Unit> {
        val r = ItemRig()
        val c = content(r)
        c.saveLogin(null, login("Kept"), null)
        val id = c.state.items.single().itemId
        val sent = r.server.calls
        r.gate.forked = true
        c.reload()
        assertTrue(c.state.serverStopped)
        assertEquals(VaultSyncState.STOPPED, c.state.sync)
        assertEquals("pw", c.revealSecret(id, SecretField.PASSWORD))
        assertFalse(c.itemDetail(id)!!.editable)
        assertTrue(c.vaultsForNewItems().isEmpty())
        assertEquals(ContentCopy.SERVER_STOPPED, c.saveLogin(id, login("Changed"), null).message())
        assertEquals(ContentCopy.SERVER_STOPPED, c.deleteItem(id).message())
        assertEquals(ContentCopy.SERVER_STOPPED, c.refresh().message())
        assertEquals(sent, r.server.calls, "nothing reached the server")
        assertEquals(listOf("Kept"), c.state.items.map { it.name })
    }

    @Test
    fun aServerThatWentBackwards_isTheSyncState_andAWarningNotice() = runBlocking<Unit> {
        val r = ItemRig()
        val c = content(r)
        r.server.queue.add(r.response(3, items = listOf(r.itemRow(r.id(), r.personal, r.personalKey))))
        assertEquals(ContentCopy.ROLLBACK, c.refresh().message())
        assertEquals(VaultSyncState.ROLLBACK, c.state.sync)
        assertTrue(c.state.items.isEmpty(), "nothing of it was applied")
        assertTrue(c.state.vaultNotices.single().warning)
    }

    @Test
    fun aDeniedWrite_isNeverSilent() = runBlocking<Unit> {
        val r = ItemRig()
        val c = content(r)
        r.server.denyVaults.add(r.personal)
        assertEquals(ContentCopy.denied(1), c.saveLogin(null, login("No"), null).message())
    }
}
