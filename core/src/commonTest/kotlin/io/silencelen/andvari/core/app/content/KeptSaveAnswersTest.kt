package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.InMemoryBlobs
import io.silencelen.andvari.core.app.InMemoryFillSnapshots
import io.silencelen.andvari.core.app.InMemorySaveQueue
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.items.DurableCache
import io.silencelen.andvari.core.client.items.FakeItemServer
import io.silencelen.andvari.core.client.items.ItemFailure
import io.silencelen.andvari.core.client.items.ItemRig
import io.silencelen.andvari.core.client.items.VaultClosedReason
import io.silencelen.andvari.core.client.items.Written
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.core.trust.VerifiedGenesis
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A save with files that a lock cut short is finished by a later unlock. What the server answers then decides whether it
 * is kept or let go: only an answer that the change itself can never be taken lets it go, and then the line says so and
 * names what was lost. A session the server ended is not such an answer: the save stays kept, its files stay set aside,
 * and the account's next session finishes it. Over the real item engine.
 */
class KeptSaveAnswersTest {
    private class Stores {
        val moves = InMemoryFillSnapshots()
        val keptSaves = InMemoryFillSnapshots()
        val files = InMemoryBlobs()
        val applied = InMemoryFillSnapshots()
        val queue = InMemorySaveQueue()
    }

    private fun unlock(r: ItemRig): OpenedAccount {
        val seed = ByteArray(32) { 4 }
        val identity = r.crypto.boxKeypairFromSeed(seed)
        val genesis = VerifiedGenesis(GenesisFields(r.userId, Bytes.toB64(identity.publicKey), "instance", r.personal, 0), "00".repeat(32))
        return OpenedAccount(r.userId, ByteArray(32) { 1 }, identity, r.crypto.signKeypairFromSeed(seed), genesis, r.personal, ByteArray(32) { 7 })
    }

    private class TestHost(val r: ItemRig, val atRest: Boolean) : ContentHost {
        override fun wallMs(): Long = r.now
        override fun attachmentLimits() = AttachmentRules.limits(null, null)
        override fun origin(): String = "https://vault.example.com"
        override fun userId(): String = r.userId
        override fun accountId(): String = "0123456789abcdef0123456789abcdef"
        override fun backupKdfParams(): KdfParams? = null
        override fun offlineCacheAllowed(): Boolean = atRest
    }

    /** One unlock's content: a new item engine over the same cache and server, and the same stores on the device. */
    private fun content(r: ItemRig, s: Stores, restarted: Boolean, atRest: Boolean = false): EngineVaultContent {
        r.server.echo = true
        r.server.journal = true
        return EngineVaultContent(if (restarted) r.restarted() else r.engine, r.crypto, TestHost(r, atRest), ContentKeeping(unlock(r), s.moves, s.keptSaves, s.files, s.applied, s.queue))
    }

    private fun login(name: String) = LoginInput(name, "me", "pw", listOf("https://example.com"), "", "", false)

    /** A new item "Passport" with one file, whose save no answer cut short: kept, its file set aside. The content is closed. */
    private suspend fun keptSave(r: ItemRig, s: Stores, vaultId: String? = null, atRest: Boolean = false) {
        val a = content(r, s, restarted = false, atRest = atRest)
        a.openAttachmentDraft(null)
        assertEquals(ActionResult.Ok, a.addAttachment("scan.pdf", "page one".encodeToByteArray()))
        r.server.offline = true
        assertEquals(ContentCopy.SAVE_FAILED_OFFLINE, (a.saveLogin(null, login("Passport"), vaultId) as ActionResult.Failed).message)
        assertNotNull(s.keptSaves.bytes)
        assertEquals(1, s.files.ids().size)
        a.close()
        r.server.offline = false
    }

    /** The next unlock finishes it, with its file. */
    private suspend fun finishedWithItsFile(r: ItemRig, s: Stores, atRest: Boolean = false, why: String) {
        val c = content(r, s, restarted = true, atRest = atRest)
        assertEquals(ActionResult.Ok, c.syncQuietly(), why)
        assertEquals(ContentCopy.KEPT_SAVE_DONE, c.state.notice, why)
        val item = c.state.items.single { it.name == "Passport" }
        assertEquals(listOf("scan.pdf"), c.itemDetail(item.itemId)!!.attachments.map { it.name }, why)
        val ref = c.itemDetail(item.itemId)!!.attachments.single()
        assertEquals("page one", c.readAttachment(item.itemId, ref.id).bytes!!.decodeToString(), why)
        assertNull(s.keptSaves.bytes, "done: the record goes ($why)")
        assertTrue(s.files.ids().isEmpty(), "and the file set aside for it ($why)")
        c.close()
    }

    @Test
    fun aSessionTheServerEnded_keepsTheSaveAndItsFiles_andTheNextSignInFinishesIt() = runBlocking<Unit> {
        // The server ends the session as the file goes up, or as the item goes after its file landed.
        for (at in listOf("upload", "push")) {
            val r = ItemRig()
            val s = Stores()
            keptSave(r, s)
            val kept = s.keptSaves.bytes!!.copyOf()
            if (at == "upload") r.server.uploadRefuseWith = 401 to "session_revoked" else r.server.refuseWith = 401 to "session_revoked"

            val b = content(r, s, restarted = true)
            assertEquals(ActionResult.Ok, b.syncQuietly(), at)
            assertEquals(ContentCopy.savedLater("Passport", ItemFailure.Refused("session_revoked", 401)), b.state.notice, at)
            assertEquals(ContentCopy.fillNames(CopyKey.KEPT_SAVE_LATER_SIGN_IN, ContentCopy.Slot("Passport", true)), b.state.notice, at)
            assertTrue(kept.contentEquals(s.keptSaves.bytes), "the save is still kept, as it was ($at)")
            assertEquals(1, s.files.ids().size, "its file is still set aside ($at)")
            assertTrue(b.state.items.none { it.name == "Passport" }, at)
            b.close()

            // Signed in again, more than a day later: the server removed the upload no item named (the check's P1b).
            aDayLater(r, at)
            r.server.uploadRefuseWith = null
            r.server.refuseWith = null
            finishedWithItsFile(r, s, why = at)
        }
    }

    /**
     * The server keeps an upload that no item names for a day: a day and an hour pass on the driven clock, its hourly
     * sweep runs, and from then on it rejects a put that names a file it no longer holds.
     */
    private fun aDayLater(r: ItemRig, why: String) {
        r.now += FakeItemServer.ORPHAN_TTL_MS + 60 * 60 * 1000L
        r.server.checkAttachmentRefs = true
        r.server.sweepOrphans()
        assertTrue(r.server.attachments.isEmpty(), "the server removed the upload no item names ($why)")
    }

    /** The server holds a live "Passport" naming its one file, and holds that file. */
    private fun onTheServerWithItsFile(r: ItemRig, why: String) {
        val row = r.server.itemRows.values.singleOrNull { !it.deleted && it.attachmentIds.isNotEmpty() }
        assertNotNull(row, "the item landed ($why)")
        assertTrue(row.attachmentIds.all { it in r.server.attachments }, "with its file ($why)")
    }

    /**
     * On a copy kept at rest, finishing a kept save puts its file on the server, and then the server refuses the item's
     * change for now (it ended the session; a fault of its own). The change waits in the durable queue, and the record and
     * the file set aside stay until the item itself has landed: the next sign-in comes more than a day later, after the
     * server removed the upload no item named, and the file goes up again before the waiting change is sent. The item and
     * its file land, and only then do the record and the file go.
     */
    @Test
    fun onACopyKeptAtRest_aKeptSaveWhoseItemTheServerRefusesForNow_landsWithItsFile_atASignInMoreThanADayLater() = runBlocking<Unit> {
        for (answer in listOf(401 to "session_revoked", 503 to "unavailable")) {
            val why = "${answer.first}"
            val cache: VaultCache = DurableCache()
            val r = ItemRig(cache)
            val s = Stores()
            keptSave(r, s, atRest = true)
            r.server.refuseWith = answer
            val b = content(r, s, restarted = true, atRest = true)
            b.syncQuietly()
            assertEquals(ContentCopy.kept(Written.keptFor(ItemFailure.Refused(answer.second, answer.first))!!), b.state.notice, why)
            assertEquals(1, cache.pending().size, "the change waits in the durable queue ($why)")
            assertNotNull(s.keptSaves.bytes, "the record stays until the item has landed ($why)")
            assertEquals(1, s.files.ids().size, "and the file set aside for it ($why)")
            assertEquals(0, b.keptSavesWaiting(), "counted once, as the change in the queue ($why)")
            b.close()

            aDayLater(r, why)
            r.server.refuseWith = null
            val c = content(r, s, restarted = true, atRest = true)
            assertEquals(ActionResult.Ok, c.syncQuietly(), why)
            assertEquals(0, cache.pending().size, why)
            onTheServerWithItsFile(r, why)
            val item = c.state.items.single { it.name == "Passport" }
            val ref = c.itemDetail(item.itemId)!!.attachments.single()
            assertEquals("page one", c.readAttachment(item.itemId, ref.id).bytes!!.decodeToString(), why)
            assertEquals(ContentCopy.KEPT_SAVE_DONE, c.state.notice, why)
            assertNull(s.keptSaves.bytes, "landed: the record goes ($why)")
            assertTrue(s.files.ids().isEmpty(), "and the file set aside for it ($why)")
            c.close()
        }
    }

    /**
     * The editor's own save on a copy kept at rest: its file goes up, the server ends the session at the item, and the
     * change waits in the durable queue. The save stays kept with its file until the item has landed, whichever drain
     * sends the change at the next sign-in a day later: the sync, or a save of another item that drains the queue first.
     */
    @Test
    fun anEditorSaveAtRestWhoseItemMeetsAnEndedSession_landsWithItsFile_whicheverDrainSendsItADayLater() = runBlocking<Unit> {
        for (road in listOf("sync", "another save")) {
            val cache: VaultCache = DurableCache()
            val r = ItemRig(cache)
            val s = Stores()
            val a = content(r, s, restarted = false, atRest = true)
            a.openAttachmentDraft(null)
            assertEquals(ActionResult.Ok, a.addAttachment("scan.pdf", "page one".encodeToByteArray()), road)
            r.server.refuseWith = 401 to "session_revoked"
            assertEquals(ActionResult.Ok, a.saveLogin(null, login("Passport"), null), road)
            assertEquals(ContentCopy.kept(Written.KEPT_SESSION_ENDED), a.state.notice, road)
            assertEquals(1, cache.pending().size, road)
            assertNotNull(s.keptSaves.bytes, "kept until the item has landed ($road)")
            assertEquals(1, s.files.ids().size, road)
            a.close()

            aDayLater(r, road)
            r.server.refuseWith = null
            val c = content(r, s, restarted = true, atRest = true)
            if (road == "sync") assertEquals(ActionResult.Ok, c.syncQuietly(), road)
            else assertEquals(ActionResult.Ok, c.saveLogin(null, login("Bank"), null), road)
            assertEquals(0, cache.pending().size, road)
            onTheServerWithItsFile(r, road)
            c.syncQuietly()
            val item = c.state.items.single { it.name == "Passport" }
            val ref = c.itemDetail(item.itemId)!!.attachments.single()
            assertEquals("page one", c.readAttachment(item.itemId, ref.id).bytes!!.decodeToString(), road)
            assertNull(s.keptSaves.bytes, "landed: the record goes ($road)")
            assertTrue(s.files.ids().isEmpty(), road)
            c.close()
        }
    }

    /**
     * On a copy kept at rest, a kept save's change waits in the durable queue, and a later drain of this unlock sends it:
     * the server refuses it for good. The save is let go once, then and there, with the line that names what was lost; the
     * next sign-in sends nothing of it again. A refusal for now at that drain keeps it, as before. Before, nothing was said
     * at the drain, and every later sign-in finished the save afresh (its file uploaded and its item put again).
     */
    @Test
    fun aKeptSaveWhoseWaitingChangeTheServerRefusesForGood_isGivenUpOnceAndSaid_andNeverSentAgain() = runBlocking<Unit> {
        for (forNow in listOf(false, true)) {
            val why = if (forNow) "for now" else "for good"
            val cache: VaultCache = DurableCache()
            val r = ItemRig(cache)
            val s = Stores()
            keptSave(r, s, atRest = true)
            r.server.refuseWith = 503 to "unavailable"
            val b = content(r, s, restarted = true, atRest = true)
            b.syncQuietly()
            val newId = cache.pending().single().itemId
            assertNotNull(s.keptSaves.bytes, why)
            // A later sync of the same unlock drains the queue.
            r.server.refuseWith = if (forNow) 429 to "rate_limited" else null
            if (!forNow) r.server.rejectItems[newId] = "item_too_large"
            b.syncQuietly()
            if (forNow) {
                assertNotNull(s.keptSaves.bytes, "a refusal for now keeps it ($why)")
                assertEquals(1, s.files.ids().size, why)
                b.close()
                continue
            }
            val lost = ContentCopy.forFailure(ItemFailure.Refused("item_too_large", 400), ContentCopy.During.SAVE)
            assertEquals(ContentCopy.keptSaveGivenUp("Passport", newItem = true, files = 1, why = lost), b.state.notice, why)
            assertNull(s.keptSaves.bytes, "given up: the record goes ($why)")
            assertTrue(s.files.ids().isEmpty(), "and its file ($why)")
            assertTrue(cache.pending().isEmpty(), why)
            b.close()

            val uploads = r.server.uploadsTried.size
            val puts = r.server.pushes.flatten().count { it.itemId == newId }
            val c = content(r, s, restarted = true, atRest = true)
            assertEquals(ActionResult.Ok, c.syncQuietly(), why)
            assertEquals(uploads, r.server.uploadsTried.size, "no file is sent again ($why)")
            assertEquals(puts, r.server.pushes.flatten().count { it.itemId == newId }, "and no put ($why)")
            assertNull(c.state.notice, "said once ($why)")
            c.close()
        }
    }

    /** A save kept while its change waits in the queue is let go when the person deletes the item: it never brings it back. */
    @Test
    fun aKeptSaveWhoseChangeWaits_isLetGoWhenThePersonDeletesTheItem() = runBlocking<Unit> {
        val cache: VaultCache = DurableCache()
        val r = ItemRig(cache)
        val s = Stores()
        val a = content(r, s, restarted = false, atRest = true)
        a.openAttachmentDraft(null)
        assertEquals(ActionResult.Ok, a.addAttachment("scan.pdf", "page one".encodeToByteArray()))
        r.server.refuseWith = 503 to "unavailable"
        assertEquals(ActionResult.Ok, a.saveLogin(null, login("Passport"), null))
        assertNotNull(s.keptSaves.bytes)
        val id = a.state.items.single { it.name == "Passport" }.itemId
        assertEquals(ActionResult.Ok, a.deleteItem(id))
        assertNull(s.keptSaves.bytes, "the person deleted it: nothing is kept to send")
        assertTrue(s.files.ids().isEmpty())
        a.close()

        r.server.refuseWith = null
        val c = content(r, s, restarted = true, atRest = true)
        assertEquals(ActionResult.Ok, c.syncQuietly())
        assertTrue(c.state.items.none { it.name == "Passport" })
        assertTrue(r.server.itemRows.values.none { !it.deleted && it.attachmentIds.isNotEmpty() }, "never sent behind the person's back")
    }

    /** A vault closed for writing while a change of it waits opens again when that change settles: the save waits for it. */
    @Test
    fun aVaultClosedForWritingForNow_keepsTheSave() = runBlocking<Unit> {
        val r = ItemRig()
        r.openShared()
        val s = Stores()
        keptSave(r, s, vaultId = r.shared)
        r.engine.markClosedForWriting(r.shared, VaultClosedReason.DELETION_WAITING)
        val b = content(r, s, restarted = true)
        b.syncQuietly()
        assertEquals(ContentCopy.savedLater("Passport"), b.state.notice)
        assertNotNull(s.keptSaves.bytes)
        assertEquals(1, s.files.ids().size)
        b.close()

        r.engine.markClosedForWriting(r.shared, null)
        finishedWithItsFile(r, s, why = "opened again")
    }

    /**
     * A file set aside for the save that is no longer on this device is said as that, never as an item that is no longer
     * here; and a save let go for good says that andvari stopped trying and names what was lost.
     */
    @Test
    fun aSaveLetGoForGood_saysSoAndWhatWasLost_andAFileNoLongerOnTheDeviceIsSaidAsThat() = runBlocking<Unit> {
        run {
            val r = ItemRig()
            val s = Stores()
            keptSave(r, s)
            s.files.delete(s.files.ids().single())
            val b = content(r, s, restarted = true)
            b.syncQuietly()
            assertEquals(ContentCopy.keptSaveGivenUp("Passport", newItem = true, files = 1, why = ContentCopy.KEPT_FILE_NOT_ON_DEVICE), b.state.notice)
            assertEquals(ContentCopy.fillNames(CopyKey.KEPT_SAVE_GIVEN_UP_NEW, ContentCopy.Slot("Passport", true), ContentCopy.Slot(ContentCopy.KEPT_FILE_NOT_ON_DEVICE, true), ContentCopy.Slot(CopyKey.COUNT_FILES_ONE.english, false)), b.state.notice)
            assertFalse(b.state.notice!!.contains(ContentCopy.ITEM_GONE), "never \"this item is no longer here\"")
            assertNull(s.keptSaves.bytes, "let go")
        }
        run {
            // The server refuses the file for good (no write access to the vault any more).
            val r = ItemRig()
            val s = Stores()
            keptSave(r, s)
            r.server.uploadRefuseWith = 403 to "no_grant"
            val b = content(r, s, restarted = true)
            b.syncQuietly()
            val why = ContentCopy.forFailure(ItemFailure.Refused("no_grant", 403), ContentCopy.During.SAVE)
            assertEquals(ContentCopy.keptSaveGivenUp("Passport", newItem = true, files = 1, why = why), b.state.notice)
            assertNull(s.keptSaves.bytes)
            assertTrue(s.files.ids().isEmpty())
        }
    }

    @Test
    fun theGivenUpLineNamesTheChangesOfAnEditAndCountsTheFiles() {
        assertEquals(
            ContentCopy.fillNames(
                CopyKey.KEPT_SAVE_GIVEN_UP_EDIT, ContentCopy.Slot("Wifi", true), ContentCopy.Slot("Why.", true),
                ContentCopy.Slot(ContentCopy.fillNames(CopyKey.COUNT_FILES_MANY, ContentCopy.Slot("3", false)), false),
            ),
            ContentCopy.keptSaveGivenUp("Wifi", newItem = false, files = 3, why = "Why."),
        )
    }
}
