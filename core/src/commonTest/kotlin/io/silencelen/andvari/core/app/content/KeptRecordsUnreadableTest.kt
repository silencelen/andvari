package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.BlobStore
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.InMemoryBlobs
import io.silencelen.andvari.core.app.InMemoryFillSnapshots
import io.silencelen.andvari.core.app.InMemorySaveQueue
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.SaveQueue
import io.silencelen.andvari.core.app.SaveQueueStore
import io.silencelen.andvari.core.client.items.ItemRig
import io.silencelen.andvari.core.client.items.VaultAccess
import io.silencelen.andvari.core.client.items.VaultStanding
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.wire.MutationOp
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.core.trust.VerifiedGenesis
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A kept record that cannot be read (the host's storage failed) is unknown, never empty.
 * Nothing is replaced and nothing is swept, the operation that needed it answers a refusal a screen can show, and a
 * later read that works finds everything as it was.
 */
class KeptRecordsUnreadableTest {
    /** A record whose reads fail while [failing] (a disk error); writes and deletes still reach it. */
    private class FlakyRecord : FillSnapshotStore {
        val inner = InMemoryFillSnapshots()
        var failing = false
        override fun write(bytes: ByteArray): Boolean = inner.write(bytes)
        override fun read(): ByteArray? = if (failing) throw IllegalStateException("I/O error") else inner.read()
        override fun delete() = inner.delete()
        val bytes: ByteArray? get() = inner.bytes
    }

    /** Files whose reads (one file, or the list of them) fail while [failing]. */
    private class FlakyBlobs : BlobStore {
        val inner = InMemoryBlobs()
        var failing = false
        override fun put(id: String, bytes: ByteArray): Boolean = inner.put(id, bytes)
        override fun get(id: String): ByteArray? = if (failing) throw IllegalStateException("I/O error") else inner.get(id)
        override fun delete(id: String) = inner.delete(id)
        override fun ids(): List<String> = if (failing) throw IllegalStateException("I/O error") else inner.ids()
        override fun clear() = inner.clear()
    }

    /** The extensions' queue, whose entries cannot be listed while [failing]. */
    private class FlakyQueue(val inner: InMemorySaveQueue = InMemorySaveQueue()) : SaveQueueStore by inner {
        var failing = false
        override fun entries(): Map<String, ByteArray> = if (failing) throw IllegalStateException("I/O error") else inner.entries()
    }

    private class Stores {
        val moves = FlakyRecord()
        val keptSaves = FlakyRecord()
        val files = FlakyBlobs()
        val applied = FlakyRecord()
        val queue = FlakyQueue()
    }

    private fun unlock(r: ItemRig): OpenedAccount {
        val seed = ByteArray(32) { 4 }
        val identity = r.crypto.boxKeypairFromSeed(seed)
        val genesis = VerifiedGenesis(GenesisFields(r.userId, Bytes.toB64(identity.publicKey), "instance", r.personal, 0), "00".repeat(32))
        return OpenedAccount(r.userId, ByteArray(32) { 1 }, identity, r.crypto.signKeypairFromSeed(seed), genesis, r.personal, ByteArray(32) { 7 })
    }

    private class TestHost(val r: ItemRig) : ContentHost {
        override fun wallMs(): Long = r.now
        override fun attachmentLimits() = AttachmentRules.limits(null, null)
        override fun origin(): String = "https://vault.example.com"
        override fun userId(): String = r.userId
        override fun accountId(): String = "0123456789abcdef0123456789abcdef"
        override fun backupKdfParams(): KdfParams? = null
        override fun offlineCacheAllowed(): Boolean = true
    }

    private fun content(r: ItemRig, s: Stores, restarted: Boolean): EngineVaultContent {
        r.server.echo = true
        r.server.journal = true
        val engine = if (restarted) r.restarted() else r.engine
        return EngineVaultContent(engine, r.crypto, TestHost(r), ContentKeeping(unlock(r), s.moves, s.keptSaves, s.files, s.applied, s.queue))
    }

    private fun login(name: String) = LoginInput(name, "me", "pw", listOf("https://example.com"), "", "", false)

    @Test
    fun aKeptMoveThatCannotBeRead_isNeitherReplacedNorPlannedAgain_andIsFinishedOnceItReads() = runBlocking<Unit> {
        val r = ItemRig()
        r.openShared()
        val s = Stores()
        val a = content(r, s, restarted = false)
        a.saveLogin(null, login("Wifi"), null)
        val id = a.state.items.single().itemId
        r.server.offlineAfterNextPush = true // the copy lands; the delete leg gets no answer
        assertEquals(ContentCopy.MOVE_RETRY, (a.moveOrCopyItem(id, r.shared, true) as ActionResult.Failed).message)
        val copyId = r.server.pushes.last().single().mutationId
        val kept = assertNotNull(s.moves.bytes)
        a.close()
        r.server.offline = false

        s.moves.failing = true
        val b = content(r, s, restarted = true)
        b.syncQuietly()
        val before = r.server.pushes.size
        assertEquals(ContentCopy.MOVES_UNREADABLE, (b.moveOrCopyItem(id, r.shared, true) as ActionResult.Failed).message)
        assertEquals(before, r.server.pushes.size, "no new plan: its copy would be a second one")
        assertContentEquals(kept, s.moves.bytes, "the record is not replaced")

        s.moves.failing = false
        assertEquals(ActionResult.Ok, b.moveOrCopyItem(id, r.shared, true))
        val replay = r.server.pushes.drop(before).flatten()
        assertEquals(listOf(copyId), replay.filter { it.op == MutationOp.PUT }.map { it.mutationId }, "the kept plan, read now, is replayed")
        assertEquals(1, b.state.items.size)
    }

    @Test
    fun keptSavesThatCannotBeRead_areNeitherSweptNorReplaced_andAreFinishedOnceTheyRead() = runBlocking<Unit> {
        val r = ItemRig()
        val s = Stores()
        val a = content(r, s, restarted = false)
        a.openAttachmentDraft(null)
        assertEquals(ActionResult.Ok, a.addAttachment("scan.pdf", "page one".encodeToByteArray()))
        r.server.offline = true
        a.saveLogin(null, login("Passport"), null)
        val kept = assertNotNull(s.keptSaves.bytes)
        assertEquals(1, s.files.inner.ids().size)
        a.close()
        r.server.offline = false

        s.keptSaves.failing = true
        val b = content(r, s, restarted = true)
        b.syncQuietly()
        assertEquals(ContentCopy.KEPT_SAVES_UNREADABLE, b.state.notice)
        assertEquals(1, s.files.inner.ids().size, "nothing is swept while the saves that name the files cannot be read")
        assertContentEquals(kept, s.keptSaves.bytes)
        assertTrue(r.server.attachments.isEmpty())
        // A new save with a file is refused rather than written over the record it could not read.
        b.openAttachmentDraft(null)
        b.addAttachment("other.txt", "x".encodeToByteArray())
        assertEquals(ContentCopy.KEPT_SAVES_UNREADABLE, (b.saveLogin(null, login("Other"), null) as ActionResult.Failed).message)
        assertContentEquals(kept, s.keptSaves.bytes)
        b.closeAttachmentDraft()

        s.keptSaves.failing = false
        assertEquals(ActionResult.Ok, b.syncQuietly())
        assertEquals(ContentCopy.KEPT_SAVE_DONE, b.state.notice)
        val item = b.state.items.single()
        assertEquals("page one", b.readAttachment(item.itemId, r.server.attachments.keys.single()).bytes!!.decodeToString())
    }

    @Test
    fun aFileSetAsideThatCannotBeRead_doesNotGiveItsSaveUp() = runBlocking<Unit> {
        val r = ItemRig()
        val s = Stores()
        val a = content(r, s, restarted = false)
        a.openAttachmentDraft(null)
        a.addAttachment("scan.pdf", "page one".encodeToByteArray())
        r.server.offline = true
        a.saveLogin(null, login("Passport"), null)
        a.close()
        r.server.offline = false

        s.files.failing = true
        val b = content(r, s, restarted = true)
        b.syncQuietly()
        assertEquals(ContentCopy.savedLater("Passport"), b.state.notice)
        assertNotNull(s.keptSaves.bytes, "the save is kept, not given up")
        b.close()

        s.files.failing = false
        val c = content(r, s, restarted = true)
        assertEquals(ActionResult.Ok, c.syncQuietly())
        assertEquals(ContentCopy.KEPT_SAVE_DONE, c.state.notice)
        assertEquals(listOf("scan.pdf"), c.itemDetail(c.state.items.single().itemId)!!.attachments.map { it.name })
    }

    @Test
    fun anAppliedListThatCannotBeRead_isNeitherReplacedNorDismissed() = runBlocking<Unit> {
        val r = ItemRig()
        val s = Stores()
        val a = content(r, s, restarted = false)
        a.syncQuietly()
        SaveQueue.enqueue(s.queue, r.crypto, "https://shop.test/login", "ana", "s3cret", r.now, "safari")
        assertEquals(ActionResult.Ok, a.readSaveQueue())
        assertEquals(1, a.state.appliedSaves.size)
        val list = assertNotNull(s.applied.bytes)
        a.close()

        s.applied.failing = true
        val b = content(r, s, restarted = true)
        b.syncQuietly()
        SaveQueue.enqueue(s.queue, r.crypto, "https://news.test/login", "ana", "other", r.now, "safari")
        assertEquals(ContentCopy.SAVES_LIST_UNREADABLE, (b.readSaveQueue() as ActionResult.Failed).message)
        assertEquals(1, s.queue.inner.map.size, "the capture waits in the queue")
        assertEquals(1, b.state.items.size, "nothing is applied over a list that was not read")
        assertEquals(ContentCopy.SAVES_LIST_UNREADABLE, (b.dismissAppliedSaves() as ActionResult.Failed).message)
        assertContentEquals(list, s.applied.bytes, "neither replaced nor removed")

        s.applied.failing = false
        assertEquals(ActionResult.Ok, b.readSaveQueue())
        assertEquals(setOf("shop.test", "news.test"), b.state.appliedSaves.map { it.host }.toSet(), "the earlier save is still listed, with its undo")
    }

    @Test
    fun aQueueThatCannotBeListed_leavesWhatIsListedAsItWas() = runBlocking<Unit> {
        val r = ItemRig()
        val s = Stores()
        val a = content(r, s, restarted = false)
        a.syncQuietly()
        r.keys.put(r.personal, r.personalKey, VaultAccess.ROLE_OWNER, VaultStanding.FROZEN)
        SaveQueue.enqueue(s.queue, r.crypto, "https://shop.test", "ana", "s3cret", r.now, "safari")
        a.readSaveQueue()
        val pending = a.state.pendingSaves.single().id
        s.queue.failing = true
        assertEquals(ContentCopy.SAVES_LIST_UNREADABLE, (a.readSaveQueue() as ActionResult.Failed).message)
        assertEquals(listOf(pending), a.state.pendingSaves.map { it.id }, "unknown is not empty")
        assertEquals(1, s.queue.inner.map.size)
    }
}
