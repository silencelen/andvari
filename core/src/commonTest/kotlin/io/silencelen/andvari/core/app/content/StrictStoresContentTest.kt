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
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.core.trust.VerifiedGenesis
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Stores like the iPhone's: their old readers swallow a read that failed as "not there" (the extensions rely on that),
 * and their strict readers ([StrictRecordStore], [StrictBlobStore], [StrictSaveQueueStore]) throw instead. The vault's
 * content reads through the strict ones, so a record it could not read is unknown, never empty, on such a
 * store too. Before, the content asked the old readers and took the failure for an empty record.
 */
class StrictStoresContentTest {
    /** A record whose reads fail while [failing]: [read] answers null as the iPhone's does, [readOrThrow] throws. */
    private class SwallowingRecord : FillSnapshotStore, StrictRecordStore {
        val inner = InMemoryFillSnapshots()
        var failing = false
        override fun write(bytes: ByteArray): Boolean = inner.write(bytes)
        override fun read(): ByteArray? = if (failing) null else inner.read()
        override fun readOrThrow(): ByteArray? = StrictReads.value("the record", { if (failing) null else inner.read() }) { inner.bytes != null }
        override fun delete() = inner.delete()
        val bytes: ByteArray? get() = inner.bytes
    }

    /** Files whose reads fail while [failing]: the old readers answer null and empty, the strict ones throw. */
    private class SwallowingBlobs : BlobStore, StrictBlobStore {
        val inner = InMemoryBlobs()
        var failing = false
        override fun put(id: String, bytes: ByteArray): Boolean = inner.put(id, bytes)
        override fun get(id: String): ByteArray? = if (failing) null else inner.get(id)
        override fun getOrThrow(id: String): ByteArray? = StrictReads.value("a file", { get(id) }) { id in inner.ids() }
        override fun delete(id: String) = inner.delete(id)
        override fun ids(): List<String> = if (failing) emptyList() else inner.ids()
        override fun idsOrThrow(): List<String> = StrictReads.names("the files", { if (failing) null else inner.ids() }) { true }
        override fun clear() = inner.clear()
    }

    /** The extensions' queue, whose listing fails while [failing]: [entries] answers empty, [entriesOrThrow] throws. */
    private class SwallowingQueue(val inner: InMemorySaveQueue = InMemorySaveQueue()) : SaveQueueStore by inner, StrictSaveQueueStore {
        var failing = false
        override fun entries(): Map<String, ByteArray> = if (failing) emptyMap() else inner.entries()
        override fun entriesOrThrow(): Map<String, ByteArray> = StrictReads.value("the queue", { if (failing) null else inner.entries() }) { true }.orEmpty()
    }

    private class Stores {
        val moves = SwallowingRecord()
        val keptSaves = SwallowingRecord()
        val files = SwallowingBlobs()
        val applied = SwallowingRecord()
        val queue = SwallowingQueue()
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
    fun theStrictRule_notThereOnlyWhenThereIsNothing() {
        val bytes = byteArrayOf(1, 2)
        assertContentEquals(bytes, StrictReads.value("r", { bytes }) { error("not asked when the read gave something") })
        assertNull(StrictReads.value<ByteArray>("r", { null }) { false }, "no file: not there")
        assertFailsWith<StoreUnreadableException> { StrictReads.value<ByteArray>("r", { null }) { true } }
        assertFailsWith<IllegalStateException> { StrictReads.value<ByteArray>("r", { throw IllegalStateException("I/O") }) { false } }
        assertEquals(emptyList(), StrictReads.names("d", { null }) { false }, "no directory: empty")
        assertFailsWith<StoreUnreadableException> { StrictReads.names("d", { null }) { true } }
        // A record removed between the read and the check is not there.
        var there = true
        assertNull(StrictReads.value<ByteArray>("r", { there = false; null }) { there })
    }

    @Test
    fun keptSavesThatCannotBeRead_onAStoreThatSwallows_areNeitherSweptNorReplaced() = runBlocking<Unit> {
        val r = ItemRig()
        val s = Stores()
        val a = content(r, s, restarted = false)
        a.openAttachmentDraft(null)
        assertEquals(ActionResult.Ok, a.addAttachment("scan.pdf", "page one".encodeToByteArray()))
        r.server.offline = true
        a.saveLogin(null, login("Passport"), null)
        val kept = assertNotNull(s.keptSaves.bytes)
        a.close()
        r.server.offline = false

        s.keptSaves.failing = true
        val b = content(r, s, restarted = true)
        b.syncQuietly()
        assertEquals(ContentCopy.KEPT_SAVES_UNREADABLE, b.state.notice)
        assertEquals(1, s.files.inner.ids().size, "nothing is swept")
        b.openAttachmentDraft(null)
        b.addAttachment("other.txt", "x".encodeToByteArray())
        assertEquals(ContentCopy.KEPT_SAVES_UNREADABLE, (b.saveLogin(null, login("Other"), null) as ActionResult.Failed).message)
        assertContentEquals(kept, s.keptSaves.bytes, "not written over")
        b.closeAttachmentDraft()

        s.keptSaves.failing = false
        assertEquals(ActionResult.Ok, b.syncQuietly())
        assertEquals(ContentCopy.KEPT_SAVE_DONE, b.state.notice)
    }

    @Test
    fun aFileSetAsideThatCannotBeRead_onAStoreThatSwallows_doesNotGiveItsSaveUp() = runBlocking<Unit> {
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
        assertEquals(listOf("scan.pdf"), c.itemDetail(c.state.items.single().itemId)!!.attachments.map { it.name })
    }

    @Test
    fun aQueueThatCannotBeListed_onAStoreThatSwallows_leavesWhatIsListed_andIsNotCarriedAsEmpty() = runBlocking<Unit> {
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

        // A followed move while the queue cannot be listed: not "carried, there was nothing".
        val before = s.queue.inner.map.keys.toSet()
        assertEquals(QueueEntries.Carried.NOT_ALL, QueueEntries.carry(s.queue, r.crypto, "https://vault.example.com", "https://vault2.example.com", r.userId))
        assertEquals(before, s.queue.inner.map.keys.toSet(), "every entry kept where it was")
    }

    @Test
    fun theStrictReaders_areOnlyAskedWhenAStoreOffersThem() {
        val plain = InMemoryFillSnapshots()
        assertTrue(plain.readKept().let { it is KeptRead.Read && it.value == null }, "a store without one: its old reader, as before")
        val strict = SwallowingRecord()
        strict.inner.write(byteArrayOf(9))
        strict.failing = true
        assertTrue(strict.readKept() is KeptRead.Unreadable)
        assertNull(strict.read(), "the old reader still answers as before")
    }
}
