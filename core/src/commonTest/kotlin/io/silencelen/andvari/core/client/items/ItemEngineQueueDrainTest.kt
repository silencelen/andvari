package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.WireItem
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** An in-memory cache that claims a durable queue, as the SQLite cache has. */
class DurableCache(private val d: InMemoryVaultCache = InMemoryVaultCache()) : VaultCache by d {
    override val durable: Boolean get() = true
}

/**
 * The durable outbound queue and its drain (spec 03 §5), ported from `SyncEngineQueueDrainTest` onto [ItemEngine] with
 * a fake transport: per-row `rejected`, the bisected whole-batch refusal, the count and byte bounds, transient failures,
 * success-as-queued over a durable queue only, and queue coalescing.
 */
class ItemEngineQueueDrainTest {
    @Test
    fun rejectedRow_isDroppedSiblingsLandAndThePullProceeds() = runBlocking<Unit> {
        val s = ItemRig()
        val good = s.planned("good")
        val poison = s.planned("poison")
        s.server.rejectItems[poison.itemId] = "unknown_attachment"
        val syncsBefore = s.server.syncs

        s.engine.importAll(listOf(good, poison)).ok()

        assertEquals(1, s.server.pushes.size, "one batch carried both rows")
        assertTrue(s.cache.pending().isEmpty(), "the rejected row is dropped durably, not left at the head of the queue")
        assertEquals(syncsBefore + 1, s.server.syncs, "the drain proceeded to the pull")
        val n = s.engine.notices().single()
        assertEquals(ItemNotice.WRITE_REJECTED, n.kind)
        assertEquals(1, n.count)
        assertEquals("unknown_attachment", n.reason)
        // And the queue is not wedged: the next cycle sends nothing and pulls again.
        s.engine.sync().ok()
        assertEquals(1, s.server.pushes.size)
        assertEquals(syncsBefore + 2, s.server.syncs)
    }

    @Test
    fun directSave_ofARejectedRow_reportsTheHonestReason() = runBlocking<Unit> {
        val s = ItemRig()
        val id = "11111111-2222-4333-8444-555555555555"
        s.server.rejectItems[id] = "attachment_mismatch"

        val e = assertIs<ItemFailure.Refused>(s.engine.save(null, s.doc, draftItemId = id).failure())
        assertEquals(400, e.status)
        assertEquals("attachment_mismatch", e.code)
        assertTrue(s.cache.pending().isEmpty())
        assertNull(s.engine.item(id), "nothing is projected for a row the server refused")
        assertEquals(ItemNotice.WRITE_REJECTED, s.engine.notices().single().kind)
        // The verdict is consumed by the save that sent it: a later background cycle is clean.
        s.engine.sync().ok()
        assertEquals(ItemNotice.WRITE_REJECTED, s.engine.notices().single().kind)
    }

    @Test
    fun wholeBatch400_isBisectedDownToThePoisonRow() = runBlocking<Unit> {
        val s = ItemRig()
        val items = (1..5).map { s.planned("item $it") }
        val poison = items[2]
        s.server.refuseBatchIfContains.add(poison.itemId)

        s.engine.importAll(items).ok()

        assertTrue(s.cache.pending().isEmpty(), "the poison row was isolated and dropped; nothing stays queued")
        assertEquals(items.filter { it !== poison }.map { it.itemId }.toSet(), s.server.applied(), "every healthy sibling landed")
        val n = s.engine.notices().single()
        assertEquals(ItemNotice.WRITE_REJECTED, n.kind)
        assertEquals(1, n.count)
        assertEquals("unknown_attachment", n.reason)
        assertEquals(4, s.server.pushes.flatten().size, "each healthy id was applied exactly once")
    }

    @Test
    fun oversizedRow413_isDroppedAloneAndTheQueueDrains() = runBlocking<Unit> {
        val s = ItemRig()
        s.server.refuseBodyOverBytes = 600_000
        val small1 = s.planned("small 1")
        val big = s.planned("big", noteBytes = 700_000)
        val small2 = s.planned("small 2")

        s.engine.importAll(listOf(small1, big, small2)).ok()

        assertTrue(s.cache.pending().isEmpty(), "the over-cap row is dropped, not left at the head of the queue")
        assertEquals(setOf(small1.itemId, small2.itemId), s.server.applied())
        val n = s.engine.notices().single()
        assertEquals(ItemNotice.WRITE_REJECTED, n.kind)
        assertEquals("body_too_large", n.reason)
        // Later edits are no longer stuck behind it.
        s.engine.save(null, s.doc.copy(name = "after")).ok()
        assertTrue(s.cache.pending().isEmpty())
    }

    @Test
    fun batches_areBoundedByEncodedBytesNotOnlyByCount() = runBlocking<Unit> {
        val s = ItemRig()
        val twoMiB = 2 * 1024 * 1024
        val items = (1..3).map { s.planned("big $it", noteBytes = twoMiB) }

        s.engine.importAll(items).ok()

        assertEquals(listOf(2, 1), s.server.pushes.map { it.size }, "three ~2.7 MiB rows split under the 6 MiB soft cap")
        for (p in s.server.pushes) {
            val bytes = p.sumOf { (it.item?.blob?.length ?: 0).toLong() }
            assertTrue(bytes <= ItemEngine.PUSH_BODY_SOFT_CAP_BYTES, "batch blob bytes $bytes under the soft cap")
        }
        assertTrue(s.cache.pending().isEmpty())
    }

    @Test
    fun aBatchIsNeverLargerThanTheServersCount() = runBlocking<Unit> {
        val s = ItemRig()
        s.engine.importAll((1..450).map { s.planned("n$it") }).ok()
        assertEquals(listOf(200, 200, 50), s.server.pushes.map { it.size })
    }

    @Test
    fun transientFailures_stillKeepTheRowsQueued() = runBlocking<Unit> {
        val s = ItemRig(DurableCache())
        s.server.offline = true
        assertEquals(Written.QUEUED, s.engine.save(null, s.doc).ok().outcome)
        assertEquals(1, s.cache.pending().size)
        assertEquals(ItemFailure.Unreachable(NoAnswerKind.TRANSPORT), s.engine.sync().failure(), "an offline sync says so; it is never reported as done")
        s.server.offline = false
        s.engine.sync().ok()
        assertTrue(s.cache.pending().isEmpty())
    }

    /** The poison path is `400 || 413` on purpose: a rate limit or a server hiccup must never discard a row. */
    @Test
    fun aFiveHundredOrATwentyNineOnThePush_keepsTheRowQueuedAndMintsNoRejectedNotice() = runBlocking<Unit> {
        for (status in listOf(500, 429, 503)) {
            val s = ItemRig(DurableCache())
            s.server.offline = true
            assertEquals(Written.QUEUED, s.engine.save(null, s.doc).ok().outcome)
            s.server.offline = false
            s.server.refuseWith = status to "transient_$status"
            val e = assertIs<ItemFailure.Refused>(s.engine.sync().failure(), "$status must surface as the transient failure it is")
            assertEquals(status, e.status)
            assertEquals(1, s.cache.pending().size, "$status: the row stays queued")
            assertTrue(s.engine.notices().none { it.kind == ItemNotice.WRITE_REJECTED }, "$status: nothing was refused")
            s.server.refuseWith = null
            s.engine.sync().ok()
            assertTrue(s.cache.pending().isEmpty(), "$status: drained once the server recovers")
        }
    }

    @Test
    fun offlineSave_onADurableCache_returnsQueued_projectsTheRow_andFlushesLater() = runBlocking<Unit> {
        val s = ItemRig(DurableCache())
        s.server.offline = true

        val saved = s.engine.save(null, s.doc.copy(name = "train wifi"), draftItemId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee").ok()

        assertEquals(Written.QUEUED, saved.outcome)
        val row = s.engine.items().single()
        assertEquals("train wifi", row.doc.name, "the queued save is visible in the list at once")
        assertEquals(0, row.rev)
        assertEquals(s.now, row.updatedAt, "stamped with the local clock, not the epoch")
        assertTrue(s.engine.hasPendingSync(row.itemId))
        assertEquals(setOf(row.itemId), s.engine.pendingSyncItemIds())
        assertNotNull(s.engine.item(row.itemId))
        // An offline EDIT of the queued (never-sent) item is the SAME new item: one row, not two puts.
        assertEquals(Written.QUEUED, s.engine.save(row.itemId, s.doc.copy(name = "train wifi 2"), s.personal).ok().outcome)
        assertEquals("train wifi 2", s.engine.item(row.itemId)?.doc?.name)
        assertEquals(1, s.cache.pending().size, "the older queued put of a never-sent new item is coalesced away")
        s.server.offline = false
        s.engine.sync().ok()
        assertTrue(s.cache.pending().isEmpty())
        assertEquals(1, s.server.pushes.flatten().size, "exactly one put reached the server")
        assertEquals("train wifi 2", s.pushedDoc(s.server.pushes.single().single()).name)
        assertFalse(s.engine.hasPendingSync(row.itemId))
    }

    @Test
    fun removingAQueuedNewItem_dropsItsQueuedPut_andNothingReachesTheServer() = runBlocking<Unit> {
        val s = ItemRig(DurableCache())
        s.server.offline = true
        val id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        assertEquals(Written.QUEUED, s.engine.save(null, s.doc, draftItemId = id).ok().outcome)
        assertEquals(Written.APPLIED, s.engine.remove(id).ok())
        assertTrue(s.cache.pending().isEmpty())
        assertTrue(s.engine.items().isEmpty())
        s.server.offline = false
        s.engine.sync().ok()
        assertTrue(s.server.pushes.isEmpty())
    }

    /** One server-confirmed item at global rev 6, on both sides. */
    private fun ItemRig.seedItem(id: String, name: String = "Router") {
        server.rev = 6
        serve(itemRow(id, personal, personalKey, doc.copy(name = name), rev = 6))
        runBlocking { engine.sync().ok() }
    }

    @Test
    fun offlineEditAndDelete_onADurableCache_projectIntoTheList() = runBlocking<Unit> {
        val s = ItemRig(DurableCache())
        val id = s.id()
        s.seedItem(id)
        assertEquals("Router", s.engine.item(id)?.doc?.name)

        s.server.offline = true
        assertEquals(Written.QUEUED, s.engine.save(id, s.doc.copy(name = "Router (edited offline)"), s.personal).ok().outcome)
        assertEquals("Router (edited offline)", s.engine.item(id)?.doc?.name, "the queued edit overlays the cached row")
        assertEquals(6, s.engine.item(id)?.rev, "the overlay keeps the server rev: last-writer-wins stays server-relative")
        assertEquals(Written.QUEUED, s.engine.remove(id).ok())
        assertNull(s.engine.item(id), "a queued delete hides the row")
        assertTrue(s.engine.items().none { it.itemId == id })
    }

    @Test
    fun twoOfflineEditsOfOneItem_drainAsASinglePut_atTheOriginalBaseRev() = runBlocking<Unit> {
        val s = ItemRig(DurableCache())
        val id = s.id()
        s.seedItem(id)
        val pushesBefore = s.server.pushes.size

        s.server.offline = true
        assertEquals(Written.QUEUED, s.engine.save(id, s.doc.copy(name = "draft 1"), s.personal).ok().outcome)
        assertEquals(Written.QUEUED, s.engine.save(id, s.doc.copy(name = "draft 2"), s.personal).ok().outcome)
        assertEquals(1, s.cache.pending().size, "the two queued puts of one item coalesce into one")
        assertEquals("draft 2", s.engine.item(id)?.doc?.name, "the list shows the LATEST draft")

        s.server.offline = false
        s.engine.sync().ok()

        val sent = s.server.pushes.drop(pushesBefore).flatten()
        assertEquals(1, sent.size, "exactly one put reached the server")
        assertEquals(6L, sent.single().baseItemRev, "sent at the base the burst was minted against, not a bumped one")
        assertEquals("draft 2", s.pushedDoc(sent.single()).name, "and it carries the newest draft")
        assertFalse(s.server.itemRows.getValue(id).conflict, "the server graded it a clean write")
        assertEquals(setOf(id), s.server.itemRows.keys, "no junk copy of the user's own draft was created")
        assertTrue(s.cache.pending().isEmpty())
    }

    @Test
    fun coalescingKeepsTheOriginalBaseRev_soAPeersEditStillConflicts() = runBlocking<Unit> {
        val s = ItemRig(DurableCache())
        val id = s.id()
        s.seedItem(id)

        s.server.offline = true
        assertEquals(Written.QUEUED, s.engine.save(id, s.doc.copy(name = "draft 1"), s.personal).ok().outcome)
        // A pull that succeeded while the push leg stayed down: the peer's row is the cache's truth and the server's,
        // and our queued put still carries base 6.
        val peer = s.itemRow(id, s.personal, s.personalKey, s.doc.copy(name = "peer edit"), rev = 9)
        s.cache.upsertItem(
            WireItem(id, s.personal, 9, 0, 0, false, false, peer.formatVersion, emptyList(), peer.blob),
            VaultItem(id, s.personal, 9, 0, s.doc.copy(name = "peer edit")),
        )
        s.server.itemRows[id] = peer
        s.server.rev = 9

        assertEquals(Written.QUEUED, s.engine.save(id, s.doc.copy(name = "draft 2"), s.personal).ok().outcome)
        assertEquals(1, s.cache.pending().size)
        assertEquals(6L, s.cache.pending().single().baseItemRev, "the burst's original base, NOT the peer's rev 9")

        s.server.offline = false
        s.engine.sync().ok()

        assertTrue(s.server.itemRows.getValue(id).conflict, "the server saw a genuine cross-device conflict")
        val copy = assertNotNull(s.server.pushes.flatten().find { it.itemId != id && it.op == "put" }, "the peer's displaced edit is preserved as a conflict copy")
        val copyName = s.pushedDoc(copy).name
        assertTrue(copyName.startsWith("peer edit"), "the copy carries the PEER's value, not our draft: $copyName")
        assertTrue(copyName.contains("(conflict "))
        assertEquals(io.silencelen.andvari.core.client.ConflictCopy.id(s.crypto, id, s.server.itemRows.getValue(id).rev), copy.itemId, "the copy id is the vector-pinned derivation")
    }

    /** One queued offline edit ("draft 1", base 6) of a server-confirmed item, then a save WITH an upload, back online. */
    private suspend fun ItemRig.queuedDraftThenUpload(id: String, onUpload: () -> Unit): ItemResult<SavedItem> {
        server.offline = true
        assertEquals(Written.QUEUED, engine.save(id, doc.copy(name = "draft 1"), personal).ok().outcome)
        server.offline = false
        server.onUpload = onUpload
        val ref = AttachmentRef(id(), "note.txt", 3, Bytes.toB64(crypto.randomBytes(32)))
        return engine.save(id, doc.copy(name = "draft 2", attachments = listOf(ref)), personal, listOf(NewAttachment(ref, "abc".encodeToByteArray()))).also { server.onUpload = null }
    }

    @Test
    fun aSealThatRefusesAfterTheFold_leavesTheOfflineBacklogQueued_andItStillDrains() = runBlocking<Unit> {
        val s = ItemRig(DurableCache())
        val id = s.id()
        s.seedItem(id)
        val res = s.queuedDraftThenUpload(id) { s.cache.setItemHome(id, s.id()) }
        assertEquals(ItemFailure.NotAllowed(ItemRefusal.ITEM_CHANGED_VAULTS), res.failure(), "the seal refused")
        val left = s.cache.pending()
        assertEquals(1, left.size, "the folded offline edit is still queued, not destroyed by a refused seal")
        assertEquals(6L, left.single().baseItemRev)

        // Once the item is home again, the backlog drains as it would have: draft 1, once, at the original base.
        s.cache.setItemHome(id, s.personal)
        val pushesBefore = s.server.pushes.size
        s.engine.sync().ok()
        val sent = s.server.pushes.drop(pushesBefore).flatten()
        assertEquals(listOf("draft 1"), sent.map { s.pushedDoc(it).name })
        assertEquals(6L, sent.single().baseItemRev)
        assertTrue(s.cache.pending().isEmpty())
    }

    @Test
    fun aSealWithNoKeyAfterTheFold_leavesTheOfflineBacklogQueued() = runBlocking<Unit> {
        val s = ItemRig(DurableCache())
        val id = s.id()
        s.seedItem(id)
        val res = s.queuedDraftThenUpload(id) { s.keys.open.remove(s.personal) }
        assertIs<ItemFailure.NotAllowed>(res.failure(), "a seal with no vault key cannot succeed")
        val left = s.cache.pending()
        assertEquals(1, left.size, "the folded offline edit is still queued")
        assertEquals(6L, left.single().baseItemRev)
    }

    @Test
    fun offlineSave_onAnInMemoryCache_failsAndQueuesNothing() = runBlocking<Unit> {
        val s = ItemRig(InMemoryVaultCache())
        s.server.offline = true

        assertIs<ItemFailure.Unreachable>(s.engine.save(null, s.doc).failure(), "never promise a queue that does not exist")

        assertTrue(s.cache.pending().isEmpty(), "no ghost row for a later same-session flush to land after a hand re-save")
        assertTrue(s.engine.items().isEmpty())
    }

    @Test
    fun aFailedReconcilePull_doesNotFailALandedSave() = runBlocking<Unit> {
        val s = ItemRig(DurableCache())
        s.server.offlineAfterNextPush = true
        assertEquals(Written.APPLIED, s.engine.save(null, s.doc.copy(name = "landed")).ok().outcome)
        assertTrue(s.cache.pending().isEmpty())
        assertEquals(1, s.server.pushes.size)
        assertTrue(s.server.offline, "the reconcile pull did hit the dead network")
    }

    @Test
    fun aGenuineDenial_isDroppedAndReported_neverSilent() = runBlocking<Unit> {
        val s = ItemRig(DurableCache())
        s.server.denyVaults.add(s.personal)
        assertEquals(ItemFailure.Denied(1), s.engine.save(null, s.doc).failure(), "the vault is still this account's: the denial is genuine")
        assertTrue(s.cache.pending().isEmpty() && s.cache.stagedDenied().isEmpty(), "the row is dropped for good")
        assertTrue(s.engine.items().isEmpty())
        s.engine.sync().ok()
    }
}
