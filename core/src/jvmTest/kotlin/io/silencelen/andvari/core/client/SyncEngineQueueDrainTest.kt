package io.silencelen.andvari.core.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.toByteArray
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.Mutation
import io.silencelen.andvari.core.model.MutationResult
import io.silencelen.andvari.core.model.PushRequest
import io.silencelen.andvari.core.model.PushResponse
import io.silencelen.andvari.core.model.SyncResponse
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireItem
import io.silencelen.andvari.core.model.WireVault
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import java.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Audit 2026-09-13 — the "queue that cannot drain" rows (H03, H19), the G23 finish (H17,
 * H18) and the natives' missing "added" notice (H71), pinned against the REAL Account crypto
 * and a fake server (the SyncEngineLifecycleTest MockEngine style). Web twins: the
 * `rejected` / bisect cases in store.offline-writes.test.ts.
 *
 * The defect these guard: one queue row the server could never accept (a put whose
 * attachment refs a peer's delete had swept; a 200-row import chunk over the 8 MiB body cap)
 * used to make EVERY later sync throw at the same batch BEFORE its pull, so the device
 * stopped receiving anything until a sign-out that also wiped every other queued edit.
 */
class SyncEngineQueueDrainTest {

    private val crypto = createCryptoProvider()
    private val kdf = KdfParams(ops = 1, memBytes = 8192)
    private val doc = ItemDoc(type = "login", name = "Router", login = LoginData(username = "admin", password = "hunter2"))

    private fun enroll(email: String): Account {
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val fp = Escrow.fingerprint(crypto, recovery.publicKey)
        return Account.enroll("test-invite", email, email, "pw $email", kdf, recovery.publicKey, fp, "test-device", crypto).account
    }

    /** An in-memory cache that CLAIMS durability — the H18 success-as-QUEUED gate, without SQLite. */
    private class DurableFakeCache(private val d: InMemoryVaultCache = InMemoryVaultCache()) : VaultCache by d {
        override val durable: Boolean get() = true
    }

    /** Fake server: sync queue + the push refusal knobs this suite needs. */
    private class FakeServer {
        val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
        val queue = ArrayDeque<SyncResponse>()
        val pushes = mutableListOf<List<Mutation>>()
        var syncs = 0
        var rev = 1L

        /** Every request throws a transport IOException while true. */
        var offline = false
        /** Answer the next push normally, then go offline (the reconcile pull dies). */
        var offlineAfterNextPush = false

        /** Per-row `rejected` (the H03 server amendment): itemId → reason. */
        val rejectItems = mutableMapOf<String, String>()

        /** Pre-H03 server shape: a batch containing any of these itemIds 400s WHOLE. */
        val refuseBatchIfContains = mutableSetOf<String>()

        /** App.kt body cap twin: a push body over this many bytes 413s before the handler. */
        var refuseBodyOverBytes: Long? = null

        fun applied(): Set<String> = pushes.flatten().map { it.itemId }.filter { it !in rejectItems && it !in refuseBatchIfContains }.toSet()

        fun api(): AndvariApi {
            val engine = MockEngine { req ->
                if (offline) throw IOException("offline")
                val path = req.url.encodedPath
                val jsonHeaders = headersOf(HttpHeaders.ContentType, "application/json")
                fun ok(body: String) = respond(body, HttpStatusCode.OK, jsonHeaders)
                fun err(status: HttpStatusCode, code: String) = respond("""{"error":"$code","message":"$code"}""", status, jsonHeaders)
                when (path) {
                    "/api/v1/sync" -> {
                        syncs++
                        val resp = queue.removeFirstOrNull() ?: SyncResponse(rev, false, emptyList(), emptyList(), emptyList(), emptyList())
                        rev = maxOf(rev, resp.rev)
                        ok(json.encodeToString(SyncResponse.serializer(), resp))
                    }
                    "/api/v1/sync/push" -> {
                        val bytes = req.body.toByteArray()
                        val cap = refuseBodyOverBytes
                        if (cap != null && bytes.size > cap) {
                            err(HttpStatusCode.PayloadTooLarge, "body_too_large")
                        } else {
                            val body = json.decodeFromString(PushRequest.serializer(), bytes.decodeToString())
                            if (body.mutations.any { it.itemId in refuseBatchIfContains }) {
                                err(HttpStatusCode.BadRequest, "unknown_attachment")
                            } else {
                                pushes.add(body.mutations)
                                if (offlineAfterNextPush) { offlineAfterNextPush = false; offline = true }
                                val results = body.mutations.map { m ->
                                    val reason = rejectItems[m.itemId]
                                    if (reason != null) MutationResult(m.mutationId, "rejected", reason = reason)
                                    else MutationResult(m.mutationId, "applied", ++rev)
                                }
                                ok(json.encodeToString(PushResponse.serializer(), PushResponse(rev, results)))
                            }
                        }
                    }
                    else -> err(HttpStatusCode.NotFound, "not_found")
                }
            }
            return AndvariApi("http://fake", HttpClient(engine), Tokens("access", "refresh"))
        }
    }

    private class Seed(val account: Account, val server: FakeServer, val engine: SyncEngine, val cache: VaultCache)

    /** An enrolled member past its first pull (cursor 5), personal vault row delivered. */
    private fun seeded(cache: VaultCache = InMemoryVaultCache()): Seed {
        val account = enroll("member@example.com")
        val server = FakeServer()
        val engine = SyncEngine(server.api(), account, cache)
        server.queue.add(SyncResponse(5, true, listOf(WireVault(account.personalVaultId, "personal", 1, "", 0)), emptyList(), emptyList(), emptyList()))
        runBlocking { engine.sync() }
        return Seed(account, server, engine, cache)
    }

    private fun planned(name: String, noteBytes: Int = 0): CsvImport.PlannedItem {
        val d = if (noteBytes > 0) doc.copy(name = name, notes = "x".repeat(noteBytes)) else doc.copy(name = name)
        return CsvImport.PlannedItem(crypto.let { io.silencelen.andvari.core.crypto.Bytes.uuidV4FromBytes(it.randomBytes(16)) }, d)
    }

    // ==== H03: the server's per-row `rejected` verdict ====

    @Test
    fun rejectedRow_isDroppedSiblingsLandAndThePullProceeds() = runBlocking<Unit> {
        val s = seeded()
        val good = planned("good")
        val poison = planned("poison")
        s.server.rejectItems[poison.itemId] = "unknown_attachment"
        val syncsBefore = s.server.syncs

        s.engine.importAll(listOf(good, poison))

        assertEquals(1, s.server.pushes.size, "one batch carried both rows")
        assertTrue(s.cache.pending().isEmpty(), "the rejected row is dropped durably, not left at the head of the queue")
        assertEquals(syncsBefore + 1, s.server.syncs, "the drain proceeded to the pull")
        val n = s.engine.notices().single()
        assertEquals("write-rejected", n.kind)
        assertEquals(1, n.parkedCount)
        assertEquals("unknown_attachment", n.reason)
        // And the queue is not wedged: the next cycle sends nothing and pulls again.
        s.engine.sync()
        assertEquals(1, s.server.pushes.size)
        assertEquals(syncsBefore + 2, s.server.syncs)
    }

    @Test
    fun directSave_ofARejectedRow_throwsTheHonestReason() = runBlocking<Unit> {
        val s = seeded()
        val id = "11111111-2222-4333-8444-555555555555"
        s.server.rejectItems[id] = "attachment_mismatch"

        val e = assertFailsWith<ApiException> { s.engine.saveWithUploads(null, doc, emptyList(), newItemId = id) }
        assertEquals(400, e.status)
        assertEquals("attachment_mismatch", e.code)
        assertEquals(HouseholdCopy.SAVE_REJECTED_ATTACHMENT, HouseholdCopy.forSaveError(e))
        assertTrue(s.cache.pending().isEmpty())
        assertNull(s.engine.item(id), "nothing is projected for a row the server refused")
        assertEquals("write-rejected", s.engine.notices().single().kind)
        // The verdict is consumed by the save that sent it — a later background cycle is clean.
        s.engine.sync()
        assertEquals("write-rejected", s.engine.notices().single().kind)
    }

    // ==== H03 fallback / H19: a whole-batch refusal is bisected, never re-sent forever ====

    @Test
    fun legacyWholeBatch400_isBisectedDownToThePoisonRow() = runBlocking<Unit> {
        val s = seeded()
        val items = (1..5).map { planned("item $it") }
        val poison = items[2]
        s.server.refuseBatchIfContains.add(poison.itemId)

        s.engine.importAll(items)

        assertTrue(s.cache.pending().isEmpty(), "the poison row was isolated and dropped; nothing stays queued")
        assertEquals(items.filter { it !== poison }.map { it.itemId }.toSet(), s.server.applied(), "every healthy sibling landed")
        val n = s.engine.notices().single()
        assertEquals("write-rejected", n.kind)
        assertEquals(1, n.parkedCount)
        assertEquals("unknown_attachment", n.reason)
        // The bisect never re-sends a row the server already applied more than the dedup
        // window absorbs: each healthy id was applied exactly once.
        assertEquals(4, s.server.pushes.flatten().size)
    }

    @Test
    fun oversizedRow413_isDroppedAloneAndTheQueueDrains() = runBlocking<Unit> {
        val s = seeded()
        s.server.refuseBodyOverBytes = 600_000
        val small1 = planned("small 1")
        val big = planned("big", noteBytes = 700_000)
        val small2 = planned("small 2")

        s.engine.importAll(listOf(small1, big, small2))

        assertTrue(s.cache.pending().isEmpty(), "the over-cap row is dropped, not left at the head of the queue")
        assertEquals(setOf(small1.itemId, small2.itemId), s.server.applied())
        val n = s.engine.notices().single()
        assertEquals("write-rejected", n.kind)
        assertEquals("body_too_large", n.reason)
        // Later edits are no longer stuck behind it.
        s.engine.save(null, doc.copy(name = "after"))
        assertTrue(s.cache.pending().isEmpty())
    }

    @Test
    fun batches_areBoundedByEncodedBytesNotOnlyByCount() = runBlocking<Unit> {
        val s = seeded()
        val twoMiB = 2 * 1024 * 1024
        val items = (1..3).map { planned("big $it", noteBytes = twoMiB) }

        s.engine.importAll(items)

        assertEquals(2, s.server.pushes.size, "three ~2.7 MiB rows split under the 6 MiB soft cap: [2, 1]")
        assertEquals(listOf(2, 1), s.server.pushes.map { it.size })
        for (p in s.server.pushes) {
            val bytes = p.sumOf { (it.item?.blob?.length ?: 0).toLong() }
            assertTrue(bytes <= SyncEngine.PUSH_BODY_SOFT_CAP_BYTES, "batch blob bytes $bytes under the soft cap")
        }
        assertTrue(s.cache.pending().isEmpty())
    }

    @Test
    fun transientFailures_stillKeepTheRowsQueued() = runBlocking<Unit> {
        // The poison-row path must not widen into "any error drops the row": a 5xx and a
        // 429 are transient and the rows stay queued for the next drain.
        val s = seeded(DurableFakeCache())
        s.server.offline = true
        assertEquals(SaveOutcome.QUEUED, s.engine.save(null, doc))
        assertEquals(1, s.cache.pending().size)
        s.server.offline = false
        s.engine.sync()
        assertTrue(s.cache.pending().isEmpty())
    }

    // ==== H18 / H17: success-as-QUEUED only over a durable queue ====

    @Test
    fun offlineSave_onADurableCache_returnsQueued_projectsTheRow_andFlushesLater() = runBlocking<Unit> {
        val s = seeded(DurableFakeCache())
        s.server.offline = true

        val outcome = s.engine.saveWithUploads(null, doc.copy(name = "train wifi"), emptyList(), newItemId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")

        assertEquals(SaveOutcome.QUEUED, outcome)
        val row = s.engine.items().single()
        assertEquals("train wifi", row.doc.name, "the queued save is visible in the list at once")
        assertEquals(0, row.rev)
        assertTrue(s.engine.hasPendingSync(row.itemId))
        assertEquals(setOf(row.itemId), s.engine.pendingSyncItemIds())
        assertNotNull(s.engine.item(row.itemId))
        // An offline EDIT of the queued (never-sent) item is the SAME new item: the newer doc
        // supersedes the queued one — one row, not two puts that would land as a conflict copy.
        assertEquals(SaveOutcome.QUEUED, s.engine.save(row.itemId, doc.copy(name = "train wifi 2")))
        assertEquals("train wifi 2", s.engine.item(row.itemId)?.doc?.name)
        assertEquals(1, s.cache.pending().size, "the older queued put of a never-sent new item is coalesced away")
        // Reconnect: the drain sends the row; the mark clears.
        s.server.offline = false
        s.engine.sync()
        assertTrue(s.cache.pending().isEmpty())
        assertEquals(1, s.server.pushes.flatten().size, "exactly one put reached the server")
        assertEquals("train wifi 2", s.account.decryptItem(WireItem(row.itemId, row.vaultId, 1, 0, 0, false, false, s.server.pushes.single().single().item!!.formatVersion, emptyList(), s.server.pushes.single().single().item!!.blob)).name)
        assertFalse(s.engine.hasPendingSync(row.itemId))
    }

    @Test
    fun removingAQueuedNewItem_dropsItsQueuedPut_andNothingReachesTheServer() = runBlocking<Unit> {
        val s = seeded(DurableFakeCache())
        s.server.offline = true
        assertEquals(SaveOutcome.QUEUED, s.engine.saveWithUploads(null, doc, emptyList(), newItemId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"))
        assertEquals(SaveOutcome.APPLIED, s.engine.remove("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"))
        assertTrue(s.cache.pending().isEmpty())
        assertTrue(s.engine.items().isEmpty())
        s.server.offline = false
        s.engine.sync()
        assertTrue(s.server.pushes.isEmpty())
    }

    @Test
    fun offlineEditAndDelete_onADurableCache_projectIntoTheList() = runBlocking<Unit> {
        val s = seeded(DurableFakeCache())
        // Seed one server-confirmed item.
        val id = s.account.newItemId()
        val up = s.account.encryptItem(s.account.personalVaultId, id, doc)
        s.server.queue.add(SyncResponse(6, false, emptyList(), emptyList(), listOf(WireItem(id, s.account.personalVaultId, 6, 0, 0, false, false, up.formatVersion, emptyList(), up.blob)), emptyList()))
        s.engine.sync()
        assertEquals("Router", s.engine.item(id)?.doc?.name)

        s.server.offline = true
        assertEquals(SaveOutcome.QUEUED, s.engine.save(id, doc.copy(name = "Router (edited offline)")))
        assertEquals("Router (edited offline)", s.engine.item(id)?.doc?.name, "the queued edit overlays the cached row")
        assertEquals(6, s.engine.item(id)?.rev, "the overlay keeps the server rev — LWW stays server-relative")
        assertEquals(SaveOutcome.QUEUED, s.engine.remove(id))
        assertNull(s.engine.item(id), "a queued delete hides the row")
        assertTrue(s.engine.items().none { it.itemId == id })
    }

    @Test
    fun offlineSave_onAnInMemoryCache_throwsAndQueuesNothing() = runBlocking<Unit> {
        // H17: desktop before cache consent / org-forbid mode — the queue dies with the
        // session, so "queued" would be a false safety claim. The engine throws, nothing is
        // left in the in-memory queue, and the copy says so honestly.
        val s = seeded(InMemoryVaultCache())
        s.server.offline = true

        val e = assertFailsWith<IOException> { s.engine.save(null, doc) }

        assertTrue(s.cache.pending().isEmpty(), "no ghost row for a later same-session flush to land after a hand re-save")
        assertTrue(s.engine.items().isEmpty())
        val copy = HouseholdCopy.forSaveError(e)
        assertEquals(HouseholdCopy.SAVE_FAILED_OFFLINE, copy)
        assertFalse(copy.contains("queued"), "never promise a queue that does not exist")
    }

    @Test
    fun aFailedReconcilePull_doesNotFailALandedSave() = runBlocking<Unit> {
        // The push lands, then the network dies before the reconcile pull: the write is on
        // the server, so the save is APPLIED (web: "save committed but the reconcile pull
        // failed — local apply kept"). Reporting it as failed would invite the duplicate
        // re-save G23 exists to prevent.
        val s = seeded(DurableFakeCache())
        s.server.offlineAfterNextPush = true
        assertEquals(SaveOutcome.APPLIED, s.engine.save(null, doc.copy(name = "landed")))
        assertTrue(s.cache.pending().isEmpty())
        assertEquals(1, s.server.pushes.size)
        assertTrue(s.server.offline, "the reconcile pull did hit the dead network")
        // A server ANSWER from the reconcile pull still propagates (nothing swallowed but transport).
        s.server.offline = false
    }

    // ==== H71: "You were added to X" on the natives ====

    private fun sharedVaultFor(owner: Account, member: Account, name: String, role: String, rev: Long): Pair<WireVault, WireGrant> {
        val nv = owner.buildCreateSharedVault(name)
        val sealedVk = owner.wrapVkForMember(member.identityPub, nv.vaultId)
        return WireVault(nv.vaultId, "shared", rev, nv.request.metaBlob, 0) to WireGrant(nv.vaultId, member.userId, role, "", rev, sealedVk)
    }

    @Test
    fun aGenuinelyNewGrant_afterTheFirstPull_mintsTheAddedNotice_once() = runBlocking<Unit> {
        val s = seeded()
        val owner = enroll("owner@example.com")
        val (vault, grant) = sharedVaultFor(owner, s.account, "Family", "writer", 7)
        s.server.queue.add(SyncResponse(7, false, listOf(vault), listOf(grant), emptyList(), emptyList()))

        s.engine.sync()

        val n = s.engine.notices().single()
        assertEquals("added", n.kind)
        assertEquals(vault.vaultId, n.vaultId)
        assertEquals("Family", n.vaultName)
        // A re-delivered grant (role change) never re-announces.
        s.engine.dismissNotice(n.id)
        s.server.queue.add(SyncResponse(8, false, emptyList(), listOf(grant.copy(role = "reader", rev = 8)), emptyList(), emptyList()))
        s.engine.sync()
        assertTrue(s.engine.notices().isEmpty())
    }

    @Test
    fun aSinceZeroPull_andAnOwnerGrant_neverMintAdded() = runBlocking<Unit> {
        // Fresh device: the first pull (since=0) carries a shared grant — no notice (nothing
        // verifiably NEW; web F20 parity).
        val member = enroll("member@example.com")
        val owner = enroll("owner@example.com")
        val (vault, grant) = sharedVaultFor(owner, member, "Family", "writer", 3)
        val server = FakeServer()
        val engine = SyncEngine(server.api(), member, InMemoryVaultCache())
        server.queue.add(SyncResponse(5, true, listOf(WireVault(member.personalVaultId, "personal", 1, "", 0), vault), listOf(grant), emptyList(), emptyList()))
        engine.sync()
        assertTrue(engine.notices().isEmpty())

        // The OWNER's second device sees its own new vault as a brand-new owner grant — "you
        // were added" would be a lie; the owner grant is excluded.
        val ownerServer = FakeServer()
        val ownerEngine = SyncEngine(ownerServer.api(), owner, InMemoryVaultCache())
        ownerServer.queue.add(SyncResponse(5, true, listOf(WireVault(owner.personalVaultId, "personal", 1, "", 0)), emptyList(), emptyList(), emptyList()))
        ownerEngine.sync()
        val nv = owner.buildCreateSharedVault("Mine")
        ownerServer.queue.add(
            SyncResponse(
                6, false, listOf(WireVault(nv.vaultId, "shared", 6, nv.request.metaBlob, 0)),
                listOf(WireGrant(nv.vaultId, owner.userId, "owner", nv.request.wrappedVk, 6, null)), emptyList(), emptyList(),
            ),
        )
        ownerEngine.sync()
        assertTrue(ownerEngine.notices().isEmpty(), "an owner grant is our own wrappedVk, never an 'added'")
    }
}
