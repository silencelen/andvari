package io.silencelen.andvari.core.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.toByteArray
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.LifecycleProof
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AttachmentMeta
import io.silencelen.andvari.core.model.DeletedVaultSummary
import io.silencelen.andvari.core.model.ItemVersion
import io.silencelen.andvari.core.model.ItemVersionsResponse
import io.silencelen.andvari.core.model.Mutation
import io.silencelen.andvari.core.model.MutationResult
import io.silencelen.andvari.core.model.PendingTransfer
import io.silencelen.andvari.core.model.PushRequest
import io.silencelen.andvari.core.model.PushResponse
import io.silencelen.andvari.core.model.RemovedGrantInfo
import io.silencelen.andvari.core.model.SyncResponse
import io.silencelen.andvari.core.model.TransferRecord
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireItem
import io.silencelen.andvari.core.model.WireVault
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Lifecycle (Skipti, spec 03 §11) SyncEngine tests against the REAL Account crypto and a
 * fake server (ktor MockEngine — the jvmTest fake-api style of AndvariApiRefreshTest).
 * Mirrors web/src/vault/store.lifecycle.test.ts: proof-verify tri-state, holding-area
 * park/reinstate/replay (F21), consumed-deleteId recognition, transfer offer/completion
 * verification, and the F19 copy-leg-first sequencing.
 */
class SyncEngineLifecycleTest {

    private val crypto = createCryptoProvider()
    private val kdf = KdfParams(ops = 1, memBytes = 8192) // test-speed argon2id (web test parity)
    private val doc = ItemDoc(type = "login", name = "Shared login", login = LoginData(username = "fam", password = "hunter2"))

    private fun enroll(email: String): Account {
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val fp = Escrow.fingerprint(crypto, recovery.publicKey)
        return Account.enroll("test-invite", email, email, "pw $email", kdf, recovery.publicKey, fp, "test-device", crypto).second
    }

    /** Fake server: sync queue + push knobs, same drive pattern as the web FakeApi. */
    private class FakeServer {
        val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
        val queue = ArrayDeque<SyncResponse>()
        val pushes = mutableListOf<List<Mutation>>()
        var rev = 1L

        /** Deny every push whose mutation targets one of these vaults (role violation). */
        val denyVaults = mutableSetOf<String>()

        /** Return `conflict` for a push (put or delete) of one of these itemIds. */
        val conflictItems = mutableSetOf<String>()

        /** PDD-1: one-shot `conflict` carrying the DISPLACED (losing) serverItem + winner rev, keyed by itemId. */
        val conflictWithLosing = mutableMapOf<String, Pair<WireItem, Long>>()

        /** Return an unknown/future per-mutation status for pushes targeting these vaults. */
        val unknownStatusVaults = mutableSetOf<String>()

        /** Return an EMPTY results array for pushes targeting these vaults (malformed reply). */
        val emptyResultsVaults = mutableSetOf<String>()

        /** Fail the next GET /sync with a 500 (transport-ish failure mid-cycle). */
        var failNextSync = false

        /** Fail the next POST /sync/push with a 500 (leaves the mutation queued client-side). */
        var failNextPush = false

        /** When set, the next GET /sync completes [syncEntered] then suspends until
         *  [syncRelease] — lets a test hold one sync open while another interleaves. */
        var syncEntered: CompletableDeferred<Unit>? = null
        var syncRelease: CompletableDeferred<Unit>? = null

        val attachments = HashMap<String, ByteArray>()
        val itemVersionsById = HashMap<String, List<ItemVersion>>() // item history: archived versions the server holds
        var deletedList: List<DeletedVaultSummary> = emptyList()
        val calls = mutableListOf<String>()

        fun emptySync(rev: Long) = SyncResponse(rev, false, emptyList(), emptyList(), emptyList(), emptyList())

        private fun handleSync(): SyncResponse {
            val resp = queue.removeFirstOrNull() ?: emptySync(rev)
            rev = maxOf(rev, resp.rev)
            return resp
        }

        private fun handlePush(req: PushRequest): PushResponse {
            pushes.add(req.mutations)
            if (req.mutations.any { it.vaultId in emptyResultsVaults }) return PushResponse(++rev, emptyList())
            val results = req.mutations.map { m ->
                val losing = conflictWithLosing.remove(m.itemId) // PDD-1: one-shot displaced-value conflict
                if (losing != null) {
                    MutationResult(m.mutationId, "conflict", losing.second, serverItem = losing.first)
                } else {
                    val status = when {
                        m.vaultId in denyVaults -> "denied"
                        m.itemId in conflictItems -> "conflict"
                        m.vaultId in unknownStatusVaults -> "rate_limited" // a future status this client doesn't know
                        else -> "applied"
                    }
                    MutationResult(m.mutationId, status, if (status == "conflict") null else 1L)
                }
            }
            return PushResponse(++rev, results)
        }

        fun api(): AndvariApi {
            val engine = MockEngine { req ->
                val path = req.url.encodedPath
                val jsonHeaders = headersOf(HttpHeaders.ContentType, "application/json")
                fun ok(body: String) = respond(body, HttpStatusCode.OK, jsonHeaders)
                when {
                    path == "/api/v1/sync" -> {
                        syncEntered?.let { gate -> syncEntered = null; gate.complete(Unit); syncRelease?.await() }
                        if (failNextSync) {
                            failNextSync = false
                            respond("""{"error":"boom","message":"transient server failure"}""", HttpStatusCode.InternalServerError, jsonHeaders)
                        } else {
                            ok(json.encodeToString(SyncResponse.serializer(), handleSync()))
                        }
                    }
                    path == "/api/v1/sync/push" -> {
                        if (failNextPush) {
                            failNextPush = false
                            respond("""{"error":"boom","message":"transient push failure"}""", HttpStatusCode.InternalServerError, jsonHeaders)
                        } else {
                            val body = json.decodeFromString(PushRequest.serializer(), req.body.toByteArray().decodeToString())
                            ok(json.encodeToString(PushResponse.serializer(), handlePush(body)))
                        }
                    }
                    path.startsWith("/api/v1/attachments/") && req.method.value == "POST" -> {
                        val id = path.removePrefix("/api/v1/attachments/")
                        attachments[id] = req.body.toByteArray()
                        ok(json.encodeToString(AttachmentMeta.serializer(), AttachmentMeta(id, "", "", 0, "")))
                    }
                    path.startsWith("/api/v1/attachments/") -> {
                        val b = attachments[path.removePrefix("/api/v1/attachments/")]
                        if (b == null) {
                            respond("""{"error":"not_found","message":"no such attachment"}""", HttpStatusCode.NotFound, jsonHeaders)
                        } else {
                            respond(b, HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/octet-stream"))
                        }
                    }
                    path.startsWith("/api/v1/items/") && path.endsWith("/versions") -> {
                        val id = path.removePrefix("/api/v1/items/").removeSuffix("/versions")
                        ok(json.encodeToString(ItemVersionsResponse.serializer(), ItemVersionsResponse(id, itemVersionsById[id] ?: emptyList())))
                    }
                    path == "/api/v1/vaults/deleted" -> {
                        calls.add("deletedVaults")
                        ok(json.encodeToString(ListSerializer(DeletedVaultSummary.serializer()), deletedList))
                    }
                    path.endsWith("/delete") -> { calls.add("deleteVault"); ok("""{"rev":${++rev},"purgeAt":${System.currentTimeMillis() + 7L * 86_400_000}}""") }
                    path.endsWith("/restore") -> { calls.add("restoreVault"); ok("""{"rev":${++rev}}""") }
                    path.endsWith("/leave") -> { calls.add("leaveVault"); ok("""{"rev":${++rev}}""") }
                    path.endsWith("/transfer/accept") -> { calls.add("acceptTransfer"); ok("""{"rev":${++rev}}""") }
                    path.endsWith("/transfer") && req.method.value == "POST" -> { calls.add("offerTransfer"); ok("""{"rev":${++rev},"expiresAt":0}""") }
                    path.endsWith("/transfer") && req.method.value == "DELETE" -> { calls.add("cancelTransfer"); ok("""{"rev":${++rev}}""") }
                    path.endsWith("/meta") -> { calls.add("updateVaultMeta"); ok("""{"rev":${++rev}}""") }
                    else -> respond("""{"error":"not_found","message":"unexpected $path"}""", HttpStatusCode.NotFound, jsonHeaders)
                }
            }
            return AndvariApi("http://fake", HttpClient(engine), Tokens("access", "refresh"))
        }
    }

    private class Seed(
        val owner: Account,
        val member: Account,
        val engine: SyncEngine,
        val server: FakeServer,
        val cache: InMemoryVaultCache,
        val vaultId: String,
        val itemId: String,
        val vault: WireVault,
        val grant: WireGrant,
        val item: WireItem,
    )

    /** A member holding a shared vault (owner-created, VK sealed to the member) at cursor 5. */
    private fun seededMember(role: String = "writer"): Seed {
        val owner = enroll("owner@example.com")
        val member = enroll("member@example.com")
        val nv = owner.buildCreateSharedVault("Family")
        val vaultId = nv.vaultId
        val sealedVk = owner.wrapVkForMember(member.identityPub, vaultId)
        val itemId = owner.newItemId()
        val vault = WireVault(vaultId, "shared", 2, nv.request.metaBlob, 0)
        val grant = WireGrant(vaultId, member.userId, role, "", 3, sealedVk)
        val item = WireItem(itemId, vaultId, 4, 0, 0, false, false, 1, emptyList(), owner.encryptItem(vaultId, itemId, doc).blob)
        val server = FakeServer()
        val cache = InMemoryVaultCache()
        val engine = SyncEngine(server.api(), member, cache)
        server.queue.add(SyncResponse(5, true, listOf(vault), listOf(grant), listOf(item), emptyList()))
        runBlocking { engine.sync() }
        return Seed(owner, member, engine, server, cache, vaultId, itemId, vault, grant, item)
    }

    private fun Seed.key(): ByteArray = owner.lifecycleKeyFor(vaultId)

    private fun uuid() = io.silencelen.andvari.core.crypto.Bytes.uuidV4FromBytes(crypto.randomBytes(16))

    // ==== tri-state removedGrants (spec 03 §11) ====

    @Test
    fun validDeleteProof_softHidesWithAttributedNotice() = runBlocking<Unit> {
        val s = seededMember()
        val deleteId = uuid()
        val purgeAt = System.currentTimeMillis() + 7L * 86_400_000
        s.server.queue.add(
            SyncResponse(
                6, false, emptyList(), emptyList(), emptyList(), listOf(s.vaultId),
                listOf(RemovedGrantInfo(s.vaultId, "deleted", purgeAt = purgeAt, deleteId = deleteId, deleteProof = LifecycleProof.delete(crypto, s.key(), s.vaultId, deleteId))),
            ),
        )
        s.engine.sync()

        assertNull(s.engine.item(s.itemId))
        assertFalse(s.member.hasVault(s.vaultId))
        val held = s.engine.heldVaultInfos().find { it.vaultId == s.vaultId }
        assertNotNull(held)
        assertTrue(held.verified)
        assertEquals(purgeAt, held.purgeAt)
        assertEquals("Family", held.name) // re-derived via the retained grant, never persisted
        val n = s.engine.notices().find { it.vaultId == s.vaultId }
        assertEquals("deleted", n?.kind)
        assertEquals(purgeAt, n?.purgeAt)
    }

    @Test
    fun invalidDeleteProof_anomalyWarningUnverifiedHolding() = runBlocking<Unit> {
        val s = seededMember()
        s.server.queue.add(
            SyncResponse(
                6, false, emptyList(), emptyList(), emptyList(), listOf(s.vaultId),
                listOf(RemovedGrantInfo(s.vaultId, "deleted", purgeAt = System.currentTimeMillis() + 1000, deleteId = uuid(), deleteProof = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")),
            ),
        )
        s.engine.sync()
        assertEquals("anomaly", s.engine.notices().find { it.vaultId == s.vaultId }?.kind)
        assertEquals(false, s.engine.heldVaultInfos().find { it.vaultId == s.vaultId }?.verified)
    }

    @Test
    fun bareRevocationOfHeldVault_anomaly() = runBlocking<Unit> {
        val s = seededMember()
        s.server.queue.add(SyncResponse(6, false, emptyList(), emptyList(), emptyList(), listOf(s.vaultId)))
        s.engine.sync()
        assertEquals("anomaly", s.engine.notices().find { it.vaultId == s.vaultId }?.kind)
        assertNotNull(s.engine.heldVaultInfos().find { it.vaultId == s.vaultId })
    }

    @Test
    fun unknownVaultRevocation_silentNoOp() = runBlocking<Unit> {
        val s = seededMember()
        s.server.queue.add(SyncResponse(6, false, emptyList(), emptyList(), emptyList(), listOf("a-vault-we-never-had")))
        s.engine.sync()
        assertTrue(s.engine.notices().isEmpty())
        assertTrue(s.engine.heldVaultInfos().isEmpty())
        assertNotNull(s.engine.item(s.itemId)) // our real vault is untouched
    }

    @Test
    fun sinceZeroPull_neverNotices() = runBlocking<Unit> {
        val member = enroll("member@example.com")
        val server = FakeServer()
        val engine = SyncEngine(server.api(), member, InMemoryVaultCache())
        // First pull (since=0) already carries removedGrants for a vault this device never held.
        server.queue.add(
            SyncResponse(
                5, true, emptyList(), emptyList(), emptyList(), listOf("gone-vault"),
                listOf(RemovedGrantInfo("gone-vault", "deleted", deleteId = "x", deleteProof = "y")),
            ),
        )
        engine.sync()
        assertTrue(engine.notices().isEmpty())
        assertTrue(engine.heldVaultInfos().isEmpty())
    }

    @Test
    fun leftReason_calmNotice() = runBlocking<Unit> {
        val s = seededMember()
        s.server.queue.add(
            SyncResponse(6, false, emptyList(), emptyList(), emptyList(), listOf(s.vaultId), listOf(RemovedGrantInfo(s.vaultId, "left"))),
        )
        s.engine.sync()
        assertEquals("left", s.engine.notices().find { it.vaultId == s.vaultId }?.kind)
    }

    @Test
    fun removedWithValidProof_attributed_withoutProof_anomaly() = runBlocking<Unit> {
        val s = seededMember()
        val nonce = uuid()
        s.server.queue.add(
            SyncResponse(
                6, false, emptyList(), emptyList(), emptyList(), listOf(s.vaultId),
                listOf(RemovedGrantInfo(s.vaultId, "removed", removeProof = LifecycleProof.remove(crypto, s.key(), s.vaultId, s.member.userId, nonce), removeNonce = nonce)),
            ),
        )
        s.engine.sync()
        assertEquals("removed", s.engine.notices().find { it.vaultId == s.vaultId }?.kind)

        // A second held vault, removed WITHOUT a proof → anomaly.
        val s2 = seededMember()
        s2.server.queue.add(
            SyncResponse(6, false, emptyList(), emptyList(), emptyList(), listOf(s2.vaultId), listOf(RemovedGrantInfo(s2.vaultId, "removed"))),
        )
        s2.engine.sync()
        assertEquals("anomaly", s2.engine.notices().find { it.vaultId == s2.vaultId }?.kind)
    }

    // ==== holding area: park, reinstate, replay (F21) ====

    @Test
    fun deniedEditParked_notThrown_replayedOnRestoreWithSameMutationId() = runBlocking<Unit> {
        val s = seededMember("writer")
        val deleteId = uuid()
        val purgeAt = System.currentTimeMillis() + 7L * 86_400_000

        // The owner deletes mid-edit: the member's save is DENIED, then the delete lands
        // in the SAME cycle's pull (F21 one-cycle fix).
        s.server.denyVaults.add(s.vaultId)
        s.server.queue.add(
            SyncResponse(
                6, false, emptyList(), emptyList(), emptyList(), listOf(s.vaultId),
                listOf(RemovedGrantInfo(s.vaultId, "deleted", purgeAt = purgeAt, deleteId = deleteId, deleteProof = LifecycleProof.delete(crypto, s.key(), s.vaultId, deleteId))),
            ),
        )

        // Must NOT throw — the edit is parked, not lost, and the pull is never aborted.
        s.engine.save(s.itemId, doc.copy(name = "edited in-flight"))
        val n = s.engine.notices().find { it.vaultId == s.vaultId }
        assertEquals("deleted", n?.kind)
        assertEquals(1, n?.parkedCount)
        assertNotNull(s.engine.heldVaultInfos().find { it.vaultId == s.vaultId })
        val deniedMutation = s.server.pushes.flatten().first { it.itemId == s.itemId && it.op == "put" }

        // Restore: a live grant + the restore-marked vault + the item re-arrive → reinstate
        // + replay the parked mutation with its ORIGINAL mutationId.
        s.server.denyVaults.remove(s.vaultId)
        val restoredVault = s.vault.copy(rev = 8, restoreProof = LifecycleProof.restore(crypto, s.key(), s.vaultId, deleteId), deleteId = deleteId)
        s.server.queue.add(SyncResponse(9, false, listOf(restoredVault), listOf(s.grant.copy(rev = 9)), listOf(s.item.copy(rev = 9)), emptyList()))
        s.engine.sync()

        val replays = s.server.pushes.flatten().filter { it.mutationId == deniedMutation.mutationId }
        assertEquals(2, replays.size, "the parked edit must replay with the SAME mutationId")
        assertNotNull(s.engine.item(s.itemId))
        assertTrue(s.engine.heldVaultInfos().isEmpty())
        assertTrue(s.engine.notices().any { it.vaultId == s.vaultId && it.kind == "restored" })
    }

    @Test
    fun readerDeniedEditOnLiveVault_rethrows() = runBlocking<Unit> {
        val s = seededMember("reader")
        s.server.denyVaults.add(s.vaultId)
        // No delete arrives — the reconcile pull is empty, so the vault stays live.
        val e = assertFailsWith<ApiException> { s.engine.save(s.itemId, doc.copy(name = "reader edit")) }
        assertEquals("denied", e.code)
        assertTrue(s.engine.heldVaultInfos().isEmpty())
    }

    @Test
    fun pushSideMaterializesConflictCopyFromLosingServerItem() = runBlocking<Unit> {
        val s = seededMember("writer")
        // The DISPLACED (losing) value the server returns on our conflicting push — a concurrent
        // edit by another device, encrypted under the shared VK.
        val losingDoc = doc.copy(login = LoginData(username = "fam", password = "THEIRS-lost"))
        val losing = WireItem(
            s.itemId, s.vaultId, 6, 0, 1_690_000_000_000, false, false, 1, emptyList(),
            s.owner.encryptItem(s.vaultId, s.itemId, losingDoc).blob,
        )
        s.server.conflictWithLosing[s.itemId] = losing to 9L
        val pushesBefore = s.server.pushes.size

        // Our edit — the winner. save() pushes it; the server keeps ours live (LWW) and returns
        // the losing value, so the push side must materialize the copy FROM THE LOSING value.
        s.engine.save(s.itemId, doc.copy(login = LoginData(username = "fam", password = "OURS-wins")))

        // A copy was pushed, keyed by the deterministic id over the WINNER rev (9) — the SAME id
        // the pull-side fallback uses, so the two converge (spec 03 §5, PDD-1).
        val copyId = ConflictCopy.id(crypto, s.itemId, 9L)
        val copyMut = s.server.pushes.drop(pushesBefore).flatten().find { it.itemId == copyId }
        assertNotNull(copyMut, "a conflict copy must be materialized from the losing serverItem")
        assertEquals(0L, copyMut.baseItemRev, "the copy is a fresh item, not a rewrite of the winner")
        // Its content is the LOSING value, dated — NOT ours.
        val copyDoc = s.member.decryptItem(
            WireItem(copyId, s.vaultId, 1, 0, 0, false, false, copyMut.item!!.formatVersion, copyMut.item!!.attachmentIds, copyMut.item!!.blob),
        )
        assertEquals("THEIRS-lost", copyDoc.login?.password, "the copy must carry the LOSING value, not the winner")
        assertTrue(copyDoc.name.contains("(conflict ") && copyDoc.name.endsWith(")"), "copy name should be dated: ${copyDoc.name}")
    }

    @Test
    fun deleteThatLosesToNewerEdit_materializesNoSpuriousCopy() = runBlocking<Unit> {
        val s = seededMember("writer")
        // A delete that loses to a newer concurrent edit returns conflict + serverItem, but there
        // serverItem is the SURVIVING winner, not a displaced value — the push side must NOT copy it.
        val survivor = WireItem(s.itemId, s.vaultId, 7, 0, 0, false, false, 1, emptyList(), s.owner.encryptItem(s.vaultId, s.itemId, doc).blob)
        s.server.conflictWithLosing[s.itemId] = survivor to 7L
        val pushesBefore = s.server.pushes.size

        s.engine.remove(s.itemId)

        val copyId = ConflictCopy.id(crypto, s.itemId, 7L)
        val spurious = s.server.pushes.drop(pushesBefore).flatten().find { it.itemId == copyId }
        assertNull(spurious, "a losing delete must not spawn a conflict-copy duplicate")
    }

    @Test
    fun resealEscrowFor_bindsPubkeyToVerifiedFingerprint_andRoundTrips() {
        // F57: after a recovery-key re-ceremony the client re-seals its UVK to the NEW key.
        // Enroll against recovery key #1.
        val rec1 = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val fp1 = Escrow.fingerprint(crypto, rec1.publicKey)
        val (reg, account) = Account.enroll("inv", "u@e.com", "u", "pw", kdf, rec1.publicKey, fp1, "dev", crypto)
        // Oracle: the UVK recovered from the ORIGINAL escrow (sealed to key #1).
        val uvkFrom1 = Escrow.open(crypto, rec1.publicKey, rec1.privateKey, Bytes.fromB64(reg.escrow.sealed))

        // Re-ceremony rotates to recovery key #2. The user confirmed fp2 against the new sheet.
        val rec2 = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val fp2 = Escrow.fingerprint(crypto, rec2.publicKey)
        val upload = account.resealEscrowFor(Bytes.toB64(rec2.publicKey), fp2)
        assertEquals(fp2, upload.fingerprint)
        // The re-sealed blob opens with key #2 and yields the SAME UVK (data stays recoverable).
        val uvkFrom2 = Escrow.open(crypto, rec2.publicKey, rec2.privateKey, Bytes.fromB64(upload.sealed))
        assertEquals(uvkFrom1.key, uvkFrom2.key, "re-sealed escrow must recover the identical UVK")

        // SECURITY: refuse to seal if the fetched pubkey doesn't match the sheet-verified
        // fingerprint — a hostile server cannot redirect the UVK escrow to an attacker key.
        assertFailsWith<IllegalArgumentException> { account.resealEscrowFor(Bytes.toB64(rec2.publicKey), fp1) }
    }

    @Test
    fun decryptItemVersion_opensArchivedVersionUnderCurrentVk() {
        // Feature: item history — an archived version's ciphertext (AD bound to vaultId+itemId+
        // formatVersion, not rev) decrypts under the VK the member already holds.
        val member = enroll("hist@example.com")
        val vaultId = member.personalVaultId
        val itemId = member.newItemId()
        val old = doc.copy(name = "Netflix", login = LoginData(username = "fam", password = "last-week-pw"))
        val enc = member.encryptItem(vaultId, itemId, old) // the "archived" ciphertext blob
        val version = ItemVersion(rev = 7, blob = enc.blob, formatVersion = enc.formatVersion, archivedAt = 1_690_000_000_000L)

        val decoded = member.decryptItemVersion(vaultId, itemId, version)
        assertEquals("Netflix", decoded.name)
        assertEquals("last-week-pw", decoded.login?.password, "the old version decrypts to its historical secret")
    }

    @Test
    fun itemVersions_fetchesDecryptsNewestFirst_dropsUndecryptable() = runBlocking<Unit> {
        // Item history end-to-end through the engine: fetch the server's archive + decrypt each.
        val s = seededMember("writer")
        val v1 = doc.copy(login = LoginData(username = "fam", password = "old-1"))
        val v2 = doc.copy(login = LoginData(username = "fam", password = "old-2"))
        s.server.itemVersionsById[s.itemId] = listOf(
            ItemVersion(rev = 8L, blob = s.owner.encryptItem(s.vaultId, s.itemId, v2).blob, formatVersion = 1, archivedAt = 1_690_000_100_000L),
            ItemVersion(rev = 7L, blob = s.owner.encryptItem(s.vaultId, s.itemId, v1).blob, formatVersion = 1, archivedAt = 1_690_000_000_000L),
            // A blob this key can't open (e.g. sealed under a superseded VK) is silently dropped.
            ItemVersion(rev = 6L, blob = Bytes.toB64(ByteArray(8)), formatVersion = 1, archivedAt = 1_680_000_000_000L),
        )

        val versions = s.engine.itemVersions(s.itemId, s.vaultId)
        assertEquals(listOf(8L, 7L), versions.map { it.rev }, "decrypted, newest first; the undecryptable version dropped")
        assertEquals("old-2", versions[0].doc.login?.password)
        assertEquals("old-1", versions[1].doc.login?.password)
    }

    // ==== consumed-deleteId recognition ====

    @Test
    fun replayedTombstoneWithConsumedDeleteId_recognizedNotRewarned() = runBlocking<Unit> {
        val s = seededMember("writer")
        val deleteId = uuid()

        // The vault re-arrives carrying a valid restore marker → the deleteId is consumed.
        val rProof = LifecycleProof.restore(crypto, s.key(), s.vaultId, deleteId)
        s.server.queue.add(SyncResponse(6, false, listOf(s.vault.copy(rev = 6, restoreProof = rProof, deleteId = deleteId)), emptyList(), emptyList(), emptyList()))
        s.engine.sync()

        // A stale/malicious server now replays the OLD tombstone bearing that deleteId.
        s.server.queue.add(
            SyncResponse(
                7, false, emptyList(), emptyList(), emptyList(), listOf(s.vaultId),
                listOf(RemovedGrantInfo(s.vaultId, "deleted", purgeAt = System.currentTimeMillis() + 1000, deleteId = deleteId, deleteProof = LifecycleProof.delete(crypto, s.key(), s.vaultId, deleteId))),
            ),
        )
        s.engine.sync()

        // Recognized as stale: the vault stays live, nothing held, no notice.
        assertNotNull(s.engine.item(s.itemId))
        assertTrue(s.engine.heldVaultInfos().isEmpty())
        assertFalse(s.engine.notices().any { it.vaultId == s.vaultId })
    }

    // ==== transfer verification (spec 03 §11) ====

    @Test
    fun incomingOfferSurfacesOnlyAfterProofVerifies() = runBlocking<Unit> {
        val s = seededMember("writer")
        val offerId = uuid()
        val expiresAt = System.currentTimeMillis() + 14L * 86_400_000
        val goodProof = LifecycleProof.offer(crypto, s.key(), s.vaultId, offerId, s.member.userId, expiresAt, 1)

        s.server.queue.add(
            SyncResponse(
                6, false, listOf(s.vault.copy(rev = 6, pendingTransfer = PendingTransfer(s.member.userId, offerId, goodProof, expiresAt, 1))),
                emptyList(), emptyList(), emptyList(),
            ),
        )
        s.engine.sync()
        assertTrue(s.engine.incomingTransfers().map { it.vaultId }.contains(s.vaultId))

        // A tampered proof on a new offer → NOT surfaced (consent screen never renders).
        val s2 = seededMember("writer")
        s2.server.queue.add(
            SyncResponse(
                6, false, listOf(s2.vault.copy(rev = 6, pendingTransfer = PendingTransfer(s2.member.userId, uuid(), "AAAA", expiresAt, 1))),
                emptyList(), emptyList(), emptyList(),
            ),
        )
        s2.engine.sync()
        assertTrue(s2.engine.incomingTransfers().isEmpty())
    }

    @Test
    fun unverifiedCompletionWarns_doesNotBurnSeq_verifiedRedeliveryRetracts() = runBlocking<Unit> {
        val s = seededMember("writer")
        val offerId = uuid()
        val seq = 1L
        val wrapHash = "00".repeat(32)

        // Bogus acceptProof (server-side ownership rewrite): anomaly warning, no completion.
        s.server.queue.add(
            SyncResponse(
                6, false, listOf(s.vault.copy(rev = 6, lastTransfer = TransferRecord(offerId, s.member.userId, "AAAA", seq, wrapHash))),
                emptyList(), emptyList(), emptyList(),
            ),
        )
        s.engine.sync()
        assertEquals("transfer-anomaly", s.engine.notices().find { it.vaultId == s.vaultId }?.kind)

        // The same row re-delivered later WITH the genuine proof: the unverified sighting
        // must not have marked the seq seen — the real completion notice still fires, and
        // the earlier anomaly warning is retracted.
        val goodAccept = LifecycleProof.acceptFromHash(crypto, s.key(), s.vaultId, offerId, s.member.userId, seq, wrapHash)
        s.server.queue.add(
            SyncResponse(
                7, false, listOf(s.vault.copy(rev = 7, lastTransfer = TransferRecord(offerId, s.member.userId, goodAccept, seq, wrapHash))),
                emptyList(), emptyList(), emptyList(),
            ),
        )
        s.engine.sync()
        val kinds = s.engine.notices().filter { it.vaultId == s.vaultId }.map { it.kind }
        assertTrue("transfer-complete" in kinds)
        assertFalse("transfer-anomaly" in kinds)
    }

    // ==== F19 move/copy copy-leg-first sequencing (design §8) ====

    @Test
    fun deniedCopyLeg_abortsSourceUntouched_noDeleteLeg() = runBlocking<Unit> {
        val s = seededMember("writer")
        val target = s.member.personalVaultId
        s.server.denyVaults.add(target)
        val g = s.engine.newMoveGesture(s.itemId, target, del = true)
        assertFailsWith<CopyDeniedException> { s.engine.runGesture(g) }
        assertEquals(1, s.server.pushes.size) // ONLY the copy leg — the delete leg never ran
        assertNotNull(s.engine.item(s.itemId)) // source untouched
    }

    @Test
    fun deleteLegConflict_abortsWithoutDeletingSource() = runBlocking<Unit> {
        val s = seededMember("writer")
        s.server.conflictItems.add(s.itemId) // the delete of the SOURCE conflicts (source moved on)
        val g = s.engine.newMoveGesture(s.itemId, s.member.personalVaultId, del = true)
        assertFailsWith<ItemChangedException> { s.engine.runGesture(g) }
        assertTrue(s.server.pushes.size >= 2) // copy leg applied, delete leg attempted
        assertNotNull(s.engine.item(s.itemId)) // source NOT deleted
    }

    @Test
    fun deleteLegUsesRevOfContentCopied_notCacheRev() = runBlocking<Unit> {
        val s = seededMember("writer")
        val g = s.engine.newMoveGesture(s.itemId, s.member.personalVaultId, del = true)
        s.engine.runGesture(g)
        val delLeg = s.server.pushes.first { it.firstOrNull()?.op == "delete" }.first()
        assertEquals(s.item.rev, delLeg.baseItemRev)
        assertNull(s.engine.item(s.itemId)) // moved out
    }

    @Test
    fun unknownCopyStatus_abortsSourceUntouched() = runBlocking<Unit> {
        val s = seededMember("writer")
        val target = s.member.personalVaultId
        s.server.unknownStatusVaults.add(target) // future/unknown per-mutation status on the copy
        val g = s.engine.newMoveGesture(s.itemId, target, del = true)
        val e = assertFailsWith<ApiException> { s.engine.runGesture(g) }
        assertEquals("copy_unconfirmed", e.code)
        assertEquals(1, s.server.pushes.size) // the delete leg never ran
        assertNotNull(s.engine.item(s.itemId))
    }

    @Test
    fun emptyCopyResults_abortsSourceUntouched() = runBlocking<Unit> {
        val s = seededMember("writer")
        val target = s.member.personalVaultId
        s.server.emptyResultsVaults.add(target) // malformed reply — no per-mutation result at all
        val g = s.engine.newMoveGesture(s.itemId, target, del = true)
        val e = assertFailsWith<ApiException> { s.engine.runGesture(g) }
        assertEquals("copy_unconfirmed", e.code)
        assertEquals(1, s.server.pushes.size)
        assertNotNull(s.engine.item(s.itemId))
    }

    @Test
    fun copyRetryReusesGestureDerivedMutationId() = runBlocking<Unit> {
        val s = seededMember("writer")
        val g = s.engine.newMoveGesture(s.itemId, s.member.personalVaultId, del = false) // copy only
        s.engine.runGesture(g)
        val firstCopyId = s.server.pushes.first { it.firstOrNull()?.itemId == g.newItemId }.first().mutationId
        val before = s.server.pushes.size
        s.engine.runGesture(g) // the SAME gesture again (a retry)
        assertTrue(s.server.pushes.size > before)
        val retryCopyId = s.server.pushes.drop(before).first { it.firstOrNull()?.itemId == g.newItemId }.first().mutationId
        assertEquals(firstCopyId, retryCopyId) // deterministic from gestureId → server dedup converges
    }

    @Test
    fun bulkCopyMemoizesGesturesPerSourceItem_retryConverges() = runBlocking<Unit> {
        val s = seededMember("writer")
        val copied = s.engine.copyAllToPersonal(s.vaultId)
        assertEquals(1, copied)
        val firstIds = s.server.pushes.flatten().filter { it.op == "put" && it.vaultId == s.member.personalVaultId }.map { it.mutationId }
        val before = s.server.pushes.size
        s.engine.copyAllToPersonal(s.vaultId) // a retry of the same bulk rescue
        val retryIds = s.server.pushes.drop(before).flatten().filter { it.op == "put" && it.vaultId == s.member.personalVaultId }.map { it.mutationId }
        assertEquals(firstIds, retryIds) // memoized gestures → identical mutationIds → dedup, not duplicates
    }

    @Test
    fun bulkCopyRemintsGestureWhenSourceRevChanges() = runBlocking<Unit> {
        // #5: a gesture memo is only valid for UNCHANGED source content — a rev bump must
        // remint (fresh ids), or a replayed stale gesture would copy a stale snapshot.
        val s = seededMember("writer")
        s.engine.copyAllToPersonal(s.vaultId)
        val firstIds = s.server.pushes.flatten().filter { it.op == "put" && it.vaultId == s.member.personalVaultId }.map { it.mutationId }.toSet()
        // The source item changes on another device (rev bump re-delivered).
        val newBlob = s.owner.encryptItem(s.vaultId, s.itemId, doc.copy(name = "changed upstream")).blob
        s.server.queue.add(SyncResponse(9, false, emptyList(), emptyList(), listOf(s.item.copy(rev = 9, blob = newBlob)), emptyList()))
        s.engine.sync()
        val before = s.server.pushes.size
        s.engine.copyAllToPersonal(s.vaultId)
        val retryIds = s.server.pushes.drop(before).flatten().filter { it.op == "put" && it.vaultId == s.member.personalVaultId }.map { it.mutationId }.toSet()
        assertTrue(retryIds.isNotEmpty() && firstIds.intersect(retryIds).isEmpty(), "changed source ⇒ fresh gesture ⇒ new mutationIds")
    }

    // ==== review fixes: concurrency, durability, and error-surfacing (#0–#4, #6) ====

    @Test
    fun interleavedSyncs_parkableEditIsNeverClassifiedOffAStalePull() = runBlocking<Unit> {
        // #0: a background sync whose snapshot PREDATES the delete must never classify the
        // save's staged denial — the whole cycle is mutex-serialized (epoch guard as belt).
        val s = seededMember("writer")
        val deleteId = uuid()
        val purgeAt = System.currentTimeMillis() + 7L * 86_400_000

        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        s.server.syncEntered = entered
        s.server.syncRelease = release
        s.server.queue.add(s.server.emptySync(6)) // background sync A's STALE response (pre-delete)
        s.server.denyVaults.add(s.vaultId)
        s.server.queue.add(
            SyncResponse(
                7, false, emptyList(), emptyList(), emptyList(), listOf(s.vaultId),
                listOf(RemovedGrantInfo(s.vaultId, "deleted", purgeAt = purgeAt, deleteId = deleteId, deleteProof = LifecycleProof.delete(crypto, s.key(), s.vaultId, deleteId))),
            ),
        )

        val a = async { runCatching { s.engine.sync() } }
        entered.await() // A is mid-pull (holding the sync serialization)
        val b = async { runCatching { s.engine.save(s.itemId, doc.copy(name = "mid-flight edit")) } }
        delay(50) // give B every chance to misbehave if serialization were missing
        release.complete(Unit)
        assertTrue(a.await().isSuccess)
        assertTrue(b.await().isSuccess, "the denied edit must be PARKED, never thrown-and-dropped")

        val n = s.engine.notices().find { it.vaultId == s.vaultId }
        assertEquals("deleted", n?.kind)
        assertEquals(1, n?.parkedCount)
        assertEquals(1, s.cache.getHeld(s.vaultId)?.parked?.size)
    }

    @Test
    fun genuineDenialOfUnrelatedEditSurfacesThroughLifecycleReconcile() = runBlocking<Unit> {
        // #1: deleting vault V must not SWALLOW the denial verdict for a queued edit to an
        // unrelated vault W — the delete stands, but the dropped-edit info must propagate.
        val s = seededMember("writer")
        val personal = s.member.personalVaultId

        // Queue an edit to W (= personal) that fails transport-side → stays queued.
        s.server.failNextPush = true
        assertFailsWith<ApiException> { s.engine.save(null, doc.copy(name = "queued edit"), vaultId = personal) }
        assertEquals(1, s.cache.pending().size)

        // The server now denies writes to W (role change), and V's tombstone arrives on
        // the delete's own reconcile pull (self-initiated → clean drop, no banner).
        s.server.denyVaults.add(personal)
        val deleteId = uuid()
        s.server.queue.add(
            SyncResponse(
                8, false, emptyList(), emptyList(), emptyList(), listOf(s.vaultId),
                listOf(RemovedGrantInfo(s.vaultId, "deleted", purgeAt = System.currentTimeMillis() + 1000, deleteId = deleteId, deleteProof = LifecycleProof.delete(crypto, s.key(), s.vaultId, deleteId))),
            ),
        )
        val e = assertFailsWith<ApiException> { s.engine.deleteSharedVault(s.vaultId) }
        assertEquals("denied", e.code)
        // The delete itself stands: V left the live view, the server call was made.
        assertTrue(s.server.calls.contains("deleteVault"))
        assertNull(s.engine.item(s.itemId))
        // The genuinely denied W-edit was durably dropped — nothing queued, nothing staged.
        assertTrue(s.cache.pending().isEmpty())
        assertTrue(s.cache.stagedDenied().isEmpty())
    }

    @Test
    fun stagedDenialSurvivesProcessDeath_thenParksOnTheNextPull() = runBlocking<Unit> {
        // #2: the denial→classifying-pull window must be crash-durable — process death in
        // between must not destroy the edit F21 promises to park.
        val tmp = java.nio.file.Files.createTempDirectory("andvari-park").toFile()
        val dbPath = java.io.File(tmp, "vault.db").absolutePath
        val owner = enroll("owner@example.com")
        val member = enroll("member@example.com")
        val nv = owner.buildCreateSharedVault("Family")
        val vaultId = nv.vaultId
        val itemId = owner.newItemId()
        val vault = WireVault(vaultId, "shared", 2, nv.request.metaBlob, 0)
        val grant = WireGrant(vaultId, member.userId, "writer", "", 3, owner.wrapVkForMember(member.identityPub, vaultId))
        val item = WireItem(itemId, vaultId, 4, 0, 0, false, false, 1, emptyList(), owner.encryptItem(vaultId, itemId, doc).blob)
        val server = FakeServer()

        val cache1 = sqliteVaultCache(dbPath, member.userId)
        val engine1 = SyncEngine(server.api(), member, cache1)
        server.queue.add(SyncResponse(5, true, listOf(vault), listOf(grant), listOf(item), emptyList()))
        engine1.sync()

        // The denial lands, but its classifying pull FAILS — then the process dies.
        server.denyVaults.add(vaultId)
        server.failNextSync = true
        assertFailsWith<ApiException> { engine1.save(itemId, doc.copy(name = "edited before death")) }
        assertEquals(1, cache1.stagedDenied().size) // durably staged, not lost with the dequeue
        engine1.close() // "process death"

        // Relaunch on the same db: hydrate reloads the staged denial; the delete arrives.
        val cache2 = sqliteVaultCache(dbPath, member.userId)
        val engine2 = SyncEngine(server.api(), member, cache2)
        engine2.hydrate()
        val deleteId = uuid()
        val key = owner.lifecycleKeyFor(vaultId)
        server.queue.add(
            SyncResponse(
                7, false, emptyList(), emptyList(), emptyList(), listOf(vaultId),
                listOf(RemovedGrantInfo(vaultId, "deleted", purgeAt = System.currentTimeMillis() + 7L * 86_400_000, deleteId = deleteId, deleteProof = LifecycleProof.delete(crypto, key, vaultId, deleteId))),
            ),
        )
        engine2.sync()
        val held = cache2.getHeld(vaultId)
        assertEquals(1, held?.parked?.size, "the pre-death edit must be parked, not destroyed")
        val n = engine2.notices().find { it.vaultId == vaultId }
        assertEquals("deleted", n?.kind)
        assertEquals(1, n?.parkedCount)
        engine2.close()
    }

    @Test
    fun replayDeniedOnLiveVault_calmNoticeNotAThrow() = runBlocking<Unit> {
        // #3+#6: parked edits replay through the durable queue on reinstate; a replay
        // denied on the now-live vault (re-added as READER) is a calm one-time notice.
        val s = seededMember("writer")
        val deleteId = uuid()
        s.server.denyVaults.add(s.vaultId)
        s.server.queue.add(
            SyncResponse(
                6, false, emptyList(), emptyList(), emptyList(), listOf(s.vaultId),
                listOf(RemovedGrantInfo(s.vaultId, "deleted", purgeAt = System.currentTimeMillis() + 7L * 86_400_000, deleteId = deleteId, deleteProof = LifecycleProof.delete(crypto, s.key(), s.vaultId, deleteId))),
            ),
        )
        s.engine.save(s.itemId, doc.copy(name = "edited in-flight")) // parked, not thrown

        // Restore arrives but our grant comes back as READER — the replay will be denied.
        val restoredVault = s.vault.copy(rev = 8, restoreProof = LifecycleProof.restore(crypto, s.key(), s.vaultId, deleteId), deleteId = deleteId)
        s.server.queue.add(SyncResponse(9, false, listOf(restoredVault), listOf(s.grant.copy(role = "reader", rev = 9)), listOf(s.item.copy(rev = 9)), emptyList()))
        s.engine.sync() // must NOT throw — the replay denial is a notice, not a failure

        val kinds = s.engine.notices().filter { it.vaultId == s.vaultId }.map { it.kind }
        assertTrue("restored" in kinds)
        assertTrue("replay-denied" in kinds, "got $kinds")
        assertNotNull(s.engine.item(s.itemId)) // the vault is live again
        assertTrue(s.cache.pending().isEmpty() && s.cache.stagedDenied().isEmpty()) // durably dropped
        val before = s.server.pushes.size
        s.engine.sync()
        assertEquals(before, s.server.pushes.size) // no retry loop
    }

    @Test
    fun failedReconcileNeverLeavesAStaleSelfInitiationMarker() = runBlocking<Unit> {
        // #4: a delete whose reconcile pull fails must not leave a suppressDrop entry that
        // later misreads a GENUINE removal as self-initiated (holding-area bypass).
        val s = seededMember("writer")
        s.server.failNextSync = true
        s.engine.deleteSharedVault(s.vaultId) // reconcile fails (transport) → swallowed
        assertNull(s.engine.item(s.itemId)) // local fallback drop ran

        // The vault is restored elsewhere and re-delivered live.
        s.server.queue.add(SyncResponse(8, false, listOf(s.vault.copy(rev = 8)), listOf(s.grant.copy(rev = 8)), listOf(s.item.copy(rev = 8)), emptyList()))
        s.engine.sync()
        assertNotNull(s.engine.item(s.itemId))

        // A LATER genuine delete must park + notice — never a silent self-initiated drop.
        val deleteId = uuid()
        s.server.queue.add(
            SyncResponse(
                9, false, emptyList(), emptyList(), emptyList(), listOf(s.vaultId),
                listOf(RemovedGrantInfo(s.vaultId, "deleted", purgeAt = System.currentTimeMillis() + 7L * 86_400_000, deleteId = deleteId, deleteProof = LifecycleProof.delete(crypto, s.key(), s.vaultId, deleteId))),
            ),
        )
        s.engine.sync()
        assertEquals("deleted", s.engine.notices().find { it.vaultId == s.vaultId }?.kind)
        assertNotNull(s.cache.getHeld(s.vaultId))
    }
}
