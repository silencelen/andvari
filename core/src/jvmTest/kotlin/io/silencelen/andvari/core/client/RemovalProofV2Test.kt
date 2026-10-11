package io.silencelen.andvari.core.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.toByteArray
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.LifecycleProof
import io.silencelen.andvari.core.crypto.RemovalProof
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountStatePut
import io.silencelen.andvari.core.model.AccountStateResponse
import io.silencelen.andvari.core.model.RemovedGrantInfo
import io.silencelen.andvari.core.model.SyncResponse
import io.silencelen.andvari.core.model.VaultLeaveRequest
import io.silencelen.andvari.core.model.VaultMemberRemoveRequest
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireItem
import io.silencelen.andvari.core.model.WireVault
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Removal proofs v2 on the path a real client takes (security review 2026-10, root cause A §6, §8.6; branch A7).
 * The invariant: no removal or leave banner is attributed as genuine without a v2 MAC under the held VK for THIS
 * target, a nonce never consumed here or in account state, and an issuedAt inside this device's own liveSince
 * window; liveSince and the consumed set never come from the server. The data handling is the same either way.
 */
class RemovalProofV2Test {
    private val crypto = createCryptoProvider()
    private val kdf = KdfParams(ops = 1, memBytes = 8192)
    private val doc = ItemDoc(type = "login", name = "Shared login", login = LoginData(username = "fam", password = "hunter2"))
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private fun enroll(email: String): Account {
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val fp = Escrow.fingerprint(crypto, recovery.publicKey)
        return Account.enroll("test-invite", email, email, "pw $email", kdf, recovery.publicKey, fp, "test-device", crypto).account
    }

    /** A scripted server: a sync queue, the account-state blob, and the lifecycle bodies a client posts. */
    private inner class FakeServer {
        val queue = ArrayDeque<SyncResponse>()
        var rev = 1L
        var accountState: String? = null
        var accountSeq = 0L
        val leaves = mutableListOf<VaultLeaveRequest?>()
        val removals = mutableListOf<Pair<String, VaultMemberRemoveRequest?>>()

        fun api(): AndvariApi {
            val engine = MockEngine { req ->
                val path = req.url.encodedPath
                val ct = headersOf(HttpHeaders.ContentType, "application/json")
                fun ok(body: String) = respond(body, HttpStatusCode.OK, ct)
                when {
                    path == "/api/v1/sync" -> {
                        val resp = queue.removeFirstOrNull() ?: SyncResponse(rev, false, emptyList(), emptyList(), emptyList(), emptyList())
                        rev = maxOf(rev, resp.rev)
                        ok(json.encodeToString(SyncResponse.serializer(), resp))
                    }
                    path == "/api/v1/account/state" && req.method == HttpMethod.Get ->
                        ok(json.encodeToString(AccountStateResponse.serializer(), AccountStateResponse(accountState, accountSeq)))
                    path == "/api/v1/account/state" && req.method == HttpMethod.Put -> {
                        val put = json.decodeFromString(AccountStatePut.serializer(), req.body.toByteArray().decodeToString())
                        if (put.baseSeq != accountSeq) respond("""{"error":"stale_state","message":"stale"}""", HttpStatusCode.Conflict, ct)
                        else {
                            accountState = put.sealedState; accountSeq += 1
                            ok(json.encodeToString(AccountStateResponse.serializer(), AccountStateResponse(accountState, accountSeq)))
                        }
                    }
                    path.endsWith("/leave") -> {
                        val b = req.body.toByteArray().decodeToString()
                        leaves.add(if (b.isBlank()) null else json.decodeFromString(VaultLeaveRequest.serializer(), b))
                        ok("""{"rev":${++rev}}""")
                    }
                    path.contains("/members/") && req.method == HttpMethod.Delete -> {
                        val b = req.body.toByteArray().decodeToString()
                        removals.add(path.substringAfterLast('/') to if (b.isBlank()) null else json.decodeFromString(VaultMemberRemoveRequest.serializer(), b))
                        ok("""{"rev":${++rev}}""")
                    }
                    else -> respond("""{"error":"not_found","message":"unexpected $path"}""", HttpStatusCode.NotFound, ct)
                }
            }
            return AndvariApi("http://fake", HttpClient(engine), Tokens("access", "refresh"))
        }
    }

    private inner class Seed(val owner: Account, val member: Account, val server: FakeServer, val cache: VaultCache, var engine: SyncEngine, val vaultId: String, val vault: WireVault, val grant: WireGrant, val item: WireItem) {
        val key: ByteArray get() = owner.lifecycleKeyFor(vaultId)
        fun removedV2(nonce: String = LifecycleProof.newNonce(crypto), at: Long = System.currentTimeMillis(), target: String = member.userId) =
            RemovedGrantInfo(vaultId, "removed", removeProof = LifecycleProof.removeV2(crypto, key, vaultId, target, nonce, at), removeNonce = nonce, proofV = 2, issuedAt = at)
        fun leftV2(nonce: String = LifecycleProof.newNonce(crypto), at: Long = System.currentTimeMillis()) =
            RemovedGrantInfo(vaultId, "left", removeProof = LifecycleProof.leave(crypto, key, vaultId, member.userId, nonce, at), removeNonce = nonce, proofV = 2, issuedAt = at)
        fun deliver(info: RemovedGrantInfo?) {
            server.queue.add(SyncResponse(++server.rev + 10, false, emptyList(), emptyList(), emptyList(), listOf(vaultId), listOfNotNull(info)))
            runBlocking { engine.sync() }
        }
        fun reAdd() {
            server.queue.add(SyncResponse(++server.rev + 10, false, listOf(vault), listOf(grant.copy(rev = server.rev + 10)), listOf(item), emptyList()))
            runBlocking { engine.sync() }
        }
        fun notice() = engine.notices().last { it.vaultId == vaultId }
    }

    private fun seeded(cache: VaultCache = InMemoryVaultCache()): Seed {
        val owner = enroll("owner@example.com")
        val member = enroll("member@example.com")
        val nv = owner.buildCreateSharedVault("Family")
        val vaultId = nv.vaultId
        val vault = WireVault(vaultId, "shared", 2, nv.request.metaBlob, 0)
        val grant = WireGrant(vaultId, member.userId, "writer", "", 3, owner.wrapVkForMember(member.identityPub, vaultId))
        val itemId = owner.newItemId()
        val item = WireItem(itemId, vaultId, 4, 0, 0, false, false, 1, emptyList(), owner.encryptItem(vaultId, itemId, doc).blob)
        val server = FakeServer()
        val engine = SyncEngine(server.api(), member, cache)
        server.queue.add(SyncResponse(5, true, listOf(vault), listOf(grant), listOf(item), emptyList()))
        runBlocking { engine.sync(); engine.acceptLegacyVault(vaultId) }
        server.rev = 5
        return Seed(owner, member, server, cache, engine, vaultId, vault, grant, item)
    }

    // ---- §6.3, every step, through the engine ----

    @Test
    fun aValidV2RemovalIsAttributedHeldAndConsumed() {
        val s = seeded()
        val info = s.removedV2()
        s.deliver(info)
        assertEquals("removed", s.notice().kind)
        assertNull(s.notice().reason)
        assertNotNull(s.engine.heldVaultInfos().singleOrNull { it.vaultId == s.vaultId }, "holding area, as before")
        assertFalse(s.member.hasVault(s.vaultId))
        assertEquals<List<String?>?>(listOf(info.removeNonce), s.cache.consumedNonces()[s.vaultId]?.map { it.nonce })
        assertEquals(info.issuedAt, s.cache.consumedNonces()[s.vaultId]?.single()?.issuedAt)
    }

    @Test
    fun aValidV2LeaveIsTheCalmYouLeft() {
        val s = seeded()
        s.deliver(s.leftV2())
        assertEquals("left", s.notice().kind)
        assertNull(s.notice().reason, "a proven leave has no 'tell your admin' line")
        assertEquals(1, s.cache.consumedNonces()[s.vaultId]?.size)
    }

    @Test
    fun aProofForAnotherTargetIsAnAnomaly() {
        val s = seeded()
        s.deliver(s.removedV2(target = s.owner.userId))
        assertEquals("anomaly", s.notice().kind)
        assertTrue(s.cache.consumedNonces().isEmpty(), "nothing is consumed on a failed verdict")
        assertNotNull(s.engine.heldVaultInfos().singleOrNull { it.vaultId == s.vaultId }, "same data handling")
    }

    @Test
    fun aLeaveProofRelayedAsARemovalIsAnAnomaly() {
        val s = seeded()
        val leave = s.leftV2()
        s.deliver(leave.copy(reason = "removed"))
        assertEquals("anomaly", s.notice().kind)
    }

    @Test
    fun aConsumedNonceIsReplayDenied() {
        val s = seeded()
        val info = s.removedV2()
        s.cache.addConsumedNonce(s.vaultId, info.removeNonce!!, info.issuedAt!!)
        s.deliver(info)
        assertEquals("replay-denied", s.notice().kind)
        assertEquals(SyncEngine.REMOVAL_REPLAY, s.notice().reason)
    }

    @Test
    fun aProofIssuedBeforeThisDevicesLiveSinceIsAnAnomaly() {
        val before = System.currentTimeMillis()
        val s = seeded()
        val liveSince = s.cache.liveSince(s.vaultId)
        assertNotNull(liveSince)
        assertTrue(liveSince >= before)
        s.deliver(s.removedV2(at = before - RemovalProof.SKEW_MS - 1))
        assertEquals("anomaly", s.notice().kind)
    }

    @Test
    fun aProofIssuedInTheFutureIsAnAnomaly() {
        val s = seeded()
        s.deliver(s.removedV2(at = System.currentTimeMillis() + RemovalProof.SKEW_MS + 60_000))
        assertEquals("anomaly", s.notice().kind)
    }

    @Test
    fun aV2RowMissingItsIssuedAtIsAnAnomaly() {
        val s = seeded()
        s.deliver(s.removedV2().copy(issuedAt = null))
        assertEquals("anomaly", s.notice().kind)
    }

    // ---- §8.6 in-window rows ----

    @Test
    fun aV1ProofInWindowIsValidLegacyOnceThenReplayDenied() {
        val s = seeded()
        val nonce = uuid()
        val v1 = RemovedGrantInfo(s.vaultId, "removed", removeProof = LifecycleProof.remove(crypto, s.key, s.vaultId, s.member.userId, nonce), removeNonce = nonce)
        s.deliver(v1)
        assertEquals("removed", s.notice().kind)
        assertEquals<List<String>?>(listOf(nonce), s.cache.consumedNonces()[s.vaultId]?.map { it.nonce }, "a legacy proof is consumed too")
        s.reAdd()
        s.deliver(v1)
        assertEquals("replay-denied", s.notice().kind, "the same v1 proof after a re-add")
    }

    @Test
    fun aProoflessLeftInWindowSaysYouLeftAndTellYourAdmin() {
        val s = seeded()
        s.deliver(RemovedGrantInfo(s.vaultId, "left"))
        assertEquals("left", s.notice().kind)
        assertEquals(SyncEngine.LEFT_UNPROVEN, s.notice().reason)
        assertTrue(HouseholdCopy.leftUnprovenNotice("Family").contains("Didn't do this? Tell your admin"))
    }

    // ---- replay after a re-add ----

    @Test
    fun aReplayAfterAReAddIsRejectedOnADeviceThatSawTheReAdd() {
        val s = seeded()
        val info = s.removedV2(at = System.currentTimeMillis())
        s.deliver(info)
        assertEquals("removed", s.notice().kind)
        s.reAdd()
        assertTrue(s.member.hasVault(s.vaultId))
        s.deliver(info)
        assertEquals("replay-denied", s.notice().kind)
    }

    @Test
    fun anOldProofAfterAReAddFailsTheWindowEvenWithoutTheConsumedRecord() {
        val s = seeded()
        val old = System.currentTimeMillis() - 3 * RemovalProof.SKEW_MS
        // The removal this proof belonged to was never seen here (consumed nowhere); the device saw the vault go live
        // again only now, so an issuedAt from before that cannot verify.
        s.deliver(RemovedGrantInfo(s.vaultId, "removed"))
        s.reAdd()
        s.deliver(s.removedV2(at = old))
        assertEquals("anomaly", s.notice().kind)
    }

    // ---- durability: restart, merge, never shrunk ----

    @Test
    fun theConsumedSetSurvivesARestartAndMergesIntoAccountState() {
        val dir = createTempDir()
        try {
            val cache = sqliteVaultCache(File(dir, "c.db").absolutePath, "member")
            val s = seeded(cache)
            val info = s.removedV2()
            s.deliver(info)
            // The flush that ran in the same sync merged the device set into account state.
            assertTrue(s.engine.accountState.doc.consumedNonces[s.vaultId].orEmpty().any { it.nonce == info.removeNonce })
            assertNotNull(s.server.accountState)
            // Restart: a new engine over the same durable cache.
            cache.close()
            val reopened = sqliteVaultCache(File(dir, "c.db").absolutePath, "member")
            assertEquals<List<String?>?>(listOf(info.removeNonce), reopened.consumedNonces()[s.vaultId]?.map { it.nonce })
            val restarted = SyncEngine(s.server.api(), s.member, reopened)
            restarted.hydrate()
            s.engine = restarted
            s.reAdd()
            s.deliver(info)
            assertEquals("replay-denied", s.notice().kind)
            reopened.close()
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun servedAccountStateNeverShrinksTheConsumedSet() {
        val s = seeded()
        val info = s.removedV2()
        s.deliver(info)
        val blobWithNonce = s.server.accountState!!
        // The server serves an authentic but EMPTY older-shaped blob: a rollback below this device's high-water mark.
        s.server.accountState = s.member.sealAccountState(AccountState.empty(s.member.userId).copy(seq = 1))
        runBlocking { s.engine.accountState.refresh() }
        assertTrue(s.engine.accountState.doc.consumedNonces[s.vaultId].orEmpty().any { it.nonce == info.removeNonce }, "still there")
        assertTrue(blobWithNonce.isNotEmpty())
        // A second device of the same user with NO device record of the nonce learns it from account state.
        val secondCache = InMemoryVaultCache()
        val second = SyncEngine(s.server.api(), s.member, secondCache)
        runBlocking { second.accountState.refresh() }
        assertTrue(second.accountState.doc.consumedNonces[s.vaultId].orEmpty().any { it.nonce == info.removeNonce })
    }

    @Test
    fun theAccountStateSetAloneDeniesAReplay() {
        val s = seeded()
        val info = s.removedV2()
        // Another device of this user consumed it and flushed; this device has no device record.
        val sealed = s.member.sealAccountState(
            AccountState.empty(s.member.userId).copy(seq = 3, consumedNonces = mapOf(s.vaultId to listOf(ConsumedNonce(info.removeNonce!!, info.issuedAt!!)))),
        )
        s.server.accountState = sealed
        s.server.accountSeq = 3
        runBlocking { s.engine.accountState.refresh() }
        assertTrue(s.cache.consumedNonces().isEmpty())
        s.deliver(info)
        assertEquals("replay-denied", s.notice().kind)
    }

    // ---- liveSince is device-local ----

    @Test
    fun liveSinceIgnoresServerInput() {
        val before = System.currentTimeMillis()
        // The server claims the vault and grant are ancient (createdAt / addedAt / rev): none of it is liveSince.
        val s = seeded()
        val live = s.cache.liveSince(s.vaultId)!!
        assertTrue(live >= before, "liveSince is this device's first sight, not a server timestamp")
        // A re-delivered row with an ancient createdAt does not move it.
        s.server.queue.add(SyncResponse(++s.server.rev + 10, false, listOf(s.vault.copy(createdAt = 1, rev = 50)), listOf(s.grant.copy(rev = 51)), emptyList(), emptyList()))
        runBlocking { s.engine.sync() }
        assertEquals(live, s.cache.liveSince(s.vaultId))
        // So a proof minted 20 minutes before this device first saw the vault cannot verify, whatever the rows say.
        s.deliver(s.removedV2(at = before - 2 * RemovalProof.SKEW_MS))
        assertEquals("anomaly", s.notice().kind)
    }

    // ---- consume and move-to-holding are one transaction ----

    /** A durable cache whose cursor write fails once: the pull transaction rolls back after the removal ran. */
    private class FailOnceCursor(private val d: VaultCache) : VaultCache by d {
        var armed = false
        override fun setCursor(rev: Long) {
            if (armed) { armed = false; throw IllegalStateException("disk full") }
            d.setCursor(rev)
        }
    }

    @Test
    fun consumeAndMoveToHoldingAreAtomic() {
        val dir = createTempDir()
        try {
            val cache = FailOnceCursor(sqliteVaultCache(File(dir, "c.db").absolutePath, "member"))
            val s = seeded(cache)
            val info = s.removedV2()
            cache.armed = true
            s.server.queue.add(SyncResponse(20, false, emptyList(), emptyList(), emptyList(), listOf(s.vaultId), listOf(info)))
            assertTrue(runCatching { runBlocking { s.engine.sync() } }.isFailure)
            assertNull(cache.getHeld(s.vaultId), "the holding move rolled back")
            assertTrue(cache.consumedNonces().isEmpty(), "and so did the consumption, with it")
            assertTrue(s.member.hasVault(s.vaultId), "the vault is live again after the rollback")
            // The next pull re-delivers: both land together.
            s.server.queue.add(SyncResponse(20, false, emptyList(), emptyList(), emptyList(), listOf(s.vaultId), listOf(info)))
            runBlocking { s.engine.sync() }
            assertNotNull(cache.getHeld(s.vaultId))
            assertEquals<List<String?>?>(listOf(info.removeNonce), cache.consumedNonces()[s.vaultId]?.map { it.nonce })
            assertEquals("removed", s.notice().kind)
        } finally {
            dir.deleteRecursively()
        }
    }

    // ---- the acting clients mint v2 ----

    @Test
    fun leaveCarriesAV2LeaveProofThatTheOtherDevicesVerify() {
        val s = seeded()
        runBlocking { s.engine.leaveSharedVault(s.vaultId) }
        val body = s.server.leaves.single()
        assertNotNull(body)
        assertEquals(2, body.proofV)
        assertTrue(LifecycleProof.isV2Nonce(body.nonce!!))
        val d = RemovalProof.decide(crypto, s.key, s.vaultId, s.member.userId, "left", body.proofV, body.proof, body.nonce, body.issuedAt, emptySet(), body.issuedAt!! - 1, System.currentTimeMillis())
        assertEquals(RemovalProof.Verdict.VALID, d.verdict)
    }

    @Test
    fun removeVaultMemberCarriesAV2RemovalProof() {
        val s = seeded()
        val ownerEngine = SyncEngine(s.server.api(), s.owner, InMemoryVaultCache())
        runBlocking { ownerEngine.removeVaultMember(s.vaultId, s.member.userId) }
        val (target, body) = s.server.removals.single()
        assertEquals(s.member.userId, target)
        assertNotNull(body)
        assertEquals(2, body.proofV)
        val d = RemovalProof.decide(crypto, s.key, s.vaultId, s.member.userId, "removed", body.proofV, body.proof, body.nonce, body.issuedAt, emptySet(), body.issuedAt!! - 1, System.currentTimeMillis())
        assertEquals(RemovalProof.Verdict.VALID, d.verdict)
    }

    private fun uuid(): String = io.silencelen.andvari.core.crypto.Bytes.uuidV4FromBytes(crypto.randomBytes(16))

    @Suppress("DEPRECATION")
    private fun createTempDir(): File = kotlin.io.createTempDir("a7-")
}
