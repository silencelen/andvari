package io.silencelen.andvari.core.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.http.headersOf
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.SharedGrant
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.RegisterRequest
import io.silencelen.andvari.core.model.SelfWrapRequest
import io.silencelen.andvari.core.model.SyncResponse
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireVault
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Canonical-key precedence, engine leg (security review 2026-10, root cause A, §3.1–§3.2): the rule
 * must hold on the path a real client takes, a `sync()` and then a cold-start `hydrate()` off the
 * durable cache, and it must be SURFACED: a seal that disagrees with our own wrap raises the
 * "vault key mismatch" notice, and a damaged wrap raises "key unreadable" instead of quietly
 * opening the seal. [VaultKeyPrecedenceTest] pins the Account rule; this pins the wiring, and that a
 * key from a server-mintable v1 seal is never auto-wrapped under the UVK.
 */
class SyncEngineVaultKeyPrecedenceTest {

    private val crypto = createCryptoProvider()
    private val kdf = KdfParams(ops = 1, memBytes = 8192)
    private val password = "correct horse battery staple"
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private class Enrolled(val reg: RegisterRequest, val account: Account, val keys: AccountKeys)

    private fun enroll(email: String): Enrolled {
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val fp = Escrow.fingerprint(crypto, recovery.publicKey)
        val (reg, account) = Account.enroll("inv", email, email, password, kdf, recovery.publicKey, fp, "dev", crypto)
        return Enrolled(
            reg, account,
            AccountKeys(
                kdfSalt = reg.kdfSalt, kdfParams = reg.kdfParams, wrappedUvk = reg.wrappedUvk,
                encryptedIdentitySeed = reg.encryptedIdentitySeed, identityPub = reg.identityPub,
                escrowFingerprint = reg.escrow!!.fingerprint,
            ),
        )
    }

    /** A fake server: serves [feed] on /sync and records every self-wrap PUT. */
    private class FakeServer(var feed: SyncResponse) {
        val selfWraps = mutableListOf<Pair<String, String>>() // vaultId → wrappedVk
    }

    private fun api(server: FakeServer): AndvariApi {
        val engine = MockEngine { req ->
            val path = req.url.encodedPath
            val jsonHeaders = headersOf(HttpHeaders.ContentType, "application/json")
            when {
                path == "/api/v1/sync" -> {
                    // A full snapshot on a fresh device; an empty delta at the same rev afterwards.
                    val since = req.url.parameters["since"]?.toLongOrNull() ?: 0L
                    val resp = if (since == 0L) server.feed else SyncResponse(
                        rev = server.feed.rev, full = false, vaults = emptyList(), grants = emptyList(),
                        items = emptyList(), removedGrants = emptyList(),
                    )
                    respond(json.encodeToString(SyncResponse.serializer(), resp), HttpStatusCode.OK, jsonHeaders)
                }
                req.method == HttpMethod.Put && path.startsWith("/api/v1/vaults/") && path.endsWith("/grant/self-wrap") -> {
                    val vaultId = path.removePrefix("/api/v1/vaults/").removeSuffix("/grant/self-wrap")
                    val body = (req.body as OutgoingContent.ByteArrayContent).bytes().decodeToString()
                    server.selfWraps.add(vaultId to json.decodeFromString(SelfWrapRequest.serializer(), body).wrappedVk)
                    respond("""{"rev":${server.feed.rev + 1}}""", HttpStatusCode.OK, jsonHeaders)
                }
                else -> respond("""{"error":"not_found","message":"unexpected $path"}""", HttpStatusCode.NotFound, jsonHeaders)
            }
        }
        return AndvariApi("http://fake", HttpClient(engine), Tokens("access", "refresh"))
    }

    @Test
    fun aSwappedSealIsRefusedAndSurfacedOnSyncAndOnColdStart() = runBlocking<Unit> {
        val owner = enroll("engine-owner@example.com")
        val shared = owner.account.buildCreateSharedVault("Household")
        val serverVk = crypto.randomBytes(32)
        val forged = Bytes.toB64(SharedGrant.seal(crypto, owner.account.identityPub, shared.vaultId, serverVk))
        val server = FakeServer(
            SyncResponse(
                rev = 7, full = true,
                vaults = listOf(WireVault(shared.vaultId, "shared", 3, shared.request.metaBlob, 0)),
                grants = listOf(WireGrant(shared.vaultId, owner.reg.userId, "owner", shared.request.wrappedVk, 3, forged)),
                items = emptyList(), removedGrants = emptyList(),
            ),
        )
        val cache = InMemoryVaultCache()

        val live = Account.unlock(owner.reg.userId, password, owner.keys, crypto)
        val liveEngine = SyncEngine(api(server), live, cache)
        liveEngine.sync()
        assertEquals("Household", live.decryptVaultName(shared.vaultId, shared.request.metaBlob), "the UVK-wrapped key is the one held")
        val notice = liveEngine.notices().single { it.vaultId == shared.vaultId }
        assertEquals("vk-mismatch", notice.kind)
        assertEquals("Household", notice.vaultName)
        assertTrue(server.selfWraps.isEmpty(), "an owner row already carries our wrap — nothing to post")

        // Cold start off the cache: the replayed row must resolve the same way (the A-1 vector).
        val restarted = Account.unlock(owner.reg.userId, password, owner.keys, crypto)
        val coldEngine = SyncEngine(api(server), restarted, cache)
        coldEngine.hydrate()
        assertEquals("Household", restarted.decryptVaultName(shared.vaultId, shared.request.metaBlob))
        assertEquals(listOf("vk-mismatch"), coldEngine.notices().map { it.kind })
    }

    @Test
    fun aDamagedWrapRaisesKeyUnreadableAndNeverOpensTheSeal() = runBlocking<Unit> {
        val owner = enroll("engine-damaged@example.com")
        val shared = owner.account.buildCreateSharedVault("Household")
        val raw = Bytes.fromB64(shared.request.wrappedVk).also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        val forged = Bytes.toB64(SharedGrant.seal(crypto, owner.account.identityPub, shared.vaultId, crypto.randomBytes(32)))
        val server = FakeServer(
            SyncResponse(
                rev = 7, full = true,
                vaults = listOf(WireVault(shared.vaultId, "shared", 3, shared.request.metaBlob, 0)),
                grants = listOf(WireGrant(shared.vaultId, owner.reg.userId, "owner", Bytes.toB64(raw), 3, forged)),
                items = emptyList(), removedGrants = emptyList(),
            ),
        )
        val device = Account.unlock(owner.reg.userId, password, owner.keys, crypto)
        val engine = SyncEngine(api(server), device, InMemoryVaultCache())
        engine.sync()
        assertFalse(device.hasVault(shared.vaultId), "no seal fallback")
        assertTrue(device.keyUnreadable(shared.vaultId))
        assertEquals(listOf("key-unreadable"), engine.notices().filter { it.vaultId == shared.vaultId }.map { it.kind })
        assertTrue(server.selfWraps.isEmpty(), "nothing is self-wrapped from a key we never adopted")
    }

    /**
     * The laundering guard: a key that arrived by a v1 seal (server-mintable) is NOT self-wrapped
     * automatically. Wrapping it under our UVK would turn a possibly server-chosen key into the
     * canonical one on every device, and make a later genuine seal read as the "mismatch". The
     * read side still works: a row that does carry our wrap is read from the wrap, seal absent.
     */
    @Test
    fun aV1SealIsNotAutoSelfWrappedButAWrapOnTheRowIsReadFirst() = runBlocking<Unit> {
        val owner = enroll("engine-sw-owner@example.com")
        val member = enroll("engine-sw-member@example.com")
        val shared = owner.account.buildCreateSharedVault("Household")
        val seal = owner.account.wrapVkForMember(member.account.identityPub, shared.vaultId)
        val vaultRow = WireVault(shared.vaultId, "shared", 3, shared.request.metaBlob, 0)
        val server = FakeServer(
            SyncResponse(
                rev = 7, full = true, vaults = listOf(vaultRow),
                grants = listOf(WireGrant(shared.vaultId, member.reg.userId, "writer", "", 4, seal)),
                items = emptyList(), removedGrants = emptyList(),
            ),
        )

        val first = Account.unlock(member.reg.userId, password, member.keys, crypto)
        val firstEngine = SyncEngine(api(server), first, InMemoryVaultCache())
        firstEngine.sync()
        firstEngine.sync()
        assertTrue(first.hasVault(shared.vaultId), "v1 seal still adopted for a vault with no wrap (legacy, read-only)")
        assertTrue(server.selfWraps.isEmpty(), "a seal-derived key must never be auto-wrapped under the UVK")

        // A row that carries our wrap (as A6 posts once the grant is verified or accepted): read from it, seal absent.
        assertTrue(first.isLegacyReadOnly(shared.vaultId), "A6: the v1-only key is read-only until vouched for")
        first.authorizeLegacyKey(shared.vaultId)
        val wrap = first.buildSelfWrap(shared.vaultId)
        server.feed = server.feed.copy(
            rev = 8,
            grants = listOf(WireGrant(shared.vaultId, member.reg.userId, "writer", wrap, 8, null)),
        )
        val second = Account.unlock(member.reg.userId, password, member.keys, crypto)
        val secondEngine = SyncEngine(api(server), second, InMemoryVaultCache())
        secondEngine.sync()
        assertEquals("Household", second.decryptVaultName(shared.vaultId, shared.request.metaBlob), "VK read from the UVK wrap")
        assertTrue(server.selfWraps.isEmpty())
        assertTrue(secondEngine.notices().none { it.vaultId == shared.vaultId })
    }
}
