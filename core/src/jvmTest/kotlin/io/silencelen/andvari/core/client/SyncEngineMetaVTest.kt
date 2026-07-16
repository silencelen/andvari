package io.silencelen.andvari.core.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.toByteArray
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.SharedGrant
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.MutationResult
import io.silencelen.andvari.core.model.PushRequest
import io.silencelen.andvari.core.model.PushResponse
import io.silencelen.andvari.core.model.SyncResponse
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireItem
import io.silencelen.andvari.core.model.WireVault
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * spec 02 §4 warn-and-keep-newer (SyncEngine.keepNewerMeta) + the pinned metaV parse rule:
 * `metaV` counts ONLY when it is an integral, non-negative JSON number, else 0 — the SAME
 * rule in [SyncEngine.metaV] and [Account.buildRenameMeta], on every client. Same fake-api
 * drive pattern as SyncEngineLifecycleTest; mirrors web/src/vault/store.metav.test.ts.
 */
class SyncEngineMetaVTest {

    private val crypto = createCryptoProvider()
    private val kdf = KdfParams(ops = 1, memBytes = 8192) // test-speed argon2id (web test parity)
    private val doc = ItemDoc(type = "login", name = "Shared login", login = LoginData(username = "fam", password = "hunter2"))

    private fun enroll(email: String): Account {
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val fp = Escrow.fingerprint(crypto, recovery.publicKey)
        return Account.enroll("test-invite", email, email, "pw $email", kdf, recovery.publicKey, fp, "test-device", crypto).account
    }

    /** Fake server: sync queue + a one-shot 410 knob (cursor gone → the engine resyncs from 0). */
    private class FakeServer {
        val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
        val queue = ArrayDeque<SyncResponse>()
        var rev = 1L
        var goneNextSync = false

        fun emptySync(rev: Long) = SyncResponse(rev, false, emptyList(), emptyList(), emptyList(), emptyList())

        fun api(): AndvariApi {
            val engine = MockEngine { req ->
                val jsonHeaders = headersOf(HttpHeaders.ContentType, "application/json")
                when (req.url.encodedPath) {
                    "/api/v1/sync" -> {
                        if (goneNextSync) {
                            goneNextSync = false
                            respond("""{"error":"gone","message":"cursor expired"}""", HttpStatusCode.Gone, jsonHeaders)
                        } else {
                            val resp = queue.removeFirstOrNull() ?: emptySync(rev)
                            rev = maxOf(rev, resp.rev)
                            respond(json.encodeToString(SyncResponse.serializer(), resp), HttpStatusCode.OK, jsonHeaders)
                        }
                    }
                    "/api/v1/sync/push" -> {
                        val body = json.decodeFromString(PushRequest.serializer(), req.body.toByteArray().decodeToString())
                        val results = body.mutations.map { MutationResult(it.mutationId, "applied", 1L) }
                        respond(json.encodeToString(PushResponse.serializer(), PushResponse(++rev, results)), HttpStatusCode.OK, jsonHeaders)
                    }
                    else -> respond("""{"error":"not_found","message":"unexpected ${req.url.encodedPath}"}""", HttpStatusCode.NotFound, jsonHeaders)
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
        val vault: WireVault,
        val grant: WireGrant,
        val item: WireItem,
    ) {
        fun row(): WireVault = cache.vaults().first { it.vaultId == vaultId }
        fun name(): String? = member.decryptVaultName(vaultId, row().metaBlob)
    }

    /** A member holding a shared vault "Family" (metaBlob has NO metaV yet — the 0 floor) at cursor 5. */
    private fun seeded(): Seed {
        val owner = enroll("owner@example.com")
        val member = enroll("member@example.com")
        val nv = owner.buildCreateSharedVault("Family")
        val vaultId = nv.vaultId
        val itemId = owner.newItemId()
        val vault = WireVault(vaultId, "shared", 2, nv.request.metaBlob, 0)
        val grant = WireGrant(vaultId, member.userId, "writer", "", 3, owner.wrapVkForMember(member.identityPub, vaultId))
        val item = WireItem(itemId, vaultId, 4, 0, 0, false, false, 1, emptyList(), owner.encryptItem(vaultId, itemId, doc).blob)
        val server = FakeServer()
        val cache = InMemoryVaultCache()
        val engine = SyncEngine(server.api(), member, cache)
        server.queue.add(SyncResponse(5, true, listOf(vault), listOf(grant), listOf(item), emptyList()))
        runBlocking { engine.sync() }
        return Seed(owner, member, engine, server, cache, vaultId, vault, grant, item)
    }

    /** Deliver a rename to "Family v2" (metaV 0 → 1) and return the renamed metaBlob. */
    private fun Seed.applyRename(): String {
        val renamed = owner.buildRenameMeta(vaultId, vault.metaBlob, "Family v2")
        server.queue.add(SyncResponse(6, false, listOf(vault.copy(rev = 6, metaBlob = renamed)), emptyList(), emptyList(), emptyList()))
        runBlocking { engine.sync() }
        return renamed
    }

    /** The VK, extracted the way any key-holder could (sealed to a keypair the test holds),
     *  used to craft adversarial metaBlob plaintexts no honest client would write. */
    private fun Seed.craftMeta(metaVJson: String): String {
        val kp = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val vk = SharedGrant.open(crypto, kp.publicKey, kp.privateKey, vaultId, Bytes.fromB64(owner.wrapVkForMember(kp.publicKey, vaultId)))
        return Envelope.sealB64(crypto, vk, """{"name":"Imposter","metaV":$metaVJson}""".encodeToByteArray(), Ad.vaultMeta(vaultId))
    }

    @Test
    fun replayedMetaVZeroBlob_keepsNewerName_revAndLifecycleFieldsStillApply() = runBlocking<Unit> {
        val s = seeded()
        val renamed = s.applyRename()
        assertEquals("Family v2", s.name())

        // A stale/malicious server replays the PRE-RENAME row (metaV absent → 0) at a
        // higher rev, with a lifecycle field set — the metaBlob must pin, the rest apply.
        s.server.queue.add(
            SyncResponse(7, false, listOf(s.vault.copy(rev = 7, deleteId = "did-replay")), emptyList(), emptyList(), emptyList()),
        )
        s.engine.sync()

        assertEquals("Family v2", s.name(), "the newer local metaBlob must be kept (warn-and-keep-newer)")
        assertEquals(renamed, s.row().metaBlob)
        assertEquals(7L, s.row().rev, "rev from the delivered row still applies")
        assertEquals("did-replay", s.row().deleteId, "lifecycle fields from the delivered row still apply")
    }

    @Test
    fun resyncFromZero_guardIsInert_snapshotAppliesAsIs() = runBlocking<Unit> {
        val s = seeded()
        s.applyRename()
        assertEquals("Family v2", s.name())

        // Cursor expired (410) → resync from 0: the cache was just cleared, so there is no
        // held row to compare against — the server's snapshot (pre-rename blob) is
        // authoritative and must apply, never pin (this guard is anti-replay, not availability).
        s.server.goneNextSync = true
        s.server.queue.add(
            SyncResponse(10, true, listOf(s.vault.copy(rev = 10)), listOf(s.grant.copy(rev = 10)), listOf(s.item.copy(rev = 10)), emptyList()),
        )
        s.engine.sync()

        assertEquals("Family", s.name(), "on a since=0 resync the guard must be inert")
        assertEquals(10L, s.row().rev)
    }

    @Test
    fun stringOrFractionalOrNegativeMetaV_readsAsZero_replayIsPinned() = runBlocking<Unit> {
        val s = seeded()
        val renamed = s.applyRename() // held metaV = 1

        // spec 02 §4 parse rule: metaV counts ONLY as an integral, non-negative JSON
        // number — "999999" (string-encoded), 2.5 (fractional) and -3 (negative) all read
        // as 0, so each delivery regresses below the held 1 and is pinned IDENTICALLY on
        // every client (the web twin runs the same three).
        var rev = 7L
        for (metaVJson in listOf("\"999999\"", "2.5", "-3")) {
            s.server.queue.add(
                SyncResponse(rev, false, listOf(s.vault.copy(rev = rev, metaBlob = s.craftMeta(metaVJson))), emptyList(), emptyList(), emptyList()),
            )
            s.engine.sync()
            assertEquals("Family v2", s.name(), "metaV $metaVJson must read as 0 and stay pinned")
            assertEquals(renamed, s.row().metaBlob, "metaV $metaVJson: the newer local blob must be kept")
            rev++
        }
    }

    @Test
    fun buildRenameMeta_appliesTheSameParseRule_counterRestartsFromZero() {
        val s = seeded()
        // Write side of the same rule: a rename on top of a crafted non-integral metaV
        // must rebase the counter to 0 and write 1 — NOT 1000000 (string) or 3.5 (fractional).
        for (metaVJson in listOf("\"999999\"", "2.5")) {
            val rebuilt = s.member.buildRenameMeta(s.vaultId, s.craftMeta(metaVJson), "Clean")
            val meta = s.member.decryptVaultMeta(s.vaultId, rebuilt)
            assertEquals(1L, meta.getValue("metaV").jsonPrimitive.long, "metaV $metaVJson must read as 0 → bump writes 1")
            assertEquals("Clean", meta.getValue("name").jsonPrimitive.content)
        }
    }

    @Test
    fun crossImplMetaVVectors_parseIdenticallyToWeb() {
        val s = seeded()
        // spec 02 §4 PINNED metaV parse — these MUST read identically on Kotlin and web
        // (web store.metav.test.ts runs the SAME table). The written counter is parsed+1, so the
        // written value directly reveals what each raw token parsed to. `2.0`, `2e3` and a >2^63
        // literal used to read 0 on Kotlin (raw toLongOrNull) but their numeric value on web — the
        // exact fleet fork this pins shut (Account.parseMetaV now reads the token as a Double under
        // the 2^53 safe-integer ceiling, matching web's Number.isSafeInteger). token → PARSED value:
        val vectors = listOf(
            "2" to 2L, //                       plain integer
            "2.0" to 2L, //                     integral double literal (was 0 on Kotlin)
            "2e3" to 2000L, //                  exponent form (was 0 on Kotlin)
            "-1" to 0L, //                      negative → 0
            "1.5" to 0L, //                     fractional → 0
            "99999999999999999999" to 0L, //    > 2^63 and > 2^53 → 0 on BOTH
            "\"2\"" to 0L, //                   JSON string → 0 (not a counter)
        )
        for ((token, parsed) in vectors) {
            val rebuilt = s.member.buildRenameMeta(s.vaultId, s.craftMeta(token), "Vec")
            val meta = s.member.decryptVaultMeta(s.vaultId, rebuilt)
            assertEquals(parsed + 1, meta.getValue("metaV").jsonPrimitive.long, "metaV token $token must parse to $parsed")
            assertEquals("Vec", meta.getValue("name").jsonPrimitive.content)
        }
    }
}
