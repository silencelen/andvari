package io.silencelen.andvari.core.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.SyncResponse
import io.silencelen.andvari.core.model.WireItem
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Audit H36: the usage-ledger prune keep-set the natives hand to `flushWithPrune` after a landed
 * sync. Both used `engine.items()` — the DECRYPTED working set — so every 5-min poll on an older
 * phone or desktop pruned the household's usage for items that device merely could not read:
 * an envelope sealed at a newer formatVersion (fail-closed, spec 02 §3) and every item in a vault
 * whose key had not arrived. Web and the extension already fold those ids in. This pins, against
 * the REAL engine and Account crypto, that [SyncEngine.liveItemIds] is the complete live set
 * while [SyncEngine.items] is not — so reverting either native to `items()` is a change a reader
 * can point at this file to refuse.
 */
class SyncEngineLiveItemIdsTest {

    private val crypto = createCryptoProvider()
    private val kdf = KdfParams(ops = 1, memBytes = 8192) // test-speed argon2id
    private val doc = ItemDoc(type = "login", name = "Readable", login = LoginData(username = "u", password = "p"))

    private fun enroll(): Account {
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val fp = Escrow.fingerprint(crypto, recovery.publicKey)
        return Account.enroll("test-invite", "live@example.com", "live@example.com", "pw live", kdf, recovery.publicKey, fp, "test-device", crypto).account
    }

    private fun envelope(id: String, vaultId: String, fv: Int, blob: String?, deleted: Boolean = false) = WireItem(
        itemId = id, vaultId = vaultId, rev = 2, createdAt = 0, updatedAt = 0,
        deleted = deleted, conflict = false, formatVersion = fv, attachmentIds = emptyList(), blob = blob,
    )

    @Test
    fun liveItemIdsKeepsWhatItemsCannotDecrypt() = runBlocking<Unit> {
        val account = enroll()
        val personal = account.personalVaultId
        val readableId = account.newItemId()
        val newerFvId = account.newItemId()
        val unheldId = account.newItemId()
        val goneId = account.newItemId()
        val sealed = account.encryptItem(personal, readableId, doc).blob
        val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
        val feed = SyncResponse(
            rev = 5, full = true, vaults = emptyList(), grants = emptyList(),
            items = listOf(
                envelope(readableId, personal, fv = 1, blob = sealed),
                // Sealed at fv 1 but declared at 99: the ceiling gate refuses it BEFORE the open
                // (fail-closed) — exactly the "N items need an app update" row on an older build.
                envelope(newerFvId, personal, fv = 99, blob = sealed),
                // A vault this device holds no key for (an unarrived grant): persisted, unreadable.
                envelope(unheldId, "vault-we-do-not-hold", fv = 1, blob = "opaque"),
                envelope(goneId, personal, fv = 1, blob = null, deleted = true),
            ),
            removedGrants = emptyList(),
        )
        val engine = MockEngine { req ->
            if (req.url.encodedPath == "/api/v1/sync") {
                respond(json.encodeToString(SyncResponse.serializer(), feed), HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json"))
            } else {
                respond("""{"error":"not_found","message":"unexpected ${req.url.encodedPath}"}""", HttpStatusCode.NotFound, headersOf(HttpHeaders.ContentType, "application/json"))
            }
        }
        val api = AndvariApi("http://fake", HttpClient(engine), Tokens("access", "refresh"))
        val sync = SyncEngine(api, account, InMemoryVaultCache())

        sync.sync()

        assertEquals(setOf(readableId), sync.items().map { it.itemId }.toSet(), "items() is the decrypted working set — it omits the two this device cannot read")
        assertEquals(
            setOf(readableId, newerFvId, unheldId),
            sync.liveItemIds(),
            "the prune keep-set is every LIVE envelope, readable or not; only the tombstone is out",
        )
    }
}
