package io.silencelen.andvari.server

import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.Mutation
import io.silencelen.andvari.core.model.PushRequest
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Security review 2026-10 (root cause D): `/sync/push` stored whatever `itemId` a vault writer
 * sent. The item routes all run requireUuid on `{id}`, but that never helped: the planted id was
 * delivered to every OTHER member through `/items/deleted` and `/sync`, and THEIR client put it
 * into a URL path — `../admin/users/<id>/disable?` resolved to an admin route under the victim's
 * bearer token. The clients now refuse such a segment; this pins the other half — the server
 * never stores one, so no member can be handed it. A per-mutation `rejected` (the H03 shape), not
 * a thrown 400: the sibling mutations in the batch still land.
 */
class PushItemIdGateTest {
    private val crypto = createCryptoProvider()
    private val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
    private val fingerprint = Escrow.fingerprint(crypto, recovery.publicKey)
    private val bootstrap = "itemid-gate-bootstrap"
    private val tmp = Files.createTempDirectory("andvari-itemid-gate").toFile()

    private fun config() = Config(
        host = "127.0.0.1", port = 0,
        dbPath = File(tmp, "gate-${System.nanoTime()}.db").absolutePath,
        blobDir = File(tmp, "blobs").absolutePath, webDir = null,
        recoveryPublicKey = recovery.publicKey, recoveryFingerprint = fingerprint,
        enumSecret = ByteArray(32) { 5 }, publicHostname = null, bootstrapToken = bootstrap,
    )

    @AfterTest fun cleanup() { tmp.deleteRecursively() }

    private suspend fun enroll(api: AndvariApi, email: String, password: String): Account {
        val policy = api.clientPolicy()
        val recoveryPub = Bytes.fromB64(api.recoveryPubkey())
        val (req, account) = Account.enroll(
            bootstrap, email, email.substringBefore('@'), password,
            policy.kdfParams, recoveryPub, policy.recoveryFingerprint, "device", crypto,
        )
        api.register(req)
        return account
    }

    private fun put(account: Account, itemId: String): Mutation =
        Mutation(account.newItemId(), "put", itemId, account.personalVaultId, 0, account.encryptItem(account.personalVaultId, itemId, ItemDoc(type = "login", name = "x")))

    @Test
    fun aNonUuidItemId_isRejectedPerMutation_neverStored_andTheSiblingLands() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val api = AndvariApi("", createClient { })
        val account = enroll(api, "gate@d.test", "gate password one two")

        val planted = listOf(
            "../admin/users/0f8e2c1a-3b4d-4e5f-8a9b-0c1d2e3f4a5b/disable?",
            "../recovery/self/confirm#",
            "..",
            "0F8E2C1A-3B4D-4E5F-8A9B-0C1D2E3F4A5B", // not canonical: the item routes would refuse it
            "",
        )
        val goodId = account.newItemId()
        val bad = planted.map { put(account, it) }
        val good = put(account, goodId)
        val resp = api.push(PushRequest(bad + good))
        val byId = resp.results.associateBy { it.mutationId }
        for (m in bad) {
            val r = byId.getValue(m.mutationId)
            assertEquals("rejected", r.status, "itemId ${m.itemId}")
            assertEquals("bad_item_id", r.reason, "itemId ${m.itemId}")
        }
        assertEquals("applied", byId.getValue(good.mutationId).status, "the sibling is not rolled back with it")

        // A delete of a planted id is refused the same way, so no tombstone can carry one either.
        val del = Mutation(account.newItemId(), "delete", planted.first(), account.personalVaultId, 0, null)
        assertEquals("bad_item_id", api.push(PushRequest(listOf(del))).results.single().reason)

        assertEquals(listOf(goodId), api.sync(0).items.map { it.itemId }, "nothing but the real id was stored")
        assertTrue(api.deletedItems().isEmpty(), "and nothing can surface in a member's Trash")
    }
}
