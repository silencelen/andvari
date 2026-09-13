package io.silencelen.andvari.server

import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.crypto.Attachments
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
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Audit 2026-09-13 H03 — the sync wedge, pinned against the REAL server. A put whose
 * `attachmentIds` no longer resolve used to be a thrown 400 that rolled the WHOLE batch back;
 * no fielded client dequeued on a thrown push, so the row sat at the head of the durable queue
 * and every later sync failed at the same batch BEFORE its pull — the device never received
 * anything again until a sign-out that also wiped every other queued edit.
 *
 * spec 03 §5 now answers such a row with the per-mutation `rejected` status (reason +
 * serverItem) while the rest of the batch proceeds; this suite pins the wire shape for all
 * three reasons, that a healthy sibling in the same batch lands, that a replay is re-evaluated
 * (never dedup-cached), that the restore route keeps its thrown status, and — end to end
 * through core's SyncEngine — that the drain drops the row and the pull still runs.
 */
class PushRejectedAttachmentTest {
    private val crypto = createCryptoProvider()
    private val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
    private val fingerprint = Escrow.fingerprint(crypto, recovery.publicKey)
    private val bootstrap = "rejected-bootstrap"
    private val tmp = Files.createTempDirectory("andvari-rejected").toFile()

    private fun config() = Config(
        host = "127.0.0.1", port = 0,
        dbPath = File(tmp, "rejected-${System.nanoTime()}.db").absolutePath,
        blobDir = File(tmp, "blobs").absolutePath, webDir = null,
        recoveryPublicKey = recovery.publicKey, recoveryFingerprint = fingerprint,
        enumSecret = ByteArray(32) { 9 }, publicHostname = null, bootstrapToken = bootstrap,
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

    private fun put(account: Account, itemId: String, doc: ItemDoc, baseRev: Long = 0): Mutation =
        Mutation(account.newItemId(), "put", itemId, account.personalVaultId, baseRev, account.encryptItem(account.personalVaultId, itemId, doc))

    private suspend fun upload(api: AndvariApi, account: Account, ref: AttachmentRef, itemId: String, data: ByteArray) {
        val enc = Attachments.encrypt(account.cryptoProvider(), Bytes.fromB64(ref.fileKey), data)
        api.uploadAttachment(ref.id, itemId, account.personalVaultId, enc.header + enc.ciphertext)
    }

    @Test
    fun aDanglingRef_isRejectedPerMutation_andTheHealthySiblingLands() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val api = AndvariApi("", createClient { })
        val account = enroll(api, "dangling@h03.com", "dangling password one")

        val goodId = account.newItemId()
        val poisonId = account.newItemId()
        val ghostRef = AttachmentRef(id = account.newItemId(), name = "gone.txt", size = 3, fileKey = Bytes.toB64(account.newFileKey()))
        val good = put(account, goodId, ItemDoc(type = "login", name = "good"))
        val poison = put(account, poisonId, ItemDoc(type = "login", name = "poison", attachments = listOf(ghostRef)))

        // The stale row FIRST, the healthy one behind it — the exact head-of-queue shape.
        val resp = api.push(PushRequest(listOf(poison, good)))

        val byId = resp.results.associateBy { it.mutationId }
        val r = byId.getValue(poison.mutationId)
        assertEquals("rejected", r.status)
        assertEquals("unknown_attachment", r.reason)
        assertNull(r.serverItem, "a never-created item has no server row to carry")
        assertEquals("applied", byId.getValue(good.mutationId).status, "the sibling is not rolled back with it")
        val pulled = api.sync(0)
        assertEquals(listOf(goodId), pulled.items.map { it.itemId }, "only the healthy row exists server-side")

        // Never dedup-cached: the SAME mutationId replayed after the attachment appears LANDS.
        upload(api, account, ghostRef, poisonId, "now here".encodeToByteArray())
        val replay = api.push(PushRequest(listOf(poison)))
        assertEquals("applied", replay.results.single().status)
    }

    @Test
    fun aRefBoundToAnotherItem_isRejectedWithMismatch_andCarriesTheServerRow() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val api = AndvariApi("", createClient { })
        val account = enroll(api, "mismatch@h03.com", "mismatch password two")

        val ownerId = account.newItemId()
        val data = "bound to ownerId".encodeToByteArray()
        val ref = AttachmentRef(id = account.newItemId(), name = "a.txt", size = data.size.toLong(), fileKey = Bytes.toB64(account.newFileKey()))
        upload(api, account, ref, ownerId, data)
        assertEquals("applied", api.push(PushRequest(listOf(put(account, ownerId, ItemDoc(type = "login", name = "owner", attachments = listOf(ref)))))).results.single().status)

        // A different, EXISTING item referencing that attachment: the server row rides along.
        val otherId = account.newItemId()
        val created = api.push(PushRequest(listOf(put(account, otherId, ItemDoc(type = "login", name = "other"))))).results.single()
        val stale = put(account, otherId, ItemDoc(type = "login", name = "other + stolen ref", attachments = listOf(ref)), baseRev = created.newItemRev!!)
        val r = api.push(PushRequest(listOf(stale))).results.single()
        assertEquals("rejected", r.status)
        assertEquals("attachment_mismatch", r.reason)
        assertEquals(otherId, r.serverItem?.itemId, "serverItem = the server's current row for the rejected put")
        assertEquals("other", account.decryptItem(r.serverItem!!).name, "the live row is untouched")
    }

    @Test
    fun theRestoreRoute_keepsItsThrownStatus() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val api = AndvariApi("", createClient { })
        val account = enroll(api, "restore@h03.com", "restore password three")
        val engine = SyncEngine(api, account, InMemoryVaultCache())
        engine.sync()
        engine.save(null, ItemDoc(type = "login", name = "to trash"))
        val item = engine.items().single()
        engine.remove(item.itemId)
        val ghost = AttachmentRef(id = account.newItemId(), name = "gone.txt", size = 1, fileKey = Bytes.toB64(account.newFileKey()))
        // A single direct request with no queue behind it: the 400 stays (spec 03 §8/§9). Sent
        // raw — SyncEngine.restoreDeleted itself strips every ref before the call, so only a
        // hand-built upload can carry one; the server must still refuse it.
        val e = assertFailsWith<ApiException> {
            api.restoreItem(item.itemId, account.encryptItem(item.vaultId, item.itemId, item.doc.copy(attachments = listOf(ghost))))
        }
        assertEquals(400, e.status)
        assertEquals("unknown_attachment", e.code)
    }

    @Test
    fun endToEnd_theDrainDropsTheRow_andTheDeviceKeepsSyncing() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val api = AndvariApi("", createClient { })
        val account = enroll(api, "e2e@h03.com", "e2e password four")
        val engine = SyncEngine(api, account, InMemoryVaultCache())
        engine.sync()

        // A save whose doc references an attachment that was never uploaded (the sweep /
        // peer-delete shape, minus the wait): the editor hears the honest reason ...
        val ghost = AttachmentRef(id = account.newItemId(), name = "gone.txt", size = 1, fileKey = Bytes.toB64(account.newFileKey()))
        val e = assertFailsWith<ApiException> { engine.save(null, ItemDoc(type = "login", name = "stale", attachments = listOf(ghost))) }
        assertEquals("unknown_attachment", e.code)
        // ... the row is gone from the queue, the notice is minted ...
        assertTrue(engine.items().none { it.doc.name == "stale" })
        val n = engine.notices().single()
        assertEquals("write-rejected", n.kind)
        assertEquals("unknown_attachment", n.reason)
        // ... and the device is NOT wedged: a later save lands and a later sync pulls.
        engine.save(null, ItemDoc(type = "login", name = "after the poison"))
        engine.sync()
        assertNotNull(engine.items().single { it.doc.name == "after the poison" })
        assertEquals(listOf("after the poison"), api.sync(0).items.map { account.decryptItem(it).name })
    }
}
