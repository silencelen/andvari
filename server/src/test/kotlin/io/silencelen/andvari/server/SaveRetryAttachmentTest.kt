package io.silencelen.andvari.server

import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.PendingUpload
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.createCryptoProvider
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * F71 review (HIGH): a RETRY after a partially-successful save must not wedge on
 * `attachment_id_taken`. The failure shape: attempt 1 commits an attachment (its bytes carry
 * that attempt's random secretstream header), then dies before the item push; the editor
 * stays open (F71) and the user re-clicks Save with the SAME once-minted refs. The retry
 * re-encrypts from plaintext — fresh header, different sha — so the server's sha-matched
 * dedup refuses the id, and before the fix every retry failed identically forever.
 *
 * Pinned here end-to-end against the real server: the retry now treats `attachment_id_taken`
 * for its own once-minted id as "already committed" and completes. Both save shapes are
 * covered — an EDIT (stable itemId) and a NEW item, where id stability comes from the
 * [SyncEngine.saveWithUploads] `newItemId` draft parameter (a fresh mint per retry would bind
 * the committed attachment to a dead draft id and trip `attachment_mismatch` at push).
 */
class SaveRetryAttachmentTest {
    private val crypto = createCryptoProvider()
    private val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
    private val fingerprint = Escrow.fingerprint(crypto, recovery.publicKey)
    private val bootstrap = "retry-bootstrap"
    private val tmp = Files.createTempDirectory("andvari-retry").toFile()

    private fun config() = Config(
        host = "127.0.0.1", port = 0,
        dbPath = File(tmp, "retry-${System.nanoTime()}.db").absolutePath,
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

    /** Simulate attempt 1's partial success: commit the ref's attachment server-side with
     *  ITS OWN encryption pass (its own random header — sha necessarily differs from any
     *  later re-encryption of the same plaintext). */
    private suspend fun commitFirstAttempt(api: AndvariApi, account: Account, ref: AttachmentRef, itemId: String, vaultId: String, data: ByteArray) {
        val enc = Attachments.encrypt(account.cryptoProvider(), Bytes.fromB64(ref.fileKey), data)
        api.uploadAttachment(ref.id, itemId, vaultId, enc.header + enc.ciphertext)
    }

    @Test
    fun editRetry_afterPartialUpload_completesInsteadOfWedging() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }

        val api = AndvariApi("", createClient { })
        val account = enroll(api, "edit@retry.com", "edit retry password one")
        val engine = SyncEngine(api, account, InMemoryVaultCache())
        engine.sync()

        engine.save(null, ItemDoc(type = "login", name = "router"))
        val item = engine.items().single()

        val data = "the attachment plaintext".encodeToByteArray()
        val ref = AttachmentRef(id = account.newItemId(), name = "note.txt", size = data.size.toLong(), fileKey = Bytes.toB64(account.newFileKey()))
        commitFirstAttempt(api, account, ref, item.itemId, item.vaultId, data)

        // The retry: same once-minted ref, re-encrypted from plaintext (fresh header).
        engine.saveWithUploads(item.itemId, item.doc.copy(attachments = listOf(ref)), listOf(PendingUpload(ref, data)))

        val saved = engine.items().single()
        assertEquals(listOf(ref.id), saved.doc.attachments.map { it.id }, "the retried edit landed with its attachment")
    }

    @Test
    fun newItemRetry_reusesTheDraftId_andCompletes() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }

        val api = AndvariApi("", createClient { })
        val account = enroll(api, "new@retry.com", "new retry password two")
        val engine = SyncEngine(api, account, InMemoryVaultCache())
        engine.sync()

        // Attempt 1 minted the draft id and committed one attachment under it, then died
        // before the push. The editor's retry passes the SAME draft id back in.
        val draftId = account.newItemId()
        val data = "brand new item attachment".encodeToByteArray()
        val ref = AttachmentRef(id = account.newItemId(), name = "seed.bin", size = data.size.toLong(), fileKey = Bytes.toB64(account.newFileKey()))
        commitFirstAttempt(api, account, ref, draftId, account.personalVaultId, data)

        engine.saveWithUploads(
            null,
            ItemDoc(type = "login", name = "brand-new", attachments = listOf(ref)),
            listOf(PendingUpload(ref, data)),
            newItemId = draftId,
        )

        val saved = engine.items().single { it.doc.name == "brand-new" }
        assertEquals(draftId, saved.itemId, "the retry created the item under the FIRST attempt's draft id")
        assertTrue(saved.doc.attachments.any { it.id == ref.id }, "the committed attachment survived the retry")
    }
}
