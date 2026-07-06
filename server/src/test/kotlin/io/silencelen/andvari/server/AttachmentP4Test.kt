package io.silencelen.andvari.server

import io.ktor.client.request.get
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsBytes
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.AttachmentMeta
import io.silencelen.andvari.core.model.ClientPolicy
import io.silencelen.andvari.core.model.Mutation
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** P4 attachments: blob-first upload, item binding, quotas, tombstone cleanup, orphan GC (spec 02 §6). */
class AttachmentP4Test : P4TestSupport() {

    @Test
    fun attachmentRoundtrip_uploadPushDownloadDecrypt() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("att1@x.com", "attachment password one")
        client.register(vc, bootstrapToken)

        // Client-side crypto exactly as a conforming client: random fileKey, chunked secretstream.
        val fileKey = crypto.randomBytes(32)
        val plaintext = crypto.randomBytes(150 * 1024) // 3 chunks — crosses the 64 KiB chunk boundary
        val enc = Attachments.encrypt(crypto, fileKey, plaintext)

        val attId = uuid()
        val itemId = vc.newItemId()
        val up = client.uploadAttachment(vc, attId, itemId, enc.header + enc.ciphertext)
        assertEquals(HttpStatusCode.OK, up.status, up.bodyAsText())
        val meta = json.decodeFromString(AttachmentMeta.serializer(), up.bodyAsText())
        assertEquals(enc.ciphertext.size.toLong(), meta.size, "meta.size is the ciphertext size (header excluded)")
        assertEquals(Bytes.toHexLower(crypto.sha256(enc.ciphertext)), meta.sha256)
        assertEquals(itemId, meta.itemId)
        assertEquals(vc.personalVaultId, meta.vaultId)

        // Idempotent re-upload: same id + same bytes → the same stored meta.
        val again = client.uploadAttachment(vc, attId, itemId, enc.header + enc.ciphertext)
        assertEquals(HttpStatusCode.OK, again.status, again.bodyAsText())
        assertEquals(meta, json.decodeFromString(AttachmentMeta.serializer(), again.bodyAsText()))

        // Same id, different bytes → rejected.
        val other = Attachments.encrypt(crypto, fileKey, crypto.randomBytes(64))
        val taken = client.uploadAttachment(vc, attId, itemId, other.header + other.ciphertext)
        assertEquals(HttpStatusCode.BadRequest, taken.status)
        assertEquals("attachment_id_taken", errorOf(taken))

        // The item referencing the blob (the plaintext half would carry name + fileKey).
        val push = client.push(vc, putMutation(vc, itemId, """{"type":"note","name":"with file"}""", 0, listOf(attId)))
        assertEquals("applied", push.results[0].status)
        assertEquals(listOf(attId), client.sync(vc).items.single { it.itemId == itemId }.attachmentIds)

        // Download: header(24) || ciphertext, byte-identical, decrypts back to the original.
        val dl = client.get("/api/v1/attachments/$attId") { authed(vc) }
        assertEquals(HttpStatusCode.OK, dl.status)
        val body = dl.bodyAsBytes()
        assertEquals(Attachments.HEADER_BYTES + enc.ciphertext.size, body.size)
        val header = body.copyOfRange(0, Attachments.HEADER_BYTES)
        val cipher = body.copyOfRange(Attachments.HEADER_BYTES, body.size)
        assertContentEquals(enc.header, header)
        assertContentEquals(enc.ciphertext, cipher)
        assertContentEquals(plaintext, Attachments.decrypt(crypto, fileKey, header, cipher))
    }

    @Test
    fun quotasAndReferenceValidation() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("att2@x.com", "attachment password two")
        client.register(vc, bootstrapToken)

        // Shrink the budgets via the admin policy endpoint so nothing here exceeds a few KB.
        // maxCipher(1000)=1017, maxCipher(400)=417, maxCipher(500)=517 (each +17B/chunk overhead).
        val policyResp = client.put("/api/v1/admin/policy") {
            contentType(ContentType.Application.Json); authed(vc)
            setBody(ClientPolicy(attachmentMaxBytes = 1000, itemAttachmentsMaxBytes = 400, userAttachmentsMaxBytes = 500))
        }
        assertEquals(HttpStatusCode.OK, policyResp.status, policyResp.bodyAsText())

        val fileKey = crypto.randomBytes(32)
        val itemA = vc.newItemId()

        // 1. Per-attachment cap: ~2 KB of ciphertext against the 1000-byte budget → 413.
        val big = Attachments.encrypt(crypto, fileKey, crypto.randomBytes(2048))
        val tooBig = client.uploadAttachment(vc, uuid(), itemA, big.header + big.ciphertext)
        assertEquals(HttpStatusCode.PayloadTooLarge, tooBig.status)
        assertEquals("attachment_too_large", errorOf(tooBig))

        // 2. put referencing a never-uploaded id → 400, and the WHOLE batch rolls back.
        val itemX = vc.newItemId()
        val ghostPush = client.pushRaw(
            vc,
            putMutation(vc, itemX, """{"type":"note","name":"fine"}""", 0),
            putMutation(vc, vc.newItemId(), """{"type":"note","name":"ghost"}""", 0, listOf(uuid())),
        )
        assertEquals(HttpStatusCode.BadRequest, ghostPush.status)
        assertEquals("unknown_attachment", errorOf(ghostPush))
        assertTrue(client.sync(vc).items.none { it.itemId == itemX }, "a failed batch must roll back completely")

        // 3. An attachment bound to itemA cannot be referenced from another item.
        val att1 = uuid()
        val enc1 = Attachments.encrypt(crypto, fileKey, crypto.randomBytes(100))
        assertEquals(HttpStatusCode.OK, client.uploadAttachment(vc, att1, itemA, enc1.header + enc1.ciphertext).status)
        val mismatch = client.pushRaw(vc, putMutation(vc, vc.newItemId(), """{"type":"note","name":"thief"}""", 0, listOf(att1)))
        assertEquals(HttpStatusCode.BadRequest, mismatch.status)
        assertEquals("attachment_mismatch", errorOf(mismatch))

        // 4. Per-item budget: att1(117) + att2(367) ciphertext > maxCipher(400)=417 → 413.
        val att2 = uuid()
        val enc2 = Attachments.encrypt(crypto, fileKey, crypto.randomBytes(350))
        assertEquals(HttpStatusCode.OK, client.uploadAttachment(vc, att2, itemA, enc2.header + enc2.ciphertext).status)
        val overItem = client.pushRaw(vc, putMutation(vc, itemA, """{"type":"note","name":"itemA"}""", 0, listOf(att1, att2)))
        assertEquals(HttpStatusCode.PayloadTooLarge, overItem.status)
        assertEquals("item_attachment_quota", errorOf(overItem))

        // 5. Per-user budget: stored 484 + 117 more > maxCipher(500)=517 → 413.
        val enc3 = Attachments.encrypt(crypto, fileKey, crypto.randomBytes(100))
        val overUser = client.uploadAttachment(vc, uuid(), itemA, enc3.header + enc3.ciphertext)
        assertEquals(HttpStatusCode.PayloadTooLarge, overUser.status)
        assertEquals("user_attachment_quota", errorOf(overUser))

        // Within all budgets the reference is accepted.
        val ok = client.push(vc, putMutation(vc, itemA, """{"type":"note","name":"itemA"}""", 0, listOf(att1)))
        assertEquals("applied", ok.results[0].status)
    }

    @Test
    fun tombstoneDropsBlobs_andOrphanSweepCollects() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val vc = VirtualClient("att3@x.com", "attachment password three")
        client.register(vc, bootstrapToken)
        val store = services.service.attachments
        val fileKey = crypto.randomBytes(32)

        // Item with an attachment → delete mutation drops row + blob and hides the download.
        val attId = uuid()
        val itemId = vc.newItemId()
        val enc = Attachments.encrypt(crypto, fileKey, crypto.randomBytes(1024))
        assertEquals(HttpStatusCode.OK, client.uploadAttachment(vc, attId, itemId, enc.header + enc.ciphertext).status)
        val rev = client.push(vc, putMutation(vc, itemId, """{"type":"note","name":"doomed"}""", 0, listOf(attId))).results[0].newItemRev!!
        assertTrue(store.file(attId).isFile)

        val del = client.push(vc, Mutation(uuid(), "delete", itemId, vc.personalVaultId, rev, null))
        assertEquals("applied", del.results[0].status)
        assertFalse(store.file(attId).isFile, "tombstone must delete the blob file")
        assertNull(services.repo.db.read { c -> store.rowById(c, attId) }, "tombstone must delete the attachment row")
        assertEquals(HttpStatusCode.Forbidden, client.get("/api/v1/attachments/$attId") { authed(vc) }.status)

        // Orphan GC: an uploaded-but-never-referenced blob is swept once the TTL elapses;
        // a blob referenced by a live item survives the same sweep.
        val liveId = uuid()
        val liveItem = vc.newItemId()
        val liveEnc = Attachments.encrypt(crypto, fileKey, crypto.randomBytes(256))
        assertEquals(HttpStatusCode.OK, client.uploadAttachment(vc, liveId, liveItem, liveEnc.header + liveEnc.ciphertext).status)
        client.push(vc, putMutation(vc, liveItem, """{"type":"note","name":"live"}""", 0, listOf(liveId)))

        val orphanId = uuid()
        val orphanEnc = Attachments.encrypt(crypto, fileKey, crypto.randomBytes(512))
        assertEquals(HttpStatusCode.OK, client.uploadAttachment(vc, orphanId, vc.newItemId(), orphanEnc.header + orphanEnc.ciphertext).status)

        assertEquals(0, store.sweepOrphans(), "nothing is old enough under the default 24h TTL")
        store.orphanTtlMs = -1 // everything is now "older than the TTL"
        assertEquals(1, store.sweepOrphans(), "exactly the orphan is collected")
        assertNull(services.repo.db.read { c -> store.rowById(c, orphanId) })
        assertFalse(store.file(orphanId).isFile)
        assertNotNull(services.repo.db.read { c -> store.rowById(c, liveId) }, "referenced attachments survive the sweep")
        assertTrue(store.file(liveId).isFile)
    }
}
