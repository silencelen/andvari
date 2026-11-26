package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsBytes
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.AttachmentMeta
import io.silencelen.andvari.core.model.wire.DeletedItemsResponse
import io.silencelen.andvari.core.model.wire.ItemVersionsResponse
import io.silencelen.andvari.core.model.wire.MutationStatus
import io.silencelen.andvari.core.model.wire.SyncResponse
import io.silencelen.andvari.core.model.wire.WireJson
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Index rows 36–43 (spec 03 §4, §5, §5.1, §9): sync, push, history, trash and attachments. */
class RoutesItemsTest {
    private val post = HttpMethod.Post
    private val get = HttpMethod.Get

    private fun restoreBody(fv: Int = 2, ids: List<String> = emptyList(), blob: String = "QUJD") =
        """{"formatVersion":$fv,"attachmentIds":${ids.joinToString(",", "[", "]") { "\"$it\"" }},"blob":"$blob"}"""

    @Test
    fun row36_sync_full_delta_badSince_resyncRequired() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val pv = me.personalVaultId
        val full = WireJson.json.decodeFromString(SyncResponse.serializer(), c.call(get, "/api/v1/sync?since=0", token = me.token).bodyAsText())
        assertTrue(full.full); assertEquals(listOf(pv), full.vaults.map { it.vaultId })
        val item = c.putItem(me, pv)
        val delta = WireJson.json.decodeFromString(SyncResponse.serializer(), c.call(get, "/api/v1/sync?since=${full.rev}", token = me.token).bodyAsText())
        assertEquals(false, delta.full); assertEquals(1, delta.items.size); assertEquals(item.newItemRev, delta.items.single().rev)
        assertEquals("bad_since", c.call(get, "/api/v1/sync?since=x", token = me.token).errorCode())
        // A cursor older than the retained history.
        s.db.tx { it.exec("INSERT INTO meta(key,value) VALUES('oldestRetainedRev','1000') ON CONFLICT(key) DO UPDATE SET value=excluded.value") }
        val gone = c.call(get, "/api/v1/sync?since=5", token = me.token)
        assertEquals(410, gone.status.value); assertEquals("resync_required", gone.errorCode())
        assertEquals(200, c.call(get, "/api/v1/sync?since=0", token = me.token).status.value)
    }

    @Test
    fun row37_push_thrownRefusalsRollTheWholeBatchBack_andReplay() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val pv = me.personalVaultId
        fun put(id: String, mid: String = uuid()) = """{"mutationId":"$mid","op":"put","itemId":"$id","vaultId":"$pv","baseItemRev":0,"item":{"formatVersion":2,"attachmentIds":[],"blob":"QUJD"}}"""
        val first = uuid()
        suspend fun push(muts: List<String>) = c.call(post, "/api/v1/sync/push", """{"mutations":${muts.joinToString(",", "[", "]")}}""", me.token)
        val tooMany = push(List(Items.BATCH_MAX + 1) { put(uuid()) })
        assertEquals(400, tooMany.status.value); assertEquals("batch_too_large", tooMany.errorCode())
        val badOp = push(listOf(put(first), """{"mutationId":"${uuid()}","op":"move","itemId":"${uuid()}","vaultId":"$pv","baseItemRev":0}"""))
        assertEquals(400, badOp.status.value); assertEquals("bad_op", badOp.errorCode())
        val noItem = push(listOf(put(first), """{"mutationId":"${uuid()}","op":"put","itemId":"${uuid()}","vaultId":"$pv","baseItemRev":0}"""))
        assertEquals(400, noItem.status.value); assertEquals("put_without_item", noItem.errorCode())
        // Nothing of either batch was written.
        assertEquals(0L, s.db.read { it.count("SELECT COUNT(*) FROM items WHERE vaultId=?", pv) })
        // The limit itself is fine; a replayed mutationId returns the stored result verbatim.
        val mid = uuid()
        val ok = push(List(Items.BATCH_MAX - 1) { put(uuid()) } + put(first, mid))
        assertEquals(200, ok.status.value, ok.bodyAsText().take(200))
        val again = push(listOf(put(first, mid)))
        val r1 = WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.PushResponse.serializer(), ok.bodyAsText()).results.last()
        val r2 = WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.PushResponse.serializer(), again.bodyAsText()).results.single()
        assertEquals(r1, r2)
        // Per-mutation refusals are statuses, not thrown: a bad id and an over-long mutation id.
        assertEquals("bad_item_id", c.putItem(me, pv, itemId = "../admin").reason)
        val longId = push(listOf(put(uuid(), "m".repeat(65))))
        assertEquals("bad_mutation_id", WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.PushResponse.serializer(), longId.bodyAsText()).results.single().reason)
    }

    @Test
    fun rows38to41_versions_trash_restore_purge() = testApplication {
        val s = TestKit.services(TestKit.config(itemMaxBytes = 64))
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val pv = me.personalVaultId
        val id = uuid()
        val v1 = c.putItem(me, pv, id, blob = "VjE", fv = 3)
        val v2 = c.putItem(me, pv, id, blob = "VjI", base = v1.newItemRev!!, fv = 3)
        assertEquals(MutationStatus.APPLIED, v2.status)
        // Row 38: the archived version, newest first.
        val versions = WireJson.json.decodeFromString(ItemVersionsResponse.serializer(), c.call(get, "/api/v1/items/$id/versions", token = me.token).bodyAsText())
        assertEquals(id, versions.itemId); assertEquals(listOf(v1.newItemRev), versions.versions.map { it.rev }); assertEquals("VjE", versions.versions.single().blob)
        assertEquals("no_grant", c.call(get, "/api/v1/items/${uuid()}/versions", token = me.token).errorCode())
        assertEquals("no_grant", c.call(get, "/api/v1/items/not-a-uuid/versions", token = me.token).errorCode())
        // Rows 40 and 41 on a live item.
        assertEquals("item_not_deleted", c.call(post, "/api/v1/items/$id/restore", restoreBody(3), me.token).errorCode())
        assertEquals("item_not_deleted", c.call(post, "/api/v1/items/$id/purge", token = me.token).errorCode())
        assertEquals("no_grant", c.call(post, "/api/v1/items/${uuid()}/restore", restoreBody(3), me.token).errorCode())
        assertEquals("no_grant", c.call(post, "/api/v1/items/${uuid()}/purge", token = me.token).errorCode())
        // Row 39: the trash.
        assertEquals(MutationStatus.APPLIED, c.deleteItem(me, pv, id, v2.newItemRev!!).status)
        val trash = WireJson.json.decodeFromString(DeletedItemsResponse.serializer(), c.call(get, "/api/v1/items/deleted", token = me.token).bodyAsText())
        assertEquals(listOf(id), trash.items.map { it.itemId }); assertEquals(pv, trash.items.single().vaultId)
        // A tombstone keeps its versions.
        assertEquals(200, c.call(get, "/api/v1/items/$id/versions", token = me.token).status.value)
        // Row 40: every refusal, in the route's order.
        val other = uuid()
        val otherAtt = uuid()
        assertEquals(200, c.upload(me.token, otherAtt, pv, other).status.value)
        val mine = uuid()
        assertEquals(200, c.upload(me.token, mine, pv, id).status.value)
        suspend fun r(body: String) = c.call(post, "/api/v1/items/$id/restore", body, me.token)
        for ((want, body) in listOf(
            (400 to "fv_downgrade") to restoreBody(2),
            (400 to "too_many_attachments") to restoreBody(3, List(Items.ATTACHMENTS_MAX + 1) { uuid() }),
            (400 to "duplicate_attachment") to restoreBody(3, listOf(mine, mine)),
            (400 to "bad_attachment_id") to restoreBody(3, listOf("NOT-A-UUID")),
            (400 to "unknown_attachment") to restoreBody(3, listOf(uuid())),
            (400 to "attachment_mismatch") to restoreBody(3, listOf(otherAtt)),
            (413 to "item_too_large") to restoreBody(3, blob = "A".repeat(65)),
        )) {
            val resp = r(body)
            assertEquals(want.first, resp.status.value, "${want.second}: ${resp.bodyAsText()}"); assertEquals(want.second, resp.errorCode())
        }
        // The per-item attachment ceiling and the owner's quota.
        s.db.tx { s.policy.storeOn(it, s.policy.get().copy(itemAttachmentsMaxBytes = 1)) }
        val iaq = r(restoreBody(3, listOf(mine)))
        assertEquals(413, iaq.status.value, iaq.bodyAsText()); assertEquals("item_attachment_quota", iaq.errorCode())
        s.db.tx { s.policy.storeOn(it, s.policy.defaults()) }
        s.db.tx { it.exec("UPDATE users SET quotaAccountBytes=1 WHERE userId=?", me.userId) }
        val q = r(restoreBody(3))
        assertEquals(413, q.status.value); assertEquals("quota_exceeded", q.errorCode()); assertTrue(q.bodyAsText().contains("\"quota\":\"accountBytes\""))
        s.db.tx { it.exec("UPDATE users SET quotaAccountBytes=NULL WHERE userId=?", me.userId) }
        // Success: the item is live again with the attachment, and no conflict copy.
        val ok = r(restoreBody(3, listOf(mine), "UkVT"))
        assertEquals(200, ok.status.value, ok.bodyAsText()); assertTrue(ok.bodyAsText().startsWith("{\"rev\":"))
        val item = WireJson.json.decodeFromString(SyncResponse.serializer(), c.call(get, "/api/v1/sync?since=0", token = me.token).bodyAsText()).items.single { it.itemId == id }
        assertEquals(false, item.deleted); assertEquals(false, item.conflict); assertEquals("UkVT", item.blob); assertEquals(listOf(mine), item.attachmentIds)
        // Row 41: purge a tombstone; it leaves nothing, not even its versions.
        assertEquals(MutationStatus.APPLIED, c.deleteItem(me, pv, id, item.rev).status)
        val purged = c.call(post, "/api/v1/items/$id/purge", token = me.token)
        assertEquals(200, purged.status.value); assertTrue(purged.bodyAsText().startsWith("{\"rev\":"))
        assertEquals("no_grant", c.call(get, "/api/v1/items/$id/versions", token = me.token).errorCode())
        assertEquals(0L, s.db.read { it.count("SELECT COUNT(*) FROM item_versions WHERE itemId=?", id) })
        assertEquals("[]", WireJson.json.parseToJsonElement(c.call(get, "/api/v1/items/deleted", token = me.token).bodyAsText()).let { (it as kotlinx.serialization.json.JsonObject)["items"].toString() })
    }

    @Test
    fun rows42and43_upload_idempotence_caps_quota_andTheDownload() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val pv = me.personalVaultId
        val aid = uuid(); val item = uuid()
        val bytes = attachmentBytes(100, 1)
        val up = c.upload(me.token, aid, pv, item, bytes)
        assertEquals(200, up.status.value, up.bodyAsText())
        val meta = WireJson.json.decodeFromString(AttachmentMeta.serializer(), up.bodyAsText())
        assertEquals(aid, meta.attachmentId); assertEquals(item, meta.itemId); assertEquals(pv, meta.vaultId); assertEquals(100L, meta.size)
        assertEquals(sha256Hex(bytes.copyOfRange(24, bytes.size)), meta.sha256)
        // The same bytes again: the stored meta. Other bytes: attachment_id_taken.
        assertEquals(meta, WireJson.json.decodeFromString(AttachmentMeta.serializer(), c.upload(me.token, aid, pv, item, bytes).bodyAsText()))
        val taken = c.upload(me.token, aid, pv, item, attachmentBytes(100, 2))
        assertEquals(400, taken.status.value); assertEquals("attachment_id_taken", taken.errorCode())
        // Row 43: the download is the upload, byte for byte.
        val dl = c.call(get, "/api/v1/attachments/$aid", token = me.token)
        assertEquals(200, dl.status.value); assertContentEquals(bytes, dl.bodyAsBytes())
        assertEquals("no_grant", c.call(get, "/api/v1/attachments/${uuid()}", token = me.token).errorCode())
        // Over the policy's per-attachment cap.
        s.db.tx { s.policy.storeOn(it, s.policy.get().copy(attachmentMaxBytes = 10)) }
        val big = c.upload(me.token, uuid(), pv, item, attachmentBytes(200))
        assertEquals(413, big.status.value, big.bodyAsText()); assertEquals("attachment_too_large", big.errorCode())
        s.db.tx { s.policy.storeOn(it, s.policy.defaults()) }
        // Over the owner's storage quota.
        s.db.tx { it.exec("UPDATE users SET quotaAccountBytes=1 WHERE userId=?", me.userId) }
        val q = c.upload(me.token, uuid(), pv, item)
        assertEquals(413, q.status.value, q.bodyAsText()); assertEquals("quota_exceeded", q.errorCode()); assertTrue(q.bodyAsText().contains("\"quota\":\"accountBytes\""))
        s.db.tx { it.exec("UPDATE users SET quotaAccountBytes=NULL WHERE userId=?", me.userId) }
        // Malformed ids are the generic bad_<field>; a body shorter than its header is refused.
        assertEquals("bad_attachment_id", c.upload(me.token, "x", pv, item).errorCode())
        assertEquals("bad_vault_id", c.upload(me.token, uuid(), "x", item).errorCode())
        assertEquals("bad_item_id", c.upload(me.token, uuid(), pv, "x").errorCode())
        assertEquals("attachment_truncated", c.upload(me.token, uuid(), pv, item, ByteArray(10)).errorCode())
    }

    @Test
    fun row42_theConcurrentUploadCap_is429() = testApplication {
        val s = TestKit.services(TestKit.config(uploadMaxConcurrentPerUser = 0))
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val r = c.upload(me.token, uuid(), me.personalVaultId, uuid())
        assertEquals(429, r.status.value, r.bodyAsText()); assertEquals("rate_limited", r.errorCode())
        assertTrue((r.headers["Retry-After"]?.toLong() ?: 0) >= 1)
    }
}
