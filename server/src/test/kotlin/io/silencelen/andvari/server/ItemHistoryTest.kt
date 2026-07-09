package io.silencelen.andvari.server

import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.DeletedItemsResponse
import io.silencelen.andvari.core.model.ItemVersionsResponse
import io.silencelen.andvari.core.model.Mutation
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Item history (feature: item history & restore). GET /items/{id}/versions serves the archived
 * ciphertext versions the server already keeps (the last 10, pruned by Repo.archiveVersion),
 * grant-checked against the item's own vault; a non-member and an unknown item are both 403-hidden
 * (spec 03 §8 — no existence oracle). Client-side decryption is covered by the :core decode test.
 */
class ItemHistoryTest : LifecycleTestSupport() {

    @Test
    fun itemVersions_servesArchivedVersions_newestFirst() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val owner = VirtualClient("hist-owner@x.com", "history owner password one")
        client.register(owner, bootstrapToken)

        // Three saves of the same item — the server archives each PRIOR ciphertext version.
        // Chain baseRev from each response so the sequence never spuriously conflicts.
        val itemId = owner.newItemId()
        val r1 = client.push(owner, putMutation(owner, itemId, "v1-plaintext", 0))
        val rev1 = r1.results[0].newItemRev!!
        val r2 = client.push(owner, putMutation(owner, itemId, "v2-plaintext", rev1))
        val rev2 = r2.results[0].newItemRev!!
        client.push(owner, putMutation(owner, itemId, "v3-plaintext", rev2))

        val resp = client.get("/api/v1/items/$itemId/versions") { authed(owner) }
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        val body = json.decodeFromString(ItemVersionsResponse.serializer(), resp.bodyAsText())
        assertEquals(itemId, body.itemId)
        // The two PRIOR versions are archived; the current live rev is NOT in the archive.
        assertEquals(2, body.versions.size, "two prior versions archived")
        assertTrue(body.versions[0].rev > body.versions[1].rev, "newest rev first")
        assertEquals(listOf(rev1, rev2).sortedDescending(), body.versions.map { it.rev }, "the two prior revs, newest first")
        assertTrue(body.versions.all { it.blob.isNotEmpty() && it.formatVersion == 1 }, "ciphertext + formatVersion present")
    }

    @Test
    fun itemVersions_hidesCrossTenantAndUnknown_as403() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val owner = VirtualClient("hist-owner2@x.com", "history owner password two")
        client.register(owner, bootstrapToken)
        val stranger = client.enrollSecond(owner, "hist-stranger@x.com", "history stranger password two")

        val itemId = owner.newItemId()
        val r1 = client.push(owner, putMutation(owner, itemId, "v1", 0))
        client.push(owner, putMutation(owner, itemId, "v2", r1.results[0].newItemRev!!))

        // A registered user with NO grant to the owner's personal vault → 403 (hidden).
        assertEquals(HttpStatusCode.Forbidden, client.get("/api/v1/items/$itemId/versions") { authed(stranger) }.status)
        // An unknown item → also 403-hidden (not 404 — no cross-tenant existence oracle).
        assertEquals(HttpStatusCode.Forbidden, client.get("/api/v1/items/${uuid()}/versions") { authed(owner) }.status)
    }

    @Test
    fun deletedItems_grantScoped_andRestoreCleanlyUntombstones() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val owner = VirtualClient("undel-owner@x.com", "undelete owner password one")
        client.register(owner, bootstrapToken)
        val stranger = client.enrollSecond(owner, "undel-stranger@x.com", "undelete stranger password two")

        // Create then delete an item → it tombstones (row persists; its last value is in the archive).
        val itemId = owner.newItemId()
        val r1 = client.push(owner, putMutation(owner, itemId, "secret-v1", 0))
        client.push(owner, Mutation(uuid(), "delete", itemId, owner.personalVaultId, r1.results[0].newItemRev!!, null))

        // The owner sees it in the trash; a non-member never does (grant-scoped in SQL).
        suspend fun trashOf(vc: VirtualClient) =
            json.decodeFromString(DeletedItemsResponse.serializer(), client.get("/api/v1/items/deleted") { authed(vc) }.bodyAsText()).items
        assertEquals(listOf(itemId), trashOf(owner).map { it.itemId })
        assertTrue(trashOf(stranger).none { it.itemId == itemId }, "cross-tenant tombstones are never listed")

        // Restore: re-encrypt content and POST it. The stranger (no grant) is 403-hidden.
        assertEquals(
            HttpStatusCode.Forbidden,
            client.post("/api/v1/items/$itemId/restore") { authed(stranger); contentType(ContentType.Application.Json); setBody(owner.encItem(itemId, "x")) }.status,
        )
        val restore = client.post("/api/v1/items/$itemId/restore") { authed(owner); contentType(ContentType.Application.Json); setBody(owner.encItem(itemId, "secret-restored")) }
        assertEquals(HttpStatusCode.OK, restore.status, restore.bodyAsText())

        // It leaves the trash and syncs back LIVE with conflict=false (dedicated un-tombstone, not a put).
        assertTrue(trashOf(owner).none { it.itemId == itemId }, "restored item leaves the trash")
        val live = client.sync(owner).items.find { it.itemId == itemId }
        assertNotNull(live)
        assertEquals(false, live.deleted, "restored item is live")
        assertEquals(false, live.conflict, "restore does NOT flag a conflict (avoids the spurious-copy trap)")

        // Restoring a LIVE (non-deleted) item is rejected.
        assertEquals(
            HttpStatusCode.BadRequest,
            client.post("/api/v1/items/$itemId/restore") { authed(owner); contentType(ContentType.Application.Json); setBody(owner.encItem(itemId, "again")) }.status,
        )
    }

    @Test
    fun purgeItem_hardDeletes_grantChecked_onlyDeleted() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val owner = VirtualClient("purge-owner@x.com", "purge owner password one")
        client.register(owner, bootstrapToken)
        val stranger = client.enrollSecond(owner, "purge-stranger@x.com", "purge stranger password two")

        val itemId = owner.newItemId()
        val r1 = client.push(owner, putMutation(owner, itemId, "secret", 0))
        client.push(owner, Mutation(uuid(), "delete", itemId, owner.personalVaultId, r1.results[0].newItemRev!!, null))

        suspend fun trash() =
            json.decodeFromString(DeletedItemsResponse.serializer(), client.get("/api/v1/items/deleted") { authed(owner) }.bodyAsText()).items
        assertEquals(listOf(itemId), trash().map { it.itemId }) // in Trash

        // A live (non-deleted) item can't be "deleted forever" — must be trashed first.
        val liveId = owner.newItemId()
        client.push(owner, putMutation(owner, liveId, "live", 0))
        assertEquals(HttpStatusCode.BadRequest, client.post("/api/v1/items/$liveId/purge") { authed(owner) }.status)

        // Non-member is 403-hidden; the owner purges.
        assertEquals(HttpStatusCode.Forbidden, client.post("/api/v1/items/$itemId/purge") { authed(stranger) }.status)
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/items/$itemId/purge") { authed(owner) }.status, "owner purges")

        // Gone: leaves Trash, versions route 403 (row hard-deleted → itemById null), re-purge 403.
        assertTrue(trash().none { it.itemId == itemId }, "purged item leaves Trash")
        assertEquals(HttpStatusCode.Forbidden, client.get("/api/v1/items/$itemId/versions") { authed(owner) }.status)
        assertEquals(HttpStatusCode.Forbidden, client.post("/api/v1/items/$itemId/purge") { authed(owner) }.status)
    }
}
