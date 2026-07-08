package io.silencelen.andvari.server

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.ItemVersionsResponse
import kotlin.test.Test
import kotlin.test.assertEquals
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
}
