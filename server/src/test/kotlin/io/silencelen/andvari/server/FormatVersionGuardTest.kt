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
import io.silencelen.andvari.core.model.Mutation
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Monotonic-formatVersion guard (spec 03 §5; design 2026-07-09 cards). An fv downgrade over an
 * existing row is never a legitimate client write — the only fielded emitter is the 0.2.x desktop
 * re-sealing a doc it silently field-stripped on decode (ignoreUnknownKeys, field-by-field rebuild).
 * The server refuses it: audited `push_denied` (fv_downgrade), row untouched, no history slot
 * burned, never dedup-cached. Provable no-op for all current traffic: no fv≥2 row can exist until
 * a 0.7.0 client writes one, and equal-fv writes take the exact pre-guard paths (also pinned here).
 */
class FormatVersionGuardTest : P4TestSupport() {

    /** Every mutable column of an items row — data-class equality = the row is byte-identical. */
    private data class ItemRow(
        val rev: Long, val createdAt: Long, val updatedAt: Long, val deleted: Int, val conflict: Int,
        val formatVersion: Int, val attachmentIds: String, val blob: String?, val blobSize: Long,
    )

    private fun rowOf(services: Services, itemId: String): ItemRow =
        services.repo.db.read { c ->
            c.queryOne("SELECT * FROM items WHERE itemId=?", itemId) { rs ->
                ItemRow(
                    rs.getLong("rev"), rs.getLong("createdAt"), rs.getLong("updatedAt"),
                    rs.getInt("deleted"), rs.getInt("conflict"), rs.getInt("formatVersion"),
                    rs.getString("attachmentIds"), rs.getString("blob"), rs.getLong("blobSize"),
                )
            }
        } ?: error("no items row for $itemId")

    private fun versionCount(services: Services, itemId: String): Int =
        services.repo.db.read { c ->
            c.queryOne("SELECT COUNT(*) FROM item_versions WHERE itemId=?", itemId) { it.getInt(1) } ?: 0
        }

    private fun dedupCached(services: Services, mutationId: String): Boolean =
        services.repo.db.read { c ->
            (c.queryOne("SELECT COUNT(*) FROM mutations WHERE mutationId=?", mutationId) { it.getInt(1) } ?: 0) > 0
        }

    private fun putFv(vc: VirtualClient, itemId: String, plaintext: String, baseRev: Long, fv: Int, mutationId: String = uuid()) =
        Mutation(mutationId, "put", itemId, vc.personalVaultId, baseRev, vc.encItem(itemId, plaintext, fv))

    @Test
    fun fvDowngradePut_denied_rowByteIdentical_noHistorySlot_audited() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("fv-owner@x.com", "fv guard owner password one")
        client.register(owner, bootstrapToken)

        val itemId = owner.newItemId()
        val r1 = client.push(owner, putFv(owner, itemId, "card-v1", 0, fv = 2))
        assertEquals("applied", r1.results[0].status)
        val before = rowOf(services, itemId)
        assertEquals(2, before.formatVersion)

        // fv1 over fv2 at the CURRENT rev — would be a clean apply without the guard.
        val r2 = client.push(owner, putFv(owner, itemId, "card-stripped", before.rev, fv = 1))
        assertEquals("denied", r2.results[0].status)
        assertNull(r2.results[0].newItemRev)
        assertEquals(r1.rev, r2.rev, "nothing written → global rev unchanged")

        assertEquals(before, rowOf(services, itemId), "denied write leaves the row byte-identical")
        assertEquals(0, versionCount(services, itemId), "archiveVersion NOT called — no history slot burned")
        val denials = client.auditRows(owner, "push_denied")
        assertTrue(denials.any { it.meta == "fv_downgrade:${owner.personalVaultId}:$itemId" }, "audited with reason: $denials")
    }

    @Test
    fun fvDowngrade_beatsConflictOverwritePath() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("fv-owner2@x.com", "fv guard owner password two")
        client.register(owner, bootstrapToken)

        val itemId = owner.newItemId()
        val rev1 = client.push(owner, putFv(owner, itemId, "card-v1", 0, fv = 2)).results[0].newItemRev!!
        client.push(owner, putFv(owner, itemId, "card-v2", rev1, fv = 2))
        val before = rowOf(services, itemId)
        assertEquals(1, versionCount(services, itemId))

        // A stale fv1 put: WITHOUT the guard this materializes a conflict OVERWRITE of the live
        // blob (+ an archive slot). The deny must win — refused, not conflict-applied.
        val r = client.push(owner, putFv(owner, itemId, "card-stripped", rev1, fv = 1))
        assertEquals("denied", r.results[0].status)
        assertNull(r.results[0].serverItem)
        assertEquals(before, rowOf(services, itemId), "conflict-overwrite never ran")
        assertEquals(1, versionCount(services, itemId))
    }

    @Test
    fun equalAndUpgradeFv_applyExactlyAsBefore() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("fv-owner3@x.com", "fv guard owner password three")
        client.register(owner, bootstrapToken)

        // fv1→fv2 (upgrade: a 0.7.0 client re-flooring a card doc) and fv2→fv2 both apply.
        val up = owner.newItemId()
        val rev1 = client.push(owner, putFv(owner, up, "login", 0, fv = 1)).results[0].newItemRev!!
        val r2 = client.push(owner, putFv(owner, up, "now-a-card", rev1, fv = 2))
        assertEquals("applied", r2.results[0].status)
        assertEquals(2, rowOf(services, up).formatVersion)
        assertEquals("applied", client.push(owner, putFv(owner, up, "card-edit", r2.results[0].newItemRev!!, fv = 2)).results[0].status)

        // The no-op proof for current traffic: a stale fv1-over-fv1 put still takes the
        // pre-guard conflict-overwrite path (applied-with-conflict + serverItem + archive).
        val legacy = owner.newItemId()
        val lRev1 = client.push(owner, putFv(owner, legacy, "v1", 0, fv = 1)).results[0].newItemRev!!
        client.push(owner, putFv(owner, legacy, "v2", lRev1, fv = 1))
        val stale = client.push(owner, putFv(owner, legacy, "v3-stale", lRev1, fv = 1))
        assertEquals("conflict", stale.results[0].status)
        assertNotNull(stale.results[0].serverItem, "displaced version still delivered")
        assertEquals("v3-stale", owner.decItem(legacy, rowOf(services, legacy).blob!!), "conflict put still overwrites")
    }

    @Test
    fun deniedIsNotDedupCached_replayApplies() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("fv-owner4@x.com", "fv guard owner password four")
        client.register(owner, bootstrapToken)

        val itemId = owner.newItemId()
        val rev1 = client.push(owner, putFv(owner, itemId, "card-v1", 0, fv = 2)).results[0].newItemRev!!

        // Same mutationId denied first (fv1), then replayed as a LEGITIMATE fv2 write — e.g. a
        // client rebuilt after an update re-sends its queue. A cached denied would freeze it.
        val mid = uuid()
        assertEquals("denied", client.push(owner, putFv(owner, itemId, "stripped", rev1, fv = 1, mutationId = mid)).results[0].status)
        assertFalse(dedupCached(services, mid), "denied result never enters the dedup cache")
        val replay = client.push(owner, putFv(owner, itemId, "card-v2", rev1, fv = 2, mutationId = mid))
        assertEquals("applied", replay.results[0].status)
        assertTrue(dedupCached(services, mid), "the applied replay IS cached")
        assertEquals("card-v2", owner.decItem(itemId, rowOf(services, itemId).blob!!, 2))
    }

    /**
     * The 0.2.x simulation at the server boundary (the design's decisive fatal, pinned as
     * executable fact): its materializeConflict decodes the winner with ignoreUnknownKeys
     * (card silently stripped), then pushes a conflict-copy husk (new itemId, fv1) plus a
     * flag-clearing fv1 rewrite of the live card. Husk applied — clutter, never loss; the
     * flag-clear is DENIED and the live card row survives intact.
     */
    @Test
    fun simulation02x_materializeConflict_huskApplied_flagClearDenied_cardIntact() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("fv-owner5@x.com", "fv guard owner password five")
        client.register(owner, bootstrapToken)

        // A conflict-flagged fv2 card row (the state that triggers 0.2.x's automatic write path).
        val cardId = owner.newItemId()
        val rev1 = client.push(owner, putFv(owner, cardId, "card-full", 0, fv = 2)).results[0].newItemRev!!
        val rev2 = client.push(owner, putFv(owner, cardId, "card-full-v2", rev1, fv = 2)).results[0].newItemRev!!
        val rev3 = client.push(owner, putFv(owner, cardId, "card-full-v3", rev1, fv = 2)).results[0].newItemRev!!
        assertEquals(1, rowOf(services, cardId).conflict)
        val before = rowOf(services, cardId)
        assertTrue(rev3 > rev2)

        // One 0.2.x pull-side batch: husk copy + flag-clear rewrite, both fv1, base = current rev.
        val huskId = owner.newItemId()
        val r = client.push(
            owner,
            putFv(owner, huskId, "card-husk (conflict)", 0, fv = 1),
            putFv(owner, cardId, "card-husk", rev3, fv = 1),
        )
        assertEquals(listOf("applied", "denied"), r.results.map { it.status })

        assertEquals(before, rowOf(services, cardId), "live card row byte-identical (conflict flag left for a 0.7.0 writer)")
        assertEquals("card-full-v3", owner.decItem(cardId, rowOf(services, cardId).blob!!, 2), "card still decrypts at fv2")
        assertEquals(1, rowOf(services, huskId).formatVersion, "husk copy applied — clutter, never loss")
    }

    @Test
    fun restoreItem_fvDowngradeRefused_tombstonePreservesFv() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("fv-owner6@x.com", "fv guard owner password six")
        client.register(owner, bootstrapToken)

        val itemId = owner.newItemId()
        val rev1 = client.push(owner, putFv(owner, itemId, "card-full", 0, fv = 2)).results[0].newItemRev!!
        client.push(owner, Mutation(uuid(), "delete", itemId, owner.personalVaultId, rev1, null))
        val tombstone = rowOf(services, itemId)
        assertEquals(1, tombstone.deleted)
        assertEquals(2, tombstone.formatVersion, "delete preserves formatVersion — the guard's anchor")

        // Restore carrying fv1 (a degraded re-encrypt) → 400 fv_downgrade, tombstone untouched.
        val denied = client.post("/api/v1/items/$itemId/restore") {
            authed(owner); contentType(ContentType.Application.Json); setBody(owner.encItem(itemId, "stripped", 1))
        }
        assertEquals(HttpStatusCode.BadRequest, denied.status)
        assertEquals("fv_downgrade", errorOf(denied))
        assertEquals(tombstone, rowOf(services, itemId))
        val trash = json.decodeFromString(DeletedItemsResponse.serializer(), client.get("/api/v1/items/deleted") { authed(owner) }.bodyAsText())
        assertEquals(listOf(itemId), trash.items.map { it.itemId }, "still in Trash")
        assertTrue(client.auditRows(owner, "push_denied").any { it.meta == "fv_downgrade:${owner.personalVaultId}:$itemId" })

        // The legitimate fv2 restore still works.
        val ok = client.post("/api/v1/items/$itemId/restore") {
            authed(owner); contentType(ContentType.Application.Json); setBody(owner.encItem(itemId, "card-restored", 2))
        }
        assertEquals(HttpStatusCode.OK, ok.status, ok.bodyAsText())
        assertEquals(0, rowOf(services, itemId).deleted)
        assertEquals("card-restored", owner.decItem(itemId, rowOf(services, itemId).blob!!, 2))
    }
}
