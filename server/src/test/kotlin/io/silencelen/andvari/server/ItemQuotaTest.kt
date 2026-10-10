package io.silencelen.andvari.server

import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.Mutation
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Security review 2026-10 (server F6): attachments always had per-file, per-item and per-user
 * quotas, but an item blob was bounded only by the 8 MiB push body. One member — or anyone holding
 * a member's token — could push junk items back to back until the disk filled, or make every
 * co-member's full /sync of a shared vault an OOM. Now: a per-item cap, a per-user quota on live
 * item ciphertext (the attachment quota's scope: every vault the user holds a grant to), and a
 * per-user /sync/push bucket. Over-cap puts are per-mutation `rejected` (the H03 channel — a thrown
 * 4xx would wedge the client's durable queue); the single-item restore keeps its thrown 413.
 */
class ItemQuotaTest : P4TestSupport() {

    private fun small(itemMax: Long = 4 * 1024, quota: Long = 16 * 1024, pushRate: Int = 1_000): Config {
        val base = config()
        return Config(
            host = base.host, port = 0, dbPath = base.dbPath, blobDir = base.blobDir, webDir = null,
            recoveryPublicKey = base.recoveryPublicKey, recoveryFingerprint = base.recoveryFingerprint,
            enumSecret = base.enumSecret, publicHostname = null, bootstrapToken = bootstrapToken,
            itemMaxBytes = itemMax, userItemQuotaBytes = quota, pushRatePerMin = pushRate,
        )
    }

    @Test
    fun anItemOverTheCap_isRejectedPerMutation_andNotStored() = testApplication {
        application { andvariModule(buildServices(small(), Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("bigitem@x.com", "big item password")
        client.register(vc, bootstrapToken)

        val big = vc.newItemId()
        val ok = vc.newItemId()
        val resp = client.push(
            vc,
            putMutation(vc, big, "x".repeat(6_000), 0),
            putMutation(vc, ok, "a normal login", 0),
        )
        assertEquals("rejected", resp.results[0].status)
        assertEquals("item_too_large", resp.results[0].reason)
        assertEquals("applied", resp.results[1].status, "a sibling in the same batch still lands")
        val ids = client.sync(vc).items.map { it.itemId }.toSet()
        assertTrue(big !in ids && ok in ids, "the oversized item must not be stored: $ids")
    }

    @Test
    fun theUserQuota_refusesGrowth_butNotShrinkingOrDeleting() = testApplication {
        application { andvariModule(buildServices(small(itemMax = 4 * 1024, quota = 10 * 1024), Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("quota@x.com", "quota password here")
        client.register(vc, bootstrapToken)

        // Three ~3.4 KB blobs fit under 10 KiB; the fourth would not.
        val ids = List(4) { vc.newItemId() }
        val revs = ids.take(3).map { id -> client.push(vc, putMutation(vc, id, "y".repeat(2_400), 0)).results[0].also { assertEquals("applied", it.status) }.newItemRev!! }
        val over = client.push(vc, putMutation(vc, ids[3], "y".repeat(2_400), 0)).results[0]
        assertEquals("rejected", over.status)
        assertEquals("user_item_quota", over.reason)

        // Shrinking an existing item is always allowed at quota…
        val shrink = client.push(vc, putMutation(vc, ids[0], "short", revs[0])).results[0]
        assertEquals("applied", shrink.status, "an edit that frees space must never be refused")
        // …and so is a delete, after which the refused item fits.
        client.push(vc, Mutation(uuid(), "delete", ids[1], vc.personalVaultId, revs[1], null))
        assertEquals("applied", client.push(vc, putMutation(vc, ids[3], "y".repeat(2_400), 0)).results[0].status)
    }

    @Test
    fun pushIsRateLimitedPerUser() = testApplication {
        application { andvariModule(buildServices(small(pushRate = 3), Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("pushrate@x.com", "push rate password")
        client.register(vc, bootstrapToken)

        repeat(3) { client.push(vc, putMutation(vc, vc.newItemId(), "item $it", 0)) }
        val fourth = client.pushRaw(vc, putMutation(vc, vc.newItemId(), "one too many", 0))
        assertEquals(HttpStatusCode.TooManyRequests, fourth.status, fourth.bodyAsText())
        assertEquals("rate_limited", errorOf(fourth))
    }

    @Test
    fun restoreOverTheItemCap_is413() = testApplication {
        application { andvariModule(buildServices(small(), Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("restorecap@x.com", "restore cap password")
        client.register(vc, bootstrapToken)

        val id = vc.newItemId()
        val rev = client.push(vc, putMutation(vc, id, "small", 0)).results[0].newItemRev!!
        client.push(vc, Mutation(uuid(), "delete", id, vc.personalVaultId, rev, null))
        val resp = client.post("/api/v1/items/$id/restore") {
            contentType(ContentType.Application.Json); authed(vc)
            setBody(vc.encItem(id, "z".repeat(6_000)))
        }
        assertEquals(HttpStatusCode.PayloadTooLarge, resp.status, resp.bodyAsText())
        assertEquals("item_too_large", errorOf(resp))
    }

    @Test
    fun envDefaults_areGenerousAndLinted() {
        val secret = Bytes.toB64(ByteArray(32) { 1 })
        val env = { m: Map<String, String> -> { name: String -> (m + ("ANDVARI_ENUM_SECRET" to secret))[name] } }
        val d = Config.fromEnv(env(emptyMap()))
        assertEquals(2L * 1024 * 1024, d.itemMaxBytes)
        assertEquals(128L * 1024 * 1024, d.userItemQuotaBytes)
        assertEquals(120, d.pushRatePerMin)
        val c = Config.fromEnv(env(mapOf("ANDVARI_ITEM_MAX_BYTES" to "65536", "ANDVARI_PUSH_RATE_PER_MIN" to "30")))
        assertEquals(65_536L, c.itemMaxBytes)
        assertEquals(30, c.pushRatePerMin)
        assertTrue(Config.envLint(mapOf("ANDVARI_ITEM_MAX_BYTES" to "9")).problems.isNotEmpty(), "an item cap under 1 KiB is a fault")
        assertTrue(Config.envLint(mapOf("ANDVARI_USER_ITEM_QUOTA_BYTES" to "1048576")).problems.isEmpty())
        assertNull(Config.envLint(mapOf("ANDVARI_PUSH_RATE_PER_MIN" to "60")).problems.firstOrNull())
    }
}
