package io.silencelen.andvari.server

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Purge-visibility gauges (design 2026-07-07 skipti §4 step 6 ops mandate): the two
 * /metrics series the stalled-purge alert keys off. Drives the REAL flow — create +
 * delete over the wire, `purgeAt` wound back by direct SQL (only the clock is faked),
 * then the janitor's real purge bringing both series back to 0 — scraped through the
 * loopback test client exactly like Alloy scrapes production.
 */
class PurgeGaugesTest : LifecycleTestSupport() {

    /** Value of a bare (unlabelled) series in a Prometheus text scrape. */
    private fun gaugeValue(scrape: String, name: String): Double {
        val line = scrape.lineSequence().firstOrNull { it.startsWith("$name ") }
            ?: error("gauge $name missing from /metrics:\n$scrape")
        return line.substringAfterLast(' ').toDouble()
    }

    @Test
    fun purgeGauges_trackTombstones_flagOverdue_zeroAfterPurge() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner gauge password one", fast = true)
        client.register(owner, bootstrapToken)

        suspend fun scrape(): String {
            val resp = client.get("/metrics")
            assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
            return resp.bodyAsText()
        }

        // Baseline: both series exist from build time (not first-use) and read 0 —
        // an absent series can never alert, so presence itself is load-bearing.
        var s = scrape()
        assertEquals(0.0, gaugeValue(s, "andvari_vaults_deleted_pending"))
        assertEquals(0.0, gaugeValue(s, "andvari_vaults_purge_overdue"))

        // Create + soft-delete a shared vault → pending, but inside the grace window.
        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        client.deleteWithProof(owner, handle)
        s = scrape()
        assertEquals(1.0, gaugeValue(s, "andvari_vaults_deleted_pending"))
        assertEquals(0.0, gaugeValue(s, "andvari_vaults_purge_overdue"))

        // Wind purgeAt a day past the 2-day overdue window (epoch ms — the janitor's unit).
        services.repo.db.tx { c ->
            c.exec(
                "UPDATE vaults SET purgeAt=? WHERE vaultId=?",
                now() - PURGE_OVERDUE_MS - Service.DAY_MS, handle.vaultId,
            )
        }
        s = scrape()
        assertEquals(1.0, gaugeValue(s, "andvari_vaults_deleted_pending"))
        assertEquals(1.0, gaugeValue(s, "andvari_vaults_purge_overdue"))

        // The janitor's real purge stamps purgedAt → both series return to 0.
        assertEquals(listOf(handle.vaultId), services.janitor.purgeDueVaults(now()))
        s = scrape()
        assertEquals(0.0, gaugeValue(s, "andvari_vaults_deleted_pending"))
        assertEquals(0.0, gaugeValue(s, "andvari_vaults_purge_overdue"))
    }
}
