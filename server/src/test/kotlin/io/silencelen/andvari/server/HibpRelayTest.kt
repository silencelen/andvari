package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * HIBP relay upstream failure handling (polish audit 2026-07-27 bug-server--2): the upstream
 * call is timeout-bounded (a black-holed HIBP used to park the request coroutine — and the web
 * Health scan with it — forever), outage/timeout surface as 502 BadGateway rather than a 400
 * indistinguishable from a malformed prefix, and the route carries a per-user bucket like its
 * siblings. Scripted upstream via MockEngine; the route bucket via the real module.
 */
class HibpRelayTest : P4TestSupport() {

    private fun bareRepo() = Repo(Db(File(tmpDir, "hibp-${System.nanoTime()}.db").absolutePath))

    @Test
    fun upstreamNon2xx_surfacesAsBadGateway_not400() {
        val http = HttpClient(MockEngine { respond("", HttpStatusCode.ServiceUnavailable) })
        val relay = HibpRelay(bareRepo(), http)
        val e = assertFailsWith<BadGateway> { runBlocking { relay.range("ABCDE") } }
        assertEquals("hibp_upstream_503", e.reason)
    }

    @Test
    fun upstreamHang_isBoundedByTimeout_asBadGateway() {
        // A handler that never answers inside the bound; the relay's withTimeout must cut it off
        // (timeoutMs is injectable so this test doesn't park for the production 10 s).
        val http = HttpClient(MockEngine { delay(60_000); respond("never") })
        val relay = HibpRelay(bareRepo(), http, timeoutMs = 100)
        val e = assertFailsWith<BadGateway> { runBlocking { relay.range("ABCDE") } }
        assertEquals("hibp_timeout", e.reason)
    }

    @Test
    fun hibpRoute_perUserBucket_trips429() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("hibp-rate@x.com", "hibp rate password one", fast = true)
        client.register(vc, bootstrapToken)

        // 600 in-window requests consume the bucket without touching upstream (the non-hex prefix
        // 400s AFTER the bucket check, so no network I/O rides this loop)…
        repeat(600) {
            assertEquals(HttpStatusCode.BadRequest, client.get("/api/v1/hibp/range/ZZZZZ") { authed(vc) }.status)
        }
        // …and the 601st is refused up front.
        val limited = client.get("/api/v1/hibp/range/ZZZZZ") { authed(vc) }
        assertEquals(HttpStatusCode.TooManyRequests, limited.status, limited.bodyAsText())
    }
}
