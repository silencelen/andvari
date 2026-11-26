package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.delay
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Index rows 87–92 (spec 03 §8): the HIBP relay and the routes at the origin's root. No test reaches the real HIBP. */
class RoutesMiscTest {
    @Test
    fun row87_hibp_relaysTheRange_andEachRefusal() = testApplication {
        val s = TestKit.services()
        val seen = ArrayList<String>()
        s.hibp = HibpRelay(
            HttpClient(MockEngine { req ->
                seen += "${req.url.encodedPath} padding=${req.headers["Add-Padding"]}"
                when {
                    req.url.encodedPath.endsWith("/ABCDE") -> respond("0018A45C4D1DEF81644B54AB7F969B88D65:1")
                    req.url.encodedPath.endsWith("/FFFFF") -> respond("down", HttpStatusCode.ServiceUnavailable)
                    req.url.encodedPath.endsWith("/11111") -> throw java.net.ConnectException("Connection refused")
                    else -> { delay(5_000); respond("late") }
                }
            }),
            timeoutMs = 200,
        )
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val ok = c.call(HttpMethod.Get, "/api/v1/hibp/range/abcde", token = me.token)
        assertEquals(200, ok.status.value, ok.bodyAsText()); assertEquals("0018A45C4D1DEF81644B54AB7F969B88D65:1", ok.bodyAsText())
        assertEquals(listOf("/range/ABCDE padding=true"), seen)
        for (p in listOf("ABCD", "ABCDEF", "GGGGG")) {
            val r = c.call(HttpMethod.Get, "/api/v1/hibp/range/$p", token = me.token)
            assertEquals(400, r.status.value, p); assertEquals("bad_prefix", r.errorCode(), p)
        }
        assertEquals(1, seen.size, "a bad prefix never leaves the server")
        val down = c.call(HttpMethod.Get, "/api/v1/hibp/range/FFFFF", token = me.token)
        assertEquals(502, down.status.value); assertEquals("hibp_upstream_503", down.errorCode())
        val slow = c.call(HttpMethod.Get, "/api/v1/hibp/range/00000", token = me.token)
        assertEquals(502, slow.status.value); assertEquals("hibp_timeout", slow.errorCode())
        // A connect failure is the same 502 as a timeout (HIBP unreachable), not a 500.
        val refused = c.call(HttpMethod.Get, "/api/v1/hibp/range/11111", token = me.token)
        assertEquals(502, refused.status.value, refused.bodyAsText()); assertEquals("hibp_timeout", refused.errorCode())
        // Nothing of it is kept (§8): no row anywhere names a prefix.
        assertEquals(0L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE meta LIKE '%ABCDE%'") })
    }

    @Test
    fun rows88to90_healthz_metrics_robots() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val h = client.get("/healthz")
        assertEquals(200, h.status.value); assertEquals("ok", h.bodyAsText())
        // Row 89: loopback without a forwarding header only.
        val m = client.get("/metrics")
        assertEquals(200, m.status.value, m.bodyAsText().take(200)); assertTrue(m.bodyAsText().contains("andvari_mail_outbox_oldest_seconds"))
        for (hdr in listOf("X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP", "Forwarded")) {
            assertEquals(403, client.get("/metrics") { header(hdr, "127.0.0.1") }.status.value, hdr)
        }
        val r = client.get("/robots.txt")
        assertEquals(200, r.status.value); assertEquals("User-agent: *\nDisallow: /\n", r.bodyAsText())
        // Row 88: an unreadable database is 503.
        s.db.close()
        assertEquals(503, client.get("/healthz").status.value)
    }

    @Test
    fun row91_downloads_servesTheChannel_andNothingElse() = testApplication {
        val dir = TestKit.tempDir("andvari-downloads")
        File(dir, "manifest.json").writeText("""{"v":1}""")
        File(dir, "manifest.json.sig").writeText("sig")
        File(dir, "andvari.apk").writeBytes(ByteArray(10) { 1 })
        File(dir, "sub").mkdir(); File(dir, "sub/x.txt").writeText("x")
        val s = TestKit.services(TestKit.config(downloadsDir = dir.path))
        application { andvariModule(s) }
        val mf = client.get("/downloads/manifest.json")
        assertEquals(200, mf.status.value); assertEquals("""{"v":1}""", mf.bodyAsText())
        assertTrue(mf.headers["Content-Type"]!!.startsWith("application/json"))
        assertEquals("sig", client.get("/downloads/manifest.json.sig").bodyAsText())
        assertEquals(200, client.get("/downloads/andvari.apk").status.value)
        for (p in listOf("/downloads/nope.bin", "/downloads/..%2Fandvari.db", "/downloads/sub", "/downloads/sub%2Fx.txt")) {
            assertEquals(404, client.get(p).status.value, p)
        }
    }

    @Test
    fun row92_selfhost_thePage_itsArtifacts_andNothingElse() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val page = client.get("/selfhost")
        assertEquals(200, page.status.value)
        assertTrue(page.headers["Content-Type"]!!.startsWith("text/html"))
        assertEquals(SelfHost.CSP, page.headers["Content-Security-Policy"])
        for (name in SelfHost.ARTIFACTS) {
            val a = client.get("/selfhost/$name")
            assertEquals(200, a.status.value, name)
            assertTrue(a.headers["Content-Disposition"]!!.contains(name))
            assertTrue(page.bodyAsText().contains("/selfhost/$name"), name)
        }
        assertEquals(404, client.get("/selfhost/andvari.db").status.value)
        assertEquals(404, client.get("/selfhost/..%2Fbuild.gradle.kts").status.value)
    }
}
