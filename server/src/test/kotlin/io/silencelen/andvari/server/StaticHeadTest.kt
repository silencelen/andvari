package io.silencelen.andvari.server

import io.ktor.client.request.request
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsBytes
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** The web client's files answer `HEAD` as `GET` would, without a body (spec 03 §0.2); nothing else gains a `HEAD`. */
class StaticHeadTest {
    private val compared = listOf(
        HttpHeaders.ContentType, HttpHeaders.ContentLength, HttpHeaders.CacheControl, "Content-Security-Policy",
        HttpHeaders.LastModified, HttpHeaders.ETag,
    )

    private suspend fun io.ktor.client.HttpClient.raw(method: HttpMethod, path: String): HttpResponse = request(path) { this.method = method }

    @Test
    fun head_answersAsGet_withoutABody_forTheWebAppOnly() = testApplication {
        val dir = TestKit.tempDir()
        val web = File(dir, "web").also { it.mkdirs() }
        File(web, "index.html").writeText("<!doctype html><title>andvari</title>")
        File(web, "assets").mkdirs()
        File(web, "assets/app-1a2b.js").writeText("console.log(1)")
        val s = TestKit.services(TestKit.config(dir = dir, webDir = web.path))
        application { andvariModule(s) }
        val c = createClient { followRedirects = false }

        for (path in listOf("/", "/index.html", "/vault/some/deep/link", "/assets/app-1a2b.js", "/assets/missing.js")) {
            val get = c.raw(HttpMethod.Get, path)
            val head = c.raw(HttpMethod.Head, path)
            assertEquals(get.status, head.status, path)
            for (h in compared) assertEquals(get.headers[h], head.headers[h], "$path: $h")
            assertEquals(0, head.bodyAsBytes().size, "$path: HEAD carries no body")
            assertEquals(get.bodyAsBytes().size.toString(), head.headers[HttpHeaders.ContentLength], "$path: the GET body's length")
        }
        val root = c.raw(HttpMethod.Head, "/")
        assertEquals(200, root.status.value)
        assertNotNull(root.headers["Content-Security-Policy"])
        assertTrue(root.headers[HttpHeaders.ContentType]!!.startsWith("text/html"))
        assertEquals(404, c.raw(HttpMethod.Head, "/assets/missing.js").status.value)

        // Nothing else changes: a path another GET route owns still has no HEAD (404, as before), and never
        // gets the web app's page.
        for (path in listOf("/api/v1/nothing-here", "/api/v1/client-policy", "/healthz", "/metrics", "/robots.txt", "/selfhost", "/selfhost/docker-compose.yml")) {
            val head = c.raw(HttpMethod.Head, path)
            assertEquals(404, head.status.value, path)
            assertEquals(null, head.headers["Content-Security-Policy"], "$path: not the web app")
        }
        // A path no other route owns is the web app's, also for HEAD.
        assertEquals(200, c.raw(HttpMethod.Head, "/healthz/x").status.value)
    }

    /**
     * With no downloads directory, every path under `/downloads/` is `404` for GET and HEAD, never the web app's
     * page (a desktop app read that page as an update list that failed its check). `/downloads` itself and
     * `/downloadsx/…` stay the web app's. With a directory set nothing changes.
     */
    @Test
    fun withoutADownloadsDir_everyPathUnderDownloads_is404_notTheWebApp() = testApplication {
        val dir = TestKit.tempDir()
        val web = File(dir, "web").also { it.mkdirs() }
        File(web, "index.html").writeText("<!doctype html><title>andvari</title>")
        val s = TestKit.services(TestKit.config(dir = dir, webDir = web.path))
        application { andvariModule(s) }
        val c = createClient { followRedirects = false }
        for (path in listOf("/downloads/manifest.json", "/downloads/manifest.json.sig", "/downloads/x", "/downloads/", "/downloads/a/b/c.msi", "/%64ownloads/manifest.json")) {
            val get = c.raw(HttpMethod.Get, path)
            assertEquals(404, get.status.value, path)
            assertTrue(!get.bodyAsText().contains("<!doctype html>") && get.headers["Content-Security-Policy"] == null, "$path: not the web app")
            val head = c.raw(HttpMethod.Head, path)
            assertEquals(404, head.status.value, path)
            assertEquals(0, head.bodyAsBytes().size, path)
        }
        for (path in listOf("/downloads", "/downloadsx/manifest.json")) {
            assertEquals(200, c.raw(HttpMethod.Get, path).status.value, path)
            assertEquals(200, c.raw(HttpMethod.Head, path).status.value, path)
        }
    }

    @Test
    fun withADownloadsDir_theDownloadsRouteIsUnchanged() = testApplication {
        val dir = TestKit.tempDir()
        val web = File(dir, "web").also { it.mkdirs() }
        File(web, "index.html").writeText("<!doctype html><title>andvari</title>")
        val dl = File(dir, "dl").also { it.mkdirs() }
        File(dl, "manifest.json").writeText("""{"v":1}""")
        val s = TestKit.services(TestKit.config(dir = dir, webDir = web.path, downloadsDir = dl.path))
        application { andvariModule(s) }
        val c = createClient { followRedirects = false }
        val m = c.raw(HttpMethod.Get, "/downloads/manifest.json")
        assertEquals(200, m.status.value); assertEquals("""{"v":1}""", m.bodyAsText())
        assertEquals(404, c.raw(HttpMethod.Get, "/downloads/manifest.json.sig").status.value)
        assertEquals(404, c.raw(HttpMethod.Head, "/downloads/manifest.json").status.value, "the downloads route has no HEAD, as before")
        // A deeper path is the web app's, as before.
        assertEquals("<!doctype html><title>andvari</title>", c.raw(HttpMethod.Get, "/downloads/a/b").bodyAsText())
    }

    @Test
    fun theWebAppWithoutAWebDir_hasNoHead() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        assertEquals(404, client.request("/") { method = HttpMethod.Head }.status.value)
    }

    @Test
    fun ownedByAnotherGetRoute_matchesTheRoutes() {
        val plain = TestKit.config()
        val withDownloads = TestKit.config(downloadsDir = TestKit.tempDir().path)
        assertTrue(ownedByAnotherGetRoute(listOf("api", "v1", "sync"), plain))
        assertTrue(ownedByAnotherGetRoute(listOf("selfhost", "x"), plain))
        assertTrue(ownedByAnotherGetRoute(listOf("downloads", "manifest.json"), withDownloads))
        assertEquals(false, ownedByAnotherGetRoute(listOf("downloads", "manifest.json"), plain))
        assertEquals(false, ownedByAnotherGetRoute(emptyList(), plain))
        assertEquals(false, ownedByAnotherGetRoute(listOf("selfhost", "a", "b"), plain))
        assertEquals(false, ownedByAnotherGetRoute(listOf("vault"), plain))
    }
}
