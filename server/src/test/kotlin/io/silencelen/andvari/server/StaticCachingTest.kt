package io.silencelen.andvari.server

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * H76 (audit 2026-09-13): the SPA was served with no Cache-Control at all and a missing hashed
 * asset fell through to a 200 index.html. Browsers apply heuristic freshness to a document with
 * only Last-Modified, so after a release a bookmarked index.html could be served stale, reference
 * `assets/index.<oldhash>.js`, receive index.html (text/html + nosniff) in its place, and strand
 * the tab on the pre-hydration "unsealing…" placeholder — no bundle running to show the 426 bar
 * or any error, self-healing only via a reload nobody is told to make. Pins the two Cache-Control
 * values and the loud 404, on a throw-away dist/ shaped like Vite's output.
 */
class StaticCachingTest : P4TestSupport() {

    private fun webConfig(dir: File) = Config(
        host = "127.0.0.1", port = 0,
        dbPath = File(tmpDir, "web-${System.nanoTime()}.db").absolutePath,
        blobDir = File(tmpDir, "web-blobs-${System.nanoTime()}").absolutePath,
        webDir = dir.absolutePath,
        recoveryPublicKey = recovery.publicKey, recoveryFingerprint = fingerprint,
        enumSecret = ByteArray(32) { 7 }, publicHostname = null, bootstrapToken = bootstrapToken,
    )

    @Test
    fun hashedAssetsImmutable_documentRevalidates_missingAssetIs404() = testApplication {
        val dist = File(tmpDir, "dist-${System.nanoTime()}").apply { mkdirs() }
        File(dist, "index.html").writeText("<!doctype html><div id=root>unsealing…</div>")
        File(dist, "theme-boot.js").writeText("/* un-hashed public file */")
        File(dist, "assets").mkdirs()
        File(dist, "assets/index.abc123.js").writeText("export {}")
        application { andvariModule(buildServices(webConfig(dist), Notifier())) }
        val client = jsonClient(this)

        // The document: stored but ALWAYS revalidated — a release is picked up on the next
        // navigation, not after a heuristic window (Last-Modified → 304 keeps that cheap).
        val index = client.get("/")
        assertEquals(HttpStatusCode.OK, index.status)
        assertEquals(STATIC_CACHE_REVALIDATE, index.headers[HttpHeaders.CacheControl])
        assertTrue(index.bodyAsText().contains("unsealing"))
        // The SPA fallback (a deep link into the app) is the same document, same rule.
        val deep = client.get("/vault/settings")
        assertEquals(HttpStatusCode.OK, deep.status)
        assertEquals(STATIC_CACHE_REVALIDATE, deep.headers[HttpHeaders.CacheControl])
        assertTrue(deep.bodyAsText().contains("unsealing"))
        // An un-hashed /public file changes per release under the same name: revalidate too.
        assertEquals(STATIC_CACHE_REVALIDATE, client.get("/theme-boot.js").headers[HttpHeaders.CacheControl])

        // A hash-named bundle is content-addressed: cache it forever.
        val asset = client.get("/assets/index.abc123.js")
        assertEquals(HttpStatusCode.OK, asset.status)
        assertEquals(STATIC_CACHE_IMMUTABLE, asset.headers[HttpHeaders.CacheControl])

        // A stale reference fails LOUD: 404, never index.html fed to a module loader.
        val gone = client.get("/assets/index.oldhash.js")
        assertEquals(HttpStatusCode.NotFound, gone.status)
        assertTrue(!gone.bodyAsText().contains("unsealing"), "a missing asset must not fall through to the SPA document")

        // The CSP the SPA route always carried is untouched by the new headers.
        assertTrue(index.headers["Content-Security-Policy"]?.contains("default-src 'self'") == true)
    }

    /**
     * H76 follow-up (0.27.0 deploy, 2026-09-14): the loud 404 shipped with NO Cache-Control, so
     * Cloudflare applied its default edge TTL to it (`cf-cache-status: HIT`,
     * `cache-control: max-age=14400`, observed still serving at age 158 s while the origin had
     * the file). A few seconds of a mis-deployed web dir became a multi-hour cached 404 for the
     * bundle name every new index.html referenced. Pins no-store on the negative answer.
     */
    @Test
    fun missingHashedAssetIsNeverCacheable() = testApplication {
        val dist = File(tmpDir, "dist-${System.nanoTime()}").apply { mkdirs() }
        File(dist, "index.html").writeText("<!doctype html><div id=root>unsealing…</div>")
        File(dist, "assets").mkdirs()
        File(dist, "assets/index.abc123.js").writeText("export {}")
        application { andvariModule(buildServices(webConfig(dist), Notifier())) }
        val client = jsonClient(this)

        // The negative answer about a content-addressed name: 404 that no intermediary may store.
        val gone = client.get("/assets/index.doesnotexist.js")
        assertEquals(HttpStatusCode.NotFound, gone.status)
        assertEquals(STATIC_CACHE_NOSTORE, gone.headers[HttpHeaders.CacheControl])

        // A missing NON-asset path is not a negative answer at all — it is the SPA fallback, and
        // its caching rule is unchanged: 200 index.html, no-cache (store + always revalidate).
        val fallback = client.get("/vault/some/deep/link")
        assertEquals(HttpStatusCode.OK, fallback.status)
        assertEquals(STATIC_CACHE_REVALIDATE, fallback.headers[HttpHeaders.CacheControl])
        assertTrue(fallback.bodyAsText().contains("unsealing"))

        // The asset that IS present keeps its year+immutable — no-store must not leak sideways.
        assertEquals(STATIC_CACHE_IMMUTABLE, client.get("/assets/index.abc123.js").headers[HttpHeaders.CacheControl])
    }

    /** The other 404 branch: a web dir with no index.html (absent or half-deployed) — the state
     *  the 0.27.0 incident hit first, and the one an edge is most eager to keep. */
    @Test
    fun missingIndexHtmlIsNeverCacheable() = testApplication {
        val dist = File(tmpDir, "dist-empty-${System.nanoTime()}").apply { mkdirs() }
        application { andvariModule(buildServices(webConfig(dist), Notifier())) }
        val client = jsonClient(this)

        val root = client.get("/")
        assertEquals(HttpStatusCode.NotFound, root.status)
        assertEquals(STATIC_CACHE_NOSTORE, root.headers[HttpHeaders.CacheControl])

        val deep = client.get("/vault/settings")
        assertEquals(HttpStatusCode.NotFound, deep.status)
        assertEquals(STATIC_CACHE_NOSTORE, deep.headers[HttpHeaders.CacheControl])
    }
}
