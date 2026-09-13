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
}
