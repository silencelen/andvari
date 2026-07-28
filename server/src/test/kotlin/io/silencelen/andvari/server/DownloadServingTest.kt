package io.silencelen.andvari.server

import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.readRawBytes
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/**
 * quality-perf--1: /downloads/{file} (and the SPA fallback — same respondFileContent helper) is
 * STREAMED, never heap-buffered per request, and the streamed content's Last-Modified version is
 * honored: Range → 206 (resumable installer downloads), If-Modified-Since → 304 (no cold-cache
 * full re-download of the web bundle on every navigation).
 */
class DownloadServingTest : P4TestSupport() {

    private fun downloadsConfig(dir: File) = Config(
        host = "127.0.0.1", port = 0,
        dbPath = File(tmpDir, "dl-${System.nanoTime()}.db").absolutePath,
        blobDir = File(tmpDir, "dl-blobs-${System.nanoTime()}").absolutePath, webDir = null,
        downloadsDir = dir.absolutePath,
        recoveryPublicKey = recovery.publicKey, recoveryFingerprint = fingerprint,
        enumSecret = ByteArray(32) { 7 }, publicHostname = null, bootstrapToken = bootstrapToken,
    )

    @Test
    fun downloads_streamed_withRangeAndNotModifiedSupport() = testApplication {
        val dir = File(tmpDir, "downloads-${System.nanoTime()}").apply { mkdirs() }
        val bytes = ByteArray(64 * 1024) { (it % 251).toByte() }
        File(dir, "andvari-setup.bin").writeBytes(bytes)
        application { andvariModule(buildServices(downloadsConfig(dir), Notifier())) }
        val client = jsonClient(this)

        // Full download: exact bytes, plus the Last-Modified validator the streamed content carries.
        val full = client.get("/downloads/andvari-setup.bin")
        assertEquals(HttpStatusCode.OK, full.status)
        assertContentEquals(bytes, full.readRawBytes())
        val lastModified = full.headers[HttpHeaders.LastModified]
        assertNotNull(lastModified, "the streamed file response must carry Last-Modified")

        // Range (a resumed installer download) → 206 with exactly the requested slice.
        val part = client.get("/downloads/andvari-setup.bin") { header(HttpHeaders.Range, "bytes=0-1023") }
        assertEquals(HttpStatusCode.PartialContent, part.status)
        assertContentEquals(bytes.copyOfRange(0, 1024), part.readRawBytes())

        // Revalidation: If-Modified-Since with the served validator → 304, no body re-sent.
        val cached = client.get("/downloads/andvari-setup.bin") { header(HttpHeaders.IfModifiedSince, lastModified) }
        assertEquals(HttpStatusCode.NotModified, cached.status)
    }
}
