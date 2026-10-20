package io.silencelen.andvari.desktop

import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.net.http.HttpClient
import java.time.Duration
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertNull

/**
 * Security review 2026-10, branch A13 (q19): the update manifest and its signature are UNVERIFIED server bytes, so
 * the desktop caps them while reading — a declared oversized body is refused before any read, and a chunked one stops
 * at the cap — instead of buffering the whole answer on the heap before the signature check.
 */
class UpdateFetchBoundTest {
    private lateinit var server: HttpServer
    private lateinit var base: String
    private val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(4)).build()

    @BeforeTest
    fun start() {
        server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        fun route(path: String, body: ByteArray, chunked: Boolean, status: Int = 200) = server.createContext(path) { ex ->
            ex.sendResponseHeaders(status, if (chunked) 0 else body.size.toLong())
            ex.responseBody.use { out -> runCatching { out.write(body) } }
        }
        route("/small", "{\"seq\":1}".toByteArray(), chunked = false)
        route("/declared-big", ByteArray(UPDATE_MANIFEST_MAX_BYTES + 1) { 'a'.code.toByte() }, chunked = false)
        route("/chunked-big", ByteArray(UPDATE_MANIFEST_MAX_BYTES * 4) { 'a'.code.toByte() }, chunked = true)
        route("/chunked-small", "sig".toByteArray(), chunked = true)
        route("/missing", "nope".toByteArray(), chunked = false, status = 404)
        server.start()
        base = "http://127.0.0.1:${server.address.port}"
    }

    @AfterTest
    fun stop() = server.stop(0)

    @Test
    fun bodiesWithinTheCapAreReturnedWhole() {
        assertContentEquals("{\"seq\":1}".toByteArray(), fetchBounded(client, "$base/small", UPDATE_MANIFEST_MAX_BYTES))
        assertContentEquals("sig".toByteArray(), fetchBounded(client, "$base/chunked-small", UPDATE_SIG_MAX_BYTES))
    }

    @Test
    fun anOversizedBodyIsRefusedDeclaredOrNot() {
        assertNull(fetchBounded(client, "$base/declared-big", UPDATE_MANIFEST_MAX_BYTES), "declared Content-Length over the cap")
        assertNull(fetchBounded(client, "$base/chunked-big", UPDATE_MANIFEST_MAX_BYTES), "chunked body over the cap")
        assertNull(fetchBounded(client, "$base/small", 4), "the signature cap applies the same way")
        assertNull(fetchBounded(client, "$base/missing", UPDATE_MANIFEST_MAX_BYTES), "a non-200 answer")
    }

    @Test
    fun theCapsAreSizedForTheRealFiles() {
        // 64-byte Ed25519 signature → 86 base64url chars; the live manifest is a few KiB.
        kotlin.test.assertTrue(UPDATE_SIG_MAX_BYTES in 128..4096)
        kotlin.test.assertTrue(UPDATE_MANIFEST_MAX_BYTES in 64 * 1024..1024 * 1024)
    }
}
