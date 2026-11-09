package io.silencelen.andvari.core.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.silencelen.andvari.core.crypto.Hibp
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

/**
 * The item-password breach lookup the Health scan runs: `Hibp.sha1UpperHex` locally, then
 * [AndvariApi.hibpRange] with the prefix, then `Hibp.countInRange` locally. Asserts on the
 * REQUEST that left the client — the URL carries the 5-hex prefix and nothing else.
 *
 * (This file used to pin `Strength.breachCount`, the master-password / backup-passphrase seam.
 * That seam is gone — security review 2026-10, root cause C; see [MasterBreachNoRelayTest].)
 */
class HibpRangeTransportTest {
    private val crypto = createCryptoProvider()
    private val password = "correct horse battery staple"

    @Test
    fun onlyTheFiveCharPrefixReachesTheWire() = runBlocking {
        val hash = Hibp.sha1UpperHex(crypto, password)
        val urls = ArrayList<String>()
        val engine = MockEngine { req ->
            urls.add(req.url.toString())
            // Upstream's own format: suffixes + counts, CRLF-separated, matched LOCALLY.
            respond("${Hibp.suffix(hash)}:1337\r\n", HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "text/plain"))
        }
        val api = AndvariApi("http://fake", HttpClient(engine), Tokens("access", "refresh"))
        val count = Hibp.countInRange(api.hibpRange(Hibp.prefix(hash)), hash)
        assertEquals(1337L, count)
        val url = urls.single()
        assertEquals("http://fake/api/v1/hibp/range/${Hibp.prefix(hash)}", url)
        assertFalse(url.contains(password), "the password must never reach the wire")
        assertFalse(url.contains(hash), "the FULL hash must never reach the wire — only its first five characters")
        api.close()
    }

    @Test
    fun aMissOrGarbageIsZero_neverAFalseBreach() {
        val hash = Hibp.sha1UpperHex(crypto, password)
        assertEquals(0L, Hibp.countInRange("0000000000000000000000000000000000000:9\r\n", hash))
        assertEquals(0L, Hibp.countInRange("<html>502 Bad Gateway</html>", hash))
    }

    /** A refused relay is an exception the scan counts as a failed range ("—"), never a zero. */
    @Test
    fun aRefusedRelayThrows() = runBlocking {
        val engine = MockEngine { respond("""{"error":"unauthorized"}""", HttpStatusCode.Unauthorized, headersOf(HttpHeaders.ContentType, "application/json")) }
        val api = AndvariApi("http://fake", HttpClient(engine))
        assertFailsWith<Exception> { api.hibpRange("ABCDE") }
        api.close()
    }
}
