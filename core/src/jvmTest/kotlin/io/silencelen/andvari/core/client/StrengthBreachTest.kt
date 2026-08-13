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
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * F31: the master password / backup passphrase finally get the k-anonymity check that shipped
 * in Hibp.kt and had no production consumer at all. These tests pin the two properties the
 * owner decision rests on — ONLY a prefix leaves the device, and an unreachable breach API
 * never blocks anyone — because neither is visible in a UI screenshot.
 *
 * [theWholeProductionPathSendsNothingButThePrefix] covers the same ground through the REAL
 * transport the native surfaces use ([AndvariApi.hibpRange]), because a seam that is only ever
 * exercised with a lambda in a test is exactly how F31's first fix shipped uncalled.
 */
class StrengthBreachTest {
    private val crypto = createCryptoProvider()
    private val password = "correct horse battery staple"

    @Test
    fun onlyTheFiveCharPrefixIsEverHandedToTheFetcher() = runBlocking {
        val hash = Hibp.sha1UpperHex(crypto, password)
        val seen = ArrayList<String>()
        val count = Strength.breachCount(crypto, password) { prefix ->
            seen.add(prefix)
            "${Hibp.suffix(hash)}:42\r\n"
        }
        assertEquals(42L, count)
        assertEquals(listOf(Hibp.prefix(hash)), seen)
        val sent = seen.single()
        assertEquals(5, sent.length)
        assertTrue(hash.startsWith(sent))
        // The two things that must NEVER cross the seam.
        assertNotEquals(hash, sent)
        assertFalse(sent.contains(password))
    }

    @Test
    fun aMissFromTheRangeIsZero_notNull() = runBlocking {
        // A well-formed range response that simply doesn't list this suffix.
        assertEquals(0L, Strength.breachCount(crypto, password) { "0000000000000000000000000000000000000:9\r\n" })
    }

    @Test
    fun anUnreachableRelayFailsOpenAndSilent() = runBlocking {
        assertNull(Strength.breachCount(crypto, password) { error("relay down") })
        assertNull(Strength.breachCount(crypto, password) { throw java.io.IOException("no route to host") })
        // Garbage that isn't a range response is a miss, never a false "breached".
        assertEquals(0L, Strength.breachCount(crypto, password) { "<html>502 Bad Gateway</html>" })
    }

    @Test
    fun emptyPasswordIsNotEvenLookedUp() = runBlocking {
        var called = false
        assertNull(
            Strength.breachCount(crypto, "") {
                called = true
                ""
            },
        )
        assertFalse(called)
    }

    /**
     * The shape the natives actually run: `Strength.breachCount(crypto, pw) { api.hibpRange(it) }`.
     * Asserts on the REQUEST that left the client — the URL carries the 5-hex prefix and nothing
     * else, and neither the password nor the full hash appears anywhere in it.
     */
    @Test
    fun theWholeProductionPathSendsNothingButThePrefix() = runBlocking {
        val hash = Hibp.sha1UpperHex(crypto, password)
        val urls = ArrayList<String>()
        val engine = MockEngine { req ->
            urls.add(req.url.toString())
            // Upstream's own format: suffixes + counts, CRLF-separated, matched LOCALLY.
            respond("${Hibp.suffix(hash)}:1337\r\n", HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "text/plain"))
        }
        val api = AndvariApi("http://fake", HttpClient(engine), Tokens("access", "refresh"))
        val count = Strength.breachCount(crypto, password) { api.hibpRange(it) }
        assertEquals(1337L, count)
        val url = urls.single()
        assertEquals("http://fake/api/v1/hibp/range/${Hibp.prefix(hash)}", url)
        assertFalse(url.contains(password), "the password must never reach the wire")
        assertFalse(url.contains(hash), "the FULL hash must never reach the wire — only its first five characters")
        api.close()
    }

    /** The relay is session-gated, so a 401/500 is the ordinary case on a pre-session surface —
     *  and it must be indistinguishable from "not breached" to the user: null, no exception. */
    @Test
    fun aRefusedRelayIsSilentThroughTheRealTransport() = runBlocking {
        val engine = MockEngine { respond("""{"error":"unauthorized"}""", HttpStatusCode.Unauthorized, headersOf(HttpHeaders.ContentType, "application/json")) }
        val api = AndvariApi("http://fake", HttpClient(engine))
        assertNull(Strength.breachCount(crypto, password) { api.hibpRange(it) })
        api.close()
    }
}
