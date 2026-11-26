package io.silencelen.andvari.core.client.net

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

/**
 * A server's "wait this long" (`Retry-After` on a `429 rate_limited`) is handed up only as a number of seconds from 0 to a
 * day. A wait beyond a day, a negative one, one that does not read as a whole number of seconds (a date, text, a number
 * past any integer) is handed up as no number ("later"), on every route, so that no line can show an absurd, a wrapped
 * or a negative wait.
 */
class RetryAfterBoundTest {
    private val o = "https://h.example"

    @Test fun aServersWaitIsADayAtMostAndOtherwiseNoNumber() = runBlocking<Unit> {
        var named = ""
        val engine = MockEngine {
            respond("""{"error":"rate_limited","message":"m"}""", HttpStatusCode.TooManyRequests, headersOf("Retry-After", named))
        }
        val c = KtorWireClient(o, HttpClient(engine), "linux")
        val vault = "0b6f3c2e-4d5a-4b7c-8d9e-0f1a2b3c4d5e"
        val routes = listOf<suspend () -> WireResult<String>>(
            { c.call(WireRoute.REFRESH, bodyJson = "{}", decode = { it }) },
            { c.call(WireRoute.LOG_APPEND, mapOf("vaultId" to vault), bodyJson = "{}", decode = { it }) },
            { c.call(WireRoute.SIGNUP_START, bodyJson = "{}", decode = { it }) },
        )
        val cases = listOf(
            "0" to 0L,
            "17" to 17L,
            " 60 " to 60L,
            "86400" to 86_400L,
            "86401" to null,
            "2147483648" to null,
            "9223372036854775807" to null,
            "99999999999999999999999" to null,
            "-5" to null,
            "-9223372036854775808" to null,
            "soon" to null,
            "Wed, 21 Oct 2015 07:28:00 GMT" to null,
            "1.5" to null,
            "" to null,
        )
        for ((header, expected) in cases) {
            named = header
            for (route in routes) {
                val r = assertIs<WireResult.Refused>(route())
                assertEquals("rate_limited", r.code)
                assertEquals(expected, r.retryAfterSeconds, "Retry-After '$header'")
            }
        }
    }
}
