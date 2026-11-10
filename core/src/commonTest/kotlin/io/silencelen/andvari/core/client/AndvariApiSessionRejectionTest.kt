package io.silencelen.andvari.core.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/** The signal a client needs to follow the spec 02 §8 purge path on a definitive in-session rejection. */
class AndvariApiSessionRejectionTest {
    private fun headers() = headersOf(HttpHeaders.ContentType, "application/json")

    private fun client(refresh: HttpStatusCode, events: MutableList<String>): AndvariApi {
        val engine = MockEngine { request ->
            when (request.url.encodedPath) {
                "/api/v1/auth/refresh" -> respond("""{"error":"refused","message":"no"}""", refresh, headers())
                "/api/v1/auth/logout" -> respond("", HttpStatusCode.OK)
                else -> respond("""{"error":"unauthorized","message":"bad access token"}""", HttpStatusCode.Unauthorized, headers())
            }
        }
        return AndvariApi(
            "http://fake",
            HttpClient(engine),
            Tokens("a", "r"),
            onTokens = { t -> events += if (t == null) "tokens-null" else "tokens" },
            onSessionRejected = { events += "rejected" },
        )
    }

    @Test
    fun aDefinitiveRefusalSignalsBeforeTheTokensDrop() = runBlocking<Unit> {
        for (status in listOf(HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden)) {
            val events = mutableListOf<String>()
            val api = client(status, events)
            assertFailsWith<ApiException> { api.sync(0) }
            assertEquals(listOf("rejected", "tokens-null"), events, "$status: the purge needs the session's identity before the tokens are erased")
            assertNull(api.currentTokens())
            api.close()
        }
    }

    @Test
    fun aTransientRefreshFailureIsNotARejection() = runBlocking<Unit> {
        val events = mutableListOf<String>()
        val api = client(HttpStatusCode.ServiceUnavailable, events)
        assertFailsWith<ApiException> { api.sync(0) }
        assertEquals(emptyList(), events, "a 503 keeps the session")
        assertNotNull(api.currentTokens())
        api.close()
    }

    @Test
    fun anOrdinaryLogoutIsNotARejection() = runBlocking<Unit> {
        val events = mutableListOf<String>()
        val api = client(HttpStatusCode.Unauthorized, events)
        api.logout()
        assertEquals(listOf("tokens-null"), events, "only a refused refresh signals; logout just drops the tokens")
        api.close()
    }
}
