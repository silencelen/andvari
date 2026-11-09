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
import kotlin.test.assertFalse

/**
 * Pins errorFrom's upgrade_required mapping (N2 §1): the BODY code is the server's
 * contract — its min-version pin always sends ApiError("upgrade_required", …) with the
 * 426 (App.kt StatusPages) — so the status alone must NOT raise the typed exception. An
 * intermediary/captive-portal 426 with a garbage body would otherwise brick both natives
 * behind the full-screen "update required" gate.
 */
class AndvariApiErrorTest {

    private fun apiRespondingWith(status: HttpStatusCode, body: String, contentType: String): AndvariApi {
        val engine = MockEngine { _ ->
            respond(body, status, headersOf(HttpHeaders.ContentType, contentType))
        }
        return AndvariApi("http://fake", HttpClient(engine))
    }

    @Test
    fun bare426WithNonJsonBodyIsAPlainApiException() = runBlocking {
        val api = apiRespondingWith(HttpStatusCode(426, "Upgrade Required"), "<html>captive portal</html>", "text/html")
        val e = assertFailsWith<ApiException> { api.clientPolicy() }
        assertFalse(e is UpgradeRequiredException, "an intermediary 426 must not brick the client")
        assertEquals(426, e.status)
        assertEquals("http_426", e.code)
        api.close()
    }

    @Test
    fun status426WithUpgradeRequiredBodyRaisesTyped() = runBlocking {
        val api = apiRespondingWith(
            HttpStatusCode(426, "Upgrade Required"),
            """{"error":"upgrade_required","message":"min android 0.9.0"}""",
            "application/json",
        )
        val e = assertFailsWith<UpgradeRequiredException> { api.clientPolicy() }
        assertEquals(426, e.status)
        assertEquals("upgrade_required", e.code)
        api.close()
    }

    @Test
    fun upgradeRequiredBodyOnNon426StatusStillRaisesTyped() = runBlocking {
        // The body code matters more than the status — a server-shaped upgrade_required
        // stays typed even if some hop rewrote the status line.
        val api = apiRespondingWith(
            HttpStatusCode.BadRequest,
            """{"error":"upgrade_required","message":"min android 0.9.0"}""",
            "application/json",
        )
        assertFailsWith<UpgradeRequiredException> { api.clientPolicy() }
        api.close()
    }
}
