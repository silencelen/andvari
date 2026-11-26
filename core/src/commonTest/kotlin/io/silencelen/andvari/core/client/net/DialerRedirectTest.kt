package io.silencelen.andvari.core.client.net

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.pin.CardPin
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * No route of the wire protocol answers with a redirect (spec 03 §0), so the [Dialer] follows none: an answer that
 * redirects is no answer. Whatever the server names in `Location` (another path on the origin, another host, plain
 * http, an address the origin grammar refuses), the engine is asked exactly once, for the origin, and nothing is
 * taken from the redirect: a credential or a password proof never reaches another host, and an address that fails the
 * dial rules is never dialled because a server said so.
 */
class DialerRedirectTest {
    private val origin = "https://home.example"

    private fun pin() = CardPin("0b6f3c2e-4d5a-4b7c-8d9e-0f1a2b3c4d5e", 1, "a".repeat(64), origin, "Home", "private",
        "1c7f4d3e-5e6b-4c8d-9e0f-1a2b3c4d5e6f", "A".repeat(43), "none", PinRoot.TRUST_GATE, null, "b".repeat(64))

    private val tokens = object : TokenSource {
        override fun accessToken() = "the-bearer"
        override suspend fun refresh(staleAccessToken: String) = false
    }

    private val locations = listOf(
        "/api/v1/account/state",
        "https://home.example/api/v1/somewhere-else",
        "https://other.example/api/v1/sync",
        "http://home.example/api/v1/sync",
        "http://169.254.169.254/latest/meta-data/",
        "https://10.0.0.1/api/v1/sync",
    )

    private val statuses = listOf(HttpStatusCode.MovedPermanently, HttpStatusCode.Found, HttpStatusCode.SeeOther, HttpStatusCode.TemporaryRedirect, HttpStatusCode.PermanentRedirect)

    @Test fun noAnswerThatRedirectsIsFollowed_withACredentialOrWithout_beforeAPinOrAfter() = runBlocking<Unit> {
        for (pinned in listOf(false, true)) for (status in statuses) for (location in locations) {
            val seen = ArrayList<String>()
            val http = HttpClient(MockEngine { req ->
                seen += "${req.method.value} ${req.url} ${req.headers[HttpHeaders.Authorization]}"
                respond("", status, headersOf(HttpHeaders.Location, location))
            })
            val state = MemoryDeviceState()
            if (pinned) PinStore(state).put(pin())
            val dialer = Dialer(PinStore(state), http, "linux")
            val calls = buildList {
                // Before a pin: what a first pin needs (no credential). After: the same, a credentialed GET and a POST.
                add(WireRoute.INSTANCE to dialer.open(origin, null))
                add(WireRoute.CLIENT_POLICY to dialer.open(origin, null))
                if (pinned) {
                    add(WireRoute.SYNC to dialer.open(origin, tokens))
                    add(WireRoute.ACCOUNT_KEYS to dialer.open(origin, tokens))
                    add(WireRoute.PRELOGIN to dialer.open(origin, null))
                }
            }
            for ((route, client) in calls) {
                seen.clear()
                val what = "pinned=$pinned $route answered ${status.value} to $location"
                val r = if (route == WireRoute.PRELOGIN) client.call(route, bodyJson = """{"email":"a@b.example"}""", decode = { it })
                else client.call(route, decode = { it })
                assertTrue(r !is WireResult.Ok, "$what: a redirect is not an answer: $r")
                assertIs<WireResult.NoAnswer>(r, "$what: $r")
                assertEquals(1, seen.size, "$what: the engine was asked once, for the origin: $seen")
                assertTrue(seen.single().contains("://home.example/api/v1/"), "$what: ${seen.single()}")
                if (route == WireRoute.PRELOGIN) continue
                val bytes = client.fetchBytes(route, emptyMap(), null, route == WireRoute.SYNC || route == WireRoute.ACCOUNT_KEYS, 1024)
                assertIs<WireResult.NoAnswer>(bytes, "$what (bytes): $bytes")
                assertEquals(2, seen.size, "$what (bytes): $seen")
            }
        }
    }
}
