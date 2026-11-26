package io.silencelen.andvari.core.client.net

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * `POST /auth/end-session` (spec 03 §2, index row 93): one request, the refresh token in the body and no bearer;
 * best effort, answering nothing; never throwing to a caller that is locking; nothing to an origin with no pin in force.
 */
class EndSessionTest {
    private class Sent(val route: WireRoute, val body: String?, val authenticated: Boolean)

    /** Answers every call with [answer]; records what was sent. */
    private class Scripted(var answer: () -> WireResult<Unit>) : WireClient {
        override val origin = "https://home.example"
        val sent = ArrayList<Sent>()
        override suspend fun <T> call(
            route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T,
        ): WireResult<T> {
            sent += Sent(route, bodyJson, authenticated)
            @Suppress("UNCHECKED_CAST")
            return answer() as WireResult<T>
        }
    }

    @Test fun endsOneSessionByItsRefreshTokenAndNeverThrows() = runBlocking<Unit> {
        val c = Scripted { WireResult.Ok(Unit, 200) }
        c.endSession("rt-newest")
        val s = c.sent.single()
        assertEquals(WireRoute.END_SESSION, s.route)
        assertEquals("""{"refreshToken":"rt-newest"}""", s.body)
        assertTrue(!s.authenticated, "no bearer")
        assertEquals("/api/v1/auth/end-session", s.route.path)
        assertEquals(93, s.route.row)

        // Every answer, and a client that throws, returns normally: the caller is locking.
        for (a in listOf<() -> WireResult<Unit>>(
            { WireResult.Refused(429, WireError("rate_limited", "slow down")) },
            { WireResult.Refused(400, WireError("bad_request", "")) },
            { WireResult.Refused(500, WireError("internal", "")) },
            { WireResult.NoAnswer(NoAnswerKind.TRANSPORT) },
            { throw IllegalStateException("the engine broke") },
        )) {
            c.answer = a
            c.endSession("rt-newest")
        }
        assertEquals(6, c.sent.size, "each sent once, nothing retried")

        // A token that is empty or absurdly long is not sent.
        c.endSession("")
        c.endSession("x".repeat(4097))
        assertEquals(6, c.sent.size)
    }

    @Test fun nothingIsSentToAnOriginWithNoPinInForce() = runBlocking<Unit> {
        val inner = Scripted { WireResult.Ok(Unit, 200) }
        val guarded = OriginGuard(PinStore(MemoryDeviceState())).guard(inner)
        guarded.endSession("rt")
        assertTrue(inner.sent.isEmpty(), "the refresh token is a credential: it goes only where a pin is in force")
    }
}
