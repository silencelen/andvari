package io.silencelen.andvari.core.client.onboard

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.UserIds
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * A user id of all zeros is never an account (the escrow's canary uses it): a session answer that names it opens
 * nothing. Before, a sign-in whose answer named the nil id, with keys that open, made it this device's account.
 */
class NilUserIdAnswerTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    private class Sink : SessionSink {
        val sessions = ArrayList<EstablishedSession>()
        override suspend fun established(session: EstablishedSession) { sessions += session }
    }

    /** The server's answers, with every account id in a session answer swapped for the nil id once [nil] is on. */
    private class Swap(private val inner: FakeInstance) : WireClient by inner {
        var nil = false
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            if (!nil || route != WireRoute.LOGIN) return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
            val r = inner.call(route, pathParams, query, bodyJson, authenticated) { it }
            if (r !is WireResult.Ok) return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
            val id = inner.accounts.values.single().userId
            return WireResult.Ok(decode(r.value.replace(id, UserIds.NIL)), r.status)
        }
    }

    @Test fun aSignInAnswerNamingTheNilUserIdOpensNothing() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val swap = Swap(server)
        suspend fun onboarding(state: MemoryDeviceState, sink: Sink) = WireOnboarding(server.origin, swap, server.pinnedTrust(state), KnownDevices(state, crypto), sink, crypto, state,
            "android", "Pixel", { server.now }, work = Dispatchers.Unconfined)
        val o = onboarding(MemoryDeviceState(), Sink())
        o.signupStart("alice@example.com", true)
        val t = assertIs<SignupVerify.Ticket>(o.signupVerify("alice@example.com", "482915"))
        assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(t),
            RegistrationForm("alice@example.com", "Alice", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android")))

        val sink = Sink()
        val other = onboarding(MemoryDeviceState(), sink)
        swap.nil = true
        val r = other.signIn("alice@example.com", strong.toCharArray(), null)
        assertTrue(r is SignIn.Refused, "refused: $r")
        assertTrue(sink.sessions.isEmpty(), "no session names the nil id")
        swap.nil = false
        other.signIn("alice@example.com", strong.toCharArray(), null)
        assertEquals(1, sink.sessions.size, "the honest answer opens")
    }
}
