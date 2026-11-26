package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A sign-in names the session it replaces (spec 03 §2, `replacesRefreshToken`): when this device keeps a session of the
 * same account at the same server and signs in on that session's own device row, the login carries the kept session's
 * refresh token, and the server ends exactly that session with the sign-in. Otherwise it names none. The device sends
 * nothing else for the replaced session, before or after: no end-session and no sign-out. A kept session on another row
 * is still ended by the device by its own token. Before, the login named nothing: on a server that does not end a row's
 * earlier sessions by itself, the replaced session stayed live with nobody holding it.
 */
class SignInNamesReplacedSessionTest {
    private val plain = createCryptoProvider()
    private val password = "correct horse Battery 9 staple"
    private val email = "alice@example.com"

    private class Env(val server: FakeInstance, val transport: BearerTransport, val keeper: SessionKeeper, val state: MemoryDeviceState, val onboarding: WireOnboarding) {
        /** The refresh token of the session the keeper holds, as the server knows it. */
        fun keptRefresh(): String = assertNotNull(server.live.entries.single { it.value.deviceId == assertNotNull(keeper.session).deviceId }).key

        fun ends(since: Int) = transport.sent.drop(since).filter { it.route == WireRoute.END_SESSION || it.route == WireRoute.LOGOUT }
    }

    /**
     * Registered, signed in and locked. The server counts its live sessions, ends a session a sign-in names, and does NOT
     * end a row's earlier sessions by itself: whatever ends the kept session here, the name did it.
     */
    private suspend fun registered(): Env {
        val server = FakeInstance(plain)
        server.countSessions = true
        server.endsNamedSession = true
        val state = MemoryDeviceState()
        val trust = server.pinnedTrust(state)
        val transport = BearerTransport(mapOf(server.origin to server))
        val keeper = SessionKeeper(transport, MemoryDeviceState(), state, trust, plain)
        val o = WireOnboarding(server.origin, keeper.clientFor(server.origin), trust, KnownDevices(state, plain), keeper, plain, state, "android", "Pixel",
            { server.now }, knownIdentity = keeper::knownIdentity, work = Dispatchers.Unconfined)
        o.signupStart(email, true)
        val t = assertIs<SignupVerify.Ticket>(o.signupVerify(email, "482915"))
        assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(t),
            RegistrationForm(email, "Alice", password.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android")))
        keeper.lock()
        return Env(server, transport, keeper, state, o)
    }

    @Test fun aSignInOnTheKeptSessionsOwnRowNamesItsTokenAndTheServerEndsItWithNothingElseSent() = runBlocking<Unit> {
        val e = registered()
        val kept = e.keptRefresh()
        val sent = e.transport.sent.size
        assertIs<SignIn.SignedIn>(e.onboarding.signIn(email, password.toCharArray()))
        assertEquals(listOf<String?>(kept), e.server.namedAtSignIn.takeLast(1), "the login names the kept session by its refresh token")
        assertEquals(setOf(e.keptRefresh()), e.server.live.keys.toSet(), "the server ended the named session; only the new one is live")
        assertTrue(kept != e.keptRefresh())
        assertEquals(emptyList(), e.ends(sent).map { it.route }, "no end-session and no sign-out from the device")
    }

    /** A sign-in whose two-step code is asked for names the kept session in the login that is finally answered. */
    @Test fun aSignInWithATwoStepCodeNamesTheKeptSessionInTheLoginThatSucceeds() = runBlocking<Unit> {
        val e = registered()
        e.server.account(email).totp = "123456"
        val kept = e.keptRefresh()
        val sent = e.transport.sent.size
        val step = assertIs<SignIn.TotpRequired>(e.onboarding.signIn(email, password.toCharArray()))
        assertIs<SignIn.SignedIn>(e.onboarding.signInCode(step, "123456"))
        assertEquals(listOf<String?>(kept), e.server.namedAtSignIn.takeLast(1))
        assertEquals(setOf(e.keptRefresh()), e.server.live.keys.toSet())
        assertEquals(emptyList(), e.ends(sent).map { it.route })
    }

    /**
     * The login is made on another row (this device's record of its row for the address is gone, so the server makes a
     * new one): it names nothing, and the device ends the kept session itself, by its own token, as before.
     */
    @Test fun aSignInOnAnotherRowNamesNothingAndTheDeviceEndsTheKeptSessionByItsOwnToken() = runBlocking<Unit> {
        val e = registered()
        val kept = e.keptRefresh()
        KnownDevices(e.state, plain).forget(e.server.origin, email)
        val sent = e.transport.sent.size
        assertIs<SignIn.SignedIn>(e.onboarding.signIn(email, password.toCharArray()))
        assertEquals(listOf<String?>(null), e.server.namedAtSignIn.takeLast(1), "nothing is named for a session on another row")
        assertEquals(listOf(WireRoute.END_SESSION), e.ends(sent).map { it.route }, "the kept session, ended by the device by its own token")
        assertTrue(kept !in e.server.live.keys)
        assertEquals(1, e.server.live.size)
    }

    /** A device that keeps no session names none. */
    @Test fun aDeviceThatKeepsNoSessionNamesNone() = runBlocking<Unit> {
        val e = registered()
        val fresh = MemoryDeviceState()
        val trust = e.server.pinnedTrust(fresh)
        val keeper = SessionKeeper(e.transport, MemoryDeviceState(), fresh, trust, plain)
        val o = WireOnboarding(e.server.origin, keeper.clientFor(e.server.origin), trust, KnownDevices(fresh, plain), keeper, plain, fresh,
            "android", "Tablet", { e.server.now }, knownIdentity = keeper::knownIdentity, work = Dispatchers.Unconfined)
        assertIs<SignIn.SignedIn>(o.signIn(email, password.toCharArray()))
        assertEquals(listOf<String?>(null), e.server.namedAtSignIn.takeLast(1))
    }

    /**
     * What the keeper names, case by case: only the same address at the same origin on the kept session's own row while
     * that session holds its tokens. Another address, another origin, another row, and no row: none.
     */
    @Test fun theKeeperNamesOnlyTheSameAccountsSessionOnItsOwnRow() = runBlocking<Unit> {
        val e = registered()
        val origin = e.server.origin
        val row = assertNotNull(e.keeper.session).deviceId
        val kept = e.keptRefresh()
        assertEquals(kept, e.keeper.signInReplaces(origin, email, row))
        assertNull(e.keeper.signInReplaces(origin, "bob@example.com", row))
        assertNull(e.keeper.signInReplaces("https://other.example", email, row))
        assertNull(e.keeper.signInReplaces(origin, email, "00000000-0000-4000-8000-000000000001"))
        assertNull(e.keeper.signInReplaces(origin, email, null))
    }
}
