package io.silencelen.andvari.core.client.net

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.account.ReauthKey
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KeptSetup
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
import io.silencelen.andvari.core.client.onboard.SetupOffers
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.client.pin.GateDecision
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.client.pin.GateInput
import io.silencelen.andvari.core.client.pin.GatePin
import io.silencelen.andvari.core.client.pin.GatePurpose
import io.silencelen.andvari.core.client.pin.GateSession
import io.silencelen.andvari.core.client.pin.PasswordGate
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.client.session.KeptPhase
import io.silencelen.andvari.core.client.session.SessionKeeper
import io.silencelen.andvari.core.client.state.AccountStateRead
import io.silencelen.andvari.core.client.state.StoredAccountState
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Design §4.4 "No credential goes to an origin without a pin in force".
 * A session kept at an origin whose pin record is gone (a move that stopped half-way, a lost record) sends nothing:
 * no sync, no refresh, no logout, no re-authentication's prelogin, no account-state read. A request with no
 * credential (the card chain, what a first pin needs) still goes to an origin with no pin.
 */
class NoPinNoCredentialTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    private class Env(val server: FakeInstance, val transport: BearerTransport, val state: MemoryDeviceState, val keeper: SessionKeeper, val onboarding: WireOnboarding)

    private suspend fun signedUp(): Env {
        val server = FakeInstance(crypto)
        val state = MemoryDeviceState()
        val transport = BearerTransport(mapOf(server.origin to server))
        val trust = server.pinnedTrust(state)
        val keeper = SessionKeeper(transport, MemoryDeviceState(), state, trust, crypto)
        val o = WireOnboarding(server.origin, keeper.clientFor(server.origin), trust, KnownDevices(state, crypto), keeper, crypto, state, "android", "Pixel",
            { server.now }, knownIdentity = keeper::knownIdentity, work = Dispatchers.Unconfined)
        o.signupStart("alice@example.com", true)
        val t = assertIs<SignupVerify.Ticket>(o.signupVerify("alice@example.com", "482915"))
        val form = RegistrationForm("alice@example.com", "Alice", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android")
        assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(t), form))
        return Env(server, transport, state, keeper, o)
    }

    @Test fun aSessionKeptAtAnOriginWithNoPinRecordSendsNothing() = runBlocking<Unit> {
        val e = signedUp()
        val origin = e.server.origin
        val client = e.keeper.clientFor(origin)
        // In force: the session's routes go.
        assertTrue(e.keeper.mayDial(origin))
        assertIs<WireResult.Ok<String>>(client.call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it })
        val reauth = assertNotNull(e.keeper.reauth())

        // The pin record goes (a move stopped between its writes, a record lost); the session stays on the device.
        PinStore(e.state).remove(origin)
        assertNotNull(e.keeper.session)
        e.transport.expired += "at-${e.keeper.session!!.deviceId}"
        val sent = e.transport.sent.size
        val rotations = e.transport.rotations

        assertFalse(e.keeper.mayDial(origin), "a WebSocket asks the same guard")
        assertTrue(client.stopped)
        // Sync, and the refresh a 401 would start.
        assertTrue(client.call(WireRoute.SYNC, authenticated = true) { it }.originStopped, "sync")
        assertTrue(client.call(WireRoute.REFRESH, bodyJson = """{"refreshToken":"rt"}""", authenticated = false) { it }.originStopped, "refresh by route")
        // Ending one session carries the refresh token: credentialed by its route (row 93), and the call never throws.
        assertTrue(client.call(WireRoute.END_SESSION, bodyJson = """{"refreshToken":"rt"}""", authenticated = false) { it }.originStopped, "end-session by route")
        client.endSession("rt")
        // A re-authentication: the password rule refuses, and its prelogin is stopped at the dialer too.
        assertEquals(ReauthKey.Refused, reauth.currentAuthKey(strong.toCharArray()))
        assertTrue(client.call(WireRoute.PRELOGIN, bodyJson = """{"email":"alice@example.com"}""", authenticated = false) { it }.originStopped, "prelogin")
        // The account-state read.
        val account = StoredAccountState(e.keeper.session!!.userId, ByteArray(32) { 3 }, client, crypto, e.state)
        assertEquals(AccountStateRead.Stopped(ORIGIN_STOPPED), account.read())
        // The logout: the session ends on this device only.
        e.keeper.signOut()
        assertEquals(KeptPhase.NONE, e.keeper.phase.value)

        assertEquals(sent, e.transport.sent.size, "nothing was dialed: ${e.transport.sent.drop(sent).map { it.route }}")
        assertEquals(rotations, e.transport.rotations, "no refresh was dialed")
        assertTrue(e.transport.bearersFor(WireRoute.LOGOUT).isEmpty(), "no logout was sent")
    }

    @Test fun aRequestWithNoCredentialStillGoesToAnOriginWithNoPin() = runBlocking<Unit> {
        val origin = "https://new.example"
        val transport = BearerTransport(emptyMap())
        val state = MemoryDeviceState()
        val guard = OriginGuard(PinStore(state))
        val c = guard.guard(transport.open(origin, null))
        assertTrue(guard.mayFetchPublic(origin))
        assertFalse(guard.mayDial(origin))
        for (route in listOf(WireRoute.INSTANCE, WireRoute.CLIENT_POLICY, WireRoute.LINK_FETCH, WireRoute.RECOVERY_PUBKEY)) {
            assertFalse(c.call(route, mapOf("linkId" to "l1"), decode = { it }).originStopped, "$route")
        }
        assertEquals(listOf(WireRoute.INSTANCE, WireRoute.CLIENT_POLICY, WireRoute.LINK_FETCH, WireRoute.RECOVERY_PUBKEY), transport.sent.map { it.route })
        // The same route with a bearer asked for carries a credential.
        assertTrue(c.call(WireRoute.INSTANCE, authenticated = true, decode = { it }).originStopped)
        // Every credentialed route is stopped, whatever flag the caller passes.
        for (route in WireRoute.entries.filter { !it.credentialFree }) {
            for (auth in listOf(false, true)) {
                assertTrue(c.call(route, mapOf("linkId" to "l1"), authenticated = auth, decode = { it }).originStopped, "$route auth=$auth")
                assertTrue(c.callBytes(route, mapOf("attachmentId" to "a1"), null, byteArrayOf(1), authenticated = auth, decode = { it }).originStopped, "$route bytes")
                assertTrue(c.fetchBytes(route, mapOf("attachmentId" to "a1"), null, authenticated = auth).originStopped, "$route fetch")
            }
        }
        assertEquals(4, transport.sent.size)
        // The guarded token source reads no bearer and refreshes nothing for that origin.
        var reads = 0
        val tokens = guard.guard(origin, object : TokenSource {
            override fun accessToken(): String { reads++; return "t" }
            override suspend fun refresh(staleAccessToken: String): Boolean { reads++; return true }
        })
        assertEquals(null, tokens.accessToken())
        assertFalse(tokens.refresh("t"))
        assertEquals(0, reads)
    }

    @Test fun aSetupThisDeviceOpenedMayRegisterBeforeAnyPinExists() = runBlocking<Unit> {
        val origin = "https://setup.example"
        val transport = BearerTransport(emptyMap())
        val state = MemoryDeviceState()
        val guard = OriginGuard(PinStore(state))
        val c = guard.guard(transport.open(origin, null))
        assertTrue(c.call(WireRoute.REGISTER, bodyJson = "{}", decode = { it }).originStopped)
        SetupOffers(state).put(KeptSetup(origin, "0b6f3c2e-4d5a-4b7c-8d9e-0f1a2b3c4d5e", "Home", "private", "none"))
        assertTrue(guard.mayDial(origin))
        assertFalse(c.call(WireRoute.REGISTER, bodyJson = "{}", decode = { it }).originStopped)
        assertFalse(c.call(WireRoute.INSTANCE_CARD_PUT, bodyJson = "{}", decode = { it }).originStopped)
        // A setup offer for another origin opens nothing here.
        val other = guard.guard(transport.open("https://other.example", null))
        assertTrue(other.call(WireRoute.REGISTER, bodyJson = "{}", decode = { it }).originStopped)
        // An unreadable offer counts as none.
        state.set("ovh.setup|$origin", "{not json")
        assertFalse(guard.mayDial(origin))
    }

    @Test fun thePasswordRulesSessionCaseNeedsAPinInForce() {
        val origin = "https://h.example"
        val session = GateSession(origin, "alice@example.com")
        fun decide(purpose: GatePurpose, pins: List<GatePin>) = PasswordGate.decide(
            GateInput(purpose, if (purpose == GatePurpose.REAUTH) null else GateEntry.SERVER_CHOICE, null, origin, "alice@example.com", pins, session),
        )
        val inForce = listOf(GatePin(origin, PinRoot.TRUST_GATE))
        assertEquals(GateDecision.PROCEED, decide(GatePurpose.REAUTH, inForce))
        assertEquals(GateDecision.PROCEED, decide(GatePurpose.SIGN_IN, inForce))
        // No pin record at the session's origin: nothing derived from the password goes there.
        assertEquals(GateDecision.REFUSE_ENTRY, decide(GatePurpose.REAUTH, emptyList()))
        assertEquals(GateDecision.TRUST_GATE, decide(GatePurpose.SIGN_IN, emptyList()))
        // A pin at another origin is not one here.
        assertEquals(GateDecision.REFUSE_ENTRY, decide(GatePurpose.REAUTH, listOf(GatePin("https://other.example", PinRoot.TRUST_GATE))))
    }
}
