package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.client.pin.CardTrust
import io.silencelen.andvari.core.client.pin.ServerForgotten
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.ClientPolicy
import io.silencelen.andvari.core.model.wire.SignupPolicy
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The session keeper's records of a server: a refresh that never left the device costs nothing; account keys served in
 * a form this device does not take are refused with the keeper's own reason; "Forget this server" removes the keeper's
 * records of which account an address is and of each account's identity key there.
 */
class KeeperServerRecordsTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    private class Env(
        val server: FakeInstance, val transport: BearerTransport, val state: MemoryDeviceState, val secure: MemoryDeviceState,
        val trust: CardTrust, val keeper: SessionKeeper, val onboarding: WireOnboarding,
    )

    private suspend fun env(): Env {
        val server = FakeInstance(crypto)
        val state = MemoryDeviceState()
        val secure = MemoryDeviceState()
        val transport = BearerTransport(mapOf(server.origin to server))
        transport.clock = { server.now }
        val trust = server.pinnedTrust(state)
        val keeper = SessionKeeper(transport, secure, state, trust, crypto, clock = { server.now })
        val o = WireOnboarding(server.origin, keeper.clientFor(server.origin), trust, KnownDevices(state, crypto), keeper, crypto, state, "android", "Pixel",
            { server.now }, knownIdentity = keeper::knownIdentity, work = Dispatchers.Unconfined)
        return Env(server, transport, state, secure, trust, keeper, o)
    }

    private suspend fun register(e: Env): Registration.Registered {
        e.onboarding.signupStart("alice@example.com", true)
        val t = assertIs<SignupVerify.Ticket>(e.onboarding.signupVerify("alice@example.com", "482915"))
        val form = RegistrationForm("alice@example.com", "Alice", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android")
        return assertIs<Registration.Registered>(e.onboarding.register(RegistrationAuth.Ticket(t), form))
    }

    /**
     * A refresh that never left the device costs nothing: where the transport says that nothing of the request left (no
     * connection was made), the record that a refresh is out is put back as it was, as it is when the device's own guard
     * stops the request; a later refresh, after the minute too, then goes as an ordinary one and the session lives. Where
     * the transport cannot say so (the secure connection could not be set up, a proxy refused, the network could not be
     * reached), the request may have left: the record stays, and after the minute no try is left.
     */
    @Test fun aRefreshThatNeverLeftTheDeviceCostsNothing() = runBlocking<Unit> {
        for (neverLeft in listOf(true, false)) {
            val e = env()
            register(e)
            val dev = assertNotNull(e.keeper.session).deviceId
            e.transport.refreshAnswer = {
                e.transport.refreshAnswer = null
                WireResult.NoAnswer(NoAnswerKind.TRANSPORT, neverLeft)
            }
            e.transport.expired += "at-$dev"
            e.keeper.clientFor(e.server.origin).call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
            assertEquals(!neverLeft, assertNotNull(e.secure.get(SessionKeeper.KEY)).contains("refreshLostAt"), "never left: $neverLeft: the record")
            e.server.now += 10 * 60_000
            val last = e.keeper.clientFor(e.server.origin).call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
            if (neverLeft) {
                assertIs<WireResult.Ok<String>>(last, "the later refresh went as an ordinary one")
                assertFalse(assertNotNull(e.keeper.session).endedByServer)
                assertEquals(listOf("rt-$dev", "rt-$dev"), e.transport.refreshTokensReceived)
            } else {
                assertTrue(assertNotNull(e.keeper.session).endedByServer, "may have left: no try is left after the minute")
                assertEquals(SessionEndReason.SESSION_NOT_CONFIRMED, e.keeper.lastEnd)
            }
        }
    }

    /**
     * Account keys served in a form this device does not take (here a wrapped key with padding where the canonical text
     * has none) are refused with the keeper's own reason, at an unlock that asks the server for the keys: never the
     * identity fault's reason, nor the flows' code for an answer that is not the session it must be. Nothing opens.
     */
    @Test fun keysServedInAFormThisDeviceDoesNotTakeAreRefusedWithTheKeepersOwnReason() = runBlocking<Unit> {
        val e = env()
        register(e)
        val origin = e.server.origin
        KeptPolicies(e.state).record(origin, ClientPolicy(emptyMap(), io.silencelen.andvari.core.crypto.KdfParams.DEFAULT,
            300, 30, false, 3600, 30, 1, 1, e.server.now, SignupPolicy("open", false, true, 0), false), e.server.now)
        e.keeper.policyRecorded(origin)
        e.keeper.lock()
        val account = e.server.accounts.values.single()
        account.wrappedUvk = account.wrappedUvk.trimEnd('=') + "\n"
        assertEquals(KeptUnlock.IdentityFault(Establishing.SERVED_KEY_FORM), e.keeper.unlockAsking(strong.toCharArray()))
        assertEquals(KeptPhase.LOCKED, e.keeper.phase.value, "nothing opened")
    }

    /**
     * "Forget this server" ([CardTrust.forgetServer]) removes the keeper's records of that server, of every account there:
     * which account each address there is, and each such account's identity key, unless an address at ANOTHER server still
     * names that account. Before, both stayed. Records of another server stay.
     */
    @Test fun forgettingTheServerRemovesItsAddressRecordsAndItsAccountsIdentityKeys() = runBlocking<Unit> {
        val e = env()
        val reg = register(e)
        val origin = e.server.origin
        val other = "https://other.example"
        e.keeper.signOut()
        fun address(at: String, email: String) = SessionKeeper.EMAIL_BINDING_PREFIX + at + "|" + email
        assertNotNull(e.state.get(address(origin, "alice@example.com")), "a sign-out keeps the address's record")
        assertNotNull(e.state.get("ovh.identity|${reg.userId}"), "and the identity record")
        // bob is known here by his address's record only; carol by one here and one at another server; dave only there.
        val bob = "44444444-4444-4444-8444-444444444444"
        val carol = "55555555-5555-4555-8555-555555555555"
        val dave = "66666666-6666-4666-8666-666666666666"
        e.state.set(address(origin, "bob@example.com"), "$bob|key")
        e.state.set(address(origin, "carol@example.com"), "$carol|key")
        e.state.set(address(other, "carol@example.com"), "$carol|key")
        e.state.set(address(other, "dave@example.com"), "$dave|key")
        for (u in listOf(bob, carol, dave)) e.state.set("ovh.identity|$u", "key")
        assertEquals(ServerForgotten.Done, e.trust.forgetServer(origin))
        assertEquals(emptyList(), e.state.keys().filter { it.startsWith(SessionKeeper.EMAIL_BINDING_PREFIX + origin + "|") }, "the addresses' records")
        assertNull(e.state.get("ovh.identity|${reg.userId}"), "the signed-out account's identity record")
        assertNull(e.state.get("ovh.identity|$bob"), "an account known by its address only")
        assertEquals("key", e.state.get("ovh.identity|$carol"), "named by an address at another server: it stays")
        assertEquals("key", e.state.get("ovh.identity|$dave"), "another server's account")
        assertEquals("$carol|key", e.state.get(address(other, "carol@example.com")))
        assertEquals("$dave|key", e.state.get(address(other, "dave@example.com")))
    }

    /**
     * The check's p1, at a deletion: one account id known at two addresses, and a deletion confirmed by the first server.
     * The keeper forgets the session and the identity record, but not while something at another server ties that
     * account (here the other address's record naming it): one server's word does not undo what another serves. With
     * nothing at the other server, the identity record goes as before.
     */
    @Test fun aDeletionConfirmedByOneServerKeepsTheIdentityRecordOfAnAccountAnotherServerServes() = runBlocking<Unit> {
        for (twice in listOf(true, false)) {
            val e = env()
            val reg = register(e)
            val atOther = SessionKeeper.EMAIL_BINDING_PREFIX + "https://other.example|alice@example.com"
            if (twice) e.state.set(atOther, "${reg.userId}|key")
            val key = assertNotNull(e.state.get("ovh.identity|${reg.userId}"))
            e.keeper.forget(forgetIdentity = true)
            if (twice) {
                assertEquals(key, e.state.get("ovh.identity|${reg.userId}"), "another server serves that account: it stays")
                assertEquals("${reg.userId}|key", e.state.get(atOther))
            } else {
                assertNull(e.state.get("ovh.identity|${reg.userId}"), "nothing else serves it: it goes")
            }
        }
    }
}
