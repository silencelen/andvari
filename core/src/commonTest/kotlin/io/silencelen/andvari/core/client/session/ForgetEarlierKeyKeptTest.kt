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
import io.silencelen.andvari.core.client.pin.CardTrust
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * The forgetting of an earlier account keeps that account's id and identity key (decided on 2026-11-19), and nothing else
 * of it, as a record of the server's: it moves with a followed move of the server's address and goes when the server is
 * forgotten. Taken again under that key, the account's own identity record holds the key and the kept record goes, so that
 * a deletion this device runs later leaves nothing of the account, as before.
 */
class ForgetEarlierKeyKeptTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val alice = "alice@example.com"

    private class Env(val state: MemoryDeviceState, val trust: CardTrust, val keeper: SessionKeeper, val onboarding: WireOnboarding)

    private suspend fun env(server: FakeInstance): Env {
        val state = MemoryDeviceState()
        val trust = server.pinnedTrust(state)
        val keeper = SessionKeeper(BearerTransport(mapOf(server.origin to server)), MemoryDeviceState(), state, trust, crypto)
        val o = WireOnboarding(server.origin, keeper.clientFor(server.origin), trust, KnownDevices(state, crypto), keeper, crypto, state, "android", "Pixel",
            { server.now }, knownIdentity = keeper::knownIdentity, work = Dispatchers.Unconfined)
        return Env(state, trust, keeper, o)
    }

    private suspend fun register(o: WireOnboarding, email: String): Registration.Registered {
        o.signupStart(email, true)
        val t = assertIs<SignupVerify.Ticket>(o.signupVerify(email, "482915"))
        return assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(t),
            RegistrationForm(email, "Someone", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android")))
    }

    /** The server's record of the forgotten account, as it was before the account was deleted there. */
    private val earlier = HashMap<FakeInstance, FakeInstance.Account?>()

    private fun Env.binding(origin: String) = state.get("${SessionKeeper.EMAIL_BINDING_PREFIX}$origin|$alice")

    /**
     * The keys of the keeper's identity records (`ovh.identity…`) that name [userId], in their key or their value. The
     * account's other records are the layer above's to delete (`EngineForgetEarlierFixTest` holds it to that).
     */
    private fun Env.naming(userId: String): List<String> =
        state.keys()!!.filter { it.startsWith("ovh.identity") && (it.contains(userId) || state.get(it)?.contains(userId) == true) }.sorted()

    /**
     * [alice]'s account U taken on a fresh device and signed out; the account deleted at the server and made again (another
     * id), and U forgotten here. Answers U and the key this device knew for it.
     */
    private suspend fun forgotten(server: FakeInstance, e: Env): Pair<String, String> {
        val u = register(e.onboarding, alice).userId
        val key = assertNotNull(e.binding(server.origin)).substringAfter('|')
        e.keeper.signOut()
        earlier[server] = server.accounts.remove(alice)
        register(env(server).onboarding, alice)
        assertIs<SignIn.IdentityFault>(e.onboarding.signIn(alice, strong.toCharArray()))
        assertEquals(ForgetEarlier.Forgotten(u, copyRemoved = false), e.keeper.forgetEarlierAccount(server.origin, alice))
        return u to key
    }

    /** Before: nothing of the account was kept, so a server could serve it again under any key. */
    @Test fun theKeptKeyIsTheServersRecordItMovesWithAFollowedMoveAndGoesWithTheServer() = runBlocking<Unit> {
        for (then in listOf("server forgotten", "server moved")) {
            val server = FakeInstance(crypto)
            val e = env(server)
            val (u, key) = forgotten(server, e)
            val kept = "ovh.identity-earlier|${server.origin}|$u"
            assertEquals(key, e.state.get(kept), "$then: the earlier account's key is kept, under the server")
            assertEquals(listOf(kept), e.naming(u), "$then: nothing else of the earlier account")
            assertNull(e.binding(server.origin))
            assertNull(e.keeper.knownIdentity(u))
            if (then == "server forgotten") {
                e.trust.forgetServer(server.origin)
                assertEquals(emptyList(), e.naming(u), "the server's forgetting takes it")
            } else {
                val to = "https://moved.example"
                val store = PinStore(e.state)
                store.carry(assertNotNull(store.planMove(server.origin, to), "the move can be carried"))
                assertNull(e.state.get(kept))
                assertEquals(key, e.state.get("ovh.identity-earlier|$to|$u"), "carried with the server's move")
            }
        }
    }

    /**
     * Served again under its own key (it was never deleted after all), the forgotten account is taken as itself and the kept
     * record goes (its identity record holds the key again); a deletion of it that this device runs and the server confirms
     * then leaves nothing of it, the record of its key neither, as before.
     */
    @Test fun theForgottenAccountTakenUnderItsOwnKeyAndThenDeletedLeavesNothing() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val e = env(server)
        val (u, key) = forgotten(server, e)
        val kept = "ovh.identity-earlier|${server.origin}|$u"
        assertEquals(key, e.state.get(kept))
        server.accounts[alice] = assertNotNull(earlier[server])
        assertIs<SignIn.SignedIn>(e.onboarding.signIn(alice, strong.toCharArray()))
        assertEquals(u, assertNotNull(e.keeper.session).userId)
        assertNull(e.state.get(kept), "the identity record holds the key again")
        assertEquals(key, assertNotNull(e.binding(server.origin)).substringAfter('|'))
        // The deletion's removal on this device (the server confirmed it).
        e.keeper.forget(forgetIdentity = true)
        assertEquals(emptyList(), e.naming(u))
    }
}
