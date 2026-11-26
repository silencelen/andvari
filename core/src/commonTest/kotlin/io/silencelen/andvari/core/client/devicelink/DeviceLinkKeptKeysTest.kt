package io.silencelen.andvari.core.client.devicelink

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.items.copyOut
import io.silencelen.andvari.core.client.link.LinkAccount
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.AccountOpen
import io.silencelen.andvari.core.client.onboard.AccountOpenResult
import io.silencelen.andvari.core.client.onboard.EstablishedSession
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
import io.silencelen.andvari.core.client.onboard.SessionHow
import io.silencelen.andvari.core.client.onboard.SessionSink
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.client.pin.CardTrust
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.client.session.KeptPhase
import io.silencelen.andvari.core.client.session.KeptUnlock
import io.silencelen.andvari.core.client.session.SessionKeeper
import io.silencelen.andvari.core.client.state.StoredAccountState
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AccountKeys
import io.silencelen.andvari.core.model.wire.PersonalWrap
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.AccountGenesis
import io.silencelen.andvari.core.trust.GenesisFields
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A device link's pickup on a device that keeps the account: the served account-key texts are taken only in their
 * canonical form (design §2.2), the account the pickup opens is held to this device's own record of its identity key
 * (design §2.4, as a sign-in's is), and the key that proves the typed password (the wrap key a kept wrap opened under) is
 * wiped on every way out of the pickup's last step, a cancellation while it reads the server's chain included.
 */
class DeviceLinkKeptKeysTest {
    private val crypto = createCryptoProvider()
    private val password = "correct horse Battery 9 staple"
    private val email = "alice@example.com"

    private class Sink : SessionSink {
        val sessions = ArrayList<EstablishedSession>()
        override suspend fun established(session: EstablishedSession) { sessions += session }
    }

    private inner class World {
        val instance = FakeInstance(crypto)
        val server = DeviceLinkServer(instance)
        val eState = MemoryDeviceState()
        lateinit var eTrust: CardTrust
        lateinit var eSink: Sink
        lateinit var eSession: EstablishedSession
        lateinit var e: WireDeviceLinks
        val nState = MemoryDeviceState()
        lateinit var nTrust: CardTrust
        lateinit var transport: BearerTransport
        lateinit var keeper: SessionKeeper
        val discarded = ArrayList<String>()
        val account get() = instance.accounts.values.single()

        /** alice registered on E; this device (N) signed in to her account once and keeps it, locked. */
        suspend fun setUp(): World {
            eTrust = instance.pinnedTrust(eState)
            eSink = Sink()
            val onboarding = WireOnboarding(instance.origin, server.client(null), eTrust, KnownDevices(eState, crypto), eSink, crypto, eState, "desktop", "Laptop",
                { instance.now }, work = Dispatchers.Unconfined)
            onboarding.signupStart(email, true)
            val ticket = assertIs<SignupVerify.Ticket>(onboarding.signupVerify(email, "482915"))
            val reg = assertIs<Registration.Registered>(onboarding.register(RegistrationAuth.Ticket(ticket),
                RegistrationForm(email, "Alice", password.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Laptop", "desktop")))
            eSession = eSink.sessions.single()
            e = existing(eSession)
            nTrust = instance.pinnedTrust(nState)
            transport = BearerTransport(mapOf(instance.origin to server.client(null)))
            keeper = SessionKeeper(transport, MemoryDeviceState(), nState, nTrust, crypto)
            val nOnboarding = WireOnboarding(instance.origin, keeper.clientFor(instance.origin), nTrust, KnownDevices(nState, crypto), keeper, crypto, nState,
                "android", "Pixel 9", { instance.now }, knownIdentity = keeper::knownIdentity, work = Dispatchers.Unconfined)
            assertIs<SignIn.SignedIn>(nOnboarding.signIn(email, password.toCharArray()))
            keeper.lock()
            return this
        }

        /** E's side of a link, for the account [session] opened. */
        fun existing(session: EstablishedSession): WireDeviceLinks {
            val acct = LinkAccount.of(session, "Alice", StoredAccountState(session.userId, session.account.uvk, server.client(session.userId), crypto, eState))
            return WireDeviceLinks({ server.client(session.userId, it) }, eTrust, eState, crypto, { instance.now }, { acct }, KnownDevices(eState, crypto), eSink,
                { _, _ -> }, "Laptop", "desktop")
        }

        fun keptKeys(): AccountKeys = assertNotNull(keeper.keptForSignIn(instance.origin)).own

        /** As the app engine is to bind it; [wrap] wraps each client N dials. */
        fun n(wrap: (WireClient) -> WireClient = { it }) = WireDeviceLinks({ wrap(keeper.clientFor(it)) }, nTrust, nState, crypto, { instance.now }, { null },
            KnownDevices(nState, crypto), keeper, { o, token -> keeper.discard(o, token) }, "Pixel 9", "android",
            endOne = { o, refresh -> discarded += refresh; keeper.notTaken(o, "", refresh) })

        /** Runs both sides to [eSide]'s approval; returns N's PasswordNeeded step. */
        suspend fun approved(n: WireDeviceLinks, eSide: WireDeviceLinks = e): NewStep.PasswordNeeded {
            val shown = assertIs<ExistingStep.Shown>(eSide.create())
            val claimed = assertIs<NewStep.Claimed>(n.start(shown.url, GateEntry.LINK_DEVICE_SCREEN))
            val fixed = assertIs<ExistingStep.ClaimFixed>(eSide.advance(shown))
            val code = assertIs<NewStep.ShowCode>(n.advance(claimed))
            val type = assertIs<ExistingStep.TypeDigits>(eSide.advance(fixed))
            val ok = assertIs<ExistingStep.Approvable>(eSide.typeDigits(type, code.code))
            assertIs<ExistingStep.Approved>(eSide.approve(ok))
            return assertIs<NewStep.PasswordNeeded>(n.advance(code))
        }
    }

    /** A pickup that serves the account's own seed padded: refused as the server's fault, nothing kept. Before: linked, kept padded. */
    @Test fun aPickupWhoseSeedIsNotCanonicalStopsAndKeepsNothing() = runBlocking<Unit> {
        val w = World().setUp()
        val before = w.keptKeys()
        val takes = w.keeper.takes
        val n = w.n()
        val need = w.approved(n)
        val seed = w.account.encryptedIdentitySeed
        assertTrue(seed.length % 4 != 0)
        w.account.encryptedIdentitySeed = seed + "=".repeat(4 - seed.length % 4)
        assertNull(Bytes.fromB64Canonical(w.account.encryptedIdentitySeed))
        assertEquals(NewStep.Stopped(DeviceLinkStop.IDENTITY_MISMATCH), n.pickup(need, password.toCharArray()))
        assertEquals(takes, w.keeper.takes)
        assertEquals(before, w.keptKeys())
        assertEquals(1, w.discarded.size, "exactly the pickup's session is ended at the server")
        assertEquals(KeptUnlock.Unlocked, w.keeper.unlock(password.toCharArray()))
    }

    /**
     * A removed device that kept alice's key, with the server, links this device to a seed of another identity sealed under
     * that key (its own genesis and personal vault, and a bundle made for them). This device knows alice's identity key,
     * and the address's binding is gone (as after a followed server move): the pickup's own opening refuses it, before the
     * session keeper is handed anything. Before, the pickup passed no record of the identity to the opening, and the
     * keeper took the session (the copy's seed opens under the same key) with the other identity.
     */
    @Test fun aPickupOfAnotherIdentityStopsWhereTheDeviceKnowsTheAccount() = runBlocking<Unit> {
        val w = World().setUp()
        w.nState.set("${SessionKeeper.EMAIL_BINDING_PREFIX}${w.instance.origin}|$email", null)
        val userId = w.account.userId
        val uvk = w.eSession.account.uvk.copyOut()
        val seed = crypto.randomBytes(32)
        val vk = crypto.randomBytes(32)
        val identity = crypto.boxKeypairFromSeed(seed)
        val signing = crypto.signKeypairFromSeed(seed)
        val pvid = "33333333-3333-4333-8333-333333333333"
        try {
            val idB64 = Bytes.toB64(identity.publicKey)
            w.account.encryptedIdentitySeed = Envelope.sealB64(crypto, uvk, seed, Ad.idkey(userId))
            w.account.identityPub = idB64
            w.account.genesis = Bytes.toB64(AccountGenesis.sign(crypto, signing, GenesisFields(userId, idB64, w.instance.instanceId, pvid, w.instance.now)))
            w.account.personalWrap = PersonalWrap(pvid, Envelope.sealB64(crypto, uvk, vk, Ad.vkPersonal(pvid, userId)))
        } finally {
            seed.fill(0)
            vk.fill(0)
            identity.privateKey.fill(0)
            signing.privateKey.fill(0)
        }
        val keys = w.instance.keys(w.account)
        val forged = assertIs<AccountOpenResult.Opened>(AccountOpen.open(crypto, userId, uvk, keys, w.instance.instanceId)).account
        val forgedE = w.existing(EstablishedSession(w.instance.origin, email, userId, w.eSession.deviceId, "member", false, false, true, SessionHow.REGISTERED,
            "at-forged", "rt-forged", keys, forged))
        val before = w.keptKeys()
        val takes = w.keeper.takes
        val refusals = w.keeper.refusals
        val n = w.n()
        val need = w.approved(n, forgedE)
        assertEquals(NewStep.Stopped(DeviceLinkStop.IDENTITY_MISMATCH), n.pickup(need, password.toCharArray()))
        assertEquals(refusals, w.keeper.refusals, "the keeper was never handed the session")
        assertEquals(takes, w.keeper.takes)
        assertEquals(before, w.keptKeys())
        assertEquals(KeptPhase.LOCKED, w.keeper.phase.value)
        assertEquals(1, w.discarded.size)
    }

    /**
     * The pickup's last step holds the key that proves the typed password (a kept wrap opened under it) across its read of
     * the server's chain. A cancellation there wipes it: the very array is zero afterwards. Before, it was dropped as it was.
     */
    @Test fun aCancellationWhileTheChainIsReadWipesTheProvingKey() = runBlocking<Unit> {
        val w = World().setUp()
        var armed = false
        val entered = CompletableDeferred<Unit>()
        val n = w.n { inner ->
            object : WireClient by inner {
                override suspend fun <T> call(
                    route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T,
                ): WireResult<T> {
                    if (armed && route == WireRoute.INSTANCE) {
                        entered.complete(Unit)
                        awaitCancellation()
                    }
                    return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
                }
            }
        }
        var wiped: (() -> Boolean)? = null
        n.provingKeyHeld = { wiped = it }
        val need = w.approved(n)
        val takes = w.keeper.takes
        armed = true
        val job = launch { n.pickup(need, password.toCharArray()) }
        entered.await()
        val isWiped = assertNotNull(wiped, "a kept wrap opened with the typed password: the step holds its key")
        assertFalse(isWiped(), "held while the chain is read")
        job.cancelAndJoin()
        assertTrue(isWiped(), "wiped by the cancellation")
        assertEquals(takes, w.keeper.takes)
    }
}
