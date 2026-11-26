package io.silencelen.andvari.core.client.onboard

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.account.Reauth
import io.silencelen.andvari.core.client.account.ReauthSession
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.link.RecipientStep
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.pin.CardTrust
import io.silencelen.andvari.core.client.pin.GatePin
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.InstanceSetup
import io.silencelen.andvari.core.model.wire.PreloginRequest
import io.silencelen.andvari.core.model.wire.PreloginResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.InstanceCard
import io.silencelen.andvari.core.trust.SignedFrame
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** "Finish setting up this server" (design §6.7 Resume, §9.5): from the kept offer, or from the served setup block. */
class SetupResumeTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    private class Env(val server: FakeInstance, val state: MemoryDeviceState, val trust: CardTrust, val session: EstablishedSession, val resume: SetupResume)

    /** The operator registered through the setup link, and the card 0 upload had no answer. */
    private suspend fun interrupted(): Env {
        val server = FakeInstance(crypto, withCard = false)
        val state = MemoryDeviceState()
        val trust = server.trust(state)
        val setup = LinkRegistration.Setup(server.origin, server.instanceId, "Family", "private", "none", "bGlua2lkbGlua2lkbGlua2", Bytes.toB64(ByteArray(32) { 6 }))
        // What the link engine keeps when it resolves a setup link (design §6.7 step 2).
        SetupOffers(state).put(KeptSetup(server.origin, server.instanceId, "Family", "private", "none"))
        val links = object : LinkRegistrations {
            override fun resolve(step: RecipientStep.Confirm) = setup
            override suspend fun registered(registration: LinkRegistration, session: EstablishedSession) {}
        }
        val sessions = ArrayList<EstablishedSession>()
        val o = WireOnboarding(server.origin, server, trust, KnownDevices(state, crypto), SessionSink { sessions += it }, crypto, state, "desktop", "Laptop",
            { server.now }, links = links, work = Dispatchers.Unconfined)
        server.override[WireRoute.INSTANCE_CARD_PUT] = WireResult.NoAnswer(NoAnswerKind.TIMEOUT)
        val step = RecipientStep.Confirm(io.silencelen.andvari.core.client.link.OfferView("setup", server.origin, "Family", null, null, 0, null), true, false,
            io.silencelen.andvari.core.client.link.RecipientToken("t"))
        val reg = assertIs<Registration.Registered>(o.register(RegistrationAuth.SetupLink(step),
            RegistrationForm("op@example.org", "Op", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Laptop", "desktop")))
        assertTrue(reg.cardPending)
        server.override.remove(WireRoute.INSTANCE_CARD_PUT)
        val session = sessions.single()
        val reauth = Reauth(object : ReauthSession {
            override val origin = server.origin
            override val emailNorm = "op@example.org"
            override suspend fun deriveCurrentAuthKey(password: CharArray): String? {
                val p = (server.call(WireRoute.PRELOGIN, bodyJson = WireJson.json.encodeToString(PreloginRequest.serializer(), PreloginRequest(emailNorm)),
                    decode = { WireJson.json.decodeFromString(PreloginResponse.serializer(), it) }) as WireResult.Ok).value
                val k = PasswordKeys.derive(crypto, password.copyOf(), Bytes.fromB64(p.kdfSalt), p.kdfParams, served = true) ?: return null
                return k.authKeyB64.also { k.wipe() }
            }
        }) { listOf(GatePin(server.origin, PinRoot.TRUST_GATE)) }
        return Env(server, state, trust, session, SetupResume(session, server, crypto, state, trust, reauth, { server.now }))
    }

    @Test fun finishFromTheKeptOfferSignsUploadsAndPinsCardZero() = runBlocking<Unit> {
        val e = interrupted()
        assertTrue(e.server.cards.isEmpty())
        assertEquals(SetupDue.Due("Family", e.server.origin, "private", fromKeptOffer = true), e.resume.due())
        // This session derives its proof without a wrap of its own: the server's refusal is its own result.
        assertEquals(Reauthed.Refused(Reauthed.PROOF_REFUSED), e.resume.finish("not the password 123".toCharArray()))
        val pw = strong.toCharArray()
        val hash = assertIs<Reauthed.Done<String>>(e.resume.finish(pw)).value
        assertTrue(pw.all { it == '\u0000' })
        assertEquals(SignedFrame.hash(crypto, e.server.cards.single()), hash)
        val card = InstanceCard.verifyChain(crypto, e.server.cards).chain.cards.single().fields
        assertEquals(e.session.userId, card.operator)
        assertEquals("Family", card.name)
        assertEquals(PinRoot.SETUP, e.trust.pinFor(e.server.origin)!!.root)
        assertNull(SetupOffers(e.state).get(e.server.origin), "the kept offer has done its job")
        assertEquals(SetupDue.No, e.resume.due())
        assertEquals(Reauthed.Refused("setup_done"), e.resume.finish(strong.toCharArray()))
    }

    /**
     * Spec 01 §7: the password is proven on this device before the act sends anything, the read of the served instance
     * included. A wrong password sends nothing at all. Before, the instance was read first (`GET /instance`).
     */
    @Test fun aWrongPasswordSendsNothingAtAllNotEvenTheInstancesRead() = runBlocking<Unit> {
        val e = interrupted()
        val local = Reauth(object : ReauthSession {
            override val origin = e.server.origin
            override val emailNorm = "op@example.org"
            override suspend fun deriveCurrentAuthKey(password: CharArray): String? = error("proven on this device")
            override suspend fun proveCurrentAuthKey(password: CharArray) = io.silencelen.andvari.core.client.account.ReauthKey.WrongPassword
        }) { listOf(GatePin(e.server.origin, PinRoot.TRUST_GATE)) }
        val resume = SetupResume(e.session, e.server, crypto, e.state, e.trust, local, { e.server.now })
        val sent = e.server.calls.size
        val pw = "not the password 123".toCharArray()
        assertEquals(Reauthed.WrongPassword, resume.finish(pw))
        assertTrue(pw.all { it == '\u0000' }, "wiped")
        assertEquals(sent, e.server.calls.size, "nothing was sent")
        assertTrue(e.server.cards.isEmpty())
    }

    @Test fun aDeviceThatNeverSawTheOfferUsesTheServedSetupBlockForThisOriginOnly() = runBlocking<Unit> {
        val e = interrupted()
        SetupOffers(e.state).remove(e.server.origin)
        assertEquals(SetupDue.No, e.resume.due(), "no kept offer and no setup block: nothing to sign from")
        e.server.setupBlock = InstanceSetup(e.server.instanceId, "https://elsewhere.example", TrustGrammar.encodeName("Family")!!, "private", "none")
        assertEquals(SetupDue.No, e.resume.due(), "a block naming another origin is refused")
        e.server.setupBlock = InstanceSetup(e.server.instanceId, e.server.origin, TrustGrammar.encodeName("Family")!!, "public", "a".repeat(64))
        assertEquals(SetupDue.No, e.resume.due(), "variant R: no recovery key on a public instance")
        e.server.setupBlock = InstanceSetup(e.server.instanceId, e.server.origin, TrustGrammar.encodeName("Family")!!, "private", "none")
        assertEquals(SetupDue.Due("Family", e.server.origin, "private", fromKeptOffer = false), e.resume.due())
        assertIs<Reauthed.Done<String>>(e.resume.finish(strong.toCharArray()))
        assertEquals(PinRoot.SETUP, e.trust.pinFor(e.server.origin)!!.root)
    }
}
