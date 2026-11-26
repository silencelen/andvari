package io.silencelen.andvari.core.client.account

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.EstablishedSession
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.PasswordKeys
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
import io.silencelen.andvari.core.client.onboard.SessionSink
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.client.pin.GatePin
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.client.recovery.EscrowDecision
import io.silencelen.andvari.core.client.state.RecoveryRecord
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.PreloginRequest
import io.silencelen.andvari.core.model.wire.PreloginResponse
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.CardFields
import io.silencelen.andvari.core.trust.InstanceCard
import io.silencelen.andvari.core.trust.RecoveryRotation
import io.silencelen.andvari.core.trust.RotationFields
import io.silencelen.andvari.core.trust.SignedFrame
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A recovery copy of a form the server no longer stores (spec 03 §3.1, §3.2: `400 escrow_wrong_form`, added
 * 2026-11-16) is a refusal named by its own code at each of the three places a copy is sent: registration, turning
 * operator recovery on, and the re-seal after a signed rotation. Nothing the device keeps follows a refused copy: no
 * session at registration, the record and the device's mirror unchanged in Settings, the copy not marked as seen after a
 * refused re-seal (it is sealed again at the next look). Then, with the server taking the copy, each place goes through.
 */
class EscrowWrongFormTest {
    private val crypto = createCryptoProvider()
    private val strong = "made-up Test password 23 staple"
    private val seedA = crypto.randomBytes(32)
    private val seedB = crypto.randomBytes(32)
    private val orgA = crypto.boxKeypairFromSeed(seedA)
    private val orgB = crypto.boxKeypairFromSeed(seedB)
    private val fpA = Escrow.fingerprint(crypto, orgA.publicKey)
    private val fpB = Escrow.fingerprint(crypto, orgB.publicKey)
    private val wrongForm = WireResult.Refused(400, WireError(WireErrors.ESCROW_WRONG_FORM, "this copy is not of the form the server stores"))

    @Test fun theCodeIsTheServers() {
        assertEquals("escrow_wrong_form", WireErrors.ESCROW_WRONG_FORM)
    }

    @Test fun aCopyOfAFormTheServerNoLongerStoresIsARefusalNamedAtEachOfTheThreePlaces() = runBlocking<Unit> {
        val server = FakeInstance(crypto, recoveryFp = fpA)
        server.recoveryPub = orgA.publicKey
        val state = MemoryDeviceState()
        val trust = server.pinnedTrust(state)
        val sessions = ArrayList<EstablishedSession>()
        val o = WireOnboarding(server.origin, server, trust, KnownDevices(state, crypto), SessionSink { sessions += it }, crypto, state,
            "android", "Pixel", { server.now }, work = Dispatchers.Unconfined)
        o.signupStart("Alice@Example.com", true)
        val t = o.signupVerify("Alice@Example.com", "482915") as SignupVerify.Ticket
        val offer = assertNotNull(o.operatorRecoveryOffer())
        fun form() = RegistrationForm("Alice@Example.com", "Alice", strong.toCharArray(), true, RecoveryChoiceKind.OPERATOR, "Pixel", "android", offer, true)

        // 1. Registration with operator recovery.
        server.override[WireRoute.REGISTER] = wrongForm
        assertEquals(Registration.Refused(WireErrors.ESCROW_WRONG_FORM), o.register(RegistrationAuth.Ticket(t), form()))
        assertTrue(sessions.isEmpty(), "no session from a refused registration")
        server.override.remove(WireRoute.REGISTER)
        assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(t), form()))
        val s = sessions.single()

        val reauth = Reauth(object : ReauthSession {
            override val origin = server.origin
            override val emailNorm = "alice@example.com"
            override suspend fun deriveCurrentAuthKey(password: CharArray): String? {
                val p = (server.call(WireRoute.PRELOGIN, bodyJson = WireJson.json.encodeToString(PreloginRequest.serializer(), PreloginRequest(emailNorm)),
                    decode = { WireJson.json.decodeFromString(PreloginResponse.serializer(), it) }) as WireResult.Ok).value
                val k = PasswordKeys.derive(crypto, password.copyOf(), Bytes.fromB64(p.kdfSalt), p.kdfParams, served = true) ?: return null
                return k.authKeyB64.also { k.wipe() }
            }
        }) { listOf(GatePin(server.origin, PinRoot.TRUST_GATE)) }
        val kit = WireAccountSettings(server.origin, s.emailNorm, server.card0Hash, s.account, server, crypto, reauth, io.silencelen.andvari.core.crypto.KdfParams.DEFAULT)
        val settings = WireRecoverySettings(server.origin, s.account, server, crypto, state, trust, reauth, kit, { server.now })

        // 2. Off, then on again in Settings: the copy is refused, and the record stays off.
        assertEquals("private", assertIs<Reauthed.Done<RecoveryRecord>>(settings.setPosture(RecoveryChoiceKind.PRIVATE, null, false, strong.toCharArray())).value.posture)
        server.override[WireRoute.ACCOUNT_RECOVERY_PUT] = wrongForm
        assertEquals(Reauthed.Refused(WireErrors.ESCROW_WRONG_FORM), settings.setPosture(RecoveryChoiceKind.OPERATOR, assertNotNull(settings.operatorOffer()), true, strong.toCharArray()))
        assertEquals("private", assertIs<Fetched.Ok<RecoveryPostureView>>(settings.posture()).value.record?.posture, "nothing follows a refused copy")
        server.override.remove(WireRoute.ACCOUNT_RECOVERY_PUT)
        assertIs<Reauthed.Done<*>>(settings.setPosture(RecoveryChoiceKind.OPERATOR, assertNotNull(settings.operatorOffer()), true, strong.toCharArray()))

        // 3. A signed rotation: the re-seal is refused at every look, then taken.
        newCard(server)
        server.override[WireRoute.ESCROW_SELF] = wrongForm
        repeat(2) { assertEquals(Fetched.Refused(WireErrors.ESCROW_WRONG_FORM), settings.posture()) }
        assertEquals(2, server.calls.count { it == WireRoute.ESCROW_SELF }, "a refused re-seal is not marked done: sealed again at the next look")
        server.override.remove(WireRoute.ESCROW_SELF)
        assertIs<EscrowDecision.SealNow>(assertIs<Fetched.Ok<RecoveryPostureView>>(settings.posture()).value.pending)
        assertEquals(3, server.calls.count { it == WireRoute.ESCROW_SELF })
    }

    /** Card 1 names org key B, with the rotation from A signed by A's seed. */
    private fun newCard(server: FakeInstance) {
        val c0 = server.cards[0]
        server.cards += InstanceCard.sign(crypto, server.operatorSign, CardFields(server.instanceId, 1, SignedFrame.hash(crypto, c0), server.origin, "Home", server.kind,
            "99999999-9999-4999-8999-999999999999", Bytes.toB64(server.operatorSign.publicKey), fpB, server.now))
        server.rotations += RecoveryRotation.sign(crypto, crypto.signKeypairFromSeed(seedA), RotationFields(server.instanceId, fpA, fpB, server.now))
        server.recoveryPub = orgB.publicKey
    }
}
