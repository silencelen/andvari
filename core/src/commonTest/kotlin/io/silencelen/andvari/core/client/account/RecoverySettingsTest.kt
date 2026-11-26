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
import io.silencelen.andvari.core.client.pin.CardTrust
import io.silencelen.andvari.core.client.pin.GatePin
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.client.recovery.EscrowDecision
import io.silencelen.andvari.core.client.recovery.RecoveryMirror
import io.silencelen.andvari.core.client.state.StoredAccountState
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.PreloginRequest
import io.silencelen.andvari.core.model.wire.PreloginResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.CardFields
import io.silencelen.andvari.core.trust.InstanceCard
import io.silencelen.andvari.core.trust.InstanceKind
import io.silencelen.andvari.core.trust.RecoveryRotation
import io.silencelen.andvari.core.trust.RotationFields
import io.silencelen.andvari.core.trust.SignedFrame
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The recovery posture in Settings (design §4.5, §7.7): consent, the own mirror, signed rotations and the takeover warning. */
class RecoverySettingsTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val seedA = ByteArray(32) { 2 }
    private val seedB = ByteArray(32) { 3 }
    private val keyA = crypto.boxKeypairFromSeed(seedA).publicKey
    private val keyB = crypto.boxKeypairFromSeed(seedB).publicKey
    private val fpA = Escrow.fingerprint(crypto, keyA)
    private val fpB = Escrow.fingerprint(crypto, keyB)

    private class Env(val server: FakeInstance, val state: MemoryDeviceState, val trust: CardTrust, val session: EstablishedSession, val settings: WireRecoverySettings)

    private suspend fun env(kind: InstanceKind = InstanceKind.PRIVATE, operator: Boolean = false): Env {
        val server = FakeInstance(crypto, kind = kind, recoveryFp = fpA)
        server.recoveryPub = keyA
        val state = MemoryDeviceState()
        val trust = server.pinnedTrust(state)
        val sessions = ArrayList<EstablishedSession>()
        val o = WireOnboarding(server.origin, server, trust, KnownDevices(state, crypto), SessionSink { sessions += it }, crypto, state,
            "android", "Pixel", { server.now }, work = Dispatchers.Unconfined)
        o.signupStart("alice@example.com", true)
        val t = o.signupVerify("alice@example.com", "482915") as SignupVerify.Ticket
        val offer = if (operator) assertNotNull(o.operatorRecoveryOffer()) else null
        assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(t), RegistrationForm("alice@example.com", "Alice", strong.toCharArray(), true,
            if (operator) RecoveryChoiceKind.OPERATOR else RecoveryChoiceKind.PRIVATE, "Pixel", "android", offer, operator)))
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
        val s = sessions.single()
        val kit = WireAccountSettings(server.origin, "alice@example.com", server.card0Hash, s.account, server, crypto, reauth, io.silencelen.andvari.core.crypto.KdfParams.DEFAULT)
        return Env(server, state, trust, s, WireRecoverySettings(server.origin, s.account, server, crypto, state, trust, reauth, kit, { server.now }))
    }

    /** The operator publishes card 1 naming [fp], with [rotate] the signed rotation from A. */
    private fun newCard(server: FakeInstance, fp: String, rotate: Boolean) {
        val c0 = server.cards[0]
        server.cards += InstanceCard.sign(crypto, server.operatorSign, CardFields(server.instanceId, 1, SignedFrame.hash(crypto, c0), server.origin, "Home", server.kind,
            "99999999-9999-4999-8999-999999999999", Bytes.toB64(server.operatorSign.publicKey), fp, server.now))
        if (rotate) server.rotations += RecoveryRotation.sign(crypto, crypto.signKeypairFromSeed(seedA), RotationFields(server.instanceId, fpA, fp, server.now))
        server.recoveryPub = if (fp == fpB) keyB else crypto.boxKeypairFromSeed(ByteArray(32) { 9 }).publicKey
    }

    @Test fun turningOperatorRecoveryOffOnADeviceWhoseClockRunsBehindStillSticks() = runBlocking<Unit> {
        // design §5.4: a record that supersedes another is stamped later than it, whatever this device's clock says.
        val e = env(operator = true)
        val store = StoredAccountState(e.session.userId, e.session.account.uvk, e.server, crypto, e.state)
        val held = assertNotNull(store.local().recovery)
        assertEquals("operator", held.posture)
        val reauth = Reauth(object : ReauthSession {
            override val origin = e.server.origin
            override val emailNorm = "alice@example.com"
            override suspend fun deriveCurrentAuthKey(password: CharArray): String? {
                val p = (e.server.call(WireRoute.PRELOGIN, bodyJson = WireJson.json.encodeToString(PreloginRequest.serializer(), PreloginRequest(emailNorm)),
                    decode = { WireJson.json.decodeFromString(PreloginResponse.serializer(), it) }) as WireResult.Ok).value
                val k = PasswordKeys.derive(crypto, password.copyOf(), Bytes.fromB64(p.kdfSalt), p.kdfParams, served = true) ?: return null
                return k.authKeyB64.also { k.wipe() }
            }
        }) { listOf(GatePin(e.server.origin, PinRoot.TRUST_GATE)) }
        val kit = WireAccountSettings(e.server.origin, "alice@example.com", e.server.card0Hash, e.session.account, e.server, crypto, reauth, io.silencelen.andvari.core.crypto.KdfParams.DEFAULT)
        val behind = WireRecoverySettings(e.server.origin, e.session.account, e.server, crypto, e.state, e.trust, reauth, kit, { held.at - 86_400_000L })
        val off = assertIs<Reauthed.Done<io.silencelen.andvari.core.client.state.RecoveryRecord>>(
            behind.setPosture(RecoveryChoiceKind.PRIVATE, null, false, strong.toCharArray())).value
        assertEquals("private", off.posture)
        assertEquals(held.at + 1, off.at, "stamped after the record it replaces, not at the slow clock")
        // It wins the merge against the record it replaced, on this device and on any other that still holds the old one.
        assertEquals(off, io.silencelen.andvari.core.client.state.AccountMerge.pickRecovery(held, off))
        assertEquals(off, store.local().recovery)
        assertEquals(off, RecoveryMirror(e.state).get(e.session.userId), "the mirror follows the record as written")
        val elsewhere = StoredAccountState(e.session.userId, e.session.account.uvk, e.server, crypto, MemoryDeviceState())
        assertEquals("private", assertIs<io.silencelen.andvari.core.client.state.AccountStateRead.Ok>(elsewhere.read()).document.recovery?.posture)
    }

    @Test fun turningOperatorRecoveryOnNeedsTheOfferAndTheBoxAndNeverOnAPublicCard() = runBlocking<Unit> {
        val e = env()
        val offer = assertNotNull(e.settings.operatorOffer())
        assertFalse(offer.unsignedChange)
        fun pw() = strong.toCharArray()
        val before = e.server.calls.size
        val p = pw()
        assertEquals(Reauthed.Refused("consent_required"), e.settings.setPosture(RecoveryChoiceKind.OPERATOR, offer, false, p))
        assertTrue(p.all { it == '\u0000' })
        assertEquals(Reauthed.Refused("operator_recovery_unavailable"), e.settings.setPosture(RecoveryChoiceKind.OPERATOR, null, true, pw()))
        assertFalse(e.server.calls.drop(before).any { it == WireRoute.PRELOGIN || it == WireRoute.ACCOUNT_RECOVERY_PUT }, "nothing derived or sent")
        // This session derives its proof without a wrap of its own: the server's refusal is its own result.
        assertEquals(Reauthed.Refused(Reauthed.PROOF_REFUSED), e.settings.setPosture(RecoveryChoiceKind.OPERATOR, offer, true, "not the password 12".toCharArray()))
        val done = assertIs<Reauthed.Done<io.silencelen.andvari.core.client.state.RecoveryRecord>>(e.settings.setPosture(RecoveryChoiceKind.OPERATOR, offer, true, pw())).value
        assertEquals("operator", done.posture)
        assertEquals(fpA, done.fp)
        val a = e.server.account("alice@example.com")
        assertEquals("operator", a.posture)
        assertEquals(fpA, a.escrowFp)
        assertEquals(done, RecoveryMirror(e.state).get(e.session.userId))
        assertEquals(done, StoredAccountState(e.session.userId, e.session.account.uvk, e.server, crypto, e.state).local().recovery)
        // A card that changed since the offer was made: the offer is stale.
        newCard(e.server, fpB, rotate = true)
        e.trust.refresh(e.server.origin)
        assertEquals(Reauthed.Refused("stale_offer"), e.settings.setPosture(RecoveryChoiceKind.OPERATOR, offer, true, pw()))
        // Off again.
        assertEquals("private", assertIs<Reauthed.Done<io.silencelen.andvari.core.client.state.RecoveryRecord>>(e.settings.setPosture(RecoveryChoiceKind.PRIVATE, null, false, pw())).value.posture)
        assertNull(a.escrowFp)
        // Variant R: a public card offers nothing and refuses the choice, whatever recoveryFp it names.
        val pub = env(kind = InstanceKind.PUBLIC)
        assertNull(pub.settings.operatorOffer())
        assertEquals(Reauthed.Refused("operator_recovery_unavailable"), pub.settings.setPosture(RecoveryChoiceKind.OPERATOR, offer, true, pw()))
        val view = assertIs<Fetched.Ok<RecoveryPostureView>>(pub.settings.posture()).value
        assertFalse(view.operatorOffered)
    }

    @Test fun aSignedRotationReSealsSilentlyOnlyWithThisDevicesOwnMirror() = runBlocking<Unit> {
        val e = env(operator = true)
        assertEquals(fpA, e.server.account("alice@example.com").escrowFp)
        assertEquals(EscrowDecision.None, assertIs<Fetched.Ok<RecoveryPostureView>>(e.settings.posture()).value.pending)
        newCard(e.server, fpB, rotate = true)
        val view = assertIs<Fetched.Ok<RecoveryPostureView>>(e.settings.posture()).value
        assertIs<EscrowDecision.SealNow>(view.pending)
        assertEquals(fpB, e.server.account("alice@example.com").escrowFp, "re-sealed through PUT /escrow/self, unasked")
        assertEquals(fpB, view.record!!.fp, "the consent follows the signed rotation")
        assertEquals(fpB, RecoveryMirror(e.state).get(e.session.userId)!!.fp)
        assertEquals(EscrowDecision.None, assertIs<Fetched.Ok<RecoveryPostureView>>(e.settings.posture()).value.pending)
    }

    @Test fun aDeviceWithoutTheMirrorAsksAndTheAnswerNeedsThePassword() = runBlocking<Unit> {
        val e = env(operator = true)
        newCard(e.server, fpB, rotate = true)
        // A password-only device: no mirror of its own.
        RecoveryMirror(e.state).forget(e.session.userId)
        val ask = assertIs<EscrowDecision.AskOwnMirror>(assertIs<Fetched.Ok<RecoveryPostureView>>(e.settings.posture()).value.pending)
        assertEquals(fpA, e.server.account("alice@example.com").escrowFp, "nothing sealed unasked")
        assertEquals(Reauthed.Refused("stale_prompt"), e.settings.answerEscrowPrompt(EscrowDecision.UnsignedChange(ask.pin, fpA, fpB), true, strong.toCharArray()))
        val kept = assertIs<Reauthed.Done<io.silencelen.andvari.core.client.state.RecoveryRecord>>(e.settings.answerEscrowPrompt(ask, true, strong.toCharArray())).value
        assertEquals(fpB, kept.fp)
        assertEquals(fpB, e.server.account("alice@example.com").escrowFp)
        assertEquals(kept, RecoveryMirror(e.state).get(e.session.userId))
    }

    @Test fun anUnsignedKeyChangeShowsTheTakeoverWarningAndTurningOffIsPrivate() = runBlocking<Unit> {
        val e = env(operator = true)
        val fpC = Escrow.fingerprint(crypto, crypto.boxKeypairFromSeed(ByteArray(32) { 9 }).publicKey)
        newCard(e.server, fpC, rotate = false)
        val warn = assertIs<EscrowDecision.UnsignedChange>(assertIs<Fetched.Ok<RecoveryPostureView>>(e.settings.posture()).value.pending)
        assertEquals(fpA, warn.fromFp)
        assertEquals(fpC, warn.toFp)
        assertEquals(fpA, e.server.account("alice@example.com").escrowFp, "no silent re-seal ever")
        // The first-consent walk now finds the unsigned change: an offer made now carries the warning.
        assertTrue(assertNotNull(e.settings.operatorOffer()).unsignedChange)
        val off = assertIs<Reauthed.Done<io.silencelen.andvari.core.client.state.RecoveryRecord>>(e.settings.answerEscrowPrompt(warn, false, strong.toCharArray())).value
        assertEquals("private", off.posture)
        assertNull(e.server.account("alice@example.com").escrowFp)
    }
}
