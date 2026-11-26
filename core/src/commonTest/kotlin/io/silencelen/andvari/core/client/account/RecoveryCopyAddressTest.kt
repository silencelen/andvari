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
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.EscrowFormat
import io.silencelen.andvari.core.crypto.EscrowOpenException
import io.silencelen.andvari.core.crypto.EscrowVerdict
import io.silencelen.andvari.core.crypto.IdentityCheck
import io.silencelen.andvari.core.crypto.KeysGoneException
import io.silencelen.andvari.core.crypto.SignedStatement
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AccountRecoveryPut
import io.silencelen.andvari.core.model.wire.EscrowSelfPut
import io.silencelen.andvari.core.model.wire.PreloginRequest
import io.silencelen.andvari.core.model.wire.PreloginResponse
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
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A recovery copy says whose it is (spec 04 §3, §4 steps 7 and 8): every place a
 * client seals one (registration, turning operator recovery on, the re-seal after a signed rotation) names the account's
 * address inside what the account signs; the offline tool's opener compares it with the address the operator typed; an
 * altered address does not verify; the old form opens only through the vectors' opener; and the keys stay in their lend.
 */
class RecoveryCopyAddressTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val seedA = crypto.randomBytes(32)
    private val seedB = crypto.randomBytes(32)
    private val orgA = crypto.boxKeypairFromSeed(seedA)
    private val orgB = crypto.boxKeypairFromSeed(seedB)
    private val fpA = Escrow.fingerprint(crypto, orgA.publicKey)
    private val fpB = Escrow.fingerprint(crypto, orgB.publicKey)

    private class Env(val server: FakeInstance, val session: EstablishedSession, val settings: WireRecoverySettings)

    private suspend fun env(operator: Boolean): Env {
        val server = FakeInstance(crypto, recoveryFp = fpA)
        server.recoveryPub = orgA.publicKey
        val state = MemoryDeviceState()
        val trust = server.pinnedTrust(state)
        val sessions = ArrayList<EstablishedSession>()
        val o = WireOnboarding(server.origin, server, trust, KnownDevices(state, crypto), SessionSink { sessions += it }, crypto, state,
            "android", "Pixel", { server.now }, work = Dispatchers.Unconfined)
        o.signupStart("Alice@Example.com", true)
        val t = o.signupVerify("Alice@Example.com", "482915") as SignupVerify.Ticket
        val offer = if (operator) assertNotNull(o.operatorRecoveryOffer()) else null
        assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(t), RegistrationForm("Alice@Example.com", "Alice", strong.toCharArray(), true,
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
        val kit = WireAccountSettings(server.origin, s.emailNorm, server.card0Hash, s.account, server, crypto, reauth, io.silencelen.andvari.core.crypto.KdfParams.DEFAULT)
        return Env(server, s, WireRecoverySettings(server.origin, s.account, server, crypto, state, trust, reauth, kit, { server.now }))
    }

    private fun identity(e: Env): IdentityCheck {
        val a = e.server.account("alice@example.com")
        return IdentityCheck(a.encryptedIdentitySeed, a.identityPub)
    }

    private fun anchor(e: Env): String = Escrow.fingerprint(crypto, Bytes.fromB64(e.server.account("alice@example.com").identityPub)).take(32)

    /** The last recovery copy the device uploaded on [route]. */
    private fun lastCopy(e: Env, route: WireRoute): String {
        val body = e.server.bodies[e.server.calls.lastIndexOf(route)]
        return when (route) {
            WireRoute.REGISTER -> assertNotNull(e.server.lastRegister?.recovery?.escrow).sealed
            WireRoute.ACCOUNT_RECOVERY_PUT -> assertNotNull(WireJson.json.decodeFromString(AccountRecoveryPut.serializer(), body).escrow).sealed
            WireRoute.ESCROW_SELF -> WireJson.json.decodeFromString(EscrowSelfPut.serializer(), body).sealed
            else -> error("no copy on $route")
        }
    }

    private fun openAsTheTool(e: Env, sealed: String, org: io.silencelen.andvari.core.crypto.KeyPairBytes, typed: String) =
        Escrow.openForAssist(crypto, org, Bytes.fromB64(sealed), e.session.userId, typed, anchor(e), identity(e))

    @Test fun everyCopyAClientSealsNamesTheAccountsAddressAndTheToolComparesIt() = runBlocking<Unit> {
        // 1. Registration with operator recovery: the address the account was registered with, normalised.
        val e = env(operator = true)
        val atRegistration = lastCopy(e, WireRoute.REGISTER)
        val opened = openAsTheTool(e, atRegistration, orgA, "  ALICE@example.COM ")
        assertEquals(EscrowFormat.V3, opened.format)
        assertEquals("alice@example.com", opened.email)
        opened.wipe()
        // The operator typed the address of someone else: refused, and the refusal names whose copy it is.
        val other = assertFailsWith<EscrowOpenException> { openAsTheTool(e, atRegistration, orgA, "bob@example.com") }
        assertEquals(EscrowVerdict.EMAIL_MISMATCH, other.verdict)
        assertEquals("alice@example.com", other.copyEmail)
        // Not an address at all: refused before anything is opened.
        assertEquals(EscrowVerdict.BAD_EMAIL, assertFailsWith<EscrowOpenException> { openAsTheTool(e, atRegistration, orgB, "not an address") }.verdict)

        // 2. Off, then on again in Settings (PUT /account/recovery): a new copy, naming the same address.
        assertEquals("private", assertIs<Reauthed.Done<io.silencelen.andvari.core.client.state.RecoveryRecord>>(
            e.settings.setPosture(RecoveryChoiceKind.PRIVATE, null, false, strong.toCharArray())).value.posture)
        val offer = assertNotNull(e.settings.operatorOffer())
        assertIs<Reauthed.Done<*>>(e.settings.setPosture(RecoveryChoiceKind.OPERATOR, offer, true, strong.toCharArray()))
        val turnedOn = lastCopy(e, WireRoute.ACCOUNT_RECOVERY_PUT)
        assertEquals("alice@example.com", openAsTheTool(e, turnedOn, orgA, "alice@example.com").email)

        // 3. A signed rotation re-seals, unasked, to the new key: still the account's address.
        newCard(e.server, rotate = true)
        assertIs<EscrowDecision.SealNow>(assertIs<Fetched.Ok<RecoveryPostureView>>(e.settings.posture()).value.pending)
        val resealed = lastCopy(e, WireRoute.ESCROW_SELF)
        val again = openAsTheTool(e, resealed, orgB, "alice@example.com")
        assertEquals(EscrowFormat.V3, again.format)
        assertEquals("alice@example.com", again.email)
    }

    @Test fun anAlteredAddressDoesNotVerifyAndTheOldFormHasNoAddress() {
        val seed = crypto.randomBytes(32)
        val signer = crypto.signKeypairFromSeed(seed)
        val identity = crypto.boxKeypairFromSeed(seed)
        val userId = "1b4e28ba-2fa1-4d3b-8a5e-2c3f4d5e6a7b"
        val uvk = crypto.randomBytes(32)
        val check = IdentityCheck(Envelope.sealB64(crypto, uvk, seed, Ad.idkey(userId)), Bytes.toB64(identity.publicKey))
        val anchor = Escrow.fingerprint(crypto, identity.publicKey)
        val sealed = Escrow.sealUvkV3(crypto, orgA.publicKey, fpA, userId, "alice@example.com", identity.publicKey, signer, uvk, 1_791_590_400_000L)
        val frame = crypto.sealOpen(orgA.publicKey, orgA.privateKey, sealed)
        val statement = frame.copyOfRange(SignedStatement.STATEMENT_OFFSET, frame.size).decodeToString()
        assertTrue(statement.startsWith("""{"v":3,"purpose":"escrow-uvk","userId":"$userId","email":"${Bytes.toB64("alice@example.com".encodeToByteArray())}","identityKey":"""), statement)
        assertContentEquals(uvk, Escrow.open(crypto, orgA, sealed, userId, anchor, check).uvk, "the round trip")

        // The same copy with another address written into the signed statement: the signature no longer holds.
        val swapped = statement.replace(Bytes.toB64("alice@example.com".encodeToByteArray()), Bytes.toB64("bob@example.org".encodeToByteArray()))
        val forged = crypto.sealTo(orgA.publicKey, frame.copyOfRange(0, SignedStatement.STATEMENT_OFFSET) + swapped.encodeToByteArray())
        assertEquals(EscrowVerdict.BAD_SIGNATURE, assertFailsWith<EscrowOpenException> { Escrow.open(crypto, orgA, forged, userId, anchor, check) }.verdict)
        assertEquals(EscrowVerdict.BAD_SIGNATURE, assertFailsWith<EscrowOpenException> {
            Escrow.openForAssist(crypto, orgA, forged, userId, "bob@example.org", anchor, check)
        }.verdict)
        // An address that is not normal is not sealed.
        assertFailsWith<CryptoException> { Escrow.sealUvkV3(crypto, orgA.publicKey, fpA, userId, "Alice@example.com", identity.publicKey, signer, uvk, 1_791_590_400_000L) }

        // The old form still opens where the vectors need it, says no address, and the tool's opener refuses it.
        val old = Escrow.sealUvkV2(crypto, orgA.publicKey, fpA, userId, identity.publicKey, signer, uvk, 1_791_590_400_000L)
        val v2 = Escrow.open(crypto, orgA, old, userId, anchor, check)
        assertEquals(EscrowFormat.V2, v2.format)
        assertNull(v2.email)
        assertEquals(EscrowVerdict.NO_ADDRESS, assertFailsWith<EscrowOpenException> {
            Escrow.openForAssist(crypto, orgA, old, userId, "alice@example.com", anchor, check)
        }.verdict)
    }

    @Test fun aCopyIsSealedOnlyInsideTheKeysLendAndNothingAfterALock() = runBlocking<Unit> {
        val e = env(operator = false)
        val offer = assertNotNull(e.settings.operatorOffer())
        e.session.account.wipe()
        val before = e.server.calls.size
        val r = runCatching { e.settings.setPosture(RecoveryChoiceKind.OPERATOR, offer, true, strong.toCharArray()) }
        // The keys are gone: the seal is refused by the guard before any key is used (the tripwire counts what reaches
        // the provider under zeros, and this suite fails on any such line), and no copy is sent.
        assertTrue(r.isFailure && r.exceptionOrNull() is KeysGoneException || r.getOrNull() !is Reauthed.Done<*>, "$r")
        assertFalse(e.server.calls.drop(before).contains(WireRoute.ACCOUNT_RECOVERY_PUT), "no copy sent")
    }

    /** Card 1 names org key B, with the rotation from A signed by A's seed. */
    private fun newCard(server: FakeInstance, rotate: Boolean) {
        val c0 = server.cards[0]
        server.cards += InstanceCard.sign(crypto, server.operatorSign, CardFields(server.instanceId, 1, SignedFrame.hash(crypto, c0), server.origin, "Home", server.kind,
            "99999999-9999-4999-8999-999999999999", Bytes.toB64(server.operatorSign.publicKey), fpB, server.now))
        if (rotate) server.rotations += RecoveryRotation.sign(crypto, crypto.signKeypairFromSeed(seedA), RotationFields(server.instanceId, fpA, fpB, server.now))
        server.recoveryPub = orgB.publicKey
    }
}
