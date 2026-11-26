package io.silencelen.andvari.core.client.onboard

import io.silencelen.andvari.core.client.KdfUpgrade
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.account.Reauth
import io.silencelen.andvari.core.client.account.ReauthKey
import io.silencelen.andvari.core.client.account.ReauthSession
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.account.WireAccountSettings
import io.silencelen.andvari.core.client.link.RecipientStep
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.pin.GatePin
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.PreloginRequest
import io.silencelen.andvari.core.model.wire.PreloginResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Every new wrap of a master password is made at a cost the server takes (spec 01 §7; decided on 2026-11-17): figure by
 * figure the higher of what the account already has and what the server serves, kept inside the client's own limits;
 * where there is no account yet, the served cost. Before, a registration was made at the fixed default and a password
 * change at the caller's cost: on a server whose operator raised the floor, every registration was refused (the
 * operator's own setup through the setup link included), and an account that stands above the served cost on one figure
 * and below it on the other could not change its password. Nothing is ever derived at a cost outside the fence.
 */
class NewWrapCostTest {
    private val plain = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val next = "a whole new Passphrase 42 here"
    private val mib = 1024L * 1024L

    /** The device's crypto, recording every Argon2id cost it derives at. */
    private class Counting(private val inner: CryptoProvider) : CryptoProvider by inner {
        val costs = ArrayList<KdfParams>()
        override fun argon2id(password: ByteArray, salt: ByteArray, outLen: Int, opsLimit: Long, memLimitBytes: Long): ByteArray {
            costs += KdfParams(ops = opsLimit, memBytes = memLimitBytes)
            return inner.argon2id(password, salt, outLen, opsLimit, memLimitBytes)
        }

        fun allInsideTheFence() = costs.all { KdfUpgrade.withinFence(it) }
    }

    private val crypto = Counting(plain)

    private suspend fun onboarding(server: FakeInstance, state: MemoryDeviceState, trusted: Boolean, links: LinkRegistrations? = null, sessions: MutableList<EstablishedSession> = ArrayList()) =
        WireOnboarding(server.origin, server, if (trusted) server.pinnedTrust(state) else server.trust(state), KnownDevices(state, crypto),
            SessionSink { sessions += it }, crypto, state, "android", "Pixel", { server.now }, links = links, work = Dispatchers.Unconfined)

    private fun form(email: String = "alice@example.com") =
        RegistrationForm(email, "Alice", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android")

    private fun confirmStep() = RecipientStep.Confirm(io.silencelen.andvari.core.client.link.OfferView("enrol", "https://h.example", "Home", null, null, 0, null), true,
        false, io.silencelen.andvari.core.client.link.RecipientToken("t"))

    private suspend fun byTicket(server: FakeInstance, sessions: MutableList<EstablishedSession> = ArrayList()): Registration {
        val o = onboarding(server, MemoryDeviceState(), trusted = true, sessions = sessions)
        o.signupStart("alice@example.com", true)
        return o.register(RegistrationAuth.Ticket(o.signupVerify("alice@example.com", "482915") as SignupVerify.Ticket), form())
    }

    /** A server whose floor and policy were both raised to [raised] (the server serves the policy raised to its floor). */
    private fun raisedTo(server: FakeInstance, raised: KdfParams) = server.also { it.policyKdf = raised; it.minKdf = raised }

    @Test fun theCostOfANewWrapIsFigureByFigureTheHigherOfTheAccountsAndTheServedInsideTheFence() {
        val d = KdfParams.DEFAULT
        assertEquals(KdfParams(ops = 4, memBytes = 128 * mib), KdfUpgrade.wrapCost(KdfParams(ops = 4, memBytes = 128 * mib)), "no account: the served cost")
        assertEquals(d, KdfUpgrade.wrapCost(null), "nothing read, nothing known: the default")
        assertEquals(KdfParams(ops = 4, memBytes = 128 * mib), KdfUpgrade.wrapCost(KdfParams(ops = 3, memBytes = 128 * mib), KdfParams(ops = 4, memBytes = 64 * mib)),
            "a straddle: the higher on each figure")
        assertEquals(KdfParams(ops = 5, memBytes = 256 * mib), KdfUpgrade.wrapCost(KdfParams(ops = 3, memBytes = 64 * mib), KdfParams(ops = 5, memBytes = 256 * mib)),
            "a served cost below the account's lowers nothing")
        for (outside in listOf(KdfParams(ops = 2), KdfParams(ops = 11), KdfParams(memBytes = 2048 * mib), KdfParams(memBytes = 32 * mib), KdfParams(memBytes = 64 * mib + 1))) {
            assertEquals(KdfParams(ops = 4), KdfUpgrade.wrapCost(outside, KdfParams(ops = 4)), "a served cost outside the fence is not taken: $outside")
            assertEquals(d, KdfUpgrade.wrapCost(outside), "and with no account, the default: $outside")
        }
        assertEquals(KdfParams(ops = 10, memBytes = 1024 * mib), KdfUpgrade.wrapCost(null, KdfParams(ops = 12, memBytes = 4096 * mib)), "kept inside the client's limits")
        assertEquals(KdfParams(ops = 3, memBytes = 64 * mib + 1024), KdfUpgrade.wrapCost(null, KdfParams(ops = 3, memBytes = 64 * mib + 1)), "a whole number of KiB")
        assertTrue(KdfUpgrade.withinFence(KdfUpgrade.wrapCost(KdfParams(ops = 7, memBytes = 512 * mib), KdfParams(ops = 9, memBytes = 96 * mib), null)))
    }

    @Test fun aRegistrationByTicketOnAServerWhoseFloorWasRaisedIsMadeAtTheServedCost() = runBlocking<Unit> {
        val raised = KdfParams(ops = 4, memBytes = 128 * mib)
        val server = raisedTo(FakeInstance(plain), raised)
        assertIs<Registration.Registered>(byTicket(server))
        assertEquals(raised, server.account("alice@example.com").kdfParams)
        assertTrue(WireRoute.CLIENT_POLICY in server.calls)
        assertTrue(crypto.allInsideTheFence(), "derived: ${crypto.costs}")
    }

    @Test fun theOperatorsSetupThroughTheSetupLinkIsTakenOnAServerWhoseFloorWasRaised() = runBlocking<Unit> {
        val raised = KdfParams(ops = 4)
        val server = raisedTo(FakeInstance(plain, withCard = false), raised)
        val setup = LinkRegistration.Setup(server.origin, server.instanceId, "Family", "private", "none", "bGlua2lkbGlua2lkbGlua2", Bytes.toB64(ByteArray(32) { 6 }))
        val links = object : LinkRegistrations {
            override fun resolve(step: RecipientStep.Confirm) = setup
            override suspend fun registered(registration: LinkRegistration, session: EstablishedSession) {}
        }
        val reg = assertIs<Registration.Registered>(onboarding(server, MemoryDeviceState(), trusted = false, links = links).register(RegistrationAuth.SetupLink(confirmStep()), form("op@example.org")))
        assertEquals(raised, server.account("op@example.org").kdfParams)
        assertEquals(reg.userId, server.operatorUserId)
        assertEquals(1, server.cards.size, "card 0 signed and taken")
        assertTrue(crypto.allInsideTheFence(), "derived: ${crypto.costs}")
    }

    @Test fun aRegistrationFromAnInvitationIsTakenOnAServerWhoseFloorWasRaised() = runBlocking<Unit> {
        val raised = KdfParams(ops = 3, memBytes = 128 * mib)
        val server = raisedTo(FakeInstance(plain), raised)
        val enrol = LinkRegistration.Enrol(server.origin, server.instanceId, "bGlua2lkbGlua2lkbGlua2", Bytes.toB64(ByteArray(32) { 6 }), null)
        val links = object : LinkRegistrations {
            override fun resolve(step: RecipientStep.Confirm) = enrol
            override suspend fun registered(registration: LinkRegistration, session: EstablishedSession) {}
        }
        assertIs<Registration.Registered>(onboarding(server, MemoryDeviceState(), trusted = true, links = links).register(RegistrationAuth.EnrolLink(confirmStep()), form()))
        assertEquals(raised, server.account("alice@example.com").kdfParams)
        assertTrue(crypto.allInsideTheFence(), "derived: ${crypto.costs}")
    }

    /** A served cost outside the fence is not followed and nothing is derived at it: the registration is made at the default. */
    @Test fun aServedCostOutsideTheFenceIsNeverDerivedAt() = runBlocking<Unit> {
        for (outside in listOf(KdfParams(ops = 11), KdfParams(memBytes = 2048 * mib), KdfParams(ops = 2))) {
            val server = FakeInstance(plain).also { it.policyKdf = outside }
            crypto.costs.clear()
            assertIs<Registration.Registered>(byTicket(server), "served $outside")
            assertEquals(KdfParams.DEFAULT, server.account("alice@example.com").kdfParams, "served $outside")
            assertTrue(crypto.allInsideTheFence(), "served $outside, derived: ${crypto.costs}")
        }
    }

    private suspend fun settings(server: FakeInstance, own: KdfParams): WireAccountSettings {
        val sessions = ArrayList<EstablishedSession>()
        assertIs<Registration.Registered>(byTicket(server, sessions))
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
        return WireAccountSettings(server.origin, "alice@example.com", server.card0Hash, s.account, server, crypto, reauth, own)
    }

    /** An account made before the floor was raised changes its password: the new wrap is made at the raised cost. */
    @Test fun anAccountMadeBeforeTheFloorWasRaisedChangesItsPassword() = runBlocking<Unit> {
        val server = FakeInstance(plain)
        val s = settings(server, KdfParams.DEFAULT)
        val raised = KdfParams(ops = 3, memBytes = 128 * mib)
        raisedTo(server, raised)
        assertIs<Reauthed.Done<Unit>>(s.change(strong.toCharArray(), next.toCharArray()))
        assertEquals(raised, server.account("alice@example.com").kdfParams)
        assertTrue(crypto.allInsideTheFence(), "derived: ${crypto.costs}")
    }

    /**
     * An account above the served cost on one figure and below it on the other (made at 4 passes and 64 MiB; the policy
     * then set back to 3 passes, the floor raised to 128 MiB) changes its password at 4 passes and 128 MiB: the higher on
     * each figure. Before, at its own cost, which the floor refused.
     */
    @Test fun anAccountThatStraddlesTheServedCostChangesItsPassword() = runBlocking<Unit> {
        val made = KdfParams(ops = 4, memBytes = 64 * mib)
        val server = FakeInstance(plain).also { it.policyKdf = made }
        val s = settings(server, made)
        assertEquals(made, server.account("alice@example.com").kdfParams)
        raisedTo(server, KdfParams(ops = 3, memBytes = 128 * mib))
        assertIs<Reauthed.Done<Unit>>(s.change(strong.toCharArray(), next.toCharArray()))
        assertEquals(KdfParams(ops = 4, memBytes = 128 * mib), server.account("alice@example.com").kdfParams)
        assertTrue(crypto.allInsideTheFence(), "derived: ${crypto.costs}")
    }

    /**
     * A wrong password sends nothing at all (spec 01 §7), also now that a password change reads the served cost: the
     * typed password is proved on this device first, against the account's own wrap, and only a proof that held reads
     * the policy, once, before the change is sent. Before, the policy was read ahead of the proof, so a wrong password
     * sent that one request.
     */
    @Test fun aWrongPasswordAtAPasswordChangeSendsNothingAndARightOneReadsTheServedCostOnceAfterTheProof() = runBlocking<Unit> {
        val server = FakeInstance(plain)
        val sessions = ArrayList<EstablishedSession>()
        assertIs<Registration.Registered>(byTicket(server, sessions))
        val session = sessions.single()
        var sentWhenProved = -1
        // The engine's own proof, as its session keeper makes it: the device's wrap of the account's key, opened here.
        val reauth = Reauth(object : ReauthSession {
            override val origin = server.origin
            override val emailNorm = "alice@example.com"
            override suspend fun deriveCurrentAuthKey(password: CharArray): String? = (proveCurrentAuthKey(password) as? ReauthKey.Key)?.currentAuthKey
            override suspend fun proveCurrentAuthKey(password: CharArray): ReauthKey {
                val a = server.account(emailNorm)
                val k = PasswordKeys.derive(crypto, password, Bytes.fromB64(a.kdfSalt), a.kdfParams, served = false) ?: return ReauthKey.Unreachable
                try {
                    Envelope.openB64(crypto, k.wrapKey, a.wrappedUvk, Ad.uvk(a.userId)).fill(0)
                    return ReauthKey.Key(k.authKeyB64)
                } catch (e: CryptoException) {
                    return ReauthKey.WrongPassword
                } finally {
                    sentWhenProved = server.calls.size
                    k.wipe()
                }
            }
        }) { listOf(GatePin(server.origin, PinRoot.TRUST_GATE)) }
        val s = WireAccountSettings(server.origin, "alice@example.com", server.card0Hash, session.account, server, crypto, reauth, KdfParams.DEFAULT)
        val before = server.calls.size
        val wrap = server.account("alice@example.com").wrappedUvk

        assertEquals(Reauthed.WrongPassword, s.change("not the Password 7 at all".toCharArray(), next.toCharArray()))
        assertEquals(before, server.calls.size, "a wrong password sends nothing, not even the read of the served cost: ${server.calls.drop(before)}")
        assertEquals(wrap, server.account("alice@example.com").wrappedUvk)

        assertIs<Reauthed.Done<Unit>>(s.change(strong.toCharArray(), next.toCharArray()))
        assertEquals(before, sentWhenProved, "nothing was sent before or during the proof")
        assertEquals(listOf(WireRoute.CLIENT_POLICY, WireRoute.PASSWORD_CHANGE), server.calls.drop(before), "the served cost is read once, after the proof")
    }
}
