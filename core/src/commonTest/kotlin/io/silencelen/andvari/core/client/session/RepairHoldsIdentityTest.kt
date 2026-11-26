package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.items.copyOut
import io.silencelen.andvari.core.client.onboard.AccountOpen
import io.silencelen.andvari.core.client.onboard.EstablishedSession
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KeptAccountKeys
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
import io.silencelen.andvari.core.client.onboard.SessionSink
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.client.pin.CardTrust
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AccountKeys
import io.silencelen.andvari.core.model.wire.PersonalWrap
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.trust.AccountGenesis
import io.silencelen.andvari.core.trust.GenesisFields
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The session keeper holds a take over a kept copy (a repair, where the copy's sealed seed no longer opens) to the identity
 * this device knows for the account: its own record, or the copy's where that reads. Here the flow that hands the session
 * over compared nothing of the identity (a sign-in whose host passes no record of identity keys, through a sink that
 * hands the keeper the sign-in's proof by a kept wrap), and the address's binding is gone (it is keyed by origin, and a
 * followed server move does not carry it), so the keeper's own check is the only one. A server that serves, under the
 * account's own key, a seed of another identity (as a removed device that kept the key could make with it) is refused
 * while either record exists. Before, the proof branch compared no identity, and the copy was written with the other one.
 */
class RepairHoldsIdentityTest {
    private val plain = createCryptoProvider()
    private val password = "correct horse Battery 9 staple"
    private val email = "alice@example.com"

    private class Env(
        val server: FakeInstance, val transport: BearerTransport, val secure: MemoryDeviceState, val state: MemoryDeviceState, val trust: CardTrust,
        var keeper: SessionKeeper, val uvk: ByteArray,
    ) {
        val account get() = server.accounts.values.single()
        val userId get() = account.userId

        fun keptKeys(): AccountKeys = assertNotNull(keeper.keptForSignIn(server.origin)).own

        /** A sink that compared nothing itself and hands the keeper what the sign-in brings (its proof by a kept wrap). */
        fun proofSink(): SessionSink {
            val k = keeper
            return object : SessionSink {
                override suspend fun established(session: EstablishedSession) = k.established(session)
                override suspend fun take(session: EstablishedSession): String? = k.take(session)
                override fun keptForSignIn(origin: String): KeptAccountKeys? = k.keptForSignIn(origin)
                override suspend fun notTaken(origin: String, accessToken: String, refreshToken: String) = k.notTaken(origin, accessToken, refreshToken)
            }
        }

        /** A sign-in of [email] with [password] whose host passes no record of identity keys. */
        suspend fun signIn(email: String, password: String): SignIn = WireOnboarding(server.origin, keeper.clientFor(server.origin), trust,
            KnownDevices(state, server.crypto), proofSink(), server.crypto, state, "android", "Pixel", { server.now }, work = Dispatchers.Unconfined)
            .signIn(email, password.toCharArray())
    }

    private suspend fun Env.signIn(): SignIn = signIn(email, password)

    private suspend fun registered(): Env {
        val server = FakeInstance(plain)
        val secure = MemoryDeviceState()
        val state = MemoryDeviceState()
        val trust = server.pinnedTrust(state)
        val transport = BearerTransport(mapOf(server.origin to server))
        val keeper = SessionKeeper(transport, secure, state, trust, plain)
        val o = WireOnboarding(server.origin, keeper.clientFor(server.origin), trust, KnownDevices(state, plain), keeper, plain, state, "android", "Pixel",
            { server.now }, knownIdentity = keeper::knownIdentity, work = Dispatchers.Unconfined)
        o.signupStart(email, true)
        val t = assertIs<SignupVerify.Ticket>(o.signupVerify(email, "482915"))
        assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(t),
            RegistrationForm(email, "Alice", password.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android")))
        val uvk = assertNotNull(keeper.established).account.uvk.copyOut()
        keeper.lock()
        // The address's binding is gone, as after a followed server move: the keeper's identity check stands alone.
        state.set("${SessionKeeper.EMAIL_BINDING_PREFIX}${server.origin}|$email", null)
        return Env(server, transport, secure, state, trust, keeper, uvk)
    }

    /** One field of the kept record's keys replaced directly in the store; the device starts again from its stores. */
    private fun Env.keepField(name: String, value: String) {
        val record = WireJson.json.parseToJsonElement(assertNotNull(secure.get(SessionKeeper.KEY))).jsonObject
        val keys = assertNotNull(record["accountKeys"]).jsonObject
        secure.set(SessionKeeper.KEY, JsonObject(record + ("accountKeys" to JsonObject(keys + (name to JsonPrimitive(value))))).toString())
        keeper = SessionKeeper(transport, secure, state, trust, plain)
    }

    /** The kept seed is damaged (another seed under another key): only a proof by a kept wrap can take a session over it. */
    private fun Env.damageSeed() {
        val otherKey = plain.randomBytes(32)
        val otherSeed = plain.randomBytes(32)
        try {
            keepField("encryptedIdentitySeed", Envelope.sealB64(plain, otherKey, otherSeed, Ad.idkey(userId)))
        } finally {
            otherKey.fill(0)
            otherSeed.fill(0)
        }
        assertTrue(keeper.unlock(password.toCharArray()) is KeptUnlock.IdentityFault)
    }

    /** The server serves, under alice's own key, a seed of another identity with its own genesis and personal vault. */
    private fun Env.serveAnotherIdentity(): ByteArray {
        val seed = plain.randomBytes(32)
        val vk = plain.randomBytes(32)
        val identity = plain.boxKeypairFromSeed(seed)
        val signing = plain.signKeypairFromSeed(seed)
        val pvid = "22222222-2222-4222-8222-222222222222"
        try {
            val idB64 = Bytes.toB64(identity.publicKey)
            account.encryptedIdentitySeed = Envelope.sealB64(plain, uvk, seed, Ad.idkey(userId))
            account.identityPub = idB64
            account.genesis = Bytes.toB64(AccountGenesis.sign(plain, signing, GenesisFields(userId, idB64, server.instanceId, pvid, server.now)))
            account.personalWrap = PersonalWrap(pvid, Envelope.sealB64(plain, uvk, vk, Ad.vkPersonal(pvid, userId)))
            return identity.publicKey.copyOf()
        } finally {
            seed.fill(0)
            vk.fill(0)
            identity.privateKey.fill(0)
            signing.privateKey.fill(0)
        }
    }

    private fun Env.identityKey() = "ovh.identity|$userId"

    @Test fun anHonestRepairIsTaken() = runBlocking<Unit> {
        val e = registered()
        e.damageSeed()
        val known = assertNotNull(e.keeper.knownIdentity(e.userId))
        assertIs<SignIn.SignedIn>(e.signIn())
        assertEquals(e.account.encryptedIdentitySeed, e.keptKeys().encryptedIdentitySeed, "the seed is written again")
        assertTrue(Bytes.ctEquals(known, assertNotNull(e.keeper.established).account.identityPub()))
    }

    @Test fun aRepairToAnotherIdentityIsRefusedWhileBothRecordsStand() = runBlocking<Unit> {
        val e = registered()
        e.damageSeed()
        e.refusedAndNothingWritten()
    }

    @Test fun aRepairToAnotherIdentityIsRefusedOnTheCopysOwnRecord() = runBlocking<Unit> {
        val e = registered()
        e.damageSeed()
        e.state.set(e.identityKey(), null)
        assertNull(e.keeper.knownIdentity(e.userId))
        e.refusedAndNothingWritten()
    }

    @Test fun aRepairToAnotherIdentityIsRefusedOnTheDevicesOwnRecord() = runBlocking<Unit> {
        val e = registered()
        e.damageSeed()
        e.keepField("identityPub", "not*a*key")
        e.refusedAndNothingWritten()
    }

    /** With neither record the device stands where a new device stands: the take goes on. */
    @Test fun aRepairWithNoRecordAtAllIsTaken() = runBlocking<Unit> {
        val e = registered()
        e.damageSeed()
        e.state.set(e.identityKey(), null)
        e.keepField("identityPub", "not*a*key")
        val served = e.serveAnotherIdentity()
        assertIs<SignIn.SignedIn>(e.signIn())
        assertTrue(Bytes.ctEquals(served, assertNotNull(e.keeper.established).account.identityPub()))
    }

    /** The same over a healthy copy (its seed opens under the account's key): the take is held to the identity too. */
    @Test fun aTakeOverAHealthyCopyIsHeldToTheIdentityToo() = runBlocking<Unit> {
        val e = registered()
        e.refusedAndNothingWritten()
        assertEquals(KeptUnlock.Unlocked, e.keeper.unlock(password.toCharArray()), "the copy still opens")
    }

    private suspend fun Env.refusedAndNothingWritten() {
        val before = keptKeys()
        val takes = keeper.takes
        val identityRefusals = keeper.identityRefusals
        val stateBefore = keeper.knownIdentity(userId)?.let(Bytes::toB64)
        serveAnotherIdentity()
        assertEquals(SignIn.IdentityFault(AccountOpen.SELF_IDENTITY_MISMATCH), signIn())
        assertEquals(takes, keeper.takes, "no session was taken")
        assertEquals(identityRefusals + 1, keeper.identityRefusals)
        assertEquals(before, keptKeys(), "nothing kept was written")
        assertEquals(stateBefore, keeper.knownIdentity(userId)?.let(Bytes::toB64), "the device's record is as it was")
        assertEquals(KeptPhase.LOCKED, keeper.phase.value)
    }
}
