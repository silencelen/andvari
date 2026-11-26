package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.items.copyOut
import io.silencelen.andvari.core.client.onboard.EstablishedSession
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KeptAccountCheck
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.PasswordKeys
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
import io.silencelen.andvari.core.client.onboard.SessionSink
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.client.pin.CardTrust
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.client.recovery.KitRecoveryStep
import io.silencelen.andvari.core.client.recovery.WireKitRecovery
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AccountKeys
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.RecoveryKit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Spec 01 §7, a copy kept on this device whose sealed identity seed no longer opens (its stored bytes damaged). A sign-in
 * whose typed password opens the kept wrap to the key the server's wrap opens is the sign-in's own rule, and the session
 * keeper checks it itself with the wrap key the sign-in hands it: the session is taken and the copy is written again from
 * it, so its seed opens afterwards. Where nothing was compared with a kept wrap (a recovery, a flow that compared
 * nothing) the copy is still refused, with a reason that says the copy is damaged, and a server that serves another key
 * is still "the server's keys are not this account's". Before, every one of these was refused as the latter, a dead end
 * for an honest person with a damaged copy.
 */
class DamagedKeptCopyTest {
    private val plain = createCryptoProvider()
    private val password = "correct horse Battery 9 staple"
    private val recovered = "a whole new Passphrase 42 here"
    private val email = "alice@example.com"

    private class Env(
        val server: FakeInstance, val transport: BearerTransport, val secure: MemoryDeviceState, val state: MemoryDeviceState, val trust: CardTrust,
        val typedKit: String, var keeper: SessionKeeper,
    ) {
        val account get() = server.accounts.values.single()
        val userId get() = account.userId

        fun keptKeys(): AccountKeys = assertNotNull(keeper.keptForSignIn(server.origin)).own

        fun onboarding(sink: SessionSink = keeper) = WireOnboarding(server.origin, keeper.clientFor(server.origin), trust, KnownDevices(state, server.crypto), sink,
            server.crypto, state, "android", "Pixel", { server.now }, knownIdentity = keeper::knownIdentity, work = Dispatchers.Unconfined)
    }

    /** alice registered on this device; the device keeps her copy, locked. */
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
        val reg = assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(t),
            RegistrationForm(email, "Alice", password.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android")))
        keeper.lock()
        return Env(server, transport, secure, state, trust, RecoveryKit.displayForm(reg.kit.secret), keeper)
    }

    /**
     * The kept record's sealed identity seed is replaced by bytes of the same shape that open under no key this account
     * has (another seed under another key), as damaged storage leaves it; the device starts again from its stores.
     */
    private fun Env.damageSeed() {
        val text = assertNotNull(secure.get(SessionKeeper.KEY))
        val record = WireJson.json.parseToJsonElement(text).jsonObject
        val keys = assertNotNull(record["accountKeys"]).jsonObject
        val otherKey = plain.randomBytes(32)
        val otherSeed = plain.randomBytes(32)
        val damaged = Envelope.sealB64(plain, otherKey, otherSeed, Ad.idkey(userId))
        otherKey.fill(0)
        otherSeed.fill(0)
        val newKeys = JsonObject(keys + ("encryptedIdentitySeed" to JsonPrimitive(damaged)))
        secure.set(SessionKeeper.KEY, JsonObject(record + ("accountKeys" to newKeys)).toString())
        keeper = SessionKeeper(transport, secure, state, trust, plain)
        assertEquals(damaged, keptKeys().encryptedIdentitySeed)
        assertTrue(keeper.unlock(password.toCharArray()) is KeptUnlock.IdentityFault, "the damaged copy no longer opens by itself")
    }

    @Test fun aSignInWithTheRightPasswordOverADamagedSeedSignsInAndRepairsTheCopy() = runBlocking<Unit> {
        val e = registered()
        e.damageSeed()
        val takes = e.keeper.takes
        // Before: Refused(server_keys_not_known_here) from the keeper's floor.
        assertIs<SignIn.SignedIn>(e.onboarding().signIn(email, password.toCharArray()))
        assertEquals(takes + 1, e.keeper.takes)
        assertEquals(e.account.encryptedIdentitySeed, e.keptKeys().encryptedIdentitySeed, "the seed is written again from the verified session")
        val uvk = assertNotNull(e.keeper.established).account.uvk.copyOut()
        try {
            assertTrue(KeptAccountCheck.opensKeptSeed(plain, e.userId, uvk, e.keptKeys()), "the kept seed opens afterwards")
        } finally {
            uvk.fill(0)
        }
        e.keeper.lock()
        assertEquals(KeptUnlock.Unlocked, e.keeper.unlock(password.toCharArray()))
    }

    @Test fun aServerThatServesAnotherKeyIsStillRefusedOverADamagedSeed() = runBlocking<Unit> {
        val e = registered()
        e.damageSeed()
        val before = e.keptKeys()
        val takes = e.keeper.takes
        // The typed password opens the server's wrap, for this account's id, of another key; the kept wrap opens to the real one.
        val salt = plain.randomBytes(KdfParams.SALT_BYTES)
        val k = assertNotNull(PasswordKeys.derive(plain, password.toCharArray(), salt, KdfParams.DEFAULT, served = false))
        val other = plain.randomBytes(32)
        try {
            e.account.authKey = k.authKeyB64
            e.account.kdfSalt = Bytes.toB64(salt)
            e.account.kdfParams = k.params
            e.account.wrappedUvk = Envelope.sealB64(plain, k.wrapKey, other, Ad.uvk(e.userId))
        } finally {
            k.wipe()
            other.fill(0)
        }
        assertEquals(SignIn.Refused(WireOnboarding.SERVER_KEYS_NOT_KNOWN_HERE), e.onboarding().signIn(email, password.toCharArray()))
        assertEquals(takes, e.keeper.takes, "no session was taken")
        assertEquals(before, e.keptKeys(), "nothing kept was replaced")
        assertEquals(WireRoute.END_SESSION, e.transport.sent.last().route)
    }

    @Test fun aKitRecoveryOverADamagedSeedIsRefusedAsADamagedCopyAndCommitsNothing() = runBlocking<Unit> {
        val e = registered()
        e.damageSeed()
        val before = e.keptKeys()
        val kits = WireKitRecovery({ e.keeper.clientFor(it) }, e.trust, KnownDevices(e.state, plain), e.keeper, plain, "android", "Pixel",
            knownIdentity = e.keeper::knownIdentity)
        val target = assertIs<KitRecoveryStep.ConfirmTarget>(kits.startTyped(email, e.server.origin, e.typedKit, GateEntry.KIT_RECOVERY_SCREEN))
        // Before: Stopped(server_keys_not_known_here), which tells the person the server is not to be trusted.
        assertEquals(KitRecoveryStep.Stopped(WireKitRecovery.KEPT_COPY_DAMAGED), kits.verify(target))
        assertFalse(WireRoute.RECOVERY_SELF_COMMIT in e.server.calls, "nothing was committed")
        assertEquals(before, e.keptKeys())
        // The way out: remove this device's copy, then recover.
        e.keeper.forget(forgetIdentity = false)
        val again = assertIs<KitRecoveryStep.ConfirmTarget>(kits.startTyped(email, e.server.origin, e.typedKit, GateEntry.KIT_RECOVERY_SCREEN))
        assertIs<KitRecoveryStep.Recovered>(kits.commit(assertIs(kits.verify(again)), recovered.toCharArray()))
    }

    /**
     * A flow that compared nothing kept (here a sign-in whose host tells it of no kept copy) hands the keeper no wrap key,
     * so the damaged copy is refused at the keeper with the damaged reason, and nothing is replaced: only a flow that
     * holds a key opening the kept wrap can have the session taken over such a copy.
     */
    @Test fun aFlowThatComparedNothingIsRefusedOverADamagedSeed() = runBlocking<Unit> {
        val e = registered()
        e.damageSeed()
        val before = e.keptKeys()
        val takes = e.keeper.takes
        val keeper = e.keeper
        val hidden = object : SessionSink {
            override suspend fun established(session: EstablishedSession) = keeper.established(session)
            override suspend fun take(session: EstablishedSession): String? = keeper.take(session)
        }
        assertEquals(SignIn.Refused(WireOnboarding.KEPT_COPY_DAMAGED), e.onboarding(hidden).signIn(email, password.toCharArray()))
        assertEquals(takes, e.keeper.takes)
        assertEquals(before, e.keptKeys())
        assertNotEquals(e.account.encryptedIdentitySeed, e.keptKeys().encryptedIdentitySeed, "the copy was not written")
    }
}
