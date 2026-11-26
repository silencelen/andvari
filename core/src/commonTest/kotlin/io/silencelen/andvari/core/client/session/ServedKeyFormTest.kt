package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.items.copyOut
import io.silencelen.andvari.core.client.onboard.AccountOpen
import io.silencelen.andvari.core.client.onboard.AccountOpenResult
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
import io.silencelen.andvari.core.client.onboard.SessionHow
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
import io.silencelen.andvari.core.crypto.MemberRecovery
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AccountKeys
import io.silencelen.andvari.core.model.wire.MemberRecoveryBlock
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
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Design 2026-11-15 §2.2, strict decoding, for the account-key texts a server serves. Before, a server could serve the
 * account's own, correct sealed seed with `=` padding at a sign-in: the opening read it with a decoder that tolerates
 * padding, so the session was taken and the padded text kept, and the copy stayed healthy. From then on the judgment
 * "this device's copy is damaged" read the kept seed strictly, judged it unreadable, and any key that was not the
 * account's was told to the person as a damaged copy, whose way out is removing it. Now such a text is refused before
 * anything is kept, as the server's fault, and a copy that already holds one is judged by the decoder its opening uses.
 */
class ServedKeyFormTest {
    private val plain = createCryptoProvider()
    private val password = "correct horse Battery 9 staple"
    private val email = "alice@example.com"

    private class Env(
        val server: FakeInstance, val transport: BearerTransport, val secure: MemoryDeviceState, val state: MemoryDeviceState, val trust: CardTrust,
        var keeper: SessionKeeper,
    ) {
        val account get() = server.accounts.values.single()
        val userId get() = account.userId

        fun keptKeys(): AccountKeys = assertNotNull(keeper.keptForSignIn(server.origin)).own

        /** The sign-in as the app engine builds it; [identityRecord] false: a host that passes no record of identity keys. */
        fun onboarding(sink: SessionSink = keeper, identityRecord: Boolean = true) = WireOnboarding(server.origin, keeper.clientFor(server.origin), trust,
            KnownDevices(state, server.crypto), sink, server.crypto, state, "android", "Pixel", { server.now },
            knownIdentity = if (identityRecord) keeper::knownIdentity else { _ -> null }, work = Dispatchers.Unconfined)

        fun kits() = WireKitRecovery({ keeper.clientFor(it) }, trust, KnownDevices(state, server.crypto), keeper, server.crypto, "android", "Pixel",
            knownIdentity = keeper::knownIdentity)
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
        assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(t),
            RegistrationForm(email, "Alice", password.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android")))
        keeper.lock()
        return Env(server, transport, secure, state, trust, keeper)
    }

    /** [text] with `=` padding: the tolerant decoder still reads it to the same bytes; the strict one refuses it. */
    private fun padded(text: String): String {
        assertTrue(text.length % 4 != 0, "a text whose length padding can change")
        val p = text + "=".repeat(4 - text.length % 4)
        assertNull(Bytes.fromB64Canonical(p), "not canonical")
        assertTrue(Bytes.fromB64(p).contentEquals(Bytes.fromB64(text)), "the same bytes to the tolerant decoder")
        return p
    }

    /** The kept record's sealed seed is replaced by [seedText] directly in the store, as if kept earlier; the device starts again. */
    private fun Env.keepSeedText(seedText: String) {
        val record = WireJson.json.parseToJsonElement(assertNotNull(secure.get(SessionKeeper.KEY))).jsonObject
        val keys = assertNotNull(record["accountKeys"]).jsonObject
        secure.set(SessionKeeper.KEY, JsonObject(record + ("accountKeys" to JsonObject(keys + ("encryptedIdentitySeed" to JsonPrimitive(seedText))))).toString())
        keeper = SessionKeeper(transport, secure, state, trust, plain)
        assertEquals(seedText, keptKeys().encryptedIdentitySeed)
    }

    /** A kit of another key for this account's id, which the server now holds for it (a holder of a key that is not alice's). */
    private fun Env.servedKitOfAnotherKey(): String {
        val piece = MemberRecovery.generate(plain, userId, plain.randomBytes(32))
        try {
            account.memberRecovery = MemberRecoveryBlock(piece.recoveryWrappedUvk, piece.recoveryAuthKey)
            return RecoveryKit.displayForm(piece.recoverySecret)
        } finally {
            piece.recoverySecret.fill(0)
        }
    }

    private suspend fun Env.verify(kit: String): KitRecoveryStep {
        val kits = kits()
        return kits.verify(assertIs<KitRecoveryStep.ConfirmTarget>(kits.startTyped(email, server.origin, kit, GateEntry.KIT_RECOVERY_SCREEN)))
    }

    /**
     * The check's sequence: another key for alice's own id is "the server's keys are not this account's"; then the server
     * serves alice's own seed padded at a sign-in; then the same other key again. Before: the sign-in was taken, the padded
     * seed kept, and the other key was told as a damaged copy (with the removal of the copy as its way out).
     */
    @Test fun aSeedServedPaddedAtASignInIsRefusedAndKeepsNothing() = runBlocking<Unit> {
        val e = registered()
        val lying = e.servedKitOfAnotherKey()
        assertEquals(KitRecoveryStep.Stopped(WireKitRecovery.SERVER_KEYS_NOT_KNOWN_HERE), e.verify(lying))
        val before = e.keptKeys()
        val takes = e.keeper.takes
        e.account.encryptedIdentitySeed = padded(e.account.encryptedIdentitySeed)
        assertEquals(SignIn.Refused(WireOnboarding.BAD_RESPONSE), e.onboarding().signIn(email, password.toCharArray()))
        assertEquals(takes, e.keeper.takes, "no session was taken")
        assertEquals(before, e.keptKeys(), "nothing kept was replaced")
        assertEquals(WireRoute.END_SESSION, e.transport.sent.last().route, "exactly the refused session is ended at the server")
        assertEquals(KeptPhase.LOCKED, e.keeper.phase.value)
        assertEquals(KeptUnlock.Unlocked, e.keeper.unlock(password.toCharArray()), "the copy still opens")
        e.keeper.lock()
        assertEquals(KitRecoveryStep.Stopped(WireKitRecovery.SERVER_KEYS_NOT_KNOWN_HERE), e.verify(lying), "never a damaged copy")
        assertFalse(WireRoute.RECOVERY_SELF_COMMIT in e.server.calls, "nothing was committed")
    }

    /**
     * A copy that already holds alice's own seed padded (kept before the rule) opens, so it is never judged damaged: the
     * other key is "the server's keys are not this account's" at the recovery's own check and at the keeper's floor.
     * Before: both said the copy was damaged.
     */
    @Test fun aCopyKeptWithAPaddedSeedIsNeverToldDamagedForAnotherKey() = runBlocking<Unit> {
        val e = registered()
        e.keepSeedText(padded(e.keptKeys().encryptedIdentitySeed))
        assertEquals(KeptUnlock.Unlocked, e.keeper.unlock(password.toCharArray()), "the padded seed opens")
        e.keeper.lock()
        assertFalse(KeptAccountCheck.copyDamaged(e.keptKeys(), null))
        val before = e.keptKeys()
        assertEquals(KitRecoveryStep.Stopped(WireKitRecovery.SERVER_KEYS_NOT_KNOWN_HERE), e.verify(e.servedKitOfAnotherKey()))
        assertEquals(before, e.keptKeys())

        // The keeper's own floor, under a flow that compared nothing kept: a session of alice's id under another key.
        val other = plain.randomBytes(32)
        val salt = plain.randomBytes(KdfParams.SALT_BYTES)
        val k = assertNotNull(PasswordKeys.derive(plain, password.toCharArray(), salt, KdfParams.DEFAULT, served = false))
        val made = try {
            madeAccount(e, other, k, salt)
        } finally {
            k.wipe()
        }
        e.server.accounts["alice.other@example.com"] = made
        val keeper = e.keeper
        val hidden = object : SessionSink {
            override suspend fun established(session: EstablishedSession) = keeper.established(session)
            override suspend fun take(session: EstablishedSession): String? = keeper.take(session)
        }
        val takes = e.keeper.takes
        assertEquals(SignIn.Refused(WireOnboarding.SERVER_KEYS_NOT_KNOWN_HERE), e.onboarding(hidden, identityRecord = false).signIn("alice.other@example.com", password.toCharArray()))
        assertEquals(takes, e.keeper.takes)
        assertEquals(before, e.keptKeys())
        other.fill(0)
    }

    /** A seed that really cannot be read is a damaged copy, as before. */
    @Test fun aSeedThatCannotBeReadIsStillADamagedCopy() = runBlocking<Unit> {
        val e = registered()
        e.keepSeedText("not*base64*at*all")
        assertNull(KeptAccountCheck.keptBytes(e.keptKeys().encryptedIdentitySeed))
        assertIs<KeptUnlock.IdentityFault>(e.keeper.unlock(password.toCharArray()))
        assertEquals(KitRecoveryStep.Stopped(WireKitRecovery.KEPT_COPY_DAMAGED), e.verify(e.servedKitOfAnotherKey()))
    }

    /**
     * The keeper's floor under every flow: a session whose served keys are not in their canonical form is not kept, even
     * from a flow that checked nothing (here one handed to the keeper directly), and it ends at its server.
     */
    @Test fun theKeeperKeepsNoSessionWhoseKeysAreNotCanonical() = runBlocking<Unit> {
        val e = registered()
        assertEquals(KeptUnlock.Unlocked, e.keeper.unlock(password.toCharArray()))
        val uvk = assertNotNull(e.keeper.established).account.uvk.copyOut()
        e.keeper.lock()
        val before = e.keptKeys()
        val served = e.server.keys(e.account).let { it.copy(encryptedIdentitySeed = padded(it.encryptedIdentitySeed)) }
        val opened = assertIs<AccountOpenResult.Opened>(AccountOpen.open(plain, e.userId, uvk, served, e.server.instanceId)).account
        val session = EstablishedSession(e.server.origin, email, e.userId, assertNotNull(e.keeper.session).deviceId, "member", false, false, true,
            SessionHow.PASSWORD, "at-x", "rt-x", served, opened)
        val takes = e.keeper.takes
        assertEquals(Establishing.Refused(Establishing.SERVED_KEY_FORM), e.keeper.establish(session), "the keeper's own reason")
        assertEquals(takes, e.keeper.takes)
        assertEquals(before, e.keptKeys())
        assertTrue(opened.isWiped, "the refused session's keys are wiped")
        assertEquals(WireRoute.END_SESSION, e.transport.sent.last().route)
    }

    /**
     * A wrap the server holds in another form than the canonical one (this device's own wrap, padded) is never adopted at
     * an opening, though it opens with the password: before, it was adopted and kept as served.
     */
    @Test fun aServedWrapNotInCanonicalFormIsNotAdoptedAtAnOpening() = runBlocking<Unit> {
        val e = registered()
        val own = e.keptKeys()
        e.account.wrappedUvk = padded(own.wrappedUvk)
        assertEquals(KeptUnlock.Unlocked, e.keeper.unlock(password.toCharArray()))
        e.keeper.reKeyAfterOpening(password.toCharArray()) { null }
        assertEquals(ServedWrap.NOT_THIS_DEVICES, e.keeper.lastServedWrap)
        assertEquals(own.wrappedUvk, e.keptKeys().wrappedUvk, "this device's own wrap stays")
        assertTrue(assertNotNull(e.keeper.session).serverKeysNotKnownHere)
        // A password change's answer in that form is not kept either.
        assertFalse(e.keeper.passwordChangedTo(e.userId, own.kdfSalt, own.kdfParams, padded(own.wrappedUvk)))
        assertEquals(own.wrappedUvk, e.keptKeys().wrappedUvk)
    }

    /** An account of alice's id made for [other] under the typed password: seed, identity, genesis and personal vault. */
    private fun madeAccount(e: Env, other: ByteArray, k: PasswordKeys, salt: ByteArray): FakeInstance.Account {
        val seed = plain.randomBytes(32)
        val vk = plain.randomBytes(32)
        val identity = plain.boxKeypairFromSeed(seed)
        val signing = plain.signKeypairFromSeed(seed)
        val pvid = "11111111-1111-4111-8111-111111111111"
        try {
            val idB64 = Bytes.toB64(identity.publicKey)
            return FakeInstance.Account(e.userId, k.authKeyB64, Bytes.toB64(salt), k.params, Envelope.sealB64(plain, k.wrapKey, other, Ad.uvk(e.userId)),
                Envelope.sealB64(plain, other, seed, Ad.idkey(e.userId)), idB64,
                Bytes.toB64(io.silencelen.andvari.core.trust.AccountGenesis.sign(plain, signing,
                    io.silencelen.andvari.core.trust.GenesisFields(e.userId, idB64, e.server.instanceId, pvid, e.server.now))),
                io.silencelen.andvari.core.model.wire.PersonalWrap(pvid, Envelope.sealB64(plain, other, vk, Ad.vkPersonal(pvid, e.userId))),
                e.account.memberRecovery, "made-piece")
        } finally {
            seed.fill(0)
            vk.fill(0)
            identity.privateKey.fill(0)
            signing.privateKey.fill(0)
        }
    }
}
