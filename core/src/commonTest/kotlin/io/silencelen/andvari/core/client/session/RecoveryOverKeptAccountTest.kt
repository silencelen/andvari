package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.items.copyOut
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.PasswordKeys
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
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
import io.silencelen.andvari.core.model.wire.RecoveryVerifyResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.trust.RecoveryKit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Spec 01 §7, a recovery with the kit on a device that already keeps the account (locked, signed out by its server, or
 * with a password change whose answer never came). The key comes from the kit, not from a password's wrap, and the person
 * recovering can open no wrap the device keeps: so no kept wrap is compared. What the copy holds sealed under the
 * account's key itself (its identity seed, to the identity key kept beside it) must still open under the key the kit
 * opened, before the commit is sent. Another key commits nothing, replaces nothing and opens no session. Before, the kit's
 * key was compared only with the device's record of the identity key, where the host passed one, and a recovery whose key
 * matched nothing kept could commit the person's new password at the server before the device refused the session.
 */
class RecoveryOverKeptAccountTest {
    private val plain = createCryptoProvider()
    private val first = "correct horse Battery 9 staple"
    private val second = "a newer Password 7 for alice"
    private val recovered = "a whole new Passphrase 42 here"
    private val email = "alice@example.com"

    private class Env(
        val server: FakeInstance, val transport: BearerTransport, val keeper: SessionKeeper, val state: MemoryDeviceState, val trust: CardTrust,
        /** The kit the registration revealed, as a person types it. */
        val typedKit: String,
    ) {
        val account get() = server.accounts.values.single()
        val userId get() = account.userId

        fun keptKeys(): AccountKeys = assertNotNull(keeper.keptForSignIn(server.origin)).own

        /** The kit recovery as the app engine builds it (with this device's record of identity keys), or with none. */
        fun kits(identityRecord: Boolean = true) = WireKitRecovery(
            { keeper.clientFor(it) }, trust, KnownDevices(state, crypto), keeper, crypto, "android", "Pixel",
            knownIdentity = if (identityRecord) keeper::knownIdentity else { _ -> null },
        )

        val crypto get() = server.crypto
    }

    private suspend fun registered(): Env {
        val server = FakeInstance(plain)
        val state = MemoryDeviceState()
        val trust = server.pinnedTrust(state)
        val transport = BearerTransport(mapOf(server.origin to server))
        val keeper = SessionKeeper(transport, MemoryDeviceState(), state, trust, plain)
        val o = WireOnboarding(server.origin, keeper.clientFor(server.origin), trust, KnownDevices(state, plain), keeper, plain, state, "android", "Pixel",
            { server.now }, knownIdentity = keeper::knownIdentity, work = Dispatchers.Unconfined)
        o.signupStart(email, true)
        val t = assertIs<SignupVerify.Ticket>(o.signupVerify(email, "482915"))
        val reg = assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(t),
            RegistrationForm(email, "Alice", first.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android")))
        return Env(server, transport, keeper, state, trust, RecoveryKit.displayForm(reg.kit.secret))
    }

    /** A typed kit through the confirmation to its verify step's answer. */
    private suspend fun Env.verify(kit: String, kits: WireKitRecovery = kits()): KitRecoveryStep {
        val target = assertIs<KitRecoveryStep.ConfirmTarget>(kits.startTyped(email, server.origin, kit, GateEntry.KIT_RECOVERY_SCREEN))
        assertNull(target.gate, "the device's pin serves the recovery")
        return kits.verify(target)
    }

    /** A kit of another key for this account's id, which the server now holds for it (a kit that lies, with its server). */
    private fun Env.servedKitOfAnotherKey(): String {
        val piece = MemberRecovery.generate(plain, userId, plain.randomBytes(32))
        try {
            account.memberRecovery = MemberRecoveryBlock(piece.recoveryWrappedUvk, piece.recoveryAuthKey)
            return RecoveryKit.displayForm(piece.recoverySecret)
        } finally {
            piece.recoverySecret.fill(0)
        }
    }

    @Test fun aKitRecoveryOverALockedCopyOfTheSameAccountRecoversAndTheCopyFollowsTheNewPassword() = runBlocking<Unit> {
        val e = registered()
        e.keeper.lock()
        val takes = e.keeper.takes
        val kits = e.kits()
        val choose = assertIs<KitRecoveryStep.ChoosePassword>(e.verify(e.typedKit, kits))
        assertIs<KitRecoveryStep.Recovered>(kits.commit(choose, recovered.toCharArray()))
        assertEquals(takes + 1, e.keeper.takes)
        assertEquals(e.account.wrappedUvk, e.keptKeys().wrappedUvk, "the copy now holds the recovery's wrap")
        e.keeper.lock()
        assertEquals(KeptUnlock.WrongPassword, e.keeper.unlock(first.toCharArray()))
        assertEquals(KeptUnlock.Unlocked, e.keeper.unlock(recovered.toCharArray()))
    }

    /**
     * Where the rule gives way, and only there: the person recovering has lost the password, so neither this device's own
     * wrap nor the wrap of an unanswered change is opened or compared. Both are replaced, because the kit's key opened the
     * copy's sealed identity seed, which no password guards.
     */
    @Test fun aKitRecoveryReplacesKeptWrapsItCannotOpenWhenTheKeyOpensTheCopysSealedSeed() = runBlocking<Unit> {
        val e = registered()
        val uvk = assertNotNull(e.keeper.established).account.uvk.copyOut()
        val pending = try {
            val salt = plain.randomBytes(KdfParams.SALT_BYTES)
            val k = assertNotNull(PasswordKeys.derive(plain, second.toCharArray(), salt, KdfParams.DEFAULT, served = false))
            try { Triple(Bytes.toB64(salt), k.params, Envelope.sealB64(plain, k.wrapKey, uvk, Ad.uvk(e.userId))) } finally { k.wipe() }
        } finally {
            uvk.fill(0)
        }
        e.keeper.passwordChangePending(e.userId, pending.first, pending.second, pending.third)
        e.keeper.endedByServer(e.server.origin)
        val kits = e.kits()
        val choose = assertIs<KitRecoveryStep.ChoosePassword>(e.verify(e.typedKit, kits))
        assertIs<KitRecoveryStep.Recovered>(kits.commit(choose, recovered.toCharArray()))
        assertNull(assertNotNull(e.keeper.keptForSignIn(e.server.origin)).pending, "the unanswered change's wrap is gone")
        assertFalse(assertNotNull(e.keeper.session).endedByServer)
        e.keeper.lock()
        assertEquals(KeptUnlock.WrongPassword, e.keeper.unlock(second.toCharArray()))
        assertEquals(KeptUnlock.Unlocked, e.keeper.unlock(recovered.toCharArray()))
    }

    @Test fun aKitThatOpensAnotherKeyCommitsNothingAndReplacesNothing() = runBlocking<Unit> {
        val e = registered()
        e.keeper.lock()
        val before = e.keptKeys()
        val takes = e.keeper.takes
        val lying = e.servedKitOfAnotherKey()
        // Before: identity_mismatch (the served seed did not open), worded as the identity fault.
        assertEquals(KitRecoveryStep.Stopped(WireKitRecovery.SERVER_KEYS_NOT_KNOWN_HERE), e.verify(lying))
        assertFalse(WireRoute.RECOVERY_SELF_COMMIT in e.server.calls, "nothing was committed")
        assertEquals(takes, e.keeper.takes)
        assertEquals(before, e.keptKeys())
        assertEquals(KeptPhase.LOCKED, e.keeper.phase.value)
        assertEquals(KeptUnlock.Unlocked, e.keeper.unlock(first.toCharArray()), "the copy still opens with its own password")
    }

    /**
     * A server that serves, for this account's id, another key under the lying kit together with a seed sealed under that
     * key and its own identity key, to a host that passes no record of identity keys: before, the verify step went on to
     * ask for a new password and the commit was sent (the server took the person's new password and made a new kit), and
     * only then did the device refuse the session. Now nothing is asked and nothing is committed.
     */
    @Test fun aConsistentLieWithNoIdentityRecordIsStoppedBeforeTheCommit() = runBlocking<Unit> {
        val e = registered()
        e.keeper.endedByServer(e.server.origin)
        val before = e.keptKeys()
        val other = plain.randomBytes(32)
        val seed = plain.randomBytes(32)
        val piece = MemberRecovery.generate(plain, e.userId, other)
        val lie = RecoveryVerifyResponse(e.userId, "ticket-${e.userId}", piece.recoveryWrappedUvk, Envelope.sealB64(plain, other, seed, Ad.idkey(e.userId)),
            Bytes.toB64(plain.boxKeypairFromSeed(seed).publicKey))
        e.server.override[WireRoute.RECOVERY_SELF_VERIFY] = WireResult.Ok(WireJson.json.encodeToString(RecoveryVerifyResponse.serializer(), lie), 200)
        val typed = RecoveryKit.displayForm(piece.recoverySecret)
        piece.recoverySecret.fill(0)
        assertEquals(KitRecoveryStep.Stopped(WireKitRecovery.SERVER_KEYS_NOT_KNOWN_HERE), e.verify(typed, e.kits(identityRecord = false)))
        assertFalse(WireRoute.RECOVERY_SELF_COMMIT in e.server.calls)
        assertEquals(before, e.keptKeys())
        assertTrue(assertNotNull(e.keeper.session).endedByServer)
        seed.fill(0)
        other.fill(0)
    }

    /**
     * The keeper itself, under every flow: a session of the kept account whose key does not open the kept copy's sealed
     * seed replaces nothing, even when the flow that opened it compared nothing (here a sign-in whose host tells it of no
     * kept copy and passes no record of identity keys, at another address the server serves the kept account's id for,
     * with a whole account made for another key: seed, identity, genesis and personal vault). Before, the keeper took it
     * and the copy was replaced by the made one.
     */
    @Test fun theKeeperReplacesNothingWithASessionOfAnotherKeyWhateverTheFlowCompared() = runBlocking<Unit> {
        val e = registered()
        e.keeper.lock()
        val before = e.keptKeys()
        val takes = e.keeper.takes
        val refusals = e.keeper.refusals
        // The made account: the kept account's id, another key, under the typed password.
        val other = plain.randomBytes(32)
        val seed = plain.randomBytes(32)
        val vk = plain.randomBytes(32)
        val identity = plain.boxKeypairFromSeed(seed)
        val signing = plain.signKeypairFromSeed(seed)
        val pvid = "11111111-1111-4111-8111-111111111111"
        val salt = plain.randomBytes(KdfParams.SALT_BYTES)
        val k = assertNotNull(PasswordKeys.derive(plain, first.toCharArray(), salt, KdfParams.DEFAULT, served = false))
        val made = try {
            val idB64 = Bytes.toB64(identity.publicKey)
            FakeInstance.Account(e.userId, k.authKeyB64, Bytes.toB64(salt), k.params, Envelope.sealB64(plain, k.wrapKey, other, Ad.uvk(e.userId)),
                Envelope.sealB64(plain, other, seed, Ad.idkey(e.userId)), idB64,
                Bytes.toB64(io.silencelen.andvari.core.trust.AccountGenesis.sign(plain, signing,
                    io.silencelen.andvari.core.trust.GenesisFields(e.userId, idB64, e.server.instanceId, pvid, e.server.now))),
                io.silencelen.andvari.core.model.wire.PersonalWrap(pvid, Envelope.sealB64(plain, other, vk, Ad.vkPersonal(pvid, e.userId))),
                e.account.memberRecovery, "made-piece")
        } finally {
            k.wipe()
            seed.fill(0)
            vk.fill(0)
            identity.privateKey.fill(0)
            signing.privateKey.fill(0)
        }
        e.server.accounts["alice.other@example.com"] = made
        val hidden = object : io.silencelen.andvari.core.client.onboard.SessionSink {
            override suspend fun established(session: io.silencelen.andvari.core.client.onboard.EstablishedSession) = e.keeper.established(session)
        }
        val o = WireOnboarding(e.server.origin, e.keeper.clientFor(e.server.origin), e.trust, KnownDevices(e.state, plain), hidden, plain, e.state, "android", "Pixel",
            { e.server.now }, work = Dispatchers.Unconfined)
        o.signIn("alice.other@example.com", first.toCharArray())
        assertEquals(takes, e.keeper.takes, "the keeper took no session")
        assertEquals(refusals + 1, e.keeper.refusals)
        assertEquals(before, e.keptKeys(), "nothing kept was replaced")
        assertEquals(KeptPhase.LOCKED, e.keeper.phase.value)
        assertEquals(WireRoute.END_SESSION, e.transport.sent.last().route, "exactly the refused session is ended at the server")
        assertEquals(KeptUnlock.Unlocked, e.keeper.unlock(first.toCharArray()))
        other.fill(0)
    }

    /**
     * The kept account is held on this device as its server's operator account. A recovery with the kit of that very
     * account, and a sign-in to it, stop with a reason of their own whose way out is removing the held account from this
     * device. Before, both said "another account is kept", whose way out (signing it out) does not exist for a held account.
     */
    @Test fun aDeviceHoldingItsServersOperatorAccountSaysSoAtARecoveryAndASignInOfThatAccount() = runBlocking<Unit> {
        val e = registered()
        e.keeper.holdAsOperator()
        assertEquals(Establishing.OPERATOR_ACCOUNT_HELD, e.keeper.wouldRefuse(e.server.origin, email, e.userId, null))
        val sent = e.server.calls.size
        val kits = e.kits()
        assertEquals(KitRecoveryStep.Stopped(WireKitRecovery.OPERATOR_ACCOUNT_HELD),
            kits.startTyped(email, e.server.origin, e.typedKit, GateEntry.KIT_RECOVERY_SCREEN))
        assertEquals(sent, e.server.calls.size, "nothing was sent")
        val o = WireOnboarding(e.server.origin, e.keeper.clientFor(e.server.origin), e.trust, KnownDevices(e.state, plain), e.keeper, plain, e.state, "android", "Pixel",
            { e.server.now }, knownIdentity = e.keeper::knownIdentity, work = Dispatchers.Unconfined)
        assertEquals(io.silencelen.andvari.core.client.onboard.SignIn.Refused(WireOnboarding.OPERATOR_ACCOUNT_HELD), o.signIn(email, first.toCharArray()))
        assertTrue(assertNotNull(e.keeper.session).heldAsOperator, "the held account stays as it was")
        assertEquals(WireRoute.END_SESSION, e.transport.sent.last().route, "exactly the refused session is ended at the server")
    }

    /** A kit recovery on a device that keeps no copy of the account is as before. */
    @Test fun aKitRecoveryOnADeviceThatKeepsNothingIsAsBefore() = runBlocking<Unit> {
        val e = registered()
        val fresh = MemoryDeviceState()
        val trust = e.server.pinnedTrust(fresh)
        val keeper = SessionKeeper(BearerTransport(mapOf(e.server.origin to e.server)), MemoryDeviceState(), fresh, trust, plain)
        val kits = WireKitRecovery({ keeper.clientFor(it) }, trust, KnownDevices(fresh, plain), keeper, plain, "android", "New", knownIdentity = keeper::knownIdentity)
        val target = assertIs<KitRecoveryStep.ConfirmTarget>(kits.startTyped(email, e.server.origin, e.typedKit, GateEntry.KIT_RECOVERY_SCREEN))
        assertIs<KitRecoveryStep.Recovered>(kits.commit(assertIs(kits.verify(target)), recovered.toCharArray()))
        assertEquals(1L, keeper.takes)
    }
}
