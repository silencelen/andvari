package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.PasswordKeys
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
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
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.RecoveryKit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A session the server opened for a sign-in (or a recovery's commit) that this device then refuses is ended at the
 * server, and exactly that one: through `POST /auth/end-session` with its own refresh token, never the sign-out, which
 * ends every session of the device there, a kept one's too. And a kept session whose place a new sign-in of the same
 * account takes is ended there the same way. The server here counts its live sessions. Before: three refusals after the
 * login ended nothing, the refusal for another key signed the whole device out (the kept session too), and a replaced
 * kept session stayed open at the server.
 */
class RefusedSessionEndsTest {
    private val plain = createCryptoProvider()
    private val first = "correct horse Battery 9 staple"
    private val email = "alice@example.com"

    private class Env(
        val server: FakeInstance, val transport: BearerTransport, val keeper: SessionKeeper, val state: MemoryDeviceState, val trust: CardTrust,
        val onboarding: WireOnboarding, val typedKit: String,
    ) {
        val account get() = server.account("alice@example.com")

        /** The refresh token of the session the keeper holds. */
        fun keptRefresh(): String = assertNotNull(server.live.entries.single { it.value.deviceId == assertNotNull(keeper.session).deviceId }).key

        fun liveTokens(): Set<String> = server.live.keys.toSet()
    }

    private suspend fun registered(): Env {
        val server = FakeInstance(plain)
        server.countSessions = true
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
        keeper.lock()
        return Env(server, transport, keeper, state, trust, o, RecoveryKit.displayForm(reg.kit.secret))
    }

    /** The server's wrap of [key] under [password] for this account from now on. */
    private fun Env.serveWrapOf(key: ByteArray, password: String) {
        val salt = plain.randomBytes(KdfParams.SALT_BYTES)
        val k = assertNotNull(PasswordKeys.derive(plain, password.toCharArray(), salt, KdfParams.DEFAULT, served = false))
        try {
            account.authKey = k.authKeyB64
            account.kdfSalt = Bytes.toB64(salt)
            account.kdfParams = k.params
            account.wrappedUvk = Envelope.sealB64(plain, k.wrapKey, key, Ad.uvk(account.userId))
        } finally {
            k.wipe()
        }
    }

    /** A sign-in that the device refuses: the kept session is still live at the server, and the new one is gone. */
    private suspend fun Env.refusedLeavesOnlyTheKept(expected: SignIn) {
        val kept = keptRefresh()
        assertEquals(setOf(kept), liveTokens())
        val r = onboarding.signIn(email, first.toCharArray())
        assertEquals(expected, r)
        assertEquals(setOf(kept), liveTokens(), "the new session ended at the server, the kept one did not")
        assertTrue(WireRoute.LOGOUT !in transport.sent.map { it.route }, "no sign-out, which would end every session of the device")
        assertEquals(KeptPhase.LOCKED, keeper.phase.value)
    }

    @Test fun aWrapThatDoesNotOpenEndsTheNewSessionOnly() = runBlocking<Unit> {
        val e = registered()
        // The typed password proves (the verifier is the server's), but the wrap is sealed under no key it derives.
        e.account.wrappedUvk = Envelope.sealB64(plain, plain.randomBytes(32), plain.randomBytes(32), Ad.uvk(e.account.userId))
        e.refusedLeavesOnlyTheKept(SignIn.IdentityFault(WireOnboarding.UVK_UNOPENABLE))
    }

    @Test fun anIdentityFaultAfterTheKeptCheckEndsTheNewSessionOnly() = runBlocking<Unit> {
        val e = registered()
        // The same key and wrap, and a genesis that is not one.
        e.account.genesis = Bytes.toB64(ByteArray(40) { 3 })
        val r = e.onboarding.signIn(email, first.toCharArray())
        assertIs<SignIn.IdentityFault>(r)
        assertEquals(1, e.server.live.size)
        assertTrue(WireRoute.LOGOUT !in e.transport.sent.map { it.route })
    }

    @Test fun anotherKeyEndsTheNewSessionAndLeavesTheKeptOneLive() = runBlocking<Unit> {
        val e = registered()
        e.serveWrapOf(plain.randomBytes(32), first)
        e.refusedLeavesOnlyTheKept(SignIn.Refused(WireOnboarding.SERVER_KEYS_NOT_KNOWN_HERE))
    }

    /**
     * A sign-in that takes the kept session's place on this device's own row: the server ends that row's earlier session
     * itself (a device has one live session), and the device sends nothing with the kept session's token. Before, the
     * device ended it by that token, which an earlier refresh whose answer was lost had already made one the server
     * replaced: the server read it as a stolen token's reuse and ended the new session too.
     */
    @Test fun aSignInThatTakesTheKeptSessionsPlaceSendsNothingWithTheKeptToken() = runBlocking<Unit> {
        val e = registered()
        e.server.oneSessionPerDevice = true
        val kept = e.keptRefresh()
        val sent = e.transport.sent.size
        assertIs<SignIn.SignedIn>(e.onboarding.signIn(email, first.toCharArray()))
        val now = e.liveTokens()
        assertEquals(1, now.size, "only the new session is live")
        assertTrue(kept !in now)
        assertEquals(now.single(), e.keptRefresh())
        assertTrue(e.transport.sent.drop(sent).none { it.route == WireRoute.END_SESSION || it.route == WireRoute.LOGOUT }, "nothing ends a session from here")
    }

    /** A take that makes a new device row (a recovery's commit) still ends the kept session by its own token. */
    @Test fun aKitRecoveryOverAKeptSessionEndsItByItsOwnToken() = runBlocking<Unit> {
        val e = registered()
        e.server.oneSessionPerDevice = true
        val kits = WireKitRecovery({ e.keeper.clientFor(it) }, e.trust, KnownDevices(e.state, plain), e.keeper, plain, "android", "Pixel",
            knownIdentity = e.keeper::knownIdentity)
        val target = assertIs<KitRecoveryStep.ConfirmTarget>(kits.startTyped(email, e.server.origin, e.typedKit, GateEntry.KIT_RECOVERY_SCREEN))
        val sent = e.transport.sent.size
        assertIs<KitRecoveryStep.Recovered>(kits.commit(assertIs(kits.verify(target)), "a whole new Passphrase 42 here".toCharArray()))
        assertEquals(1, e.transport.sent.drop(sent).count { it.route == WireRoute.END_SESSION }, "the replaced session, by its own token")
    }

    /**
     * The server answers another account for the typed address (a lie): the session layer refuses it because another
     * account is kept here, and the sign-in's own answer says so (it was `SignedIn` before). The device's record of its
     * own id for the address is not rewritten, and only the new session ends at the server.
     */
    @Test fun aSessionTheKeeperRefusesIsTheSignInsRefusalAndLeavesTheDeviceRecordAlone() = runBlocking<Unit> {
        val e = registered()
        val devices = KnownDevices(e.state, plain)
        val deviceBefore = devices.deviceId(e.server.origin, email)
        // bob registers elsewhere; the server then answers bob's account for alice's address.
        val other = MemoryDeviceState()
        val ob = WireOnboarding(e.server.origin, e.server, e.server.pinnedTrust(other), KnownDevices(other, plain),
            io.silencelen.andvari.core.client.onboard.SessionSink { }, plain, other, "android", "Other", { e.server.now }, work = Dispatchers.Unconfined)
        ob.signupStart("bob@example.com", true)
        val t = assertIs<SignupVerify.Ticket>(ob.signupVerify("bob@example.com", "482915"))
        assertIs<Registration.Registered>(ob.register(RegistrationAuth.Ticket(t),
            RegistrationForm("bob@example.com", "Bob", first.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Other", "android")))
        val kept = e.keptRefresh()
        val liveBefore = e.liveTokens()
        e.server.accounts[email] = e.server.account("bob@example.com")
        val r = e.onboarding.signIn(email, first.toCharArray())
        assertEquals(SignIn.Refused(Establishing.ANOTHER_SESSION_KEPT), r)
        assertEquals(deviceBefore, devices.deviceId(e.server.origin, email), "the device's record for the address is as it was")
        assertEquals(liveBefore, e.liveTokens(), "the refused session ended; the kept one and bob's other device's are live")
        assertTrue(kept in e.liveTokens())
    }

    /** A kit recovery whose commit answer fails an identity check: the session the commit opened is ended. */
    @Test fun aKitCommitRefusedOnTheDeviceEndsItsSession() = runBlocking<Unit> {
        val e = registered()
        val kits = WireKitRecovery({ e.keeper.clientFor(it) }, e.trust, KnownDevices(e.state, plain), e.keeper, plain, "android", "Pixel",
            knownIdentity = e.keeper::knownIdentity)
        val target = assertIs<KitRecoveryStep.ConfirmTarget>(kits.startTyped(email, e.server.origin, e.typedKit, GateEntry.KIT_RECOVERY_SCREEN))
        val choose = assertIs<KitRecoveryStep.ChoosePassword>(kits.verify(target))
        // After the verify step, the server serves another identity key with the commit's session.
        e.account.identityPub = Bytes.toB64(plain.boxKeypairFromSeed(plain.randomBytes(32)).publicKey)
        assertIs<KitRecoveryStep.Stopped>(kits.commit(choose, "a whole new Passphrase 42 here".toCharArray()))
        assertTrue(e.server.live.isEmpty(), "the commit ended the account's other sessions, and the device ended the one it opened")
    }
}
