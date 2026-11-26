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
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AccountKeys
import io.silencelen.andvari.core.model.wire.WireRoute
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
 * Spec 01 §7, a sign-in on a device that already keeps the account (signed out by its server, locked, or with a password
 * change whose answer never came): before the sign-in replaces anything the device keeps, the key it opened from the
 * server's wrap must be that account's key as this device knows it. A kept wrap that opens with the typed password is
 * opened and its key compared; where none opens, the key must open the copy's own sealed identity seed to the identity
 * the device kept. Another key replaces nothing and keeps no session; the same key under another password signs in and
 * says so. Before, the sign-in replaced the kept wraps with whatever passed a sign-in's own checks, comparing nothing.
 */
class SignInOverKeptAccountTest {
    private val plain = createCryptoProvider()
    private val first = "correct horse Battery 9 staple"
    private val second = "a newer Password 7 for alice"
    private val email = "alice@example.com"

    /** The device's crypto, counting every Argon2id derivation it runs. */
    private class Counting(private val inner: CryptoProvider) : CryptoProvider by inner {
        var derivations = 0
        override fun argon2id(password: ByteArray, salt: ByteArray, outLen: Int, opsLimit: Long, memLimitBytes: Long): ByteArray {
            derivations++
            return inner.argon2id(password, salt, outLen, opsLimit, memLimitBytes)
        }
    }

    /** A wrap of the account's key as a server stores it: its salt, cost, wrapped key and the verifier that goes with it. */
    private class Wrap(val salt: String, val params: KdfParams, val wrapped: String, val authKey: String)

    private class Env(val server: FakeInstance, val transport: BearerTransport, val keeper: SessionKeeper, val onboarding: WireOnboarding, val crypto: Counting) {
        val account get() = server.accounts.values.single()
        val userId get() = account.userId

        /** The wrap the server holds now. */
        fun held() = Wrap(account.kdfSalt, account.kdfParams, account.wrappedUvk, account.authKey)

        /** The server holds [w] from now on (an honest change elsewhere, or a lie). */
        fun serve(w: Wrap) {
            account.authKey = w.authKey
            account.kdfSalt = w.salt
            account.kdfParams = w.params
            account.wrappedUvk = w.wrapped
        }

        /** The account's keys as this device keeps them. */
        fun keptKeys(): AccountKeys = assertNotNull(keeper.keptForSignIn(server.origin)).own

        suspend fun signIn(password: String): Pair<SignIn, Int> {
            val before = crypto.derivations
            val r = onboarding.signIn("alice@example.com", password.toCharArray())
            return r to crypto.derivations - before
        }
    }

    private suspend fun registered(): Env {
        val server = FakeInstance(plain)
        val crypto = Counting(plain)
        val state = MemoryDeviceState()
        val trust = server.pinnedTrust(state)
        val transport = BearerTransport(mapOf(server.origin to server))
        val keeper = SessionKeeper(transport, MemoryDeviceState(), state, trust, crypto)
        val o = WireOnboarding(server.origin, keeper.clientFor(server.origin), trust, KnownDevices(state, crypto), keeper, crypto, state, "android", "Pixel",
            { server.now }, knownIdentity = keeper::knownIdentity, work = Dispatchers.Unconfined)
        o.signupStart(email, true)
        val t = assertIs<SignupVerify.Ticket>(o.signupVerify(email, "482915"))
        assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(t), RegistrationForm(email, "Alice", first.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android")))
        return Env(server, transport, keeper, o, crypto)
    }

    /** [key] wrapped for [userId] under [password] at a fresh salt. */
    private fun wrapOf(key: ByteArray, userId: String, password: String, params: KdfParams = KdfParams.DEFAULT): Wrap {
        val salt = plain.randomBytes(KdfParams.SALT_BYTES)
        val keys = assertNotNull(PasswordKeys.derive(plain, password.toCharArray(), salt, params, served = false))
        try {
            return Wrap(Bytes.toB64(salt), params, Envelope.sealB64(plain, keys.wrapKey, key, Ad.uvk(userId)), keys.authKeyB64)
        } finally {
            keys.wipe()
        }
    }

    /** The open account's own key wrapped under [password]. */
    private fun Env.ownKeyUnder(password: String): Wrap {
        val uvk = assertNotNull(keeper.established).account.uvk.copyOut()
        try {
            return wrapOf(uvk, userId, password)
        } finally {
            uvk.fill(0)
        }
    }

    private fun Env.opensWith(password: String): KeptUnlock {
        keeper.lock()
        return keeper.unlock(password.toCharArray())
    }

    @Test fun anOlderPasswordsWrapServedToADeviceThatKeepsTheNewerOneSignsInAndSaysTheCopyFollowsTheServer() = runBlocking<Unit> {
        val e = registered()
        val older = e.held()
        // The password was changed on this device, and the server took it: this device keeps the newer wrap.
        val newer = e.ownKeyUnder(second)
        e.serve(newer)
        assertTrue(e.keeper.passwordChangedTo(e.userId, newer.salt, newer.params, newer.wrapped))
        // The server signs this device out and brings back the older wrap; the person types the older password.
        e.keeper.endedByServer(e.server.origin)
        e.serve(older)
        val (r, derived) = e.signIn(first)
        val signedIn = assertIs<SignIn.SignedIn>(r)
        // It is this account's key: none of the kept wraps opened with the typed password, the copy's sealed seed did.
        assertTrue(signedIn.copyUnderOtherPassword, "the result says the copy was sealed under another master password")
        assertEquals(2, derived, "the prelogin's cost, then the kept wrap's own salt (it does not open with the older password)")
        val kept = assertNotNull(e.keeper.session)
        assertFalse(kept.endedByServer)
        assertEquals(older.wrapped, e.keptKeys().wrappedUvk, "the copy now follows the server's wrap")
        assertEquals(KeptUnlock.Unlocked, e.opensWith(first))
    }

    @Test fun anotherKeyForTheSameAddressReplacesNothingAndKeepsNoSession() = runBlocking<Unit> {
        val e = registered()
        e.keeper.lock()
        val before = e.keptKeys()
        val takes = e.keeper.takes
        // A wrap the typed password opens, for this account's id, around another key.
        e.serve(wrapOf(plain.randomBytes(32), e.userId, first))
        val (r, derived) = e.signIn(first)
        assertEquals(SignIn.Refused(WireOnboarding.SERVER_KEYS_NOT_KNOWN_HERE), r)
        assertEquals(2, derived, "the prelogin's cost, then this device's own wrap under its own salt, which opens: compared, not the same key")
        assertEquals(takes, e.keeper.takes, "no session was handed over")
        assertEquals(before, e.keptKeys(), "nothing this device keeps was replaced")
        assertEquals(KeptPhase.LOCKED, e.keeper.phase.value)
        assertTrue(e.transport.sent.last().route == WireRoute.END_SESSION, "exactly the server's new session is ended there")
        assertTrue(WireRoute.LOGOUT !in e.transport.sent.map { it.route }, "no sign-out, which would end the kept session too")
        // The copy still opens with its own password, to its own keys.
        assertEquals(KeptUnlock.Unlocked, e.keeper.unlock(first.toCharArray()))
        assertEquals(before, assertNotNull(e.keeper.established).accountKeys)
    }

    @Test fun anotherKeyUnderAnotherPasswordReplacesNothingEither() = runBlocking<Unit> {
        val e = registered()
        e.keeper.endedByServer(e.server.origin)
        val before = e.keptKeys()
        // The person types another password, which the server's wrap of another key opens; no kept wrap opens with it, and
        // the other key does not open the copy's sealed seed.
        e.serve(wrapOf(plain.randomBytes(32), e.userId, second))
        val (r, derived) = e.signIn(second)
        assertEquals(SignIn.Refused(WireOnboarding.SERVER_KEYS_NOT_KNOWN_HERE), r)
        assertEquals(2, derived)
        assertEquals(before, e.keptKeys())
        assertTrue(assertNotNull(e.keeper.session).endedByServer, "the account stays as its server signed it out")
        assertEquals(KeptUnlock.Unlocked, e.opensWith(first))
    }

    @Test fun thePasswordChangedOnAnotherDeviceSignsInAndSaysTheCopyFollowsTheServer() = runBlocking<Unit> {
        val e = registered()
        // The honest road: another device changed the password, which ended this device's session.
        val changed = e.ownKeyUnder(second)
        e.serve(changed)
        e.keeper.endedByServer(e.server.origin)
        val (r, derived) = e.signIn(second)
        assertTrue(assertIs<SignIn.SignedIn>(r).copyUnderOtherPassword)
        assertEquals(2, derived)
        assertEquals(changed.wrapped, e.keptKeys().wrappedUvk)
        assertEquals(KeptUnlock.Unlocked, e.opensWith(second))
        assertEquals(KeptUnlock.WrongPassword, e.opensWith(first))
    }

    @Test fun aSignInAgainWithNothingChangedDerivesOnceAndSaysNothing() = runBlocking<Unit> {
        val e = registered()
        e.keeper.endedByServer(e.server.origin)
        val (r, derived) = e.signIn(first)
        assertFalse(assertIs<SignIn.SignedIn>(r).copyUnderOtherPassword)
        assertEquals(1, derived, "the kept wrap is at the prelogin's salt and cost: opened with the sign-in's own key")
        assertFalse(assertNotNull(e.keeper.session).endedByServer)
    }

    @Test fun aPendingChangeTheServerTookOpensWithTheNewPasswordAndSaysNothing() = runBlocking<Unit> {
        val e = registered()
        // A password change was sent from here and its answer never came; the server took it.
        val pending = e.ownKeyUnder(second)
        e.keeper.passwordChangePending(e.userId, pending.salt, pending.params, pending.wrapped)
        e.serve(pending)
        e.keeper.lock()
        val (r, derived) = e.signIn(second)
        assertFalse(assertIs<SignIn.SignedIn>(r).copyUnderOtherPassword, "the pending wrap opened with the typed password")
        assertEquals(2, derived, "the pending wrap is at the prelogin's salt; this device's own wrap costs one")
        assertEquals(pending.wrapped, e.keptKeys().wrappedUvk)
        assertNull(e.keeper.keptForSignIn(e.server.origin)?.pending)
    }

    @Test fun aServerThatKeptTheOlderWrapAgainstAPendingChangeIsTheSameKey() = runBlocking<Unit> {
        val e = registered()
        val pending = e.ownKeyUnder(second)
        e.keeper.passwordChangePending(e.userId, pending.salt, pending.params, pending.wrapped)
        e.keeper.endedByServer(e.server.origin)
        // The server still holds the first wrap; the person types the first password, which opens this device's own wrap.
        val (r, _) = e.signIn(first)
        assertFalse(assertIs<SignIn.SignedIn>(r).copyUnderOtherPassword)
    }
}
