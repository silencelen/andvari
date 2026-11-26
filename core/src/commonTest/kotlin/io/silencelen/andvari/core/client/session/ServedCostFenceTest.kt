package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.KdfPolicyViolationException
import io.silencelen.andvari.core.client.KdfUpgrade
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.account.ReauthKey
import io.silencelen.andvari.core.client.onboard.AccountOpen
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.PasswordOpen
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Every hashing cost a server serves passes the whole fence before anything is derived at it: never below the floor,
 * never above the ceiling, and a memory cost that is a whole number of KiB (spec 01 §7; the rule of 2026-11-17). The
 * reason given for the KiB clause (the Argon2id engines round a ragged cost differently, so the same password opens on
 * one client and reads as wrong on another) holds for every served cost, not only for a re-key's target and a served
 * wrap's try. Before, the sign-in, the unlock of a kept cost, the session's own proof and the command-line tool's
 * reopen checked the floor and the ceiling only, and derived at a ragged cost. And the step that looks at a served wrap
 * runs once per opening: before, each call of the keeper's routine read the keys and tried the served wrap again.
 */
class ServedCostFenceTest {
    private val plain = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val ragged = KdfParams(ops = 3, memBytes = 64L * 1024 * 1024 + 1)

    /** The device's crypto, counting every Argon2id derivation it runs. */
    private class Counting(private val inner: CryptoProvider) : CryptoProvider by inner {
        val costs = ArrayList<Pair<Long, Long>>()
        override fun argon2id(password: ByteArray, salt: ByteArray, outLen: Int, opsLimit: Long, memLimitBytes: Long): ByteArray {
            costs += opsLimit to memLimitBytes
            return inner.argon2id(password, salt, outLen, opsLimit, memLimitBytes)
        }
    }

    private class Env(val server: FakeInstance, val liar: QuietReKeyTest.Liar, val keeper: SessionKeeper, val crypto: Counting, val clocks: TestClocks, val policies: KeptPolicies) {
        val account get() = server.accounts.values.single()
        suspend fun reKey(): ReKeyOutcome = keeper.reKeyAfterOpening("correct horse Battery 9 staple".toCharArray()) { policies.fetch(it, clocks.wall)?.kdfParams }
    }

    private suspend fun device(server: FakeInstance, crypto: CryptoProvider, state: MemoryDeviceState = MemoryDeviceState()): Pair<SessionKeeper, WireOnboarding> {
        val trust = server.pinnedTrust(state)
        val keeper = SessionKeeper(BearerTransport(mapOf(server.origin to QuietReKeyTest.Liar(server))), MemoryDeviceState(), state, trust, crypto)
        val o = WireOnboarding(server.origin, keeper.clientFor(server.origin), trust, KnownDevices(state, crypto), keeper, crypto, state, "android", "Pixel",
            { server.now }, knownIdentity = keeper::knownIdentity, work = Dispatchers.Unconfined)
        return keeper to o
    }

    private suspend fun registered(): Env {
        val server = FakeInstance(plain)
        val liar = QuietReKeyTest.Liar(server)
        val crypto = Counting(plain)
        val state = MemoryDeviceState()
        val trust = server.pinnedTrust(state)
        val keeper = SessionKeeper(BearerTransport(mapOf(server.origin to liar)), MemoryDeviceState(), state, trust, crypto)
        val clocks = TestClocks()
        val policies = KeptPolicies(state)
        val o = WireOnboarding(server.origin, keeper.clientFor(server.origin), trust, KnownDevices(state, crypto), keeper, crypto, state, "android", "Pixel",
            { server.now }, knownIdentity = keeper::knownIdentity, work = Dispatchers.Unconfined)
        o.signupStart("alice@example.com", true)
        val t = assertIs<SignupVerify.Ticket>(o.signupVerify("alice@example.com", "482915"))
        val form = RegistrationForm("alice@example.com", "Alice", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android")
        assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(t), form))
        assertNotNull(policies.fetch(keeper.clientFor(server.origin), clocks.wall))
        return Env(server, liar, keeper, crypto, clocks, policies)
    }

    @Test fun theFenceRefusesARaggedServedCostAsTheServersFault() {
        val e = assertFailsWith<KdfPolicyViolationException> { KdfUpgrade.requireServerKdfParams(ragged) }
        assertEquals(KdfUpgrade.NOT_KIB, e.reason)
        KdfUpgrade.requireServerKdfParams(KdfParams(ops = 3, memBytes = 64L * 1024 * 1024 + 1024))
    }

    @Test fun aSecondCallInTheSameOpeningReadsNothingAndDerivesNothing() = runBlocking<Unit> {
        val e = registered()
        e.keeper.lock()
        assertEquals(KeptUnlock.Unlocked, e.keeper.unlock(strong.toCharArray()))
        // A served wrap that is not this device's own: the first call reads the keys and tries it once.
        val own = assertNotNull(e.keeper.established).accountKeys
        e.account.wrappedUvk = "x" + own.wrappedUvk.drop(1)
        val reads = e.liar.keysReads
        e.crypto.costs.clear()
        assertEquals(ReKeyOutcome.NOT_DUE, e.reKey())
        assertEquals(reads + 1, e.liar.keysReads)
        assertEquals(1, e.crypto.costs.size, "the try, once")
        assertEquals(ServedWrap.NOT_THIS_DEVICES, e.keeper.lastServedWrap)
        // Again, in the same opening: nothing read, nothing derived, nothing sent.
        e.crypto.costs.clear()
        for (i in 1..3) assertEquals(ReKeyOutcome.ALREADY_RAN, e.reKey(), "call ${i + 1}")
        assertEquals(reads + 1, e.liar.keysReads, "the keys were read once")
        assertEquals(emptyList(), e.crypto.costs, "nothing was derived again")
        assertEquals(0, e.liar.changes)
        // The next opening runs it again, once.
        e.keeper.lock()
        assertEquals(KeptUnlock.Unlocked, e.keeper.unlock(strong.toCharArray()))
        e.crypto.costs.clear()
        assertEquals(ReKeyOutcome.NOT_DUE, e.reKey())
        assertEquals(reads + 2, e.liar.keysReads)
        assertEquals(1, e.crypto.costs.size)
        assertEquals(ReKeyOutcome.ALREADY_RAN, e.reKey())
        assertEquals(reads + 2, e.liar.keysReads)
    }

    @Test fun aSignInAtARaggedServedCostDerivesNothingAndSendsNothing() = runBlocking<Unit> {
        val e = registered()
        e.account.kdfParams = ragged
        val crypto = Counting(plain)
        val (_, o) = device(e.server, crypto)
        val before = e.server.calls.count { it == WireRoute.LOGIN }
        assertEquals(SignIn.Refused(WireOnboarding.KDF_REFUSED), o.signIn("alice@example.com", strong.toCharArray(), null))
        assertEquals(emptyList(), crypto.costs, "nothing was derived at the ragged cost")
        assertEquals(before, e.server.calls.count { it == WireRoute.LOGIN }, "no proof was sent")
    }

    @Test fun anUnlockAndTheSessionsProofAtARaggedKeptCostDeriveNothingAndAreNeverAWrongPassword() = runBlocking<Unit> {
        val e = registered()
        val keys = assertNotNull(e.keeper.established).accountKeys
        // A kept record whose cost is ragged (only a server could have put it there): the record keeps that cost.
        assertTrue(e.keeper.passwordChangedTo(e.account.userId, keys.kdfSalt, ragged, keys.wrappedUvk))
        assertEquals(ragged, e.keeper.accountKdfParams())
        e.crypto.costs.clear()
        val proof = assertNotNull(e.keeper.reauth()).currentAuthKey(strong.toCharArray())
        assertNotEquals<ReauthKey>(ReauthKey.WrongPassword, proof, "never a wrong password")
        assertEquals(ReauthKey.Refused, proof)
        assertEquals(emptyList(), e.crypto.costs, "the proof derived nothing")
        e.keeper.lock()
        assertEquals(KeptUnlock.KdfRefused, e.keeper.unlock(strong.toCharArray()), "the server's fault, never a wrong password")
        assertEquals(emptyList(), e.crypto.costs, "the unlock derived nothing")
    }

    @Test fun aReopenOfServedKeysAtARaggedCostDerivesNothing() = runBlocking<Unit> {
        val e = registered()
        val keys = e.server.keys(e.account).copy(kdfParams = ragged)
        val crypto = Counting(plain)
        assertEquals(PasswordOpen.Refused(PasswordOpen.KDF_REFUSED), AccountOpen.openWithPassword(crypto, e.account.userId, strong.toCharArray(), keys, e.server.instanceId))
        assertEquals(emptyList(), crypto.costs)
    }
}
