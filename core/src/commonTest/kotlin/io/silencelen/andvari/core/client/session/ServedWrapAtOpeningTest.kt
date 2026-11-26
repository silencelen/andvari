package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.account.ReauthKey
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
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Spec 01 §7, the pending-record rule, for a served wrap that is neither this device's own nor its pending one: at an
 * opening with the full master password and the server reachable, the password it verified is tried against the served
 * wrap under the served salt and cost (inside the fence), and the wrap is adopted only when it opens to exactly the
 * account key this device holds. Before, such a wrap was left as it was: after a server answered "done" to a re-key it
 * never stored, or stored one and answered with a refusal, every proof this device made on its session derived under
 * the wrong salt and was refused as a wrong password, until the person signed in again.
 */
class ServedWrapAtOpeningTest {
    private val plain = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val up = KdfParams(ops = 4, memBytes = 64L * 1024 * 1024)

    /** The device's crypto, counting every Argon2id derivation it runs (and the cost of each), with a hook inside one. */
    private class Counting(private val inner: CryptoProvider) : CryptoProvider by inner {
        val costs = ArrayList<Pair<Long, Long>>()
        var during: (() -> Unit)? = null

        override fun argon2id(password: ByteArray, salt: ByteArray, outLen: Int, opsLimit: Long, memLimitBytes: Long): ByteArray {
            costs += opsLimit to memLimitBytes
            val out = inner.argon2id(password, salt, outLen, opsLimit, memLimitBytes)
            during?.let { during = null; it() }
            return out
        }
    }

    private class Env(
        val server: FakeInstance, val liar: QuietReKeyTest.Liar, val keeper: SessionKeeper, val crypto: Counting,
        val clocks: TestClocks, val policies: KeptPolicies, val quick: QuickUnlockKeeper,
    ) {
        val account get() = server.accounts.values.single()
        val userId get() = account.userId

        fun lockAndUnlock(password: String): KeptUnlock {
            keeper.lock()
            return keeper.unlock(password.toCharArray())
        }

        suspend fun reKey(password: CharArray): ReKeyOutcome =
            keeper.reKeyAfterOpening(password) { policies.fetch(it, clocks.wall)?.kdfParams }

        /** The wrap this device keeps as its own, as the open session holds it. */
        fun ownWrap(): String = assertNotNull(keeper.established).accountKeys.wrappedUvk

        val notKnown get() = assertNotNull(keeper.session).serverKeysNotKnownHere
    }

    private suspend fun registered(): Env {
        val server = FakeInstance(plain)
        val liar = QuietReKeyTest.Liar(server)
        val crypto = Counting(plain)
        val state = MemoryDeviceState()
        val secure = MemoryDeviceState()
        val trust = server.pinnedTrust(state)
        val keeper = SessionKeeper(BearerTransport(mapOf(server.origin to liar)), secure, state, trust, crypto)
        val clocks = TestClocks()
        val policies = KeptPolicies(state)
        val quick = QuickUnlockKeeper(keeper, TestKeyWrap(), secure, state, trust, policies, clocks, crypto)
        val o = WireOnboarding(server.origin, keeper.clientFor(server.origin), trust, KnownDevices(state, crypto), keeper, crypto, state, "android", "Pixel",
            { server.now }, knownIdentity = keeper::knownIdentity, work = Dispatchers.Unconfined)
        o.signupStart("alice@example.com", true)
        val t = assertIs<SignupVerify.Ticket>(o.signupVerify("alice@example.com", "482915"))
        val form = RegistrationForm("alice@example.com", "Alice", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android")
        assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(t), form))
        assertNotNull(policies.fetch(keeper.clientFor(server.origin), clocks.wall))
        return Env(server, liar, keeper, crypto, clocks, policies, quick)
    }

    private fun pw() = strong.toCharArray()

    /** The proof this device makes on its session now, as the server's verifier would check it. */
    private suspend fun Env.proofAccepted(): Boolean =
        assertIs<ReauthKey.Key>(assertNotNull(keeper.reauth()).currentAuthKey(pw())).currentAuthKey == account.authKey

    /**
     * A wrap made with [password] under a fresh salt at [params], sealing [key] for the account [adUser]: one the server
     * could only hand back if the person's password made it.
     */
    private fun wrapOf(key: ByteArray, adUser: String, params: KdfParams = KdfParams.DEFAULT, password: String = strong): Pair<String, String> {
        val salt = plain.randomBytes(KdfParams.SALT_BYTES)
        val keys = assertNotNull(PasswordKeys.derive(plain, password.toCharArray(), salt, params, served = false))
        try {
            return Bytes.toB64(salt) to Envelope.sealB64(plain, keys.wrapKey, key, Ad.uvk(adUser))
        } finally {
            keys.wipe()
        }
    }

    private fun Env.serve(salt: String, params: KdfParams, wrapped: String) {
        account.kdfSalt = salt
        account.kdfParams = params
        account.wrappedUvk = wrapped
    }

    /** A re-key the server answered "done" and never stored: this device keeps the wrap it sent, the server its old one. */
    private suspend fun doneNeverStored(): Env {
        val e = registered()
        e.server.policyKdf = up
        e.liar.change = QuietReKeyTest.Change.DONE_NOT_APPLIED
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(ReKeyOutcome.DONE, e.reKey(pw()))
        e.liar.change = QuietReKeyTest.Change.PASS
        assertEquals(KdfParams.DEFAULT, e.account.kdfParams, "the server kept its old wrap")
        assertEquals(up, e.keeper.accountKdfParams(), "and this device took the one it sent")
        return e
    }

    @Test fun aDoneThatWasNeverStoredIsSettledAtTheNextOpeningAndTheSessionsProofIsAccepted() = runBlocking<Unit> {
        val e = doneNeverStored()
        assertFalse(e.proofAccepted(), "before the next opening, this device's proof is under a salt the server does not hold")
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(ReKeyOutcome.DONE, e.reKey(pw()), "the served wrap was adopted, so the re-key is due again and goes for real")
        assertEquals(ServedWrap.ADOPTED, e.keeper.lastServedWrap)
        assertFalse(e.notKnown)
        assertEquals(up, e.account.kdfParams, "the server holds the policy's cost now")
        assertTrue(e.proofAccepted(), "a proof on the session is accepted")
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(e.account.wrappedUvk, e.ownWrap())
        assertEquals(ReKeyOutcome.NOT_DUE, e.reKey(pw()))
        assertEquals(ServedWrap.KNOWN, e.keeper.lastServedWrap)
    }

    @Test fun aStoredChangeAnsweredWithARefusalIsSettledAtTheNextOpeningAndTheSessionsProofIsAccepted() = runBlocking<Unit> {
        val e = registered()
        e.server.policyKdf = up
        e.liar.change = QuietReKeyTest.Change.REFUSE_APPLIED
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(ReKeyOutcome.REFUSED, e.reKey(pw()))
        e.liar.change = QuietReKeyTest.Change.PASS
        assertEquals(up, e.account.kdfParams, "the server stored it")
        assertEquals(KdfParams.DEFAULT, e.keeper.accountKdfParams(), "this device dropped it, as a refusal says")
        assertFalse(e.proofAccepted())
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(ReKeyOutcome.NOT_DUE, e.reKey(pw()), "the adopted wrap is at the policy's cost already")
        assertEquals(ServedWrap.ADOPTED, e.keeper.lastServedWrap)
        assertEquals(up, e.keeper.accountKdfParams())
        assertTrue(e.proofAccepted())
        assertEquals(1, e.liar.changes, "nothing more was sent")
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(e.account.wrappedUvk, e.ownWrap())
    }

    @Test fun aServedWrapAtACostOutsideTheFenceIsNeverDerivedAt() = runBlocking<Unit> {
        val e = registered()
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        val own = e.ownWrap()
        val ownSalt = e.account.kdfSalt
        val mib = 1024L * 1024
        // A ragged cost passes the floor and the ceiling; the wrap here really opens with the password at that cost.
        val ragged = KdfParams(ops = 3, memBytes = 64 * mib + 1)
        val uvk = assertNotNull(e.keeper.established).account.uvk.copyOut()
        val raggedWrap = wrapOf(uvk, e.userId, ragged)
        uvk.fill(0)
        val rows = listOf(
            KdfParams(ops = 11, memBytes = 64 * mib) to wrapOf(ByteArray(32) { 7 }, e.userId),
            KdfParams(ops = 3, memBytes = 2048 * mib) to wrapOf(ByteArray(32) { 7 }, e.userId),
            KdfParams(ops = 3, memBytes = 32 * mib) to wrapOf(ByteArray(32) { 7 }, e.userId),
            KdfParams(ops = 2, memBytes = 64 * mib) to wrapOf(ByteArray(32) { 7 }, e.userId),
            ragged to raggedWrap,
        )
        for ((params, wrap) in rows) {
            e.serve(wrap.first, params, wrap.second)
            assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
            e.crypto.costs.clear()
            assertEquals(ReKeyOutcome.NOT_DUE, e.reKey(pw()), "$params")
            assertEquals(emptyList(), e.crypto.costs, "no derivation ran for $params")
            assertEquals(ServedWrap.NOT_THIS_DEVICES, e.keeper.lastServedWrap, "$params")
            assertTrue(e.notKnown, "$params")
            assertEquals(own, e.ownWrap(), "$params")
        }
        assertEquals(0, e.liar.changes)
        // The server serves this device's wrap again: known, and the mark goes.
        e.serve(ownSalt, KdfParams.DEFAULT, own)
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(ReKeyOutcome.NOT_DUE, e.reKey(pw()))
        assertEquals(ServedWrap.KNOWN, e.keeper.lastServedWrap)
        assertFalse(e.notKnown)
        assertTrue(e.proofAccepted())
    }

    @Test fun aServedWrapThatOpensToAnotherKeyOrNotAtAllChangesNothing() = runBlocking<Unit> {
        val e = registered()
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        val own = e.ownWrap()
        val ownSalt = e.account.kdfSalt
        val cases = mapOf(
            // Made with the person's own password, for this account, around another key: it opens, to the wrong key.
            "another key under this account's name" to wrapOf(plain.randomBytes(32), e.userId),
            // Another account's wrap under the same password: it does not open for this account.
            "another account's wrap" to wrapOf(plain.randomBytes(32), "00000000-0000-4000-8000-000000000042"),
            // Another password altogether.
            "another password's wrap" to wrapOf(plain.randomBytes(32), e.userId, password = "a different master password 5 Q"),
        )
        for ((what, wrap) in cases) {
            e.serve(wrap.first, KdfParams.DEFAULT, wrap.second)
            assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
            e.crypto.costs.clear()
            assertEquals(ReKeyOutcome.NOT_DUE, e.reKey(pw()), what)
            assertEquals(listOf(KdfParams.DEFAULT.ops to KdfParams.DEFAULT.memBytes), e.crypto.costs, "tried once, at the served cost: $what")
            assertEquals(ServedWrap.NOT_THIS_DEVICES, e.keeper.lastServedWrap, what)
            assertTrue(e.notKnown, what)
            assertEquals(own, e.ownWrap(), what)
            assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong), "the same password still opens this device: $what")
            assertEquals(own, e.ownWrap(), what)
        }
        assertEquals(0, e.liar.changes)
        e.serve(ownSalt, KdfParams.DEFAULT, own)
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        e.reKey(pw())
        assertEquals(ServedWrap.KNOWN, e.keeper.lastServedWrap)
        assertFalse(e.notKnown)
    }

    @Test fun aServedWrapThatOpensToAnotherKeyWhileAChangeIsPendingLeavesBoth() = runBlocking<Unit> {
        val e = registered()
        e.server.policyKdf = up
        e.liar.change = QuietReKeyTest.Change.LOSE_NOT_APPLIED
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(ReKeyOutcome.UNKNOWN, e.reKey(pw()))
        assertTrue(e.keeper.hasPendingWrap(e.userId))
        e.liar.change = QuietReKeyTest.Change.PASS
        val own = e.ownWrap()
        val ownSalt = e.account.kdfSalt
        val foreign = wrapOf(plain.randomBytes(32), e.userId)
        e.serve(foreign.first, KdfParams.DEFAULT, foreign.second)
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(ReKeyOutcome.UNSETTLED, e.reKey(pw()), "nothing is sent while the pending change cannot be settled")
        assertEquals(ServedWrap.NOT_THIS_DEVICES, e.keeper.lastServedWrap)
        assertTrue(e.notKnown)
        assertTrue(e.keeper.hasPendingWrap(e.userId), "both wraps kept")
        assertEquals(own, e.ownWrap())
        assertEquals(1, e.liar.changes)
        // The server serves this device's own wrap again: the pending change is dropped, and the re-key goes.
        e.serve(ownSalt, KdfParams.DEFAULT, own)
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(ReKeyOutcome.DONE, e.reKey(pw()))
        assertEquals(ServedWrap.KNOWN, e.keeper.lastServedWrap)
        assertFalse(e.notKnown)
        assertFalse(e.keeper.hasPendingWrap(e.userId))
        assertTrue(e.proofAccepted())
    }

    @Test fun aLockDuringTheReadOrDuringTheTryChangesNothingAndTheNextOpeningSettlesIt() = runBlocking<Unit> {
        // During the keys read: nothing derived, nothing adopted.
        run {
            val e = doneNeverStored()
            val own = e.keeper.accountKdfParams()
            assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
            e.liar.beforeKeys = { e.keeper.lock() }
            e.crypto.costs.clear()
            assertEquals(ReKeyOutcome.STALE, e.reKey(pw()))
            e.liar.beforeKeys = null
            assertEquals(ServedWrap.STALE, e.keeper.lastServedWrap)
            assertEquals(emptyList(), e.crypto.costs)
            assertEquals(KeptPhase.LOCKED, e.keeper.phase.value)
            assertEquals(own, e.keeper.accountKdfParams(), "nothing adopted")
            assertFalse(e.notKnown, "a lock is not a verdict on the server's keys")
            assertEquals(KeptUnlock.Unlocked, e.keeper.unlock(pw()))
            assertEquals(ReKeyOutcome.DONE, e.reKey(pw()))
            assertEquals(ServedWrap.ADOPTED, e.keeper.lastServedWrap)
            assertTrue(e.proofAccepted())
        }
        // During the derivation of the try: the account's key is gone when it would be compared, and nothing is adopted.
        run {
            val e = doneNeverStored()
            val ownParams = e.keeper.accountKdfParams()
            assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
            val own = e.ownWrap()
            e.crypto.during = { e.keeper.lock() }
            assertEquals(ReKeyOutcome.STALE, e.reKey(pw()))
            assertEquals(ServedWrap.STALE, e.keeper.lastServedWrap)
            assertEquals(KeptPhase.LOCKED, e.keeper.phase.value)
            assertEquals(ownParams, e.keeper.accountKdfParams(), "nothing adopted")
            assertFalse(e.notKnown)
            assertEquals(1, e.liar.changes, "nothing sent after the first re-key")
            assertEquals(KeptUnlock.Unlocked, e.keeper.unlock(pw()))
            assertEquals(own, e.ownWrap())
            assertEquals(ReKeyOutcome.DONE, e.reKey(pw()))
            assertEquals(ServedWrap.ADOPTED, e.keeper.lastServedWrap)
            assertTrue(e.proofAccepted())
        }
    }

    @Test fun aQuickUnlockTriesNothing() = runBlocking<Unit> {
        val e = registered()
        assertEquals(QuickEnrolOutcome.ENROLLED, e.quick.enrol())
        e.server.policyKdf = up
        e.liar.change = QuietReKeyTest.Change.DONE_NOT_APPLIED
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(ReKeyOutcome.DONE, e.reKey(pw()))
        e.liar.change = QuietReKeyTest.Change.PASS
        e.keeper.lock()
        assertEquals(QuickUnlockOutcome.UNLOCKED, e.quick.unlock())
        val reads = e.liar.keysReads
        e.crypto.costs.clear()
        assertEquals(ReKeyOutcome.NOT_FULL_PASSWORD, e.reKey(pw()))
        assertEquals(ServedWrap.NOT_READ, e.keeper.lastServedWrap)
        assertEquals(reads, e.liar.keysReads, "no keys read")
        assertEquals(emptyList(), e.crypto.costs, "nothing derived")
        assertEquals(up, e.keeper.accountKdfParams(), "nothing adopted")
        // The next opening with the password settles it.
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(ReKeyOutcome.DONE, e.reKey(pw()))
        assertEquals(ServedWrap.ADOPTED, e.keeper.lastServedWrap)
        assertTrue(e.proofAccepted())
    }

    @Test fun offlineNothingIsTriedAndTheNextOnlineOpeningSettlesIt() = runBlocking<Unit> {
        val e = doneNeverStored()
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        e.liar.keysNoAnswer = 1
        e.liar.policyAnswers = false
        e.crypto.costs.clear()
        assertEquals(ReKeyOutcome.NO_POLICY, e.reKey(pw()))
        assertEquals(ServedWrap.NOT_READ, e.keeper.lastServedWrap)
        assertEquals(emptyList(), e.crypto.costs)
        assertEquals(up, e.keeper.accountKdfParams(), "nothing adopted")
        assertFalse(e.notKnown)
        e.liar.policyAnswers = true
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(ReKeyOutcome.DONE, e.reKey(pw()))
        assertEquals(ServedWrap.ADOPTED, e.keeper.lastServedWrap)
        assertNotEquals(KdfParams.DEFAULT, e.account.kdfParams)
        assertTrue(e.proofAccepted())
    }

    /**
     * "Known" means the same salt, cost and wrapped key together. Before, the wrapped key alone was compared, so this
     * device's own wrap served under another salt or at another cost was taken as known, with nothing derived and the
     * mark of keys this device does not know cleared.
     */
    @Test fun theOwnWrapsBytesAtAnotherSaltOrCostAreNotKnownAndGoThroughTheOpenAndTheComparison() = runBlocking<Unit> {
        val e = registered()
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        val own = e.ownWrap()
        val ownSalt = e.account.kdfSalt
        val otherSalt = Bytes.toB64(plain.randomBytes(KdfParams.SALT_BYTES))
        val variants = listOf(
            "another salt" to (otherSalt to KdfParams.DEFAULT),
            "another cost" to (ownSalt to up),
        )
        for ((what, served) in variants) {
            val (salt, params) = served
            e.serve(salt, params, own)
            assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
            e.crypto.costs.clear()
            assertEquals(ReKeyOutcome.NOT_DUE, e.reKey(pw()), what)
            assertEquals(listOf(params.ops to params.memBytes), e.crypto.costs, "tried once, at the served cost: $what")
            assertEquals(ServedWrap.NOT_THIS_DEVICES, e.keeper.lastServedWrap, what)
            assertTrue(e.notKnown, what)
            assertEquals(own, e.ownWrap(), what)
            assertEquals(KdfParams.DEFAULT, e.keeper.accountKdfParams(), "nothing adopted: $what")
        }
        assertEquals(0, e.liar.changes)
        // All three together: known, with nothing derived, and the mark goes.
        e.serve(ownSalt, KdfParams.DEFAULT, own)
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        e.crypto.costs.clear()
        assertEquals(ReKeyOutcome.NOT_DUE, e.reKey(pw()))
        assertEquals(emptyList(), e.crypto.costs)
        assertEquals(ServedWrap.KNOWN, e.keeper.lastServedWrap)
        assertFalse(e.notKnown)
        assertTrue(e.proofAccepted())
    }

    @Test fun nothingOfThePasswordOutlivesTheTry() = runBlocking<Unit> {
        fun wiped(a: CharArray) = a.all { it == '\u0000' }
        for (setup in listOf<suspend () -> Env>({ doneNeverStored() }, { registered().also { it.serve(it.account.kdfSalt, KdfParams.DEFAULT, wrapOf(plain.randomBytes(32), it.userId).second) } })) {
            val e = setup()
            assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
            val a = pw()
            e.reKey(a)
            assertTrue(wiped(a))
        }
    }
}
