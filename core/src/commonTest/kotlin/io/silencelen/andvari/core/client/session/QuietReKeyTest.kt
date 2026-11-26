package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.account.ReauthKey
import io.silencelen.andvari.core.client.items.copyOut
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AccountKeys
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
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
 * Spec 01 §7, "KDF upgrade", on the engine's own session ([SessionKeeper.reKeyAfterOpening], [QuietReKey]): after an
 * opening with the full master password, a policy that legitimately raises the KDF cost has the account's key wrapped
 * again under the same password at that cost, by the pending-record rule; every rule of the specification pinned here,
 * and the account opening with the same password whatever the server answered.
 */
class QuietReKeyTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val up = KdfParams(ops = 4, memBytes = 64L * 1024 * 1024)

    /** How [Liar] treats a password change. */
    enum class Change { PASS, LOSE_APPLIED, LOSE_NOT_APPLIED, ERROR_NOT_APPLIED, ERROR_APPLIED, REFUSE, REFUSE_APPLIED, DONE_NOT_APPLIED }

    /** The server, with what a test makes it do to a password change, a policy read and a keys read. */
    class Liar(private val inner: FakeInstance) : WireClient by inner {
        var change = Change.PASS
        var beforeChange: (suspend () -> Unit)? = null
        var policyAnswers = true
        var keysNoAnswer = 0
        var beforeKeys: (suspend () -> Unit)? = null
        val changes get() = inner.calls.count { it == WireRoute.PASSWORD_CHANGE }
        val keysReads get() = inner.calls.count { it == WireRoute.ACCOUNT_KEYS }

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            if (route == WireRoute.CLIENT_POLICY && !policyAnswers) return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
            if (route == WireRoute.ACCOUNT_KEYS) beforeKeys?.invoke()
            if (route == WireRoute.ACCOUNT_KEYS && keysNoAnswer > 0) {
                keysNoAnswer--
                return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
            }
            if (route != WireRoute.PASSWORD_CHANGE) return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
            beforeChange?.invoke()
            val refused = WireResult.Refused(403, WireError("reauth_failed", "reauth_failed"))
            return when (change) {
                Change.PASS -> inner.call(route, pathParams, query, bodyJson, authenticated, decode)
                Change.LOSE_APPLIED -> inner.call(route, pathParams, query, bodyJson, authenticated, decode).let { WireResult.NoAnswer(NoAnswerKind.TIMEOUT) }
                Change.LOSE_NOT_APPLIED -> WireResult.NoAnswer(NoAnswerKind.TRANSPORT).also { inner.calls += route }
                Change.ERROR_NOT_APPLIED -> WireResult.Refused(500, WireError("internal", "internal")).also { inner.calls += route }
                Change.ERROR_APPLIED -> inner.call(route, pathParams, query, bodyJson, authenticated, decode).let { WireResult.Refused(500, WireError("internal", "internal")) }
                Change.REFUSE -> refused.also { inner.calls += route }
                Change.REFUSE_APPLIED -> inner.call(route, pathParams, query, bodyJson, authenticated, decode).let { refused }
                Change.DONE_NOT_APPLIED -> WireResult.Ok(decode("{}"), 200).also { inner.calls += route }
            }
        }
    }

    class Env(
        val server: FakeInstance, val liar: Liar, val keeper: SessionKeeper, val onboarding: WireOnboarding, val wrap: TestKeyWrap,
        val clocks: TestClocks, val policies: KeptPolicies, val quick: QuickUnlockKeeper,
    ) {
        val account get() = server.accounts.values.single()
        val userId get() = account.userId

        fun lockAndUnlock(password: String): KeptUnlock {
            keeper.lock()
            return keeper.unlock(password.toCharArray())
        }

        suspend fun reKey(password: CharArray, putOff: Boolean = false): ReKeyOutcome =
            keeper.reKeyAfterOpening(password, putOff) { policies.fetch(it, clocks.wall)?.kdfParams }

        /** The wrap this device keeps as its own, as the next unlock opens it. */
        fun ownWrap(): String = assertNotNull(keeper.established).accountKeys.wrappedUvk
    }

    private suspend fun registered(): Env {
        val server = FakeInstance(crypto)
        val liar = Liar(server)
        val state = MemoryDeviceState()
        val secure = MemoryDeviceState()
        val trust = server.pinnedTrust(state)
        val keeper = SessionKeeper(BearerTransport(mapOf(server.origin to liar)), secure, state, trust, crypto)
        val wrap = TestKeyWrap()
        val clocks = TestClocks()
        val policies = KeptPolicies(state)
        val quick = QuickUnlockKeeper(keeper, wrap, secure, state, trust, policies, clocks, crypto)
        val o = WireOnboarding(server.origin, keeper.clientFor(server.origin), trust, KnownDevices(state, crypto), keeper, crypto, state, "android", "Pixel",
            { server.now }, knownIdentity = keeper::knownIdentity, work = Dispatchers.Unconfined)
        o.signupStart("alice@example.com", true)
        val t = assertIs<SignupVerify.Ticket>(o.signupVerify("alice@example.com", "482915"))
        val form = RegistrationForm("alice@example.com", "Alice", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android")
        assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(t), form))
        assertNotNull(policies.fetch(keeper.clientFor(server.origin), clocks.wall))
        return Env(server, liar, keeper, o, wrap, clocks, policies, quick)
    }

    private fun pw() = strong.toCharArray()

    @Test fun aDueReKeyAfterAFullPasswordUnlockRaisesTheCostAndTheSamePasswordStillOpens() = runBlocking<Unit> {
        val e = registered()
        e.server.policyKdf = up
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        val saltBefore = e.account.kdfSalt
        assertEquals(ReKeyOutcome.DONE, e.reKey(pw()))
        assertEquals(1, e.liar.changes)
        assertEquals(up, e.account.kdfParams, "the server holds the policy's cost")
        assertNotEquals(saltBefore, e.account.kdfSalt, "under a fresh salt")
        assertEquals(up, e.keeper.accountKdfParams(), "and this device keeps exactly the wrap it sent")
        assertFalse(e.keeper.hasPendingWrap(e.userId))
        // The same password opens, from the new wrap, and proves against it: the proof is the server's verifier.
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(e.account.wrappedUvk, e.ownWrap())
        assertEquals(KeptUnlock.WrongPassword, e.lockAndUnlock("not the password at all 4 X"))
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        val proof = assertIs<ReauthKey.Key>(assertNotNull(e.keeper.reauth()).currentAuthKey(pw()))
        assertEquals(e.account.authKey, proof.currentAuthKey)
        // Done once: the next full-password opening finds nothing due and sends nothing.
        assertEquals(ReKeyOutcome.NOT_DUE, e.reKey(pw()))
        assertEquals(1, e.liar.changes)
    }

    /**
     * Decided on 2026-11-17: the raising is due when the account is below the served cost on ANY figure, and the wrap is
     * made at the higher of the two, figure by figure: the figure the account lacks is raised, none is lowered, and nothing
     * is raised beyond what this device accepts. Before, an account above the served cost on one figure and below it on
     * the other was never raised (and the server now refuses a new wrap below its served cost on any figure).
     */
    @Test fun anAccountBelowTheServedCostOnEitherFigureIsRaisedOnThatFigureOnly() = runBlocking<Unit> {
        val e = registered()
        e.server.policyKdf = up
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(ReKeyOutcome.DONE, e.reKey(pw()))
        val mib = 1024L * 1024
        // Passes above, memory below: the memory is raised, the passes stay.
        e.server.policyKdf = KdfParams(ops = 3, memBytes = 64 * mib + 1024)
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(ReKeyOutcome.DONE, e.reKey(pw()))
        assertEquals(KdfParams(ops = 4, memBytes = 64 * mib + 1024), e.account.kdfParams)
        assertEquals(e.account.kdfParams, e.keeper.accountKdfParams())
        // Memory above, passes below: the passes are raised, the memory stays.
        e.server.policyKdf = KdfParams(ops = 5, memBytes = 64 * mib)
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(ReKeyOutcome.DONE, e.reKey(pw()))
        assertEquals(KdfParams(ops = 5, memBytes = 64 * mib + 1024), e.account.kdfParams)
        assertEquals(3, e.liar.changes)
        // The same password still opens, from the wrap the server holds.
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(e.account.wrappedUvk, e.ownWrap())
        // Above on both figures, or equal: nothing is due. A served cost this device does not accept, mixed or not, is not
        // followed on either figure.
        for ((policy, outcome) in listOf(
            KdfParams(ops = 5, memBytes = 64 * mib + 1024) to ReKeyOutcome.NOT_DUE,
            KdfParams(ops = 3, memBytes = 64 * mib) to ReKeyOutcome.NOT_DUE,
            KdfParams(ops = 4, memBytes = 64 * mib + 1) to ReKeyOutcome.NOT_DUE, // not a whole KiB
            KdfParams(ops = 11, memBytes = 64 * mib + 2048) to ReKeyOutcome.NO_POLICY, // passes above the ceiling
            KdfParams(ops = 6, memBytes = 2048 * mib) to ReKeyOutcome.NO_POLICY, // memory above the ceiling
            KdfParams(ops = 2, memBytes = 128 * mib) to ReKeyOutcome.NO_POLICY, // passes below the floor
        )) {
            e.server.policyKdf = policy
            assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
            assertEquals(outcome, e.reKey(pw()), "policy ${policy.ops}/${policy.memBytes}")
        }
        assertEquals(3, e.liar.changes, "nothing more was sent")
        assertEquals(KdfParams(ops = 5, memBytes = 64 * mib + 1024), e.account.kdfParams)
    }

    @Test fun aLowerMixedRaggedOrAbsurdPolicyIsNeverFollowed() = runBlocking<Unit> {
        val e = registered()
        e.server.policyKdf = up
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(ReKeyOutcome.DONE, e.reKey(pw()))
        val held = e.account.kdfSalt
        val mib = 1024L * 1024
        val cases = listOf(
            KdfParams(ops = 3, memBytes = 64 * mib) to ReKeyOutcome.NOT_DUE, // lower
            // (A mixed cost, memory up and passes down, is now due on the figure the account lacks: the test above.)
            KdfParams(ops = 5, memBytes = 64 * mib + 1) to ReKeyOutcome.NOT_DUE, // not a whole KiB
            KdfParams(ops = 11, memBytes = 64 * mib) to ReKeyOutcome.NO_POLICY, // absurd: outside the fence, not kept
            KdfParams(ops = 4, memBytes = 2048 * mib) to ReKeyOutcome.NO_POLICY,
            KdfParams(ops = 4, memBytes = 32 * mib) to ReKeyOutcome.NO_POLICY, // below the floor
        )
        for ((policy, outcome) in cases) {
            e.server.policyKdf = policy
            assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
            assertEquals(outcome, e.reKey(pw()), "policy ${policy.ops}/${policy.memBytes}")
        }
        assertEquals(1, e.liar.changes, "nothing more was sent")
        assertEquals(held, e.account.kdfSalt)
        assertEquals(up, e.account.kdfParams)
    }

    @Test fun aQuickUnlockOrARegistrationNeverCountsAsAFullPasswordOpeningAndTheQuickUnlockWrapIsUntouched() = runBlocking<Unit> {
        val e = registered()
        e.server.policyKdf = up
        // The registration's own session: not a sign-in with the password.
        assertEquals(ReKeyOutcome.NOT_FULL_PASSWORD, e.reKey(pw()))
        assertEquals(QuickEnrolOutcome.ENROLLED, e.quick.enrol())
        e.keeper.lock()
        assertEquals(QuickUnlockOutcome.UNLOCKED, e.quick.unlock())
        assertEquals(ReKeyOutcome.NOT_FULL_PASSWORD, e.reKey(pw()), "a quick unlock has no password to re-key with")
        assertEquals(0, e.liar.changes)
        assertEquals(KdfParams.DEFAULT, e.account.kdfParams)
        // A full-password unlock re-keys; a quick unlock after it still opens, from the record enrolled before.
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(ReKeyOutcome.DONE, e.reKey(pw()))
        e.keeper.lock()
        assertEquals(QuickUnlockOutcome.UNLOCKED, e.quick.unlock())
        assertEquals(ReKeyOutcome.NOT_FULL_PASSWORD, e.reKey(pw()))
        // A quick unlock opened over a session that a full-password unlock opened before does not inherit it either.
        val uvk = assertNotNull(e.keeper.established).account.uvk.copyOut()
        e.keeper.lock()
        assertEquals(KeptUnlock.Unlocked, e.keeper.unlockWithUvk(uvk))
        e.server.policyKdf = KdfParams(ops = 5, memBytes = 64L * 1024 * 1024)
        assertEquals(ReKeyOutcome.NOT_FULL_PASSWORD, e.reKey(pw()))
        assertEquals(1, e.liar.changes)
    }

    @Test fun offlineItIsSkippedWithoutAWordAndLookedAtAgainAtTheNextFullPasswordOpening() = runBlocking<Unit> {
        val e = registered()
        e.server.policyKdf = up
        e.liar.policyAnswers = false
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(ReKeyOutcome.NO_POLICY, e.reKey(pw()))
        assertEquals(0, e.liar.changes)
        e.liar.policyAnswers = true
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(ReKeyOutcome.DONE, e.reKey(pw()))
        assertEquals(up, e.account.kdfParams)
    }

    @Test fun anOpeningThatMustBeFastPutsItOff() = runBlocking<Unit> {
        val e = registered()
        e.server.policyKdf = up
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(ReKeyOutcome.PUT_OFF, e.reKey(pw(), putOff = true))
        assertEquals(0, e.liar.changes)
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(ReKeyOutcome.DONE, e.reKey(pw()))
    }

    /** Each failure: the account opens with the same password afterwards, and the next opening settles what is left. */
    @Test fun aRaceALostAnswerAServerErrorOrARefusalLeavesTheAccountOpenable() = runBlocking<Unit> {
        // Another device changed the password first: the server refuses the proof; only this request's wrap goes.
        run {
            val e = registered()
            e.server.policyKdf = up
            e.liar.change = Change.REFUSE
            assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
            assertEquals(ReKeyOutcome.REFUSED, e.reKey(pw()))
            assertFalse(e.keeper.hasPendingWrap(e.userId))
            assertEquals(KdfParams.DEFAULT, e.keeper.accountKdfParams())
            assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        }
        // The server took it and the answer was lost: pending; the old wrap still opens; the next opening adopts the new.
        run {
            val e = registered()
            e.server.policyKdf = up
            e.liar.change = Change.LOSE_APPLIED
            assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
            assertEquals(ReKeyOutcome.UNKNOWN, e.reKey(pw()))
            assertTrue(e.keeper.hasPendingWrap(e.userId))
            e.liar.change = Change.PASS
            assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
            assertEquals(ReKeyOutcome.NOT_DUE, e.reKey(pw()), "settled to the wrap the server holds, which is at the policy's cost")
            assertFalse(e.keeper.hasPendingWrap(e.userId))
            assertEquals(1, e.liar.changes)
            assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
            assertEquals(e.account.wrappedUvk, e.ownWrap())
        }
        // Lost, or a server error, before the server took it: the next opening drops the pending wrap and re-keys again.
        for (mode in listOf(Change.LOSE_NOT_APPLIED, Change.ERROR_NOT_APPLIED)) {
            val e = registered()
            e.server.policyKdf = up
            e.liar.change = mode
            assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
            assertEquals(ReKeyOutcome.UNKNOWN, e.reKey(pw()), "$mode")
            assertTrue(e.keeper.hasPendingWrap(e.userId))
            e.liar.change = Change.PASS
            assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
            assertEquals(ReKeyOutcome.DONE, e.reKey(pw()), "$mode")
            assertEquals(up, e.account.kdfParams)
            assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
            assertEquals(e.account.wrappedUvk, e.ownWrap())
        }
    }

    @Test fun aLockInTheMiddleLeavesExactlyOneWrapThatOpensAndTheNextOpeningSettlesIt() = runBlocking<Unit> {
        // Before the send: nothing sent, nothing kept.
        run {
            val e = registered()
            e.server.policyKdf = up
            assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
            assertEquals(ReKeyOutcome.STALE, e.keeper.reKeyAfterOpening(pw()) { client -> e.keeper.lock(); e.policies.fetch(client, e.clocks.wall)?.kdfParams })
            assertEquals(0, e.liar.changes)
            assertFalse(e.keeper.hasPendingWrap(e.userId))
            assertEquals(KeptUnlock.Unlocked, e.keeper.unlock(pw()))
        }
        // While the request is on its way, for each way it can end.
        for (mode in listOf(Change.PASS, Change.LOSE_APPLIED, Change.LOSE_NOT_APPLIED)) {
            val e = registered()
            e.server.policyKdf = up
            e.liar.change = mode
            e.liar.beforeChange = { e.keeper.lock() }
            assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
            val outcome = e.reKey(pw())
            assertEquals(if (mode == Change.PASS) ReKeyOutcome.DONE else ReKeyOutcome.UNKNOWN, outcome, "$mode")
            assertEquals(KeptPhase.LOCKED, e.keeper.phase.value)
            e.liar.beforeChange = null
            e.liar.change = Change.PASS
            // Never neither: the same password opens whichever wrap this device holds now.
            assertEquals(KeptUnlock.Unlocked, e.keeper.unlock(pw()), "$mode")
            // The next opening settles it, and the device's wrap is the server's.
            e.reKey(pw())
            assertFalse(e.keeper.hasPendingWrap(e.userId), "$mode")
            assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
            assertEquals(e.account.wrappedUvk, e.ownWrap(), "$mode")
            assertEquals(up, e.account.kdfParams, "$mode")
        }
    }

    @Test fun aPendingChangeIsSettledBeforeAnythingIsSentAndNothingGoesWhileItCannotBe() = runBlocking<Unit> {
        val e = registered()
        e.server.policyKdf = KdfParams(ops = 4, memBytes = 64L * 1024 * 1024)
        e.liar.change = Change.LOSE_APPLIED
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(ReKeyOutcome.UNKNOWN, e.reKey(pw()))
        assertTrue(e.keeper.hasPendingWrap(e.userId))
        e.liar.change = Change.PASS
        // The server now holds neither wrap (changed elsewhere since): nothing is sent while that stands.
        val theirs = e.account.wrappedUvk
        e.account.wrappedUvk = "changed-elsewhere"
        e.server.policyKdf = KdfParams(ops = 5, memBytes = 64L * 1024 * 1024)
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(ReKeyOutcome.UNSETTLED, e.reKey(pw()))
        assertTrue(e.keeper.hasPendingWrap(e.userId), "both wraps kept")
        assertEquals(1, e.liar.changes)
        // No answer to the keys read: the same.
        e.account.wrappedUvk = theirs
        e.liar.keysNoAnswer = 1
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(ReKeyOutcome.UNSETTLED, e.reKey(pw()))
        assertEquals(1, e.liar.changes)
        // The server's word: it holds the pending wrap. That one is this device's own, and the re-key proves against it.
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(ReKeyOutcome.DONE, e.reKey(pw()))
        assertEquals(KdfParams(ops = 5, memBytes = 64L * 1024 * 1024), e.account.kdfParams)
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(e.account.wrappedUvk, e.ownWrap())
    }

    /**
     * Keys read while the re-key's request is on its way (the opening's own read runs beside it) predate the change: they
     * must not drop its pending wrap. Before, a lost answer then left this device on the old wrap while the server held
     * the new one, so every in-session proof was refused as a wrong password.
     */
    @Test fun keysReadWhileTheRequestIsOnItsWayDoNotDropItsPendingWrap() = runBlocking<Unit> {
        val e = registered()
        e.server.policyKdf = up
        e.liar.change = Change.LOSE_APPLIED
        e.liar.beforeChange = {
            val r = e.server.call(WireRoute.ACCOUNT_KEYS) { WireJson.json.decodeFromString(AccountKeys.serializer(), it) }
            e.keeper.settleWrap(e.userId, (r as WireResult.Ok).value)
        }
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(ReKeyOutcome.UNKNOWN, e.reKey(pw()))
        assertTrue(e.keeper.hasPendingWrap(e.userId), "still pending")
        e.liar.beforeChange = null
        e.liar.change = Change.PASS
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(ReKeyOutcome.NOT_DUE, e.reKey(pw()))
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        assertEquals(e.account.wrappedUvk, e.ownWrap())
        assertIs<ReauthKey.Key>(assertNotNull(e.keeper.reauth()).currentAuthKey(pw()))
    }

    @Test fun nothingOfThePasswordOutlivesTheOpeningWhateverTheAnswer() = runBlocking<Unit> {
        val e = registered()
        fun wiped(a: CharArray) = a.all { it == '\u0000' }
        var a = pw()
        assertEquals(ReKeyOutcome.NOT_FULL_PASSWORD, e.reKey(a)); assertTrue(wiped(a))
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        a = pw(); assertEquals(ReKeyOutcome.PUT_OFF, e.reKey(a, putOff = true)); assertTrue(wiped(a))
        a = pw(); assertEquals(ReKeyOutcome.NOT_DUE, e.reKey(a)); assertTrue(wiped(a))
        // Once per opening: a second call in the same one does nothing, and still wipes what it was handed.
        a = pw(); assertEquals(ReKeyOutcome.ALREADY_RAN, e.reKey(a)); assertTrue(wiped(a))
        e.liar.policyAnswers = false
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        a = pw(); assertEquals(ReKeyOutcome.NO_POLICY, e.reKey(a)); assertTrue(wiped(a))
        e.liar.policyAnswers = true
        e.server.policyKdf = up
        e.liar.change = Change.LOSE_NOT_APPLIED
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        a = pw(); assertEquals(ReKeyOutcome.UNKNOWN, e.reKey(a)); assertTrue(wiped(a))
        e.liar.change = Change.PASS
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        // A password that is not the one this device's wrap opens with proves nothing, and nothing is sent.
        val before = e.liar.changes
        a = "not the password at all 4 X".toCharArray(); assertEquals(ReKeyOutcome.NOT_PROVEN, e.reKey(a)); assertTrue(wiped(a))
        assertEquals(before, e.liar.changes)
        assertFalse(e.keeper.hasPendingWrap(e.userId))
        assertEquals(KeptUnlock.Unlocked, e.lockAndUnlock(strong))
        a = pw(); assertEquals(ReKeyOutcome.DONE, e.reKey(a)); assertTrue(wiped(a))
    }
}
