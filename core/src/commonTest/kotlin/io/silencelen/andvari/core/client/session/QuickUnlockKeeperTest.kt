package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.client.pin.CardTrust
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** [QuickUnlockKeeper]: the account's key under the platform key, and every rule that keeps it a convenience only. */
class QuickUnlockKeeperTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    private class Env(
        val server: FakeInstance, val transport: BearerTransport, val state: MemoryDeviceState, val secure: MemoryDeviceState,
        val trust: CardTrust, val keeper: SessionKeeper, val onboarding: WireOnboarding, val wrap: TestKeyWrap, val clocks: TestClocks,
        val policies: KeptPolicies, val quick: QuickUnlockKeeper,
    )

    private suspend fun env(): Env {
        val server = FakeInstance(crypto)
        val state = MemoryDeviceState()
        val secure = MemoryDeviceState()
        val transport = BearerTransport(mapOf(server.origin to server))
        val trust = server.pinnedTrust(state)
        val keeper = SessionKeeper(transport, secure, state, trust, crypto)
        val wrap = TestKeyWrap()
        val clocks = TestClocks()
        val policies = KeptPolicies(state)
        val quick = QuickUnlockKeeper(keeper, wrap, secure, state, trust, policies, clocks, crypto)
        val o = WireOnboarding(server.origin, keeper.clientFor(server.origin), trust, KnownDevices(state, crypto), keeper, crypto, state, "android", "Pixel",
            { server.now }, knownIdentity = keeper::knownIdentity, work = Dispatchers.Unconfined)
        return Env(server, transport, state, secure, trust, keeper, o, wrap, clocks, policies, quick)
    }

    private suspend fun registered(): Env {
        val e = env()
        e.onboarding.signupStart("alice@example.com", true)
        val t = assertIs<SignupVerify.Ticket>(e.onboarding.signupVerify("alice@example.com", "482915"))
        val form = RegistrationForm("alice@example.com", "Alice", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android")
        assertIs<Registration.Registered>(e.onboarding.register(RegistrationAuth.Ticket(t), form))
        // The policy, read through the session's guarded client, permits keys at rest.
        assertNotNull(e.policies.fetch(e.keeper.clientFor(e.server.origin), e.clocks.wall))
        return e
    }

    private suspend fun enrolled(): Env {
        val e = registered()
        assertTrue(e.quick.status().offerNow, "offered once, before it is turned on")
        assertEquals(QuickEnrolOutcome.ENROLLED, e.quick.enrol())
        e.keeper.lock()
        return e
    }

    @Test fun theAccountsKeyOpensTheStoredAccountOfflineAndNothingIsSent() = runBlocking<Unit> {
        val e = enrolled()
        val status = e.quick.status()
        assertTrue(status.enrolled && status.usable)
        assertFalse(status.offerNow)
        val sent = e.transport.sent.size
        val before = e.wrap.prompts
        e.server.override[io.silencelen.andvari.core.model.wire.WireRoute.INSTANCE] =
            io.silencelen.andvari.core.client.net.WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TRANSPORT)
        assertEquals(QuickUnlockOutcome.UNLOCKED, e.quick.unlock())
        assertEquals(before + 1, e.wrap.prompts)
        assertNotNull(e.keeper.established)
        assertEquals(KeptPhase.UNLOCKED, e.keeper.phase.value)
        assertEquals(sent, e.transport.sent.size, "a quick unlock sends nothing")
        // Nothing derived from the password is kept: the sealed record holds the sealed key only.
        assertFalse(e.secure.get(QuickUnlockKeeper.KEY_SEALED)!!.contains(strong))
    }

    @Test fun aDamagedPinRefusesBeforeAnyPrompt() = runBlocking<Unit> {
        val e = enrolled()
        e.state.set(PinStore.KEY_PREFIX + e.server.origin, "not a pin record")
        val before = e.wrap.prompts
        assertEquals(QuickUnlockOutcome.BLOCKED, e.quick.unlock())
        assertEquals(before, e.wrap.prompts, "no prompt under a damaged pin")
        assertNull(e.keeper.established)
    }

    @Test fun aForkedPinOpensTheDevicesOwnCopyAndSendsNothing() = runBlocking<Unit> {
        val e = enrolled()
        val store = PinStore(e.state)
        store.markForked(store.get(e.server.origin)!!)
        val sent = e.transport.sent.size
        assertEquals(QuickUnlockOutcome.UNLOCKED, e.quick.unlock())
        assertNotNull(e.keeper.established)
        assertEquals(sent, e.transport.sent.size)
    }

    @Test fun thePeriodicFullPasswordIsDueAfterThirtyDaysAndTurningItOnDoesNotRenewIt() = runBlocking<Unit> {
        val e = registered()
        e.clocks.advance(29L * 24 * 3600 * 1000)
        e.policies.fetch(e.keeper.clientFor(e.server.origin), e.clocks.wall)
        // Turning it on late copies the old stamp; it does not start the 30 days again.
        assertEquals(QuickEnrolOutcome.ENROLLED, e.quick.enrol())
        e.keeper.lock()
        e.clocks.advance(2L * 24 * 3600 * 1000)
        // The policy was read within 7 days of the unlock, so only the password's age speaks here.
        e.policies.fetch(e.keeper.clientFor(e.server.origin), e.clocks.wall)
        assertFalse(e.quick.status().usable)
        val before = e.wrap.prompts
        assertEquals(QuickUnlockOutcome.USE_PASSWORD, e.quick.unlock())
        assertEquals(before, e.wrap.prompts, "no prompt when it cannot be used")
        // One password unlock starts the 30 days again.
        assertEquals(KeptUnlock.Unlocked, e.keeper.unlock(strong.toCharArray()))
        e.keeper.lock()
        assertEquals(QuickUnlockOutcome.UNLOCKED, e.quick.unlock())
    }

    @Test fun aRebootWithNoServerTimeSinceThePasswordFailsClosed() = runBlocking<Unit> {
        val e = enrolled()
        e.clocks.boot = "boot-2"
        e.clocks.mono = 1_000L
        assertEquals(QuickUnlockOutcome.USE_PASSWORD, e.quick.unlock())
    }

    @Test fun aPolicyThatForbidsKeysAtRestRemovesTheSealedKey() = runBlocking<Unit> {
        val e = enrolled()
        val slot = e.wrap.keys.keys.single()
        e.quick.policySeen(e.server.origin, e.policies.record(e.server.origin,
            io.silencelen.andvari.core.model.wire.ClientPolicy(emptyMap(), io.silencelen.andvari.core.crypto.KdfParams.DEFAULT, 300, 30, false, 3600, 30, 1, 1, e.server.now,
                io.silencelen.andvari.core.model.wire.SignupPolicy("open", false, true, 0), false), e.clocks.wall))
        assertFalse(e.quick.status().enrolled)
        assertTrue(slot in e.wrap.destroyed)
        assertEquals(QuickUnlockOutcome.USE_PASSWORD, e.quick.unlock())
    }

    @Test fun aPolicyNotSeenForSevenDaysStopsIt() = runBlocking<Unit> {
        val e = enrolled()
        e.clocks.advance(8L * 24 * 3600 * 1000)
        assertFalse(e.quick.status().allowed)
        assertEquals(QuickUnlockOutcome.USE_PASSWORD, e.quick.unlock())
    }

    @Test fun anInvalidatedKeyTurnsItOffAndACancelOrALockoutKeepsIt() = runBlocking<Unit> {
        val e = enrolled()
        e.wrap.next = TestKeyWrap.Next.CANCEL
        assertEquals(QuickUnlockOutcome.CANCELLED, e.quick.unlock())
        e.wrap.next = TestKeyWrap.Next.REFUSE
        assertEquals(QuickUnlockOutcome.USE_PASSWORD, e.quick.unlock())
        assertTrue(e.quick.status().enrolled, "a cancel or a lockout never removes it")
        e.wrap.next = TestKeyWrap.Next.INVALIDATED
        assertEquals(QuickUnlockOutcome.TURNED_OFF, e.quick.unlock())
        assertFalse(e.quick.status().enrolled)
        assertNull(e.secure.get(QuickUnlockKeeper.KEY_SEALED))
    }

    @Test fun itGoesWithTheSessionAndWithAMove() = runBlocking<Unit> {
        val e = enrolled()
        val slot = e.wrap.keys.keys.single()
        e.keeper.signOut()
        assertNull(e.secure.get(QuickUnlockKeeper.KEY_SEALED))
        assertTrue(slot in e.wrap.destroyed)
        assertEquals(QuickUnlockOutcome.NO_SESSION, e.quick.unlock())

        val m = enrolled()
        m.keeper.moved(m.server.origin, "https://new.example")
        assertNull(m.secure.get(QuickUnlockKeeper.KEY_SEALED), "a key sealed for the old address goes with a move")
    }

    @Test fun enrolmentNeedsTheOpenVaultAndAConsentedPrompt() = runBlocking<Unit> {
        val e = registered()
        e.wrap.next = TestKeyWrap.Next.CANCEL
        assertEquals(QuickEnrolOutcome.CANCELLED, e.quick.enrol())
        assertFalse(e.quick.status().enrolled)
        assertTrue(e.wrap.destroyed.isNotEmpty(), "a cancelled enrolment leaves no key")
        e.keeper.lock()
        assertEquals(QuickEnrolOutcome.NOT_OPEN, e.quick.enrol())
        e.keeper.unlock(strong.toCharArray())
        e.wrap.biometric = false
        assertEquals(QuickEnrolOutcome.NOT_AVAILABLE, e.quick.enrol())
    }

    @Test fun theOfferPutOffComesBackAfterThreePasswordUnlocksAtMostTwice() = runBlocking<Unit> {
        val e = registered()
        assertTrue(e.quick.status().offerNow)
        var cards = 1
        e.quick.notNow()
        repeat(12) {
            e.keeper.lock()
            assertEquals(KeptUnlock.Unlocked, e.keeper.unlock(strong.toCharArray()))
            if (e.quick.status().offerNow) {
                cards++
                e.quick.notNow()
            }
        }
        assertEquals(3, cards, "the first offer and two re-offers, and no more")
    }

    // ---- the consent first, the seal inside the guarded use after it ----

    /** A lock while the consent prompt is up: nothing is lent or sealed, nothing kept, the slot's key goes. */
    @Test fun aLockDuringThePromptSealsNothingAndKeepsNothing() = runBlocking<Unit> {
        val e = registered()
        val up = kotlinx.coroutines.CompletableDeferred<Unit>()
        e.wrap.promptUp = up
        val enrolling = async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { e.quick.enrol() }
        assertEquals(1, e.wrap.keys.size, "the prompt is up over a fresh key")
        e.keeper.lock()
        up.complete(Unit)
        assertEquals(QuickEnrolOutcome.NOT_OPEN, enrolling.await(), "the enrolment's screen is gone")
        assertTrue(e.wrap.lent.isEmpty(), "the key was never lent: nothing was sealed")
        assertEquals(1, e.wrap.discarded, "what the prompt prepared is discarded")
        assertTrue(e.wrap.keys.isEmpty(), "and the slot's key destroyed")
        assertNull(e.secure.get(QuickUnlockKeeper.KEY_SEALED))
        assertFalse(e.quick.status().enrolled)
    }

    /** A cancelled prompt lends nothing and keeps no key; a seal the platform cannot make after the prompt neither. */
    @Test fun aCancelOrAFailedSealLendsOrKeepsNothing() = runBlocking<Unit> {
        val e = registered()
        e.wrap.next = TestKeyWrap.Next.CANCEL
        assertEquals(QuickEnrolOutcome.CANCELLED, e.quick.enrol())
        assertTrue(e.wrap.lent.isEmpty() && e.wrap.keys.isEmpty())
        e.wrap.sealFails = true
        assertEquals(QuickEnrolOutcome.FAILED, e.quick.enrol())
        assertEquals(1, e.wrap.lent.size, "lent once, inside the use")
        assertTrue(e.wrap.keys.isEmpty(), "the slot's key is destroyed")
        assertNull(e.secure.get(QuickUnlockKeeper.KEY_SEALED))
    }

    /**
     * The platform is lent the guard's own buffer, never a copy, and neither zeroes nor needs it past the use: it is
     * whole while the vault is open and zero after the lock. The sealed record opens afterwards as before.
     */
    @Test fun theSealIsLentTheGuardsOwnBufferAndTheRecordOpensAfterwards() = runBlocking<Unit> {
        val e = registered()
        assertEquals(QuickEnrolOutcome.ENROLLED, e.quick.enrol())
        val lent = e.wrap.lent.single()
        assertTrue(lent.any { it != 0.toByte() }, "the platform did not zero it")
        e.keeper.lock()
        assertTrue(lent.all { it == 0.toByte() }, "it was the guard's own buffer: the lock zeroed it in place")
        assertEquals(QuickUnlockOutcome.UNLOCKED, e.quick.unlock())
        assertNotNull(e.keeper.established)
    }

    /** A second enrolment while the first's prompt is up: the newer one owns the slot; the older keeps nothing and says so. */
    @Test fun aSecondEnrolmentWhileOneIsWaitingWinsAndTheFirstKeepsNothing() = runBlocking<Unit> {
        val e = registered()
        val up = kotlinx.coroutines.CompletableDeferred<Unit>()
        e.wrap.promptUp = up
        val first = async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { e.quick.enrol() }
        assertEquals(QuickEnrolOutcome.ENROLLED, e.quick.enrol(), "the second, its prompt answered at once")
        val kept = e.secure.get(QuickUnlockKeeper.KEY_SEALED)
        up.complete(Unit)
        assertEquals(QuickEnrolOutcome.NOT_OPEN, first.await())
        assertEquals(1, e.wrap.lent.size, "only the second sealed")
        assertEquals(1, e.wrap.discarded)
        assertEquals(1, e.wrap.keys.size, "the slot keeps the second's key")
        assertEquals(kept, e.secure.get(QuickUnlockKeeper.KEY_SEALED), "the record is the second's")
        e.keeper.lock()
        assertEquals(QuickUnlockOutcome.UNLOCKED, e.quick.unlock(), "and it opens")
    }
}
