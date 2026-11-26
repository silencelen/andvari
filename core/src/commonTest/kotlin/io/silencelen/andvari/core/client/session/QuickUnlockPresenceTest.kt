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
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.ClientPolicy
import io.silencelen.andvari.core.model.wire.SignupPolicy
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * [QuickUnlockKeeper.confirmPresence]: the person's presence, confirmed by the check quick unlock uses, for an account
 * that is already open (a device link's approval, design 2026-11-15 §8.2 step 6). It never unlocks, sends nothing, keeps
 * the opened key inside the guard and wipes it on every path, and a lock during its prompt wins.
 */
class QuickUnlockPresenceTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val reason = "Add Pixel 9 (android) to your account"

    private class Env(
        val server: FakeInstance, val transport: BearerTransport, val state: MemoryDeviceState, val secure: MemoryDeviceState,
        val trust: CardTrust, val keeper: SessionKeeper, val wrap: TestKeyWrap, val clocks: TestClocks, val policies: KeptPolicies,
        val quick: QuickUnlockKeeper,
    )

    /** Registered, the policy read, quick unlock switched on, and the vault still open. */
    private suspend fun open(enrol: Boolean = true): Env {
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
        o.signupStart("alice@example.com", true)
        val t = assertIs<SignupVerify.Ticket>(o.signupVerify("alice@example.com", "482915"))
        val form = RegistrationForm("alice@example.com", "Alice", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android")
        assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(t), form))
        assertNotNull(policies.fetch(keeper.clientFor(server.origin), clocks.wall))
        if (enrol) assertEquals(QuickEnrolOutcome.ENROLLED, quick.enrol())
        assertNotNull(keeper.established)
        return Env(server, transport, state, secure, trust, keeper, wrap, clocks, policies, quick)
    }

    private fun Env.policy(offlineCacheAllowed: Boolean) = policies.record(server.origin,
        ClientPolicy(emptyMap(), io.silencelen.andvari.core.crypto.KdfParams.DEFAULT, 300, 30, offlineCacheAllowed, 3600, 30, 1, 1, server.now,
            SignupPolicy("open", false, true, 0), false), clocks.wall)

    /** The kept sealed record with one field replaced: a test's own record. */
    private fun Env.recordWith(field: String, value: String) {
        val o = Json.parseToJsonElement(secure.get(QuickUnlockKeeper.KEY_SEALED)!!).jsonObject
        secure.set(QuickUnlockKeeper.KEY_SEALED, JsonObject(o + (field to JsonPrimitive(value))).toString())
    }

    private fun Env.slot(): String = Json.parseToJsonElement(secure.get(QuickUnlockKeeper.KEY_SEALED)!!).jsonObject["slot"]!!.jsonPrimitive.content

    private fun allZero(a: ByteArray) = a.all { it == 0.toByte() }

    // ---- the four answers ----

    @Test fun theOpenAccountsOwnKeyConfirmsAndNothingElseChanges() = runBlocking<Unit> {
        val e = open()
        val sent = e.transport.sent.size
        val stamp = e.state.get(QuickUnlockKeeper.KEY_STAMP)
        val record = e.secure.get(QuickUnlockKeeper.KEY_SEALED)
        val account = e.keeper.established
        val prompts = e.wrap.prompts
        assertEquals(PresenceOutcome.CONFIRMED, e.quick.confirmPresence(reason))
        assertEquals(prompts + 1, e.wrap.prompts, "one prompt")
        assertEquals(1, e.wrap.confirmPrompts, "the confirmation's own prompt, not an unlock's")
        assertEquals(listOf<String?>(reason), e.wrap.reasons, "the prompt is told what is being approved")
        assertTrue(allZero(e.wrap.released.single()), "what it opened is wiped")
        assertEquals(sent, e.transport.sent.size, "nothing is sent")
        assertEquals(stamp, e.state.get(QuickUnlockKeeper.KEY_STAMP), "not a use of the password: the 30 days are not started again")
        assertEquals(record, e.secure.get(QuickUnlockKeeper.KEY_SEALED), "quick unlock stays as it was")
        assertTrue(e.keeper.established === account, "the open session is the same: nothing was unlocked or re-opened")
        assertTrue(e.quick.status().usable)
        // And quick unlock still opens the account after a lock.
        e.keeper.lock()
        assertEquals(QuickUnlockOutcome.UNLOCKED, e.quick.unlock())
    }

    @Test fun aCancelledPromptIsCancelledAndKeepsQuickUnlock() = runBlocking<Unit> {
        val e = open()
        e.wrap.next = TestKeyWrap.Next.CANCEL
        assertEquals(PresenceOutcome.CANCELLED, e.quick.confirmPresence(reason))
        assertTrue(e.quick.status().enrolled)
        assertTrue(e.wrap.released.isEmpty(), "nothing was released")
    }

    @Test fun eachReasonQuickUnlockWouldAskForThePasswordAsksForItWithNoPrompt() = runBlocking<Unit> {
        // No strong fingerprint or face check on this device.
        val a = open()
        a.wrap.biometric = false
        assertEquals(PresenceOutcome.USE_PASSWORD, a.quick.confirmPresence(reason))
        assertEquals(0, a.wrap.confirmPrompts)
        assertTrue(a.quick.status().enrolled, "kept")

        // Quick unlock not switched on.
        val b = open(enrol = false)
        assertEquals(PresenceOutcome.USE_PASSWORD, b.quick.confirmPresence(reason))
        assertEquals(0, b.wrap.prompts)

        // The server's policy does not allow keys at rest (read, and not yet acted on by the keeper).
        val c = open()
        c.policy(offlineCacheAllowed = false)
        assertEquals(PresenceOutcome.USE_PASSWORD, c.quick.confirmPresence(reason))
        assertEquals(0, c.wrap.confirmPrompts)

        // The policy was not seen within seven days.
        val d = open()
        d.clocks.advance(8L * 24 * 3600 * 1000)
        assertEquals(PresenceOutcome.USE_PASSWORD, d.quick.confirmPresence(reason))
        assertEquals(0, d.wrap.confirmPrompts)

        // The periodic full password is due (30 days), the policy fresh.
        val f = open()
        f.clocks.advance(31L * 24 * 3600 * 1000)
        f.policy(offlineCacheAllowed = true)
        assertEquals(PresenceOutcome.USE_PASSWORD, f.quick.confirmPresence(reason))
        assertEquals(0, f.wrap.confirmPrompts)

        // A reboot with no server time since the password: quick unlock fails closed, so this does too.
        val g = open()
        g.clocks.boot = "boot-2"
        g.clocks.mono = 1_000L
        assertEquals(PresenceOutcome.USE_PASSWORD, g.quick.confirmPresence(reason))
        assertEquals(0, g.wrap.confirmPrompts)

        // A lockout or a sensor error at the prompt: the password, and quick unlock is kept.
        val h = open()
        h.wrap.next = TestKeyWrap.Next.REFUSE
        assertEquals(PresenceOutcome.USE_PASSWORD, h.quick.confirmPresence(reason))
        assertEquals(1, h.wrap.confirmPrompts)
        assertTrue(h.quick.status().enrolled)
    }

    @Test fun confirmingDoesNotRenewThePeriodicPassword() = runBlocking<Unit> {
        val e = open()
        e.clocks.advance(29L * 24 * 3600 * 1000)
        e.policy(offlineCacheAllowed = true)
        assertEquals(PresenceOutcome.CONFIRMED, e.quick.confirmPresence(reason))
        e.clocks.advance(2L * 24 * 3600 * 1000)
        e.policy(offlineCacheAllowed = true)
        assertEquals(PresenceOutcome.USE_PASSWORD, e.quick.confirmPresence(reason), "the 30 days still run from the password")
    }

    @Test fun aRecordThatNoLongerOpensIsWipedAndTurnedOff() = runBlocking<Unit> {
        val e = open()
        val slot = e.slot()
        e.wrap.next = TestKeyWrap.Next.INVALIDATED
        assertEquals(PresenceOutcome.TURNED_OFF, e.quick.confirmPresence(reason))
        assertNull(e.secure.get(QuickUnlockKeeper.KEY_SEALED))
        assertTrue(slot in e.wrap.destroyed)
        assertNotNull(e.keeper.established, "the open vault stays open")

        // A record that cannot even be read is turned off the same way, before any prompt.
        val u = open()
        u.recordWith("sealed", "not base64url!")
        assertEquals(PresenceOutcome.TURNED_OFF, u.quick.confirmPresence(reason))
        assertEquals(0, u.wrap.confirmPrompts)
        assertNull(u.secure.get(QuickUnlockKeeper.KEY_SEALED))
    }

    /** A record kept under this account's name that seals another account's key: it opens, does not match, and goes. */
    @Test fun aRecordThatOpensToAnotherAccountsKeyIsWipedAndNeverConfirms() = runBlocking<Unit> {
        val e = open()
        val slot = e.slot()
        val other = crypto.randomBytes(32)
        e.recordWith("sealed", Bytes.toB64(e.wrap.sealWith(slot, other)))
        val sent = e.transport.sent.size
        assertEquals(PresenceOutcome.TURNED_OFF, e.quick.confirmPresence(reason))
        assertNull(e.secure.get(QuickUnlockKeeper.KEY_SEALED), "wiped, as a failed quick unlock wipes it")
        assertTrue(slot in e.wrap.destroyed)
        assertTrue(allZero(e.wrap.released.single()), "what it opened is wiped")
        assertNotNull(e.keeper.established, "the open vault stays open")
        assertEquals(sent, e.transport.sent.size)
        assertFalse(e.quick.status().enrolled)
    }

    /** A record kept for another account on this device (an earlier session): not switched on for this one; untouched. */
    @Test fun aRecordForAnotherAccountIsNotThisAccountsQuickUnlock() = runBlocking<Unit> {
        val e = open()
        e.recordWith("userId", "someone-else")
        val kept = e.secure.get(QuickUnlockKeeper.KEY_SEALED)
        assertEquals(PresenceOutcome.USE_PASSWORD, e.quick.confirmPresence(reason))
        assertEquals(0, e.wrap.confirmPrompts, "no prompt")
        assertEquals(kept, e.secure.get(QuickUnlockKeeper.KEY_SEALED))
    }

    // ---- it never unlocks; a lock wins; one at a time ----

    @Test fun withNoVaultOpenItRefusesBeforeAnyPrompt() = runBlocking<Unit> {
        val e = open()
        e.keeper.lock()
        val prompts = e.wrap.prompts
        assertEquals(PresenceOutcome.STALE, e.quick.confirmPresence(reason))
        assertEquals(prompts, e.wrap.prompts)
        assertNull(e.keeper.established, "it never unlocks")
        assertTrue(e.quick.status().enrolled)
    }

    @Test fun aLockDuringThePromptWinsAndWipesWhatWasOpened() = runBlocking<Unit> {
        val e = open()
        val up = CompletableDeferred<Unit>()
        e.wrap.openUp = up
        val confirming = async(start = CoroutineStart.UNDISPATCHED) { e.quick.confirmPresence(reason) }
        e.keeper.lock()
        up.complete(Unit)
        assertEquals(PresenceOutcome.STALE, confirming.await(), "never \"confirmed\", and never read as another account's key")
        assertTrue(allZero(e.wrap.released.single()), "what it opened is wiped")
        assertNull(e.keeper.established)
        assertTrue(e.quick.status().enrolled, "a lock is not a wrong key: quick unlock is kept")
        assertEquals(QuickUnlockOutcome.UNLOCKED, e.quick.unlock())
    }

    @Test fun aLockAndAnUnlockDuringThePromptStillWin() = runBlocking<Unit> {
        val e = open()
        val up = CompletableDeferred<Unit>()
        e.wrap.openUp = up
        val confirming = async(start = CoroutineStart.UNDISPATCHED) { e.quick.confirmPresence(reason) }
        e.keeper.lock()
        assertEquals(KeptUnlock.Unlocked, e.keeper.unlock(strong.toCharArray()))
        up.complete(Unit)
        assertEquals(PresenceOutcome.STALE, confirming.await(), "the session the prompt was up over is gone")
        assertTrue(allZero(e.wrap.released.single()))
        assertTrue(e.quick.status().enrolled)
    }

    @Test fun aCancelOrALockoutAfterALockIsStale() = runBlocking<Unit> {
        for (n in listOf(TestKeyWrap.Next.CANCEL, TestKeyWrap.Next.REFUSE)) {
            val e = open()
            e.wrap.next = n
            val up = CompletableDeferred<Unit>()
            e.wrap.openUp = up
            val confirming = async(start = CoroutineStart.UNDISPATCHED) { e.quick.confirmPresence(reason) }
            e.keeper.lock()
            up.complete(Unit)
            assertEquals(PresenceOutcome.STALE, confirming.await(), "$n")
            assertTrue(e.quick.status().enrolled)
        }
    }

    @Test fun aSecondCallWhileOneIsUpIsStaleWithNoPromptAndTheFirstAnswers() = runBlocking<Unit> {
        val e = open()
        val up = CompletableDeferred<Unit>()
        e.wrap.openUp = up
        val first = async(start = CoroutineStart.UNDISPATCHED) { e.quick.confirmPresence(reason) }
        assertEquals(PresenceOutcome.STALE, e.quick.confirmPresence(reason))
        assertEquals(1, e.wrap.confirmPrompts, "no second prompt")
        up.complete(Unit)
        assertEquals(PresenceOutcome.CONFIRMED, first.await())
        // And once it has answered, the next call prompts again.
        assertEquals(PresenceOutcome.CONFIRMED, e.quick.confirmPresence(reason))
        assertEquals(2, e.wrap.confirmPrompts)
    }

    /** Quick unlock switched on again while the prompt was up: the newer record is not this call's to wipe. */
    @Test fun aNewEnrolmentDuringThePromptIsLeftAlone() = runBlocking<Unit> {
        val e = open()
        val up = CompletableDeferred<Unit>()
        e.wrap.openUp = up
        e.wrap.next = TestKeyWrap.Next.INVALIDATED
        val confirming = async(start = CoroutineStart.UNDISPATCHED) { e.quick.confirmPresence(reason) }
        assertEquals(QuickEnrolOutcome.ENROLLED, e.quick.enrol())
        val kept = e.secure.get(QuickUnlockKeeper.KEY_SEALED)
        up.complete(Unit)
        assertEquals(PresenceOutcome.STALE, confirming.await())
        assertEquals(kept, e.secure.get(QuickUnlockKeeper.KEY_SEALED), "the newer record stays")
        assertEquals(PresenceOutcome.CONFIRMED, e.quick.confirmPresence(reason))
    }
}
