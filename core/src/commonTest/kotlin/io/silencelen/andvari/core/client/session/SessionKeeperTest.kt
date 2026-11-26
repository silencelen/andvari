package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.account.ReauthKey
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KitConfirm
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
import io.silencelen.andvari.core.client.onboard.SessionHow
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.client.pin.CardTrust
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.net.originStopped
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** [SessionKeeper]: the session's tokens on its origin's client, persistence, lock, unlock, refresh, sign-out, reauth. */
class SessionKeeperTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    private class Env(
        val server: FakeInstance, val transport: BearerTransport, val state: MemoryDeviceState, val secure: MemoryDeviceState,
        val trust: CardTrust, val keeper: SessionKeeper, val onboarding: WireOnboarding,
    )

    private suspend fun env(
        server: FakeInstance = FakeInstance(crypto), state: MemoryDeviceState = MemoryDeviceState(), secure: MemoryDeviceState = MemoryDeviceState(),
        driven: Boolean = false,
    ): Env {
        val transport = BearerTransport(mapOf(server.origin to server))
        val trust = server.pinnedTrust(state)
        val keeper = if (driven) {
            transport.clock = { server.now }
            SessionKeeper(transport, secure, state, trust, crypto, clock = { server.now })
        } else {
            SessionKeeper(transport, secure, state, trust, crypto)
        }
        val o = WireOnboarding(server.origin, keeper.clientFor(server.origin), trust, KnownDevices(state, crypto), keeper, crypto, state, "android", "Pixel",
            { server.now }, knownIdentity = keeper::knownIdentity, work = Dispatchers.Unconfined)
        return Env(server, transport, state, secure, trust, keeper, o)
    }

    private fun reopen(e: Env): SessionKeeper = SessionKeeper(e.transport, e.secure, e.state, e.trust, crypto)

    private suspend fun register(e: Env): Registration.Registered {
        e.onboarding.signupStart("alice@example.com", true)
        val t = assertIs<SignupVerify.Ticket>(e.onboarding.signupVerify("alice@example.com", "482915"))
        val form = RegistrationForm("alice@example.com", "Alice", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android")
        return assertIs<Registration.Registered>(e.onboarding.register(RegistrationAuth.Ticket(t), form))
    }

    @Test fun anEstablishedSessionsBearerGoesWithTheFlowsLaterStepsOnItsOrigin() = runBlocking<Unit> {
        val e = env()
        val reg = register(e)
        assertEquals(KeptPhase.UNLOCKED, e.keeper.phase.value)
        val kept = assertNotNull(e.keeper.session)
        assertEquals(reg.userId, kept.userId)
        assertEquals(SessionHow.REGISTERED, kept.how)
        // The kit confirmation is the registration flow's next authenticated step: it carries the new session.
        val typed = e.onboarding.kitChallenge(reg.kit).associateWith { reg.kit.groups[it - 1] }
        assertEquals(KitConfirm.Confirmed, e.onboarding.confirmKit(reg.kit, typed))
        assertEquals(listOf<String?>("at-${kept.deviceId}"), e.transport.bearersFor(WireRoute.RECOVERY_SELF_CONFIRM))
        // Nothing unauthenticated carried it.
        assertTrue(e.transport.bearersFor(WireRoute.REGISTER).all { it == null })
    }

    @Test fun aSessionsTokensAreNeverSentToAnotherOrigin() = runBlocking<Unit> {
        val e = env()
        register(e)
        val other = e.keeper.clientFor("https://elsewhere.example")
        // No pin is in force there, so a request that carries a credential is stopped before anything leaves (design §4.4).
        assertTrue(other.call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }.originStopped)
        assertTrue(e.transport.sent.none { it.origin == "https://elsewhere.example" })
    }

    /**
     * An unlock never answers Unlocked without checking the password, a lock that comes while
     * an unlock runs leaves nothing open, and a second unlock while one runs is refused.
     */
    @Test fun anUnlockChecksThePasswordAndALockMeanwhileLeavesNothingOpen() = runBlocking<Unit> {
        val e = env()
        register(e)
        // Keys open while an unlock is asked for: the password is checked all the same, and the keys found open go.
        assertNotNull(e.keeper.established)
        val wrong = "not the password at all".toCharArray()
        assertEquals(KeptUnlock.WrongPassword, e.keeper.unlock(wrong))
        assertNull(e.keeper.established, "the keys found open were wiped")

        // A lock while the unlock runs (here: at its pin check).
        var during: (() -> Unit)? = null
        val k = SessionKeeper(e.transport, e.secure, e.state, io.silencelen.andvari.core.app.engine.DelegatingTrust {
            during?.let { d -> during = null; d() }
            e.trust
        }, crypto)
        during = { k.lock() }
        assertEquals(KeptUnlock.Stale, k.unlock(strong.toCharArray()))
        assertNull(k.established, "nothing is open after the lock")
        assertEquals(KeptPhase.LOCKED, k.phase.value)

        // A second unlock while one runs is refused, and the first opens.
        var second: KeptUnlock? = null
        during = { second = k.unlock(strong.toCharArray()) }
        assertEquals(KeptUnlock.Unlocked, k.unlock(strong.toCharArray()))
        assertEquals(KeptUnlock.Stale, second)
        assertNotNull(k.established)
    }

    /** Another origin that DOES hold a pin in force may be dialed, and still never receives this session's bearer (§7.8). */
    @Test fun anotherOriginWithAPinInForceNeverReceivesTheSessionsBearer() = runBlocking<Unit> {
        val e = env()
        register(e)
        val elsewhere = "https://elsewhere.example"
        val store = PinStore(e.state)
        store.put(store.get(e.server.origin)!!.copy(origin = elsewhere))
        assertTrue(e.keeper.mayDial(elsewhere), "a pin in force there")
        e.keeper.clientFor(elsewhere).call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
        val sent = e.transport.sent.filter { it.origin == elsewhere }
        assertEquals(1, sent.size, "the request went")
        assertNull(sent.single().bearer, "without the session's bearer")
        assertTrue(e.transport.sent.none { it.origin == elsewhere && it.route == WireRoute.REFRESH })
    }

    @Test fun aRestartFindsTheSessionLockedAndThePasswordOpensItAgain() = runBlocking<Unit> {
        val e = env()
        val reg = register(e)
        val again = reopen(e)
        assertEquals(KeptPhase.LOCKED, again.phase.value)
        assertNull(again.established)
        assertEquals(reg.userId, again.session!!.userId)
        val wrong = "not the password at all".toCharArray()
        assertEquals(KeptUnlock.WrongPassword, again.unlock(wrong))
        assertTrue(wrong.all { it == '\u0000' }, "the password is wiped")
        val right = strong.toCharArray()
        assertEquals(KeptUnlock.Unlocked, again.unlock(right))
        assertTrue(right.all { it == '\u0000' })
        val open = assertNotNull(again.established)
        assertEquals(reg.userId, open.userId)
        assertEquals(reg.kit.accountId, open.account.accountId(crypto))
        // The stored tokens go with the restarted keeper's calls.
        again.clientFor(e.server.origin).call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
        assertEquals("at-${open.deviceId}", e.transport.sent.last().bearer)
        // Nothing secret is persisted: the stored record holds no password-derived key.
        val text = e.secure.get(SessionKeeper.KEY)!!
        assertTrue(!text.contains(strong))
    }

    @Test fun lockWipesTheKeysAndKeepsTheSession() = runBlocking<Unit> {
        val e = env()
        register(e)
        val account = e.keeper.established!!.account
        e.keeper.lock()
        assertEquals(KeptPhase.LOCKED, e.keeper.phase.value)
        assertNull(e.keeper.established)
        assertTrue(account.isWiped, "the UVK is wiped")
        assertNotNull(e.keeper.session)
        assertEquals(KeptUnlock.Unlocked, e.keeper.unlock(strong.toCharArray()))
    }

    /** Design §4.4: a fork stops traffic, not reading. */
    @Test fun aForkedPinStillOpensTheDevicesOwnCopyAndSendsNothing() = runBlocking<Unit> {
        val e = env()
        register(e)
        e.keeper.lock()
        val store = PinStore(e.state)
        store.markForked(store.get(e.server.origin)!!)
        val sent = e.transport.sent.size
        assertEquals(KeptUnlock.WrongPassword, e.keeper.unlock("not the password at all".toCharArray()))
        assertEquals(KeptUnlock.Unlocked, e.keeper.unlock(strong.toCharArray()))
        assertNotNull(e.keeper.established)
        assertEquals(sent, e.transport.sent.size, "the unlock sends nothing")
        // The stop is enforced where the keeper dials, by the engine's guard: no request leaves for a stopped origin,
        // with a bearer or without, and the caller gets the guard's refusal.
        val client = e.keeper.clientFor(e.server.origin)
        assertTrue(client.stopped, "a flow sees the stop before it signs anything")
        assertFalse(e.keeper.mayDial(e.server.origin), "no WebSocket either")
        assertTrue(client.call(WireRoute.LOGOUT, authenticated = true) { }.originStopped)
        assertTrue(client.call(WireRoute.INSTANCE, authenticated = false) { }.originStopped)
        assertTrue(client.callBytes(WireRoute.ACCOUNT_STATE_GET, body = ByteArray(3), authenticated = true) { it }.originStopped)
        assertTrue(client.fetchBytes(WireRoute.ACCOUNT_STATE_GET, authenticated = true).originStopped)
        // Nor do the keeper's own requests: a foreign session's logout, a sign-out. A re-authentication dials nothing at
        // all (spec 01 §7: proven against this device's own wrap), and its gate refuses under the fork.
        assertEquals(io.silencelen.andvari.core.client.account.ReauthKey.Refused, e.keeper.reauth()!!.currentAuthKey(strong.toCharArray()))
        e.keeper.discard(e.server.origin, "at-of-another-session")
        e.keeper.signOut()
        assertEquals(KeptPhase.NONE, e.keeper.phase.value)
        assertEquals(sent, e.transport.sent.size, "nothing was dialed at the stopped origin")
    }

    @Test fun aDamagedPinRecordBlocksTheUnlock() = runBlocking<Unit> {
        val e = env()
        register(e)
        e.keeper.lock()
        e.state.set(PinStore.KEY_PREFIX + e.server.origin, "not a pin record")
        assertEquals(KeptUnlock.Blocked, e.keeper.unlock(strong.toCharArray()))
        assertNull(e.keeper.established)
        // And nothing is dialed there either.
        val sent = e.transport.sent.size
        assertTrue(e.keeper.clientFor(e.server.origin).call(WireRoute.INSTANCE, authenticated = false) { }.originStopped)
        assertFalse(e.keeper.mayDial(e.server.origin))
        assertEquals(sent, e.transport.sent.size)
    }

    /** H1: a client handed out while the pin was in force is stopped at its next request once the fork is marked. */
    @Test fun aForkMarkedWhileAClientIsOutStopsItsNextRequestAndItsRefresh() = runBlocking<Unit> {
        val e = env()
        register(e)
        val client = e.keeper.clientFor(e.server.origin)
        assertTrue(e.keeper.mayDial(e.server.origin))
        assertFalse(client.stopped)
        assertIs<WireResult.Ok<String>>(client.call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it })
        val store = PinStore(e.state)
        store.markForked(store.get(e.server.origin)!!)
        // The access token is stale now: under the stop no refresh is attempted either.
        e.transport.expired += "at-${e.keeper.session!!.deviceId}"
        val sent = e.transport.sent.size
        val rotations = e.transport.rotations
        assertTrue(client.stopped)
        assertTrue(client.call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }.originStopped)
        assertEquals(sent, e.transport.sent.size, "nothing was dialed")
        assertEquals(rotations, e.transport.rotations, "no refresh was dialed")
        assertNotNull(e.keeper.session, "the session's tokens stay on this device")
    }

    @Test fun anotherIdentityKeyForTheSameUserIsTheIdentityFault() = runBlocking<Unit> {
        val e = env()
        val reg = register(e)
        e.keeper.lock()
        // This device's own record says another key: the stored keys no longer pass §2.4.
        e.state.set("ovh.identity|${reg.userId}", io.silencelen.andvari.core.crypto.Bytes.toB64(ByteArray(32) { 9 }))
        assertIs<KeptUnlock.IdentityFault>(e.keeper.unlock(strong.toCharArray()))
    }

    @Test fun a401RefreshesOnceAndTheRotatedPairIsKept() = runBlocking<Unit> {
        val e = env()
        register(e)
        val deviceId = e.keeper.session!!.deviceId
        e.transport.expired += "at-$deviceId"
        val r = e.keeper.clientFor(e.server.origin).call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
        assertIs<io.silencelen.andvari.core.client.net.WireResult.Ok<String>>(r)
        assertEquals("at1-rt-$deviceId", e.transport.sent.last().bearer)
        // The rotation survives a restart.
        val again = reopen(e)
        again.clientFor(e.server.origin).call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
        assertEquals("at1-rt-$deviceId", e.transport.sent.last().bearer)
    }

    @Test fun aRefusedRefreshEndsTheSession() = runBlocking<Unit> {
        val e = env()
        register(e)
        val account = e.keeper.established!!.account
        var ended: SessionEndReason? = null
        e.keeper.onEnded = { ended = it }
        e.transport.refreshAnswer = { io.silencelen.andvari.core.client.net.WireResult.Refused(401, io.silencelen.andvari.core.model.wire.WireError("refresh_reuse", "x")) }
        e.transport.expired += "at-${e.keeper.session!!.deviceId}"
        e.keeper.clientFor(e.server.origin).call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
        assertEquals(SessionEndReason.REFRESH_REFUSED, ended)
        // Design §4.4: the session is over, the account is not: it stays as signed out by the server, with no token.
        assertEquals(KeptPhase.LOCKED, e.keeper.phase.value)
        assertTrue(account.isWiped)
        val kept = assertNotNull(e.keeper.session)
        assertTrue(kept.endedByServer)
        val text = assertNotNull(e.secure.get(SessionKeeper.KEY))
        assertFalse("at-${kept.deviceId}" in text || "rt-${kept.deviceId}" in text, "no token is kept")
        // Nothing carries a bearer now, and the password still opens the account from this device's copy.
        e.transport.sent.clear()
        e.keeper.clientFor(e.server.origin).call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
        assertTrue(e.transport.sent.all { it.bearer == null })
        assertEquals(KeptUnlock.Unlocked, e.keeper.unlock(strong.toCharArray()))
    }

    /**
     * A refresh whose answer was lost (the server took it and replaced the token) is tried once more with the same token
     * inside the minute, at the next request, and the server's grace answers it with the same pair: the session lives, and
     * the server holds one session for it. The person sees one request that did not get through, then nothing.
     */
    @Test fun aRefreshWhoseAnswerWasLostIsTriedOnceMoreInsideTheMinuteAndTheSessionLives() = runBlocking<Unit> {
        val e = env(driven = true)
        register(e)
        val dev = e.keeper.session!!.deviceId
        e.transport.graceMs = 60_000
        e.transport.loseAnswers = 1
        e.transport.expired += "at-$dev"
        val client = e.keeper.clientFor(e.server.origin)
        assertIs<io.silencelen.andvari.core.client.net.WireResult.Refused>(client.call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it })
        assertEquals(KeptPhase.UNLOCKED, e.keeper.phase.value)
        // The edge of the window is still inside it.
        e.server.now += SessionKeeper.REFRESH_SECOND_TRY_MS
        assertIs<io.silencelen.andvari.core.client.net.WireResult.Ok<String>>(client.call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it })
        assertEquals(listOf("rt-$dev", "rt-$dev"), e.transport.refreshTokensReceived, "the same token, twice")
        assertEquals(1, e.transport.rotations, "one session at the server")
        assertEquals("at1-rt-$dev", e.transport.sent.last().bearer)
        assertEquals(KeptPhase.UNLOCKED, e.keeper.phase.value)
        // The pair is kept, also through a restart, and the next refresh is a normal one.
        val again = SessionKeeper(e.transport, e.secure, e.state, e.trust, crypto, clock = { e.server.now })
        e.server.now += 10 * 60_000
        e.transport.expired += "at1-rt-$dev"
        assertIs<io.silencelen.andvari.core.client.net.WireResult.Ok<String>>(again.clientFor(e.server.origin).call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it })
        assertEquals(listOf("rt-$dev", "rt-$dev", "rt1-rt-$dev"), e.transport.refreshTokensReceived)
    }

    /**
     * Never after the minute, never a third time, and a restart earns no try: where no try is left the session ends here as
     * one its server ended, with nothing sent (the account and its copy stay, and the password opens it; the person signs
     * in again). Before, the token went again at every request, and after the minute the server took it for a stolen
     * token's reuse and ended every session of the device.
     */
    @Test fun aRefreshWhoseAnswerWasLostIsNeverSentAfterTheMinuteNorAThirdTime() = runBlocking<Unit> {
        suspend fun lost(answersLost: Int, between: List<Long>, restart: Boolean = false): Pair<Env, SessionEndReason?> {
            val e = env(driven = true)
            register(e)
            e.transport.graceMs = 60_000
            e.transport.loseAnswers = answersLost
            e.transport.expired += "at-${e.keeper.session!!.deviceId}"
            var keeper = e.keeper
            var ended: SessionEndReason? = null
            keeper.onEnded = { ended = it }
            keeper.clientFor(e.server.origin).call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
            for (ms in between) {
                e.server.now += ms
                if (restart) {
                    keeper = SessionKeeper(e.transport, e.secure, e.state, e.trust, crypto, clock = { e.server.now })
                    keeper.onEnded = { ended = it }
                }
                keeper.clientFor(e.server.origin).call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
            }
            val s = assertNotNull(keeper.session)
            assertTrue(s.endedByServer)
            assertTrue(s.endedUnconfirmed, "an end of its own, kept through a restart")
            // The token is kept for one use only: the next sign-in's name for the session it replaces.
            assertEquals("rt-${s.deviceId}", keeper.signInReplaces(e.server.origin, s.emailNorm, s.deviceId))
            assertNull(keeper.signInReplaces(e.server.origin, s.emailNorm, "00000000-0000-4000-8000-0000000000bb"), "not on another device row")
            assertEquals(KeptUnlock.Unlocked, keeper.unlock(strong.toCharArray()), "the copy stays")
            // It is never sent as a refresh again, in this run or a later one.
            val before = e.transport.refreshTokensReceived.size
            keeper.clientFor(e.server.origin).call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
            SessionKeeper(e.transport, e.secure, e.state, e.trust, crypto, clock = { e.server.now }).clientFor(e.server.origin)
                .call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
            assertEquals(before, e.transport.refreshTokensReceived.size, "never sent again")
            assertTrue(e.transport.sent.takeLast(2).all { it.bearer == null }, "no bearer either")
            return e to ended
        }
        val (late, lateEnd) = lost(1, listOf(50_001))
        assertEquals(1, late.transport.refreshTokensReceived.size, "after the window: never sent again")
        assertEquals(SessionEndReason.SESSION_NOT_CONFIRMED, lateEnd)
        val (third, thirdEnd) = lost(2, listOf(1_000, 1_000))
        assertEquals(2, third.transport.refreshTokensReceived.size, "no third try")
        assertEquals(SessionEndReason.SESSION_NOT_CONFIRMED, thirdEnd)
        val (restarted, _) = lost(1, listOf(51_000), restart = true)
        assertEquals(1, restarted.transport.refreshTokensReceived.size, "a restart earns no try")
    }

    /**
     * The token kept after "no try left" goes with the session's record: at a sign-out (nothing is sent with it), at a
     * removal of the account, and at a take (the sign-in that named it); a left call that puts the earlier record back
     * does not bring it back.
     */
    @Test fun theTokenKeptAfterNoTryLeftGoesWithItsRecordAndIsNeverSent() = runBlocking<Unit> {
        suspend fun ended(): Env {
            val e = env(driven = true)
            register(e)
            e.transport.loseAnswers = 1
            e.transport.expired += "at-${e.keeper.session!!.deviceId}"
            e.keeper.clientFor(e.server.origin).call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
            e.server.now += SessionKeeper.REFRESH_SECOND_TRY_MS + 1
            e.keeper.clientFor(e.server.origin).call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
            assertEquals(SessionEndReason.SESSION_NOT_CONFIRMED, e.keeper.lastEnd)
            assertNotNull(e.keeper.signInReplaces(e.server.origin, "alice@example.com", e.keeper.session!!.deviceId))
            return e
        }
        fun sentWith(e: Env, token: String) = e.transport.refreshTokensReceived.count { it == token }
        // A sign-out: the record goes, and nothing is sent with the token (no refresh, no end of a session).
        ended().let { e ->
            val dev = e.keeper.session!!.deviceId
            e.keeper.signOut()
            assertNull(e.keeper.session)
            assertFalse(e.secure.get(SessionKeeper.KEY)?.contains("rt-$dev") == true)
            assertEquals(1, sentWith(e, "rt-$dev"))
            assertTrue(e.transport.sent.none { it.route == WireRoute.END_SESSION })
        }
        // A removal of the account (after a deletion whose outcome is not known): nothing to end with it either.
        ended().let { e ->
            val s = e.keeper.session!!
            assertNull(e.keeper.forgetAfterUnknownDeletion(e.server.origin, s.userId), "nothing is handed on to send")
            assertNull(e.secure.get(SessionKeeper.KEY))
        }
        // The sign-in that names it takes the record's place; a left call that puts the earlier record back keeps no token.
        ended().let { e ->
            val dev = e.keeper.session!!.deviceId
            val mark = e.keeper.takes
            assertIs<io.silencelen.andvari.core.client.onboard.SignIn.SignedIn>(e.onboarding.signIn("alice@example.com", strong.toCharArray()))
            assertFalse(assertNotNull(e.keeper.session).endedByServer)
            // (The fake names a session's tokens by its device, so the new pair's text is the old one's: the field is looked for.)
            assertFalse(e.secure.get(SessionKeeper.KEY)!!.contains("unconfirmedRefresh"), "the named token went with the record")
            assertNotNull(e.keeper.endTakenSince(mark))
            val back = assertNotNull(e.keeper.session)
            assertTrue(back.endedByServer && back.endedUnconfirmed)
            assertEquals(SessionEndReason.SESSION_NOT_CONFIRMED, e.keeper.lastEnd)
            assertNull(e.keeper.signInReplaces(e.server.origin, "alice@example.com", dev), "its one use was had")
            assertEquals(1, sentWith(e, "rt-$dev"))
        }
    }

    /**
     * A second try the server answers as reused (no grace: a restart of the server, or a server without one) is handled
     * as every reuse is: the session ends as signed out by the server, the account and its copy stay.
     */
    @Test fun aSecondTryTheServerTakesAsReusedEndsTheSessionAsAnyReuseDoes() = runBlocking<Unit> {
        val e = env(driven = true)
        register(e)
        var ended: SessionEndReason? = null
        e.keeper.onEnded = { ended = it }
        e.transport.loseAnswers = 1
        e.transport.expired += "at-${e.keeper.session!!.deviceId}"
        val client = e.keeper.clientFor(e.server.origin)
        client.call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
        assertNull(ended)
        e.server.now += 10_000
        client.call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
        assertEquals(2, e.transport.refreshTokensReceived.size)
        assertEquals(SessionEndReason.REFRESH_REFUSED, ended)
        assertTrue(assertNotNull(e.keeper.session).endedByServer)
        assertEquals(KeptPhase.LOCKED, e.keeper.phase.value)
    }

    /**
     * After a deletion whose outcome is not known, the person may forget the account on this device (behind the layer
     * above's confirmation): the kept session and its keys go; its identity record and the address's binding stay, as at a
     * sign-out; the server's pin stays; and the answer ends exactly that session at its server, by its own refresh token. Another
     * account's call removes nothing.
     */
    @Test fun anAccountWhoseDeletionOutcomeIsNotKnownCanBeForgottenOnThisDevice() = runBlocking<Unit> {
        val e = env()
        val reg = register(e)
        val origin = e.server.origin
        assertNotNull(e.state.get("ovh.identity|${reg.userId}"))
        assertNull(e.keeper.forgetAfterUnknownDeletion(origin, "00000000-0000-4000-8000-0000000000aa"), "another account: nothing")
        assertNull(e.keeper.forgetAfterUnknownDeletion("https://elsewhere.example", reg.userId), "another server: nothing")
        assertNotNull(e.keeper.session)
        val end = assertNotNull(e.keeper.forgetAfterUnknownDeletion(origin, reg.userId))
        assertTrue(e.transport.sent.none { it.route == WireRoute.END_SESSION }, "nothing sent by the removal itself")
        assertNull(e.keeper.session)
        assertEquals(KeptPhase.NONE, e.keeper.phase.value)
        assertNull(SessionKeeper(e.transport, e.secure, e.state, e.trust, crypto).session, "nothing kept through a restart")
        // Kept, as at a sign-out: the account may still exist (decided on 2026-11-19).
        assertNotNull(e.state.get("ovh.identity|${reg.userId}"), "the identity record")
        assertEquals(reg.userId, e.keeper.addressBinding(origin, "alice@example.com")?.userId, "the address's binding")
        assertNotNull(e.trust.pinFor(origin), "the server's pin stays")
        end()
        assertEquals(1, e.transport.sent.count { it.route == WireRoute.END_SESSION })
    }

    /** How a refresh's request was cut off while it was out. */
    private enum class Cut { NO_CONNECTION, TIMEOUT, CANCELLED, APP_ENDED }

    private class AfterCut(val e: Env, val keeper: SessionKeeper, val last: WireResult<String>, val markWhileOut: Boolean?)

    /**
     * A request whose first answer is a 401, so its refresh goes, and that refresh is cut off by [cut]; then, [after] ms
     * after it was sent, another request (by a new keeper over the same stores when [restart] or [Cut.APP_ENDED]).
     * [markWhileOut]: whether the stored record named the refresh as out while its request was held (the cut-off kinds
     * that hold it only).
     */
    private suspend fun kotlinx.coroutines.CoroutineScope.cutOff(cut: Cut, after: Long, restart: Boolean = false): AfterCut {
        val e = env(driven = true)
        register(e)
        e.transport.graceMs = 60_000
        e.transport.expired += "at-${e.keeper.session!!.deviceId}"
        var markWhileOut: Boolean? = null
        var hung: kotlinx.coroutines.Job? = null
        when (cut) {
            Cut.NO_CONNECTION -> {
                // Nothing reached the server: it never replaced the token.
                e.transport.refreshAnswer = { e.transport.refreshAnswer = null; WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TRANSPORT) }
            }
            Cut.TIMEOUT -> e.transport.loseAnswers = 1
            Cut.CANCELLED, Cut.APP_ENDED -> {
                val reached = kotlinx.coroutines.CompletableDeferred<Unit>()
                val never = kotlinx.coroutines.CompletableDeferred<Unit>()
                e.transport.afterRefreshMade = { reached.complete(Unit); never.await() }
                val j = launch { e.keeper.clientFor(e.server.origin).call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it } }
                hung = j
                reached.await()
                markWhileOut = e.secure.get(SessionKeeper.KEY)?.contains("refreshLostAt") == true
                e.transport.afterRefreshMade = null
                if (cut == Cut.CANCELLED) j.cancelAndJoin()
            }
        }
        if (cut == Cut.NO_CONNECTION || cut == Cut.TIMEOUT) {
            e.keeper.clientFor(e.server.origin).call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
        }
        e.server.now += after
        val keeper = if (restart || cut == Cut.APP_ENDED) SessionKeeper(e.transport, e.secure, e.state, e.trust, crypto, clock = { e.server.now }) else e.keeper
        val last = keeper.clientFor(e.server.origin).call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
        // The app that ended never gets its answer.
        hung?.cancelAndJoin()
        return AfterCut(e, keeper, last, markWhileOut)
    }

    /**
     * A refresh cut off while its request was out, whatever cut it off (no connection, a timeout, its caller cancelled, the
     * app ended), is tried once more only within fifty seconds of when it was sent, the edge included, and never after:
     * the second try has to arrive inside the server's sixty seconds. Before, a cancelled caller or the app's end left no
     * mark at all, so the token was sent again at any later time (after the server's minute, a stolen token's reuse that
     * ends every session of the device), and a lost answer's window was sixty seconds.
     */
    @Test fun aRefreshCutOffWhileOutIsTriedOnceMoreOnlyWithinFiftySecondsOfItsSending() = runBlocking<Unit> {
        // Every way is walked and every miss collected, so one run says what each cut-off does.
        val wrong = ArrayList<String>()
        fun want(ok: Boolean, what: String) { if (!ok) wrong += what }
        for (cut in Cut.entries) for (restart in listOf(false, true)) {
            val tag = "$cut restart=$restart"
            val inside = cutOff(cut, 50_000, restart)
            if (cut == Cut.CANCELLED || cut == Cut.APP_ENDED) want(inside.markWhileOut == true, "$tag: no record named the refresh as out while it was")
            want(inside.last is WireResult.Ok, "$tag: at 50,000 ms the request answered ${inside.last}")
            want(inside.e.transport.refreshTokensReceived.size == 2, "$tag: at 50,000 ms ${inside.e.transport.refreshTokensReceived.size} refreshes")
            want(inside.e.transport.rotations == 1, "$tag: at 50,000 ms ${inside.e.transport.rotations} sessions made at the server")
            want(inside.keeper.session?.endedByServer == false, "$tag: at 50,000 ms the session ended")
            want(inside.e.secure.get(SessionKeeper.KEY)?.contains("refreshLostAt") == false, "$tag: at 50,000 ms the answer left the record")

            for (after in listOf(50_001L, 10 * 60_000L)) {
                val past = cutOff(cut, after, restart)
                val sent = past.e.transport.refreshTokensReceived.size
                want(sent == 1, "$tag: at $after ms the token was sent again ($sent received; the request answered ${past.last}; " +
                    "session ended by server: ${past.keeper.session?.endedByServer}, last end ${past.keeper.lastEnd})")
                want(past.keeper.session?.endedByServer == true, "$tag: at $after ms the session did not end here")
                want(past.keeper.session?.endedUnconfirmed == true && past.keeper.lastEnd == SessionEndReason.SESSION_NOT_CONFIRMED,
                    "$tag: at $after ms the end is ${past.keeper.lastEnd}, not one of its own")
                want(past.keeper.session != null && past.keeper.unlock(strong.toCharArray()) == KeptUnlock.Unlocked, "$tag: at $after ms the copy does not open")
            }
        }
        assertEquals(emptyList(), wrong, wrong.joinToString("\n"))
    }

    /**
     * Any HTTP answer to a refresh clears the record that it was out (a rotation, a 429, a 5xx in the server's envelope),
     * and so does the guard's own stop, before which nothing left: a later refresh goes as an ordinary one. A second try
     * answered other than by a rotation or an end leaves the first try still unanswered: no third try goes.
     */
    @Test fun aRefreshThatWasAnsweredLeavesNoRecordBehind() = runBlocking<Unit> {
        fun refused(status: Int, code: String) = WireResult.Refused(status, io.silencelen.andvari.core.model.wire.WireError(code, "m"))
        for (answer in listOf<WireResult<String>?>(null, refused(429, "rate_limited"), refused(503, "unavailable"), refused(0, io.silencelen.andvari.core.client.net.ORIGIN_STOPPED))) {
            val e = env(driven = true)
            register(e)
            val dev = e.keeper.session!!.deviceId
            val once: (String) -> WireResult<String> = { e.transport.refreshAnswer = null; answer!! }
            e.transport.refreshAnswer = once.takeIf { answer != null }
            e.transport.expired += "at-$dev"
            e.keeper.clientFor(e.server.origin).call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
            val tag = answer?.let { (it as WireResult.Refused).code } ?: "rotated"
            assertFalse(e.secure.get(SessionKeeper.KEY)!!.contains("refreshLostAt"), "$tag: no record is left")
            e.server.now += 10 * 60_000
            // The access token in use now is the rotated one, or still the first (refused, so not rotated).
            if (answer == null) e.transport.expired += "at1-rt-$dev"
            assertIs<WireResult.Ok<String>>(e.keeper.clientFor(e.server.origin).call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }, tag)
            assertEquals(2, e.transport.refreshTokensReceived.size, "$tag: the later refresh went")
            assertFalse(assertNotNull(e.keeper.session).endedByServer, tag)
        }
        // A lost answer, then a second try answered 429: the first try is still unanswered, so nothing goes a third time.
        val e = env(driven = true)
        register(e)
        e.transport.graceMs = 60_000
        e.transport.loseAnswers = 1
        e.transport.expired += "at-${e.keeper.session!!.deviceId}"
        val client = e.keeper.clientFor(e.server.origin)
        client.call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
        e.server.now += 1_000
        e.transport.refreshAnswer = { refused(429, "rate_limited") }
        client.call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
        e.transport.refreshAnswer = null
        e.server.now += 1_000
        client.call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
        assertEquals(2, e.transport.refreshTokensReceived.size, "no third try")
        assertTrue(assertNotNull(e.keeper.session).endedByServer)
    }

    @Test fun aRefreshWithNoAnswerKeepsTheSession() = runBlocking<Unit> {
        val e = env()
        register(e)
        e.transport.refreshAnswer = { io.silencelen.andvari.core.client.net.WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TIMEOUT) }
        e.transport.expired += "at-${e.keeper.session!!.deviceId}"
        e.keeper.clientFor(e.server.origin).call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
        assertEquals(KeptPhase.UNLOCKED, e.keeper.phase.value)
    }

    /**
     * Any 401 to a refresh ends the session as the server's end (a revoked device: `session_revoked`; an inactive
     * account: `invalid_credentials`): the tokens and the quick-unlock key go, the account and its copy stay. A 429, a
     * 5xx or the guard's own stop never ends it.
     */
    @Test fun every401ToARefreshEndsTheSessionAndNothingElseDoes() = runBlocking<Unit> {
        fun refused(status: Int, code: String) = io.silencelen.andvari.core.client.net.WireResult.Refused(status, io.silencelen.andvari.core.model.wire.WireError(code, "m"))
        for ((answer, ends) in listOf(
            refused(401, "session_revoked") to true,
            refused(401, "invalid_credentials") to true,
            refused(401, "unauthorized") to true,
            refused(429, "rate_limited") to false,
            refused(503, "unavailable") to false,
            refused(0, io.silencelen.andvari.core.client.net.ORIGIN_STOPPED) to false,
        )) {
            val e = env()
            register(e)
            e.transport.refreshAnswer = { answer }
            e.transport.expired += "at-${e.keeper.session!!.deviceId}"
            e.keeper.clientFor(e.server.origin).call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
            val s = assertNotNull(e.keeper.session, "the account stays either way (${answer.code})")
            assertEquals(ends, s.endedByServer, "${answer.status} ${answer.code}")
            assertEquals(if (ends) KeptPhase.LOCKED else KeptPhase.UNLOCKED, e.keeper.phase.value, answer.code)
        }
    }

    @Test fun signOutSendsLogoutWithTheBearerAndForgetsTheSession() = runBlocking<Unit> {
        val e = env()
        register(e)
        val deviceId = e.keeper.session!!.deviceId
        e.keeper.signOut()
        assertEquals(listOf<String?>("at-$deviceId"), e.transport.bearersFor(WireRoute.LOGOUT))
        assertEquals(KeptPhase.NONE, e.keeper.phase.value)
        assertEquals(SessionEndReason.SIGNED_OUT, e.keeper.lastEnd)
        assertEquals(KeptPhase.NONE, reopen(e).phase.value)
        // The device row's secret stays: signing in again on this device is a known device.
        assertNotNull(KnownDevices(e.state, crypto).deviceId(e.server.origin, "alice@example.com"))
        assertIs<SignIn.SignedIn>(e.onboarding.signIn("alice@example.com", strong.toCharArray()))
        assertEquals(deviceId, e.keeper.session!!.deviceId)
    }

    @Test fun discardEndsASessionTheKeeperNeverOwned() = runBlocking<Unit> {
        val e = env()
        e.keeper.discard("https://h.example", "at-somebody-else")
        val sent = e.transport.sent.single()
        assertEquals(WireRoute.LOGOUT, sent.route)
        assertEquals("at-somebody-else", sent.bearer)
        assertEquals("https://h.example", sent.origin)
        assertEquals(KeptPhase.NONE, e.keeper.phase.value)
    }

    @Test fun reauthAsksTheGateThenDerivesTheCurrentAuthKey() = runBlocking<Unit> {
        val e = env()
        register(e)
        val reauth = assertNotNull(e.keeper.reauth())
        val key = assertIs<ReauthKey.Key>(reauth.currentAuthKey(strong.toCharArray()))
        assertEquals(e.server.account("alice@example.com").authKey, key.currentAuthKey)
        // A forked pin refuses before anything is derived or sent.
        val store = PinStore(e.state)
        store.markForked(store.get(e.server.origin)!!)
        val before = e.transport.sent.size
        assertEquals(ReauthKey.Refused, reauth.currentAuthKey(strong.toCharArray()))
        assertEquals(before, e.transport.sent.size)
    }

    @Test fun forgetDropsTheSessionWithoutTellingTheServer() = runBlocking<Unit> {
        val e = env()
        val reg = register(e)
        e.keeper.forget(forgetIdentity = true)
        assertTrue(e.transport.bearersFor(WireRoute.LOGOUT).isEmpty())
        assertEquals(KeptPhase.NONE, e.keeper.phase.value)
        assertNull(e.keeper.knownIdentity(reg.userId))
    }

    /**
     * Under a policy that keeps the account's keys at the server, the unlock whose read of the keys learns that the server
     * ended the session answers that a sign-in is needed, as every later unlock does. Before, it answered as a read about
     * an older state (the end itself moved the keys' generation), and only the next unlock said that a sign-in is needed.
     */
    @Test fun anUnlockThatLearnsTheServersEndAsksForASignInAtOnce() = runBlocking<Unit> {
        val e = env(driven = true)
        register(e)
        val origin = e.server.origin
        KeptPolicies(e.state).record(origin, io.silencelen.andvari.core.model.wire.ClientPolicy(emptyMap(), io.silencelen.andvari.core.crypto.KdfParams.DEFAULT,
            300, 30, false, 3600, 30, 1, 1, e.server.now, io.silencelen.andvari.core.model.wire.SignupPolicy("open", false, true, 0), false), e.server.now)
        e.keeper.policyRecorded(origin)
        e.keeper.lock()
        assertTrue("\"keysAtServer\":true" in assertNotNull(e.secure.get(SessionKeeper.KEY)), "the keys are kept at the server")
        // The access token is refused, and so is its refresh: the server ended the session.
        e.transport.expired += "at-${assertNotNull(e.keeper.session).deviceId}"
        e.transport.refreshAnswer = { WireResult.Refused(401, io.silencelen.andvari.core.model.wire.WireError("invalid_refresh", "m")) }
        assertEquals(KeptUnlock.KeysAtServer(signInNeeded = true), e.keeper.unlockAsking(strong.toCharArray()), "the unlock that learns the end")
        assertTrue(assertNotNull(e.keeper.session).endedByServer)
        assertEquals(KeptUnlock.KeysAtServer(signInNeeded = true), e.keeper.unlockAsking(strong.toCharArray()), "every later unlock")
    }
}
