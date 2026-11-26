package io.silencelen.andvari.core.client.devicelink

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.items.copyOut
import io.silencelen.andvari.core.client.link.LinkAccount
import io.silencelen.andvari.core.client.onboard.EstablishedSession
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.PasswordKeys
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
import io.silencelen.andvari.core.client.onboard.SessionSink
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.client.pin.CardTrust
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.client.session.KeptPhase
import io.silencelen.andvari.core.client.session.KeptUnlock
import io.silencelen.andvari.core.client.session.SessionKeeper
import io.silencelen.andvari.core.client.state.StoredAccountState
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
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
import kotlin.test.assertTrue

/**
 * Spec 01 §7, a device link on a device that already keeps the account. In the pickup the key comes from the server's
 * wrap, opened with the password the person types on this device; the other device's bundle is sealed under it. Before
 * anything kept is replaced, that key must be the account's key as this device knows it: a kept wrap the typed password
 * opens must hold it, and where none opens, it must open the copy's sealed identity seed. Another key replaces nothing:
 * the server's new session is ended there, no session is kept, and the stop says so. Before, the pickup compared nothing
 * kept: the session went to the keeper, which replaced the copy with whatever passed the pickup's own checks.
 */
class DeviceLinkOverKeptAccountTest {
    private val crypto = createCryptoProvider()
    private val password = "correct horse Battery 9 staple"
    private val second = "a newer Password 7 for alice"
    private val email = "alice@example.com"

    private class Sink : SessionSink {
        val sessions = ArrayList<EstablishedSession>()
        override suspend fun established(session: EstablishedSession) { sessions += session }
    }

    private inner class World {
        val instance = FakeInstance(crypto)
        val server = DeviceLinkServer(instance)
        val eState = MemoryDeviceState()
        lateinit var eSession: EstablishedSession
        lateinit var e: WireDeviceLinks
        val nState = MemoryDeviceState()
        lateinit var nTrust: CardTrust
        lateinit var transport: BearerTransport
        lateinit var keeper: SessionKeeper
        val discarded = ArrayList<String>()
        val account get() = instance.accounts.values.single()

        /** alice registered on E; this device (N) signed in to her account once and keeps it, locked. */
        suspend fun setUp(): World {
            val eTrust = instance.pinnedTrust(eState)
            val sink = Sink()
            val onboarding = WireOnboarding(instance.origin, server.client(null), eTrust, KnownDevices(eState, crypto), sink, crypto, eState, "desktop", "Laptop",
                { instance.now }, work = Dispatchers.Unconfined)
            onboarding.signupStart(email, true)
            val ticket = assertIs<SignupVerify.Ticket>(onboarding.signupVerify(email, "482915"))
            val reg = assertIs<Registration.Registered>(onboarding.register(RegistrationAuth.Ticket(ticket),
                RegistrationForm(email, "Alice", password.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Laptop", "desktop")))
            eSession = sink.sessions.single()
            val acct = LinkAccount.of(eSession, "Alice", StoredAccountState(reg.userId, eSession.account.uvk, server.client(reg.userId), crypto, eState))
            e = WireDeviceLinks({ server.client(reg.userId, it) }, eTrust, eState, crypto, { instance.now }, { acct }, KnownDevices(eState, crypto), sink,
                { _, _ -> }, "Laptop", "desktop")
            nTrust = instance.pinnedTrust(nState)
            transport = BearerTransport(mapOf(instance.origin to server.client(null)))
            keeper = SessionKeeper(transport, MemoryDeviceState(), nState, nTrust, crypto)
            val nOnboarding = WireOnboarding(instance.origin, keeper.clientFor(instance.origin), nTrust, KnownDevices(nState, crypto), keeper, crypto, nState,
                "android", "Pixel 9", { instance.now }, knownIdentity = keeper::knownIdentity, work = Dispatchers.Unconfined)
            assertIs<SignIn.SignedIn>(nOnboarding.signIn(email, password.toCharArray()))
            keeper.lock()
            return this
        }

        fun keptKeys(): AccountKeys = assertNotNull(keeper.keptForSignIn(instance.origin)).own

        /** As the app engine is to bind it: a refused pickup's session ends by its refresh token, never by a sign-out. */
        fun n() = WireDeviceLinks({ keeper.clientFor(it) }, nTrust, nState, crypto, { instance.now }, { null }, KnownDevices(nState, crypto), keeper,
            { o, token -> keeper.discard(o, token) }, "Pixel 9", "android", endOne = { o, refresh -> discarded += refresh; keeper.notTaken(o, "", refresh) })

        /** Runs both sides to E's approval; returns N's engine and its PasswordNeeded step. */
        suspend fun approved(n: WireDeviceLinks = n()): Pair<WireDeviceLinks, NewStep.PasswordNeeded> {
            val shown = assertIs<ExistingStep.Shown>(e.create())
            val claimed = assertIs<NewStep.Claimed>(n.start(shown.url, GateEntry.LINK_DEVICE_SCREEN))
            val fixed = assertIs<ExistingStep.ClaimFixed>(e.advance(shown))
            val code = assertIs<NewStep.ShowCode>(n.advance(claimed))
            val type = assertIs<ExistingStep.TypeDigits>(e.advance(fixed))
            val ok = assertIs<ExistingStep.Approvable>(e.typeDigits(type, code.code))
            assertIs<ExistingStep.Approved>(e.approve(ok))
            return n to assertIs<NewStep.PasswordNeeded>(n.advance(code))
        }

        /** The server holds [key] for this account wrapped under [typed] at a fresh salt from now on. */
        fun serveWrapOf(key: ByteArray, typed: String) {
            val salt = crypto.randomBytes(KdfParams.SALT_BYTES)
            val k = assertNotNull(PasswordKeys.derive(crypto, typed.toCharArray(), salt, KdfParams.DEFAULT, served = false))
            try {
                account.authKey = k.authKeyB64
                account.kdfSalt = Bytes.toB64(salt)
                account.kdfParams = k.params
                account.wrappedUvk = Envelope.sealB64(crypto, k.wrapKey, key, Ad.uvk(account.userId))
            } finally {
                k.wipe()
            }
        }
    }

    /**
     * Spec 01 §5 at a link: this device knows the link's address at its server under ANOTHER account (the one it first took
     * there: here the record names another user id, as after the account was deleted and made again). The keeper's
     * refusal at the approval, and again just before the pickup, is a stop of its own that carries the address, so the
     * layer above can offer to forget the earlier account there as at a sign-in; nothing is picked up. Before, it was the
     * bare identity fault, told apart from nothing. Once the earlier account is forgotten, the next link links.
     */
    @Test fun aLinkForAnAddressKnownHereUnderAnotherAccountStopsWithTheAddressBeforeThePickup() = runBlocking<Unit> {
        val w = World().setUp()
        val linked = assertNotNull(w.keeper.session).userId
        w.keeper.signOut()
        val bindingKey = "${SessionKeeper.EMAIL_BINDING_PREFIX}${w.instance.origin}|$email"
        val identityKey = assertNotNull(w.nState.get(bindingKey)).substringAfter('|')
        val earlier = "00000000-0000-4000-8000-0000000000dd"
        fun bindToEarlier() = w.nState.set(bindingKey, "$earlier|$identityKey")
        fun pickups() = w.transport.sent.count { it.route == WireRoute.DEVICE_LINK_PICKUP }
        // This device holds a record of the link's own account's key, and a stop before the pickup has no served key to
        // hold it to: which of the two causes it is cannot be told there, so the stop names no address (decided on
        // 2026-11-19). Without that record it can be told: another account, the address named.
        val identityRecord = "ovh.identity|$linked"
        val ownKey = assertNotNull(w.nState.get(identityRecord))
        for (recordOfTheLinksKey in listOf(true, false)) {
            if (recordOfTheLinksKey) w.nState.set(identityRecord, ownKey) else w.nState.set(identityRecord, null)
            val named = if (recordOfTheLinksKey) {
                NewStep.Stopped(DeviceLinkStop.IDENTITY_MISMATCH)
            } else {
                NewStep.Stopped(DeviceLinkStop.IDENTITY_MISMATCH, addressKnownHere = email, anotherAccountServed = linked)
            }

            // At the approval: the account is named, and the keeper refuses before the password is asked.
            bindToEarlier()
            val n = w.n()
            val shown = assertIs<ExistingStep.Shown>(w.e.create())
            val claimed = assertIs<NewStep.Claimed>(n.start(shown.url, GateEntry.LINK_DEVICE_SCREEN))
            val fixed = assertIs<ExistingStep.ClaimFixed>(w.e.advance(shown))
            val code = assertIs<NewStep.ShowCode>(n.advance(claimed))
            val type = assertIs<ExistingStep.TypeDigits>(w.e.advance(fixed))
            assertIs<ExistingStep.Approved>(w.e.approve(assertIs<ExistingStep.Approvable>(w.e.typeDigits(type, code.code))))
            assertEquals(named, n.advance(code), "a record of the link's key: $recordOfTheLinksKey")
            assertEquals(0, pickups(), "nothing picked up")
            assertEquals(io.silencelen.andvari.core.client.session.AddressBinding(earlier, identityKey, io.silencelen.andvari.core.client.session.BoundAccountHere.NOT_KEPT),
                w.keeper.addressBinding(w.instance.origin, email))

            // Just before the pickup: the record was written after the password was asked for.
            w.nState.set(bindingKey, null)
            val (n2, need) = w.approved()
            bindToEarlier()
            assertEquals(named, n2.pickup(need, password.toCharArray()), "a record of the link's key: $recordOfTheLinksKey")
            assertEquals(0, pickups(), "nothing picked up")
        }

        // The forgetting there, then a link that links.
        assertIs<io.silencelen.andvari.core.client.session.ForgetEarlier.Forgotten>(w.keeper.forgetEarlierAccount(w.instance.origin, email))
        val (n3, again) = w.approved()
        assertIs<NewStep.Linked>(n3.pickup(again, password.toCharArray()))
    }

    /**
     * A reason of the session keeper's that the link does not know is handed through unchanged, with a stop of its own,
     * never said as another account kept here; a reason it knows keeps its own stop. Nothing is picked up.
     */
    @Test fun aKeepersReasonTheLinkDoesNotKnowIsHandedThroughUnchanged() = runBlocking<Unit> {
        val w = World().setUp()
        var reason: String? = null
        val sink = object : SessionSink by w.keeper {
            override fun wouldRefuse(origin: String, emailNorm: String?, userId: String?, identityPub: ByteArray?): String? = reason
        }
        fun n() = WireDeviceLinks({ w.keeper.clientFor(it) }, w.nTrust, w.nState, crypto, { w.instance.now }, { null }, KnownDevices(w.nState, crypto), sink,
            { o, token -> w.keeper.discard(o, token) }, "Pixel 9", "android")
        // The keeper refuses at the approval, once the account is named.
        suspend fun approval(n: WireDeviceLinks, refusing: String): NewStep {
            reason = null
            val shown = assertIs<ExistingStep.Shown>(w.e.create())
            val claimed = assertIs<NewStep.Claimed>(n.start(shown.url, GateEntry.LINK_DEVICE_SCREEN))
            val fixed = assertIs<ExistingStep.ClaimFixed>(w.e.advance(shown))
            val code = assertIs<NewStep.ShowCode>(n.advance(claimed))
            val type = assertIs<ExistingStep.TypeDigits>(w.e.advance(fixed))
            assertIs<ExistingStep.Approved>(w.e.approve(assertIs<ExistingStep.Approvable>(w.e.typeDigits(type, code.code))))
            reason = refusing
            return n.advance(code)
        }
        assertEquals(NewStep.Stopped(DeviceLinkStop.KEEPER_REFUSED, keeperReason = "a_reason_of_its_own"), approval(n(), "a_reason_of_its_own"))
        assertEquals(NewStep.Stopped(DeviceLinkStop.ANOTHER_SESSION_KEPT),
            approval(n(), io.silencelen.andvari.core.client.session.Establishing.ANOTHER_SESSION_KEPT))
        assertEquals(0, w.transport.sent.count { it.route == WireRoute.DEVICE_LINK_PICKUP }, "nothing picked up")
    }

    /**
     * A stop says by itself whether the session keeper refused the link before its pickup was sent
     * ([NewStep.Stopped.keeperBeforePickup]): at the approval and at the ask just before the pickup it does; at the pickup's
     * take (the keeper refusing the pickup's session) and at the pickup's own identity check it does not. Before, the
     * keeper's identity stop at the ask before the pickup and the pickup's own identity check were the same stop, and the
     * layer above could not tell which one it had.
     */
    @Test fun aStopSaysWhetherTheKeeperRefusedBeforeThePickup() = runBlocking<Unit> {
        val w = World().setUp()
        var before: String? = null
        var atTake: String? = null
        var otherKey: ByteArray? = null
        val sink = object : SessionSink by w.keeper {
            override fun wouldRefuse(origin: String, emailNorm: String?, userId: String?, identityPub: ByteArray?): String? = before
            override suspend fun take(session: EstablishedSession): String? = atTake ?: w.keeper.take(session)
            override fun knownIdentity(userId: String): ByteArray? = otherKey ?: w.keeper.knownIdentity(userId)
        }
        fun n() = WireDeviceLinks({ w.keeper.clientFor(it) }, w.nTrust, w.nState, crypto, { w.instance.now }, { null }, KnownDevices(w.nState, crypto), sink,
            { o, token -> w.keeper.discard(o, token) }, "Pixel 9", "android")
        fun pickups() = w.transport.sent.count { it.route == WireRoute.DEVICE_LINK_PICKUP }
        val identity = io.silencelen.andvari.core.client.session.Establishing.IDENTITY_MISMATCH

        // At the approval, once the account is named.
        val n1 = n()
        val shown = assertIs<ExistingStep.Shown>(w.e.create())
        val claimed = assertIs<NewStep.Claimed>(n1.start(shown.url, GateEntry.LINK_DEVICE_SCREEN))
        val fixed = assertIs<ExistingStep.ClaimFixed>(w.e.advance(shown))
        val code = assertIs<NewStep.ShowCode>(n1.advance(claimed))
        val type = assertIs<ExistingStep.TypeDigits>(w.e.advance(fixed))
        assertIs<ExistingStep.Approved>(w.e.approve(assertIs<ExistingStep.Approvable>(w.e.typeDigits(type, code.code))))
        before = identity
        val atApproval = assertIs<NewStep.Stopped>(n1.advance(code))
        assertEquals(NewStep.Stopped(DeviceLinkStop.IDENTITY_MISMATCH), atApproval)
        assertTrue(atApproval.keeperBeforePickup, "at the approval")

        // At the ask just before the pickup (the keeper's answer changed after the password was asked for).
        before = null
        val (n2, need2) = w.approved(n())
        before = identity
        val atAsk = assertIs<NewStep.Stopped>(n2.pickup(need2, password.toCharArray()))
        assertEquals(NewStep.Stopped(DeviceLinkStop.IDENTITY_MISMATCH), atAsk)
        assertTrue(atAsk.keeperBeforePickup, "at the ask before the pickup")
        assertEquals(0, pickups(), "nothing picked up so far")

        // At the pickup's take: the keeper refuses the pickup's session.
        before = null
        atTake = identity
        val (n3, need3) = w.approved(n())
        val atTakeStop = assertIs<NewStep.Stopped>(n3.pickup(need3, password.toCharArray()))
        assertEquals(NewStep.Stopped(DeviceLinkStop.IDENTITY_MISMATCH), atTakeStop)
        assertFalse(atTakeStop.keeperBeforePickup, "at the take")
        assertEquals(1, pickups())

        // The pickup's own identity check: the account's key does not match this device's record of it.
        atTake = null
        otherKey = crypto.randomBytes(32)
        val (n4, need4) = w.approved(n())
        val ownCheck = assertIs<NewStep.Stopped>(n4.pickup(need4, password.toCharArray()))
        assertEquals(NewStep.Stopped(DeviceLinkStop.IDENTITY_MISMATCH), ownCheck)
        assertFalse(ownCheck.keeperBeforePickup, "the pickup's own check")
        assertEquals(2, pickups())
    }

    @Test fun aLinkOverTheSameAccountUnderTheSamePasswordLinksAndSaysNothing() = runBlocking<Unit> {
        val w = World().setUp()
        val takes = w.keeper.takes
        val (n, need) = w.approved()
        val linked = assertIs<NewStep.Linked>(n.pickup(need, password.toCharArray()))
        assertFalse(linked.copyUnderOtherPassword)
        assertEquals(takes + 1, w.keeper.takes)
        assertTrue(w.discarded.isEmpty())
    }

    @Test fun aLinkAfterThePasswordChangedElsewhereLinksAndSaysTheCopyFollowsTheServer() = runBlocking<Unit> {
        val w = World().setUp()
        val uvk = w.eSession.account.uvk.copyOut()
        try {
            w.serveWrapOf(uvk, second)
        } finally {
            uvk.fill(0)
        }
        val (n, need) = w.approved()
        val linked = assertIs<NewStep.Linked>(n.pickup(need, second.toCharArray()))
        assertTrue(linked.copyUnderOtherPassword, "no kept wrap opened with the typed password; the copy's sealed seed did")
        assertEquals(w.account.wrappedUvk, w.keptKeys().wrappedUvk)
        w.keeper.lock()
        assertEquals(KeptUnlock.Unlocked, w.keeper.unlock(second.toCharArray()))
    }

    @Test fun aServerWhosePickupOpensAnotherKeyReplacesNothingAndEndsItsSession() = runBlocking<Unit> {
        val w = World().setUp()
        val before = w.keptKeys()
        val takes = w.keeper.takes
        val (n, need) = w.approved()
        // The typed password opens the server's wrap, for this account's id, of another key.
        w.serveWrapOf(crypto.randomBytes(32), password)
        // Before: IDENTITY_MISMATCH (the served seed does not open under that key).
        assertEquals(NewStep.Stopped(DeviceLinkStop.SERVER_KEYS_NOT_KNOWN_HERE), n.pickup(need, password.toCharArray()))
        assertEquals(takes, w.keeper.takes, "no session was handed over")
        assertEquals(before, w.keptKeys(), "nothing this device keeps was replaced")
        assertEquals(KeptPhase.LOCKED, w.keeper.phase.value)
        assertEquals(1, w.discarded.size, "exactly the pickup's session is ended at the server, by its refresh token")
        assertEquals(1, w.transport.sent.count { it.route == WireRoute.END_SESSION })
        assertTrue(WireRoute.LOGOUT !in w.transport.sent.map { it.route }, "no sign-out, which would end the kept session too")
        assertEquals(KeptUnlock.Unlocked, w.keeper.unlock(password.toCharArray()), "the copy still opens with its own password")
    }

    /**
     * A link of alice's account on a device that keeps bob's: the session keeper would refuse the pickup's session, so the
     * link stops as soon as it names the account, before the password is asked for and before anything is picked up.
     * Before, the person typed the password, the pickup was sent (the link spent, a session opened at the server), and
     * only then was the session refused.
     */
    @Test fun aLinkOfAnotherAccountOnADeviceThatKeepsOneStopsBeforeThePickup() = runBlocking<Unit> {
        val w = World().setUp()
        w.keeper.signOut()
        val bob = WireOnboarding(w.instance.origin, w.keeper.clientFor(w.instance.origin), w.nTrust, KnownDevices(w.nState, crypto), w.keeper, crypto, w.nState,
            "android", "Pixel 9", { w.instance.now }, knownIdentity = w.keeper::knownIdentity, work = Dispatchers.Unconfined)
        bob.signupStart("bob@example.com", true)
        val t = assertIs<SignupVerify.Ticket>(bob.signupVerify("bob@example.com", "482915"))
        assertIs<Registration.Registered>(bob.register(RegistrationAuth.Ticket(t),
            RegistrationForm("bob@example.com", "Bob", password.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel 9", "android")))
        w.keeper.lock()
        val takes = w.keeper.takes
        val n = w.n()
        val shown = assertIs<ExistingStep.Shown>(w.e.create())
        val claimed = assertIs<NewStep.Claimed>(n.start(shown.url, GateEntry.LINK_DEVICE_SCREEN))
        val fixed = assertIs<ExistingStep.ClaimFixed>(w.e.advance(shown))
        val code = assertIs<NewStep.ShowCode>(n.advance(claimed))
        val type = assertIs<ExistingStep.TypeDigits>(w.e.advance(fixed))
        val ok = assertIs<ExistingStep.Approvable>(w.e.typeDigits(type, code.code))
        assertIs<ExistingStep.Approved>(w.e.approve(ok))
        assertEquals(NewStep.Stopped(DeviceLinkStop.ANOTHER_SESSION_KEPT), n.advance(code))
        assertTrue(WireRoute.DEVICE_LINK_PICKUP !in w.transport.sent.map { it.route }, "nothing was picked up")
        assertEquals(takes, w.keeper.takes)
        assertEquals("bob@example.com", assertNotNull(w.keeper.session).emailNorm)
    }

    @Test fun anotherKeyUnderAnotherPasswordReplacesNothingEither() = runBlocking<Unit> {
        val w = World().setUp()
        w.keeper.endedByServer(w.instance.origin)
        val before = w.keptKeys()
        val (n, need) = w.approved()
        // No kept wrap opens with the typed password, and the other key does not open the copy's sealed seed.
        w.serveWrapOf(crypto.randomBytes(32), second)
        assertEquals(NewStep.Stopped(DeviceLinkStop.SERVER_KEYS_NOT_KNOWN_HERE), n.pickup(need, second.toCharArray()))
        assertEquals(before, w.keptKeys())
        assertTrue(assertNotNull(w.keeper.session).endedByServer, "the account stays as its server signed it out")
        assertEquals(1, w.discarded.size)
    }

    /**
     * The server refuses the pickup's password proof (the uniform 401, no code asked for) although the typed password
     * opens this device's kept wrap of the account: a stop of its own, never "wrong password". A password that opens
     * nothing kept is still a wrong password, and the link stays. Before, both were `WrongPassword`.
     */
    @Test fun aProofTheServerRefusesForThePasswordThisDeviceKnowsIsNoWrongPassword() = runBlocking<Unit> {
        val w = World().setUp()
        val (n, need) = w.approved()
        val wrong = assertIs<NewStep.WrongPassword>(n.pickup(need, "not the password 1A!".toCharArray()))
        assertFalse(wrong.afterCode)
        assertFalse(wrong.proofRefused)
        // The server now holds another proof for the account under the same salt and cost: it refuses the right password.
        w.account.authKey = Bytes.toB64(crypto.randomBytes(32))
        val takes = w.keeper.takes
        val refused = assertIs<NewStep.WrongPassword>(n.pickup(wrong, password.toCharArray()))
        assertTrue(refused.proofRefused, "told apart from a wrong password")
        assertFalse(refused.afterCode)
        assertEquals(takes, w.keeper.takes, "nothing was linked")
        assertEquals(KeptPhase.LOCKED, w.keeper.phase.value, "the kept copy stays")
        // Past the link's own time the same refusal ends the link, as itself.
        w.instance.now += WireDeviceLinks.LIFETIME_MS
        assertEquals(NewStep.Stopped(DeviceLinkStop.PROOF_REFUSED), n.pickup(refused, password.toCharArray()))
        assertEquals(takes, w.keeper.takes)
    }

    /**
     * The password was changed on another device, and this device's copy still opens with the former one. A person who
     * types the former password at a link keeps the link: the step says the server did not take a password that opens
     * the copy here, asks again, and the current password links (the copy then follows the server's password). Before,
     * the former password ended the link, and the person started again on both devices.
     */
    @Test fun aFormerPasswordThatOpensTheCopyHereKeepsTheLinkAndTheCurrentOneLinks() = runBlocking<Unit> {
        val w = World().setUp()
        val uvk = w.eSession.account.uvk.copyOut()
        try {
            w.serveWrapOf(uvk, second)
        } finally {
            uvk.fill(0)
        }
        val (n, need) = w.approved()
        val takes = w.keeper.takes
        val former = assertIs<NewStep.WrongPassword>(n.pickup(need, password.toCharArray()))
        assertTrue(former.proofRefused)
        assertFalse(former.afterCode)
        assertEquals(KeptPhase.LOCKED, w.keeper.phase.value)
        // Typed again: the same, and the link still stays.
        val again = assertIs<NewStep.WrongPassword>(n.pickup(former, password.toCharArray()))
        assertTrue(again.proofRefused)
        // A password that opens nothing here is a wrong password, said as that.
        val typo = assertIs<NewStep.WrongPassword>(n.pickup(again, "not the password 1A!".toCharArray()))
        assertFalse(typo.proofRefused)
        assertFalse(typo.afterCode)
        assertEquals(takes, w.keeper.takes, "nothing was linked meanwhile")
        val linked = assertIs<NewStep.Linked>(n.pickup(typo, second.toCharArray()))
        assertTrue(linked.copyUnderOtherPassword)
        assertEquals(takes + 1, w.keeper.takes)
    }

    /**
     * Whether a code was asked for is the link's, not the call's: once the server asked for a two-step code in this link,
     * a later 401 to a pickup sent without a code is a refusal after the code (the link stays), never a refused proof,
     * even where the typed password opens the copy here. Before, such a 401 ended the link as a refused proof.
     */
    @Test fun aRefusalAfterACodeWasAskedInTheLinkIsNeverARefusedProof() = runBlocking<Unit> {
        val w = World().setUp()
        w.instance.account(email).totp = "123456"
        val (n, need) = w.approved()
        val code = assertIs<NewStep.TotpNeeded>(n.pickup(need, password.toCharArray()))
        val wrongCode = assertIs<NewStep.WrongPassword>(n.pickup(code, password.toCharArray(), "654321"))
        assertTrue(wrongCode.afterCode)
        // The server now refuses the password this device knows, and the next pickup carries no code.
        w.account.authKey = Bytes.toB64(crypto.randomBytes(32))
        val after = assertIs<NewStep.WrongPassword>(n.pickup(wrongCode, password.toCharArray(), null))
        assertTrue(after.afterCode)
        assertFalse(after.proofRefused)
        assertEquals(KeptPhase.LOCKED, w.keeper.phase.value)
    }

    /**
     * A device link is under way from its start to its pickup, for every address at its server until its account is
     * named: the forgetting of the earlier account answers so and removes nothing; a cancel ends the link. Before, only the
     * pickup call held, and between the start and the pickup the forgetting removed the kept copy.
     */
    @Test fun aLinkBlocksTheForgettingFromItsStartToItsEnd() = runBlocking<Unit> {
        val w = World().setUp()
        val origin = w.instance.origin
        val n = w.n()
        val shown = assertIs<ExistingStep.Shown>(w.e.create())
        val claimed = assertIs<NewStep.Claimed>(n.start(shown.url, GateEntry.LINK_DEVICE_SCREEN))
        assertEquals(io.silencelen.andvari.core.client.session.ForgetEarlier.FlowUnderWay, w.keeper.forgetEarlierAccount(origin, email), "claimed")
        val fixed = assertIs<ExistingStep.ClaimFixed>(w.e.advance(shown))
        val code = assertIs<NewStep.ShowCode>(n.advance(claimed))
        val type = assertIs<ExistingStep.TypeDigits>(w.e.advance(fixed))
        assertIs<ExistingStep.Approved>(w.e.approve(assertIs<ExistingStep.Approvable>(w.e.typeDigits(type, code.code))))
        val need = assertIs<NewStep.PasswordNeeded>(n.advance(code))
        assertEquals(io.silencelen.andvari.core.client.session.ForgetEarlier.FlowUnderWay, w.keeper.forgetEarlierAccount(origin, email), "before the pickup")
        assertEquals(KeptPhase.LOCKED, w.keeper.phase.value, "the kept copy stays")
        n.cancel(need.token)
        assertEquals(io.silencelen.andvari.core.client.session.ForgetEarlier.Forgotten(w.account.userId, copyRemoved = true),
            w.keeper.forgetEarlierAccount(origin, email), "the link ended")
    }
}
