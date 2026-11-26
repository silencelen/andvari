package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KnownDevices
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
import io.silencelen.andvari.core.client.recovery.KitRecoveryStep
import io.silencelen.andvari.core.client.recovery.WireKitRecovery
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.RecoveryKit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A recovery, a registration or a session left by the person, on a device that keeps ANOTHER account. The session keeper
 * would refuse the session such a flow opens; before, it was asked only once the server had answered: a recovery with
 * the kit had by then changed the person's password and made a new kit (the old kit dead), and a registration had made
 * an account, and the device then refused the session. Now the keeper is asked before anything is committed, and a no
 * stops the flow with nothing sent; where its answer changes while the commit is under way, the new kit goes to the
 * caller with the refusal, and a registration does nothing more under keys that are gone. The server here counts what
 * reached it and which sessions are live.
 */
class KeptAnotherAccountTest {
    private val plain = createCryptoProvider()
    private val pw = "correct horse Battery 9 staple"
    private val recovered = "a whole new Passphrase 42 here"
    private val alice = "alice@example.com"
    private val bob = "bob@example.com"
    private val carol = "carol@example.com"

    /** A client that runs [meanwhile] once, when [route] is called, before the call goes on (what changes while it is under way). */
    private class Racing(private val inner: WireClient, private val route: WireRoute, private var meanwhile: (suspend () -> Unit)?) : WireClient by inner {
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            if (route == this.route) meanwhile?.let { meanwhile = null; it() }
            return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
        }
    }

    private inner class Env {
        val server = FakeInstance(plain).also { it.countSessions = true }
        val state = MemoryDeviceState()
        val transport = BearerTransport(mapOf(server.origin to server))
        lateinit var trust: CardTrust
        lateinit var keeper: SessionKeeper
        lateinit var onboarding: WireOnboarding

        /** The kit bob's registration revealed (on his own device), as a person types it. */
        lateinit var bobKit: String

        /** bob registers on his own device; this device registers alice and keeps her account, locked, when [keepAlice]. */
        suspend fun setUp(keepAlice: Boolean = true): Env {
            trust = server.pinnedTrust(state)
            keeper = SessionKeeper(transport, MemoryDeviceState(), state, trust, plain)
            onboarding = onboardingOver(keeper.clientFor(server.origin))
            val other = MemoryDeviceState()
            val ob = WireOnboarding(server.origin, server, server.pinnedTrust(other), KnownDevices(other, plain), SessionSink { }, plain, other, "android", "Other",
                { server.now }, work = Dispatchers.Unconfined)
            bobKit = RecoveryKit.displayForm(assertIs<Registration.Registered>(registerOn(ob, bob)).kit.secret)
            if (keepAlice) {
                assertIs<Registration.Registered>(registerOn(onboarding, alice))
                keeper.lock()
            }
            return this
        }

        fun onboardingOver(client: WireClient) = WireOnboarding(server.origin, client, trust, KnownDevices(state, plain), keeper, plain, state, "android", "Pixel",
            { server.now }, knownIdentity = keeper::knownIdentity, work = Dispatchers.Unconfined)

        fun kits(clientFor: (String) -> WireClient = { keeper.clientFor(it) }) =
            WireKitRecovery(clientFor, trust, KnownDevices(state, plain), keeper, plain, "android", "Pixel", knownIdentity = keeper::knownIdentity)

        fun account(email: String) = server.account(email)

        fun liveOf(email: String) = server.live.values.count { it.userId == account(email).userId }

        /** [kit] for [email] on a device that keeps nothing: Recovered when it is the account's kit, Rejected when it is dead. */
        suspend fun onAFreshDevice(kit: String, email: String = bob): KitRecoveryStep {
            val fresh = MemoryDeviceState()
            val t = server.pinnedTrust(fresh)
            val k = SessionKeeper(BearerTransport(mapOf(server.origin to server)), MemoryDeviceState(), fresh, t, plain)
            val kits = WireKitRecovery({ k.clientFor(it) }, t, KnownDevices(fresh, plain), k, plain, "android", "New", knownIdentity = k::knownIdentity)
            val target = assertIs<KitRecoveryStep.ConfirmTarget>(kits.startTyped(email, server.origin, kit, GateEntry.KIT_RECOVERY_SCREEN))
            return when (val v = kits.verify(target)) {
                is KitRecoveryStep.ChoosePassword -> kits.commit(v, "yet another Passphrase 77 now".toCharArray())
                else -> v
            }
        }
    }

    private suspend fun registerOn(o: WireOnboarding, email: String): Registration {
        o.signupStart(email, true)
        val t = assertIs<SignupVerify.Ticket>(o.signupVerify(email, "482915"))
        return o.register(RegistrationAuth.Ticket(t), RegistrationForm(email, "P", pw.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android"))
    }

    @Test fun aKitRecoveryOfAnotherAccountOnADeviceThatKeepsOneCommitsNothing() = runBlocking<Unit> {
        val e = Env().setUp()
        val authBefore = e.account(bob).authKey
        val pieceBefore = e.account(bob).pieceId
        val takes = e.keeper.takes
        val refusals = e.keeper.refusals
        val kits = e.kits()
        val target = assertIs<KitRecoveryStep.ConfirmTarget>(kits.startTyped(bob, e.server.origin, e.bobKit, GateEntry.KIT_RECOVERY_SCREEN))
        // Before: the person was asked for a new password here, and the commit then changed bob's password and kit at the
        // server before the keeper refused the session.
        assertEquals(KitRecoveryStep.Stopped(WireKitRecovery.ANOTHER_SESSION_KEPT), kits.verify(target))
        assertFalse(WireRoute.RECOVERY_SELF_COMMIT in e.server.calls, "nothing was committed")
        assertEquals(authBefore, e.account(bob).authKey, "bob's password is unchanged at the server")
        assertEquals(pieceBefore, e.account(bob).pieceId, "and so is his kit")
        assertEquals(takes, e.keeper.takes)
        assertEquals(refusals, e.keeper.refusals, "no session was opened for the keeper to refuse")
        assertEquals(alice, assertNotNull(e.keeper.session).emailNorm, "alice's account is still the one kept")
        assertIs<KitRecoveryStep.Recovered>(e.onAFreshDevice(e.bobKit), "the old kit still opens bob's account")
    }

    @Test fun aKitRecoveryAtAnotherServerOnADeviceThatKeepsAnAccountSendsNothingAtAll() = runBlocking<Unit> {
        val e = Env().setUp()
        val reached = e.server.calls.size
        val sent = e.transport.sent.size
        // Before: the Trust Gate for the other server began (its card was fetched), on the way to a commit whose session
        // this device would refuse.
        assertEquals(KitRecoveryStep.Stopped(WireKitRecovery.ANOTHER_SESSION_KEPT),
            e.kits().startTyped(bob, "https://other.example", e.bobKit, GateEntry.KIT_RECOVERY_SCREEN))
        assertEquals(reached, e.server.calls.size)
        assertEquals(sent, e.transport.sent.size)
    }

    /** Another account signed in between the verify step and the commit: the keeper is asked again before the commit is sent. */
    @Test fun anAccountKeptSinceTheVerifyStepStopsTheCommitBeforeItIsSent() = runBlocking<Unit> {
        val e = Env().setUp(keepAlice = false)
        val kits = e.kits()
        val target = assertIs<KitRecoveryStep.ConfirmTarget>(kits.startTyped(bob, e.server.origin, e.bobKit, GateEntry.KIT_RECOVERY_SCREEN))
        val choose = assertIs<KitRecoveryStep.ChoosePassword>(kits.verify(target))
        assertIs<Registration.Registered>(registerOn(e.onboarding, alice))
        // Before: the commit was sent and answered Recovered, and the keeper then refused bob's session.
        assertEquals(KitRecoveryStep.Stopped(WireKitRecovery.ANOTHER_SESSION_KEPT), kits.commit(choose, recovered.toCharArray()))
        assertFalse(WireRoute.RECOVERY_SELF_COMMIT in e.server.calls)
        assertIs<KitRecoveryStep.Recovered>(e.onAFreshDevice(e.bobKit), "the old kit still opens bob's account")
    }

    @Test fun aRegistrationOnADeviceThatKeepsAnAccountSendsNothing() = runBlocking<Unit> {
        val e = Env().setUp()
        val registers = e.server.calls.count { it == WireRoute.REGISTER }
        // Before: the account was made at the server and the keeper then refused its session.
        assertEquals(Registration.Refused(WireOnboarding.ANOTHER_SESSION_KEPT), registerOn(e.onboarding, carol))
        assertEquals(registers, e.server.calls.count { it == WireRoute.REGISTER }, "no registration was sent")
        assertFalse(e.server.accounts.containsKey(carol))
        assertEquals(alice, assertNotNull(e.keeper.session).emailNorm)
    }

    /**
     * What the device keeps changes while the commit is under way (alice signs in here meanwhile): the commit stands at the
     * server, the keeper refuses bob's session and ends it, and the new kit, now bob's only one, is handed to the caller
     * with the refusal.
     */
    @Test fun aRecoveryCommittedWhileAnotherAccountWasTakenHandsOverTheNewKitWithTheRefusal() = runBlocking<Unit> {
        val e = Env().setUp(keepAlice = false)
        val kits = e.kits { origin -> Racing(e.keeper.clientFor(origin), WireRoute.RECOVERY_SELF_COMMIT) { assertIs<Registration.Registered>(registerOn(e.onboarding, alice)) } }
        val target = assertIs<KitRecoveryStep.ConfirmTarget>(kits.startTyped(bob, e.server.origin, e.bobKit, GateEntry.KIT_RECOVERY_SCREEN))
        val choose = assertIs<KitRecoveryStep.ChoosePassword>(kits.verify(target))
        val r = assertIs<KitRecoveryStep.Recovered>(kits.commit(choose, recovered.toCharArray()))
        assertEquals(WireKitRecovery.ANOTHER_SESSION_KEPT, r.notKept)
        assertEquals(e.account(bob).pieceId, r.newKit.pieceId, "the kit handed over is the one the server holds now")
        assertEquals(alice, assertNotNull(e.keeper.session).emailNorm)
        assertEquals(0, e.liveOf(bob), "the refused session was ended at the server")
        val newKit = RecoveryKit.displayForm(r.newKit.secret)
        assertEquals(KitRecoveryStep.Rejected, e.onAFreshDevice(e.bobKit), "the old kit is dead")
        assertIs<KitRecoveryStep.Recovered>(e.onAFreshDevice(newKit), "the kit handed over opens bob's account")
    }

    /**
     * A registration whose session the keeper refuses (alice was taken here while it was under way): before, it went on
     * under the keys the keeper had wiped (the account's record sealed and sent, a contact pinned, a card signed). Now it
     * stops: nothing more reaches the server, the kit goes to the caller with the refusal, and the account, which exists
     * at the server, opens with its password once alice is signed out.
     */
    @Test fun aRegistrationWhoseSessionTheKeeperRefusesStopsAndItsAccountSignsInLater() = runBlocking<Unit> {
        val e = Env().setUp(keepAlice = false)
        val racing = e.onboardingOver(Racing(e.keeper.clientFor(e.server.origin), WireRoute.REGISTER) { assertIs<Registration.Registered>(registerOn(e.onboarding, alice)) })
        val r = assertIs<Registration.Registered>(registerOn(racing, carol))
        assertEquals(WireOnboarding.ANOTHER_SESSION_KEPT, r.notKept)
        val after = e.server.calls.subList(e.server.calls.lastIndexOf(WireRoute.REGISTER) + 1, e.server.calls.size)
        assertFalse(WireRoute.ACCOUNT_STATE_PUT in after, "nothing was sealed or sent under the wiped keys: $after")
        assertEquals(0, e.liveOf(carol), "the refused session was ended at the server")
        assertEquals(alice, assertNotNull(e.keeper.session).emailNorm)
        assertEquals(e.account(carol).pieceId, r.kit.pieceId)
        val kit = RecoveryKit.displayForm(r.kit.secret)
        e.keeper.signOut()
        assertIs<SignIn.SignedIn>(e.onboarding.signIn(carol, pw.toCharArray()), "carol's account opens with her password")
        e.keeper.signOut()
        assertIs<KitRecoveryStep.Recovered>(e.onAFreshDevice(kit, carol), "and her kit opens it")
    }

    /** A sign-in the person left, taken on a device that kept nothing: exactly its session ends, by its refresh token. */
    @Test fun aLeftCallsSessionEndsAloneByItsRefreshToken() = runBlocking<Unit> {
        val e = Env().setUp(keepAlice = false)
        val mark = e.keeper.takes
        assertIs<Registration.Registered>(registerOn(e.onboarding, alice))
        assertEquals(1, e.liveOf(alice))
        assertNotNull(e.keeper.endTakenSince(mark)).invoke()
        assertEquals(null, e.keeper.session)
        // Before: `POST /auth/logout`, which ends every session of the device at that server.
        assertEquals(WireRoute.END_SESSION, e.transport.sent.last().route)
        assertTrue(WireRoute.LOGOUT !in e.transport.sent.map { it.route })
        assertEquals(0, e.liveOf(alice))
    }

    /** The same when the left call's session took the place of a kept record of the account: the record comes back, the new session ends alone. */
    @Test fun aLeftCallsSessionOverAKeptRecordEndsAloneAndTheRecordComesBack() = runBlocking<Unit> {
        val e = Env().setUp()
        e.keeper.endedByServer(e.server.origin)
        val mark = e.keeper.takes
        assertIs<SignIn.SignedIn>(e.onboarding.signIn(alice, pw.toCharArray()))
        val live = e.liveOf(alice)
        assertNotNull(e.keeper.endTakenSince(mark)).invoke()
        assertTrue(assertNotNull(e.keeper.session).endedByServer, "the record is back as its server's end left it")
        assertEquals(WireRoute.END_SESSION, e.transport.sent.last().route)
        assertTrue(WireRoute.LOGOUT !in e.transport.sent.map { it.route })
        assertEquals(live - 1, e.liveOf(alice))
    }
}
