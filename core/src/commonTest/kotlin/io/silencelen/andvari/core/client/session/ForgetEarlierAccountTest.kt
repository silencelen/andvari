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
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.client.pin.CardTrust
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * "Forget the earlier account on this device" (decided on 2026-11-17): a device remembers, for an address at a server,
 * the account it first took under it, and refuses any other account there under that address, for good; a person who
 * deleted their account and made it again under the same address is given this way out. It removes exactly the record
 * that ties the address to the earlier account, and the earlier account's kept copy when one is kept; it leaves what the
 * device knows of the server (its pin), every other address's record and every other account; nothing is sent. After it
 * the address is new to the device. It refuses while a flow for the address is under way, and nothing else removes the
 * record.
 */
class ForgetEarlierAccountTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val alice = "alice@example.com"

    /** [inner], calling [act] once just before the first request on [route] is sent. */
    private class During(private val inner: WireClient, private val route: WireRoute, private val act: () -> Unit) : WireClient by inner {
        private var done = false
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            if (route == this.route && !done) {
                done = true
                act()
            }
            return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
        }
    }

    private class Env(val server: FakeInstance, val state: MemoryDeviceState, val trust: CardTrust, val keeper: SessionKeeper, val onboarding: WireOnboarding) {
        lateinit var secure: MemoryDeviceState
        lateinit var transport: BearerTransport
    }

    private suspend fun env(server: FakeInstance, client: (SessionKeeper) -> WireClient = { server }): Env {
        val state = MemoryDeviceState()
        val trust = server.pinnedTrust(state)
        lateinit var keeper: SessionKeeper
        var made: WireClient? = null
        val transport = BearerTransport(mapOf(server.origin to object : WireClient by server {
            override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
                (made ?: client(keeper).also { made = it }).call(route, pathParams, query, bodyJson, authenticated, decode)
        }))
        val secure = MemoryDeviceState()
        keeper = SessionKeeper(transport, secure, state, trust, crypto)
        val o = WireOnboarding(server.origin, keeper.clientFor(server.origin), trust, KnownDevices(state, crypto), keeper, crypto, state, "android", "Pixel",
            { server.now }, knownIdentity = keeper::knownIdentity, work = Dispatchers.Unconfined)
        return Env(server, state, trust, keeper, o).also { it.secure = secure; it.transport = transport }
    }

    /**
     * The query of what this device knows of an address at a server: the account it is bound to, by its user id and its
     * identity key, and where that account stands here. It answers facts only and changes nothing.
     */
    @Test fun theBindingOfAnAddressIsAskedForFactsOnly() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val e = env(server)
        assertNull(e.keeper.addressBinding(server.origin, alice), "not known here")
        val first = register(e.onboarding, alice).userId
        val key = assertNotNull(e.binding(alice)).substringAfter('|')
        assertEquals(AddressBinding(first, key, BoundAccountHere.KEPT_OPEN), e.keeper.addressBinding(server.origin, alice))
        assertNull(e.keeper.addressBinding("https://other.example", alice), "another server's address is another address")
        e.keeper.lock()
        assertEquals(BoundAccountHere.KEPT_LOCKED, e.keeper.addressBinding(server.origin, alice)?.here)
        e.keeper.moved(server.origin, "https://moved.example")
        assertEquals(BoundAccountHere.KEPT_ELSEWHERE, e.keeper.addressBinding(server.origin, alice)?.here, "the record stays at the old address")
        e.keeper.moved("https://moved.example", server.origin)
        e.keeper.signOut()
        val before = e.state.keys()!!.associateWith { e.state.get(it) }
        val calls = server.calls.size
        assertEquals(AddressBinding(first, key, BoundAccountHere.NOT_KEPT), e.keeper.addressBinding(server.origin, alice))
        assertEquals(before, e.state.keys()!!.associateWith { e.state.get(it) }, "nothing changed")
        assertEquals(calls, server.calls.size, "nothing sent")
        assertIs<ForgetEarlier.Forgotten>(e.keeper.forgetEarlierAccount(server.origin, alice))
        assertNull(e.keeper.addressBinding(server.origin, alice))
    }

    /**
     * A session record in the secure store that the keeper cannot read (here: a newer build's sign-in kind; it holds the
     * earlier account's tokens and wrapped keys, is never loaded, and would be overwritten at the next sign-in) goes with
     * the forgetting of that account; so does one that is not JSON at all. One that names another account stays. Before,
     * every such record stayed.
     */
    @Test fun anUnreadableSessionRecordOfTheForgottenAccountGoesWithIt() = runBlocking<Unit> {
        for ((what, gone) in listOf("the forgotten account's" to true, "not JSON at all" to true, "another account's" to false)) {
            val server = FakeInstance(crypto)
            val e = env(server)
            val first = register(e.onboarding, alice).userId
            val readable = assertNotNull(e.secure.get(SessionKeeper.KEY))
            e.keeper.signOut()
            val unreadable = when (what) {
                "not JSON at all" -> "not a record {"
                else -> readable.replace("\"how\":\"", "\"how\":\"FUTURE_").let {
                    if (what == "another account's") it.replace(first, "00000000-0000-4000-8000-0000000000cc") else it
                }
            }
            assertTrue(unreadable != readable)
            e.secure.set(SessionKeeper.KEY, unreadable)
            val keeper = SessionKeeper(e.transport, e.secure, e.state, e.trust, crypto)
            assertNull(keeper.session, "$what: this keeper cannot read it")
            val sent = server.calls.size
            assertEquals(ForgetEarlier.Forgotten(first, copyRemoved = false, unreadableRecordRemoved = gone), keeper.forgetEarlierAccount(server.origin, alice), what)
            assertEquals(if (gone) null else unreadable, e.secure.get(SessionKeeper.KEY), what)
            assertEquals(sent, server.calls.size, "$what: nothing sent")
        }
    }

    private suspend fun register(o: WireOnboarding, email: String): Registration.Registered {
        o.signupStart(email, true)
        val t = assertIs<SignupVerify.Ticket>(o.signupVerify(email, "482915"))
        return assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(t),
            RegistrationForm(email, "Someone", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android")))
    }

    private fun Env.binding(email: String) = state.get("${SessionKeeper.EMAIL_BINDING_PREFIX}${server.origin}|$email")

    /** The account under [alice] deleted at the server and made again from another device: another user id, another key. */
    private suspend fun remade(server: FakeInstance): String {
        server.accounts.remove(alice)
        return register(env(server).onboarding, alice).userId
    }

    @Test fun forgettingTheEarlierAccountLetsTheRemadeOneInAndLeavesTheServerAndEveryOtherAccount() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val e = env(server)
        val first = register(e.onboarding, alice).userId
        e.keeper.signOut()
        val bobId = register(e.onboarding, "bob@example.com").userId
        e.keeper.signOut()
        val bobBinding = assertNotNull(e.binding("bob@example.com"))
        // Nothing but the person's call removes the record: a sign-out leaves it.
        val aliceBinding = assertNotNull(e.binding(alice))
        val second = remade(server)
        assertNotEquals(first, second)
        assertIs<SignIn.IdentityFault>(e.onboarding.signIn(alice, strong.toCharArray()), "the address is known here under the earlier account")
        assertEquals(aliceBinding, e.binding(alice), "a refused sign-in removes nothing")

        val pin = assertNotNull(e.trust.pinFor(server.origin))
        assertNotNull(e.keeper.knownIdentity(first))
        val bobIdentity = assertNotNull(e.keeper.knownIdentity(bobId))
        val sent = server.calls.size
        assertEquals(ForgetEarlier.NothingToForget, e.keeper.forgetEarlierAccount(server.origin, "carol@example.com"))
        assertEquals(ForgetEarlier.NothingToForget, e.keeper.forgetEarlierAccount("https://other.example", alice), "another server's address is another address")
        assertEquals(ForgetEarlier.Forgotten(first, copyRemoved = false), e.keeper.forgetEarlierAccount(server.origin, alice))
        assertEquals(sent, server.calls.size, "nothing is sent to the server")
        assertNull(e.binding(alice))
        assertNull(e.keeper.knownIdentity(first), "the earlier account's identity record goes with it")
        assertEquals(bobBinding, e.binding("bob@example.com"), "another address's record stays")
        assertTrue(bobIdentity.contentEquals(e.keeper.knownIdentity(bobId)), "another account's identity record stays")
        assertEquals(pin.hash, assertNotNull(e.trust.pinFor(server.origin)).hash, "the server's pin stays")

        // The address is new to the device: the remade account is taken, and the device now remembers it.
        assertIs<SignIn.SignedIn>(e.onboarding.signIn(alice, strong.toCharArray()))
        assertEquals(second, assertNotNull(e.keeper.session).userId)
        assertTrue(assertNotNull(e.binding(alice)).startsWith("$second|"))
    }

    @Test fun aKeptCopyOfTheEarlierAccountGoesWithTheRecordAsAtTheOwnSignOut() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val e = env(server)
        val first = register(e.onboarding, alice).userId
        assertEquals(ForgetEarlier.OpenForThatAccount, e.keeper.forgetEarlierAccount(server.origin, alice), "the vault is open for it")
        assertNotNull(e.binding(alice))
        // Its lock does not remove the record either.
        e.keeper.lock()
        assertNotNull(e.binding(alice))
        val sent = server.calls.size
        assertEquals(ForgetEarlier.Forgotten(first, copyRemoved = true), e.keeper.forgetEarlierAccount(server.origin, alice))
        assertEquals(sent, server.calls.size, "nothing is sent, not even a sign-out")
        assertNull(e.keeper.session)
        assertTrue((server.origin to first) in e.keeper.endedByOwnAct(), "the app deletes the account's data, as at a sign-out")
        assertNull(e.binding(alice))
        assertNotNull(e.trust.pinFor(server.origin))
        assertEquals(ForgetEarlier.NothingToForget, e.keeper.forgetEarlierAccount(server.origin, alice), "once")

        val f = env(FakeInstance(crypto))
        register(f.onboarding, alice)
        f.keeper.forget(forgetIdentity = false)
        assertNotNull(f.binding(alice), "a session forgotten without the account's deletion leaves the record")
    }

    @Test fun itRefusesWhileAFlowForTheAddressIsUnderWay() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val answers = ArrayList<ForgetEarlier>()
        // The person's call comes while the device's sign-in for the address is on its way (its prelogin).
        val e = env(server) { keeper -> During(server, WireRoute.PRELOGIN) { answers += keeper.forgetEarlierAccount(server.origin, alice) } }
        val id = register(e.onboarding, alice).userId
        e.keeper.signOut()
        val before = e.binding(alice)
        assertIs<SignIn.SignedIn>(e.onboarding.signIn(alice, strong.toCharArray()))
        assertEquals(listOf<ForgetEarlier>(ForgetEarlier.FlowUnderWay), answers)
        assertEquals(before, e.binding(alice), "nothing was forgotten")

        e.keeper.signOut()
        val held = e.keeper.underWay(server.origin, alice)
        assertEquals(ForgetEarlier.FlowUnderWay, e.keeper.forgetEarlierAccount(server.origin, alice))
        assertEquals(ForgetEarlier.NothingToForget, e.keeper.forgetEarlierAccount(server.origin, "bob@example.com"), "another address is not held")
        held()
        held()
        assertEquals(ForgetEarlier.Forgotten(id, copyRemoved = false), e.keeper.forgetEarlierAccount(server.origin, alice), "the flow ended")
    }

    /**
     * A sign-in is under way from its first step to its end, its two-step code included. Before, the hold covered one call
     * at a time: between the password and the code the forgetting answered `Forgotten`, and the code then signed the
     * device in to the remade account.
     */
    @Test fun aTwoStepSignInBlocksTheForgettingBetweenItsSteps() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val e = env(server)
        val first = register(e.onboarding, alice).userId
        e.keeper.signOut()
        val second = remade(server)
        server.account(alice).totp = "123456"
        val before = assertNotNull(e.binding(alice))
        val step = assertIs<SignIn.TotpRequired>(e.onboarding.signIn(alice, strong.toCharArray()))
        assertEquals(ForgetEarlier.FlowUnderWay, e.keeper.forgetEarlierAccount(server.origin, alice), "the code is still asked for")
        assertEquals(before, e.binding(alice), "nothing was removed")
        assertNotNull(e.keeper.knownIdentity(first))
        // The code's answer ends the flow: the earlier account is still the one the device knows under the address.
        assertIs<SignIn.IdentityFault>(e.onboarding.signInCode(step, "123456"))
        assertNull(e.keeper.session)
        assertEquals(ForgetEarlier.Forgotten(first, copyRemoved = false), e.keeper.forgetEarlierAccount(server.origin, alice))
        val again = assertIs<SignIn.TotpRequired>(e.onboarding.signIn(alice, strong.toCharArray()))
        assertIs<SignIn.SignedIn>(e.onboarding.signInCode(again, "123456"))
        assertEquals(second, assertNotNull(e.keeper.session).userId)

        // A sign-in left at its code (the person's cancel) ends the flow too.
        e.keeper.signOut()
        val left = assertIs<SignIn.TotpRequired>(e.onboarding.signIn(alice, strong.toCharArray()))
        assertEquals(ForgetEarlier.FlowUnderWay, e.keeper.forgetEarlierAccount(server.origin, alice))
        e.onboarding.cancelSignIn(left)
        assertEquals(ForgetEarlier.Forgotten(second, copyRemoved = false), e.keeper.forgetEarlierAccount(server.origin, alice))
    }

    /**
     * A registration is under way from its ticket to its answer. Before, between the verified ticket and the register call
     * the forgetting answered `Forgotten`, and the register call then registered the remade account.
     */
    @Test fun aRegistrationBlocksTheForgettingFromItsTicketToItsAnswer() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val e = env(server)
        val first = register(e.onboarding, alice).userId
        e.keeper.signOut()
        server.accounts.remove(alice)
        val before = assertNotNull(e.binding(alice))
        e.onboarding.signupStart(alice, true)
        val ticket = assertIs<SignupVerify.Ticket>(e.onboarding.signupVerify(alice, "482915"))
        assertEquals(ForgetEarlier.FlowUnderWay, e.keeper.forgetEarlierAccount(server.origin, alice), "a ticket is in hand")
        assertEquals(before, e.binding(alice))
        // A password under the floor is typed again under the same ticket: still under way.
        assertEquals(Registration.PasswordTooWeak, e.onboarding.register(RegistrationAuth.Ticket(ticket),
            RegistrationForm(alice, "Someone", "short".toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android")))
        assertEquals(ForgetEarlier.FlowUnderWay, e.keeper.forgetEarlierAccount(server.origin, alice))
        // Its answer ends it: here the device's own refusal, for the address is known under the earlier account.
        val refused = e.onboarding.register(RegistrationAuth.Ticket(ticket),
            RegistrationForm(alice, "Someone", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android"))
        assertTrue(refused !is Registration.Registered, "the address is known here under the earlier account: $refused")
        assertEquals(before, e.binding(alice))
        assertEquals(ForgetEarlier.Forgotten(first, copyRemoved = false), e.keeper.forgetEarlierAccount(server.origin, alice))

        // A ticket the person leaves ends the flow as well.
        val e2 = env(FakeInstance(crypto))
        val id2 = register(e2.onboarding, alice).userId
        e2.keeper.signOut()
        e2.server.accounts.remove(alice)
        e2.onboarding.signupStart(alice, true)
        val left = assertIs<SignupVerify.Ticket>(e2.onboarding.signupVerify(alice, "482915"))
        assertEquals(ForgetEarlier.FlowUnderWay, e2.keeper.forgetEarlierAccount(e2.server.origin, alice))
        e2.onboarding.leaveSignup(left)
        assertEquals(ForgetEarlier.Forgotten(id2, copyRemoved = false), e2.keeper.forgetEarlierAccount(e2.server.origin, alice))
    }

    /** A recovery with the kit is under way from its first step to its commit; a cancel ends it. Before, only the commit call held. */
    @Test fun aKitRecoveryBlocksTheForgettingFromItsStartToItsCommit() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val e = env(server)
        val reg = register(e.onboarding, alice)
        val kit = io.silencelen.andvari.core.trust.RecoveryKit.displayForm(reg.kit.secret)
        e.keeper.signOut()
        val kits = io.silencelen.andvari.core.client.recovery.WireKitRecovery(
            { e.keeper.clientFor(it) }, e.trust, KnownDevices(e.state, crypto), e.keeper, crypto, "android", "Pixel", knownIdentity = e.keeper::knownIdentity,
        )
        val target = assertIs<io.silencelen.andvari.core.client.recovery.KitRecoveryStep.ConfirmTarget>(
            kits.startTyped(alice, server.origin, kit, io.silencelen.andvari.core.client.pin.GateEntry.KIT_RECOVERY_SCREEN))
        assertEquals(ForgetEarlier.FlowUnderWay, e.keeper.forgetEarlierAccount(server.origin, alice), "at the confirmation")
        val choose = assertIs<io.silencelen.andvari.core.client.recovery.KitRecoveryStep.ChoosePassword>(kits.verify(target))
        assertEquals(ForgetEarlier.FlowUnderWay, e.keeper.forgetEarlierAccount(server.origin, alice), "checked, not yet committed")
        assertNotNull(e.binding(alice))
        kits.cancel(choose)
        assertEquals(ForgetEarlier.Forgotten(reg.userId, copyRemoved = false), e.keeper.forgetEarlierAccount(server.origin, alice))
    }

    /**
     * Judged by the account, not by the address alone: after a followed move the account is kept and open at the new
     * address while the record stays at the old one. A forgetting at the old address removes nothing and answers that the
     * account is open here; the identity record of the kept account is never taken. Before, it answered
     * `Forgotten(id, copyRemoved = false)` and removed the open account's identity record.
     */
    @Test fun aForgettingAtTheOldAddressAfterAFollowedMoveRemovesNothing() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val e = env(server)
        val id = register(e.onboarding, alice).userId
        e.keeper.moved(server.origin, "https://moved.example")
        val binding = assertNotNull(e.binding(alice))
        val identity = assertNotNull(e.keeper.knownIdentity(id))
        val sent = server.calls.size
        assertEquals(ForgetEarlier.OpenForThatAccount, e.keeper.forgetEarlierAccount(server.origin, alice))
        e.keeper.lock()
        assertEquals(ForgetEarlier.OpenForThatAccount, e.keeper.forgetEarlierAccount(server.origin, alice), "kept, if locked, at the new address")
        assertEquals(binding, e.binding(alice))
        assertTrue(identity.contentEquals(e.keeper.knownIdentity(id)), "the kept account's identity record stays")
        assertEquals(id, assertNotNull(e.keeper.session).userId)
        assertEquals(sent, server.calls.size)
    }

    /** An account held as its server's operator is kept too: nothing of it is removed. Before, its record and identity record went. */
    @Test fun aForgettingOfTheAccountHeldAsTheOperatorRemovesNothing() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val e = env(server)
        val id = register(e.onboarding, alice).userId
        e.keeper.holdAsOperator()
        assertEquals(ForgetEarlier.OpenForThatAccount, e.keeper.forgetEarlierAccount(server.origin, alice))
        assertNotNull(e.binding(alice))
        assertNotNull(e.keeper.knownIdentity(id))
        assertTrue(assertNotNull(e.keeper.session).heldAsOperator)
    }
}
