package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.ForgetEarlierResult
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.client.session.ForgetEarlier
import io.silencelen.andvari.core.client.session.SessionKeeper
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.crypto.Bytes
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
 * "Forget the earlier account on this device" (decided on 2026-11-17) over the real engine, as the screens reach it: a
 * flow the screens drop ends its hold on the address, so the forgetting is not refused as "something is under way"
 * afterwards; a remade account under an address this device knows is refused with both possibilities and the offer;
 * nothing is forgotten before the second confirmation, nor across a lock; after it nothing of the earlier account is left,
 * nothing was sent, and the server is checked as before; the offer is never made where the refusal was not about an earlier
 * account, nor for an account the device has open.
 */
class EngineForgetEarlierTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val alice = "alice@example.com"
    private val bob = "bob@example.com"

    /** Runs [meanwhile] once, the first time [route] is called, before the call goes on to [inner]. */
    private class Racing(val inner: FakeInstance, val route: WireRoute) : WireClient by inner {
        var meanwhile: (suspend () -> Unit)? = null
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            if (route == this.route) meanwhile?.let { meanwhile = null; it() }
            return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
        }
    }

    private fun device(server: WireClient): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.origin to server)), MemoryDeviceState(), MemoryDeviceState(), crypto,
            { ((server as? Racing)?.inner ?: server as FakeInstance).now }, baked = null, storeBuild = false, stores = null,
            main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
    ).also { it.start() }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** Through the screens to the sign-up's code screen for [email] at [host]. */
    private suspend fun toCode(a: EngineAppApi, host: String, email: String) {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), host))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), email, true))
        a.at<EntryScreen.SignUpCode>()
    }

    /** Through the screens to the new account's form: the registration's ticket is held. */
    private suspend fun toForm(a: EngineAppApi, email: String) {
        toCode(a, "h.example", email)
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        a.at<EntryScreen.CreateAccount>()
    }

    /** Register [email] through the screens and confirm the first kit; the account is open and kept. Its user id. */
    private suspend fun register(a: EngineAppApi, email: String): String {
        toForm(a, email)
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "P", strong, true)))
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        return assertNotNull(a.keeper.session).userId
    }

    /** From the first screen to the password screen of a sign-in at [server]. */
    private suspend fun signInScreen(a: EngineAppApi, server: FakeInstance): EntryScreen.SignIn {
        a.entry.openSignIn(a.at())
        a.entry.openPasswordSignIn(a.at())
        assertEquals(ServerResult.DONE, a.entry.chooseOwnServer(a.at(), server.origin))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        return a.at()
    }

    /**
     * [alice]'s account was made on [d] and signed out there; then it was deleted and made again under the same address on
     * another device (a new account id). [d] remembers the earlier one. The earlier account's user id.
     */
    private suspend fun remadeAfterSignOut(server: FakeInstance, d: EngineAppApi): String {
        val earlier = register(d, alice)
        assertEquals(PlainResult.DONE, d.signOut())
        server.accounts.remove(alice)
        register(device(server), alice)
        return earlier
    }

    private fun bindingOf(d: EngineAppApi, origin: String, email: String): String? = d.engine.state.get(SessionKeeper.EMAIL_BINDING_PREFIX + origin + "|" + email)

    // ---- a flow the screens drop ends its hold ----

    @Test fun aRegistrationsTicketLeftByStartingOverNoLongerHoldsTheForgetting() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val d = device(server)
        toForm(d, alice)
        assertEquals(ForgetEarlier.FlowUnderWay, d.keeper.forgetEarlierAccount(server.origin, alice), "the form's ticket holds the address")
        d.entry.startOver()
        // Before: FlowUnderWay until the app was started again (the ticket was dropped without being left).
        assertEquals(ForgetEarlier.NothingToForget, d.keeper.forgetEarlierAccount(server.origin, alice))
    }

    @Test fun aSignUpStartedAgainInTheSameFlowLeavesTheEarlierAddressesTicket() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val d = device(server)
        toForm(d, alice)
        assertTrue(d.entry.back())
        assertTrue(d.entry.back())
        assertEquals(SignUpStartResult.DONE, d.entry.startSignUp(d.at(), bob, true))
        // Before: alice's ticket stayed held under the flow that now signs bob up.
        assertEquals(ForgetEarlier.NothingToForget, d.keeper.forgetEarlierAccount(server.origin, alice))
        assertEquals(CodeResult.DONE, d.entry.verifySignUpCode(d.at(), "482915"))
        assertEquals(ForgetEarlier.FlowUnderWay, d.keeper.forgetEarlierAccount(server.origin, bob))
        d.entry.startOver()
        assertEquals(ForgetEarlier.NothingToForget, d.keeper.forgetEarlierAccount(server.origin, bob))
    }

    @Test fun aCodeVerifiedAgainLeavesTheTicketItReplaces() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val d = device(server)
        toForm(d, alice)
        assertTrue(d.entry.back())
        assertEquals(CodeResult.DONE, d.entry.verifySignUpCode(d.at(), "482915"))
        d.entry.startOver()
        // Before: the first ticket stayed held after the second replaced it.
        assertEquals(ForgetEarlier.NothingToForget, d.keeper.forgetEarlierAccount(server.origin, alice))
    }

    @Test fun aSignUpCodeThatTurnsOutStaleLeavesTheTicketItGot() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val racing = Racing(server, WireRoute.SIGNUP_VERIFY)
        val d = device(racing)
        toCode(d, "h.example", alice)
        val code = d.at<EntryScreen.SignUpCode>()
        racing.meanwhile = { d.entry.startOver() }
        assertEquals(CodeResult.STALE, d.entry.verifySignUpCode(code, "482915"))
        // Before: the ticket the verify handed out held the address until the app was started again.
        assertEquals(ForgetEarlier.NothingToForget, d.keeper.forgetEarlierAccount(server.origin, alice))
    }

    // ---- the refusal, the offer and its two steps ----

    @Test fun aRemadeAccountIsRefusedWithBothPossibilitiesAndForgottenOnlyAfterTheSecondConfirmation() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val d = device(server)
        remadeAfterSignOut(server, d)
        val screen = signInScreen(d, server)
        assertEquals(SignInAnswer.IDENTITY_FAULT, d.entry.submitSignIn(screen, alice, strong))
        // Before: no offer at all; the person could never sign in to the new account on this device.
        val offer = assertNotNull(d.snapshot.earlierAccount)
        assertFalse(offer.confirming)
        assertEquals(alice, offer.email)
        assertEquals(server.origin, offer.instance.origin)
        assertFalse(offer.keptCopy, "signed out: no copy of the earlier account is kept")
        assertEquals(CopyKey.REMADE_ACCOUNT_REFUSAL, offer.refusal.key)
        assertEquals(listOf(alice, offer.instance.name), offer.refusal.values)
        assertEquals(CopyKey.REMADE_ACCOUNT_IF_REMADE, offer.ifRemade)
        assertEquals(CopyKey.REMADE_ACCOUNT_IF_SERVER, offer.ifServer)
        assertEquals(CopyKey.REMADE_ACCOUNT_HOW_TO_TELL, offer.howToTell)
        assertEquals(CopyKey.REMADE_ACCOUNT_FORGET, offer.forgetLabel)
        assertTrue(offer.confirmLines.isEmpty())
        val sent = server.calls.size
        val bound = assertNotNull(bindingOf(d, server.origin, alice))

        // The first step alone forgets nothing.
        assertEquals(ForgetEarlierResult.NOT_CONFIRMED, d.entry.forgetEarlierAccount(offer))
        assertTrue(d.entry.askToForgetEarlierAccount(offer))
        val confirm = assertNotNull(d.snapshot.earlierAccount)
        assertTrue(confirm.confirming)
        assertEquals(listOf(CopyKey.REMADE_ACCOUNT_CONFIRM, CopyKey.REMADE_ACCOUNT_CONFIRM_ALWAYS), confirm.confirmLines.map { it.key })
        assertEquals(CopyKey.REMADE_ACCOUNT_CONFIRM_FORGET, confirm.confirmLabel)

        // A lock between the two steps takes the confirmation back.
        d.lock()
        assertFalse(assertNotNull(d.snapshot.earlierAccount).confirming)
        assertEquals(ForgetEarlierResult.STALE, d.entry.forgetEarlierAccount(confirm))
        assertEquals(bound, bindingOf(d, server.origin, alice), "nothing was forgotten")

        // Cancel at the second step goes back to the offer; at the offer, the offer goes.
        assertTrue(d.entry.askToForgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
        d.entry.keepEarlierAccount(assertNotNull(d.snapshot.earlierAccount))
        val again = assertNotNull(d.snapshot.earlierAccount)
        assertFalse(again.confirming)
        assertTrue(d.entry.askToForgetEarlierAccount(again))
        val second = assertNotNull(d.snapshot.earlierAccount)
        val r = d.entry.forgetEarlierAccount(second)
        assertEquals(ForgetEarlierResult.FORGOTTEN, r)
        assertEquals(CopyKey.REMADE_ACCOUNT_FORGOTTEN, assertNotNull(second.lineFor(r)).key)
        assertNull(d.snapshot.earlierAccount)
        assertEquals(sent, server.calls.size, "nothing was sent to the server")
        assertNull(bindingOf(d, server.origin, alice))
        assertIs<PinState.Pinned>(d.trust.pinState(server.origin), "what this device knows of the server stays")

        // The next sign-in is taken as on a device that never knew the address, and says so once.
        assertEquals(SignInAnswer.DONE, d.entry.submitSignIn(d.at(), alice, strong))
        assertEquals(AppPhase.UNLOCKED, d.snapshot.phase)
        val notice = assertNotNull(d.snapshot.rememberedNewAccount)
        assertEquals(CopyKey.REMADE_ACCOUNT_REMEMBERED, notice.line.key)
        assertEquals(listOf(alice), notice.line.values)
        d.dismissNewAccountRemembered(notice)
        assertNull(d.snapshot.rememberedNewAccount)
    }

    @Test fun afterTheForgettingNothingKeyedByTheEarlierAccountIsLeftForAServerToReuse() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val d = device(server)
        val earlier = remadeAfterSignOut(server, d)
        // What the engine leaves to this layer after a sign-out, keyed by the user id only: the account's state copy and its
        // recovery mirror (as the engine writes them), beside this layer's own records of the account.
        d.engine.state.set("ovh.acct|$earlier|checkpoint", "7|sealed")
        d.engine.state.set("ovh.rmirror|$earlier", "private|fp|1")
        fun left(): List<String> {
            val st = d.engine.state as MemoryDeviceState
            val sec = d.engine.secure as MemoryDeviceState
            return st.keys().filter { it.contains(earlier) || st.get(it)?.contains(earlier) == true } +
                sec.keys().filter { it.contains(earlier) || sec.get(it)?.contains(earlier) == true }.map { "secure:$it" }
        }
        assertTrue(left().any { it.startsWith("ovh.acct|") }, "${left()}")
        assertEquals(SignInAnswer.IDENTITY_FAULT, d.entry.submitSignIn(signInScreen(d, server), alice, strong))
        val offer = assertNotNull(d.snapshot.earlierAccount)
        assertTrue(d.entry.askToForgetEarlierAccount(offer))
        assertEquals(ForgetEarlierResult.FORGOTTEN, d.entry.forgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
        // Before (the engine's call alone): the account's state copy, its mirror and its name stayed, keyed by the user id a
        // server could serve again. Only the record of its identity key stays, as the server's (decided on 2026-11-19).
        val kept = listOf(SessionKeeper.EARLIER_IDENTITY_PREFIX + server.origin + "|" + earlier)
        assertEquals(kept, left())
        // The new account opens here, and nothing it is given was kept from the earlier one.
        assertEquals(SignInAnswer.DONE, d.entry.submitSignIn(d.at(), alice, strong))
        assertEquals(AppPhase.UNLOCKED, d.snapshot.phase)
        assertEquals(kept, left())
    }

    @Test fun aForgettingRefusedWhileSomethingIsUnderWayRemovesNothingAndTheOfferStays() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val d = device(server)
        remadeAfterSignOut(server, d)
        assertEquals(SignInAnswer.IDENTITY_FAULT, d.entry.submitSignIn(signInScreen(d, server), alice, strong))
        assertTrue(d.entry.askToForgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
        val bound = bindingOf(d, server.origin, alice)
        val done = d.keeper.underWay(server.origin, alice)
        assertEquals(ForgetEarlierResult.UNDER_WAY, d.entry.forgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
        assertEquals(bound, bindingOf(d, server.origin, alice))
        val offer = assertNotNull(d.snapshot.earlierAccount, "the offer stays")
        assertFalse(offer.confirming)
        done()
        assertTrue(d.entry.askToForgetEarlierAccount(offer))
        assertEquals(ForgetEarlierResult.FORGOTTEN, d.entry.forgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
    }

    @Test fun aForgettingWhoseRecordWentMeanwhileHasNothingToForget() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val d = device(server)
        remadeAfterSignOut(server, d)
        assertEquals(SignInAnswer.IDENTITY_FAULT, d.entry.submitSignIn(signInScreen(d, server), alice, strong))
        assertTrue(d.entry.askToForgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
        assertIs<ForgetEarlier.Forgotten>(d.keeper.forgetEarlierAccount(server.origin, alice))
        assertEquals(ForgetEarlierResult.NOTHING_TO_FORGET, d.entry.forgetEarlierAccount(assertNotNull(d.snapshot.earlierAccount)))
        assertNull(d.snapshot.earlierAccount)
    }

    // ---- never where it does not belong ----

    @Test fun anIdentityFaultOfTheServersAnswerItselfOffersNothing() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        register(device(server), alice)
        // The server serves an identity key that is not the account's own: a fault of its answer, on a device that never
        // knew the address.
        server.account(alice).identityPub = Bytes.toB64(ByteArray(32) { 9 })
        val d = device(server)
        val r = d.entry.submitSignIn(signInScreen(d, server), alice, strong)
        assertTrue(r == SignInAnswer.IDENTITY_FAULT || r == SignInAnswer.FAILED, "$r")
        assertNull(d.snapshot.earlierAccount)
    }

    @Test fun noOfferIsMadeForTheAccountThisDeviceHasOpen() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val d = device(server)
        register(d, alice)
        assertEquals(AppPhase.UNLOCKED, d.snapshot.phase)
        val another = "00000000-0000-4000-8000-0000000000ee"
        assertNull(d.earlierOffer(server.origin, alice, Any(), confirming = false, another), "the account is open here")
        assertEquals(PlainResult.DONE, d.signOut())
        assertNotNull(d.earlierOffer(server.origin, alice, Any(), confirming = false, another), "signed out: the earlier account is only remembered")
    }

    @Test fun aWrongPasswordAfterTheOfferTakesItAway() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val d = device(server)
        remadeAfterSignOut(server, d)
        val screen = signInScreen(d, server)
        assertEquals(SignInAnswer.IDENTITY_FAULT, d.entry.submitSignIn(screen, alice, strong))
        assertNotNull(d.snapshot.earlierAccount)
        assertEquals(SignInAnswer.WRONG, d.entry.submitSignIn(d.at(), alice, "not the password at all 1"))
        assertNull(d.snapshot.earlierAccount)
    }
}
