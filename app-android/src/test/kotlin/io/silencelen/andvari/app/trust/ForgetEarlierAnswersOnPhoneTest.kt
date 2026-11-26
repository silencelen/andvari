package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppApi
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EarlierAccountKnown
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.ForgetEarlierResult
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.engine.AppEngine
import io.silencelen.andvari.core.app.engine.EngineAppApi
import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.client.session.SessionKeeper
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.CoroutineScope
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
 * "Forget the earlier account on this device": what the phone says for each answer the shared code's REAL engine gives
 * to the second step's confirmation, over its own test server, and what stands on the screen afterwards. The account U
 * was this phone's (registered here, signed out); the address was deleted and made again elsewhere (V); the sign-in is
 * refused with the offer, and the person's second step is on show. What a second start of the app on the same phone does
 * meanwhile (forgetting, taking an account) is set-up the screens of the first start do not play.
 */
class ForgetEarlierAnswersOnPhoneTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val alice = "alice@example.com"

    /** A store whose next write of a key starting with [failOn] is refused (thrown), once. */
    private class Refusing(val inner: MemoryDeviceState) : DeviceState by inner {
        var failOn: String? = null
        override fun set(key: String, value: String?) {
            val p = failOn
            if (p != null && key.startsWith(p)) {
                failOn = null
                throw IllegalStateException("the store refused a write")
            }
            inner.set(key, value)
        }
    }

    private class Phone(val state: Refusing = Refusing(MemoryDeviceState()), val secure: MemoryDeviceState = MemoryDeviceState())

    private val opened = ArrayList<EngineAppApi>()

    private fun app(server: FakeInstance, phone: Phone = Phone()): EngineAppApi = EngineAppApi(
        AppEngine(
            AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.origin to server)), phone.state, phone.secure, crypto, { server.now },
            baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
        ),
    ).also { opened += it }

    private fun model(api: EngineAppApi): TrustModel =
        TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L }).also {
            it.start()
            it.onSnapshot(api.snapshot)
        }

    private fun walk(body: suspend () -> Unit) = try {
        runBlocking { body() }
    } finally {
        opened.forEach { runCatching { it.close() } }
    }

    private inline fun <reified T : EntryScreen> AppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private fun <R : IntentResult> TrustModel.done(intent: suspend AppApi.() -> R): R {
        var result: R? = null
        runBlocking { run(intent) { result = it }.join() }
        onSnapshot(api.snapshot)
        return assertNotNull(result, "the intent ended without a result: ${wentWrong.value?.text}")
    }

    private fun TrustModel.step(intent: AppApi.() -> Unit) {
        act(intent)
        onSnapshot(api.snapshot)
    }

    private fun TrustModel.register(email: String) {
        step { entry.openOwnServer(at()) }
        assertEquals(ServerResult.DONE, done { entry.submitServerAddress(at(), "h.example") })
        (api.snapshot.entry as? EntryScreen.TrustGate)?.let { gate -> assertEquals(ServerResult.DONE, done { entry.confirmTrustGate(gate) }) }
        assertEquals(ServerResult.DONE, done { entry.createAccountHere(at()) })
        assertEquals(SignUpStartResult.DONE, done { entry.startSignUp(at(), email, true) })
        assertEquals(CodeResult.DONE, done { entry.verifySignUpCode(at(), "482915") })
        assertEquals(CreateAccountResult.DONE, done { entry.createAccount(at(), NewAccountInput("", "P", strong, true)) })
        val reveal = api.at<EntryScreen.Kit>().kit
        val doc = assertNotNull(api.kit.kitDocument(reveal))
        step { kit.proceedToConfirm(reveal) }
        val confirm = api.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, done { kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }) })
    }

    private fun TrustModel.toSignIn(server: FakeInstance) {
        step { entry.openSignIn(at()) }
        step { entry.openPasswordSignIn(at()) }
        assertEquals(ServerResult.DONE, done { entry.chooseOwnServer(at(), server.origin) })
        (api.snapshot.entry as? EntryScreen.TrustGate)?.let { gate -> assertEquals(ServerResult.DONE, done { entry.confirmTrustGate(gate) }) }
        api.at<EntryScreen.SignIn>()
    }

    /** U registered on the phone and signed out, the address made again elsewhere as V; [beforeSignIn] after that. */
    private class Road(val server: FakeInstance, val phone: Phone, val d: EngineAppApi, val m: TrustModel, val u: String, val confirm: EarlierAccountKnown)

    /** The road to the second step on show, with what the phone draws on it. */
    private fun road(beforeSignIn: (FakeInstance, Phone, String) -> Unit = { _, _, _ -> }): Road {
        val server = FakeInstance(crypto)
        val phone = Phone()
        val d = app(server, phone)
        val m = model(d)
        m.register(alice)
        val u = server.account(alice).userId
        assertEquals(PlainResult.DONE, m.done { signOut() })
        server.accounts.remove(alice)
        model(app(server)).register(alice)
        beforeSignIn(server, phone, u)
        m.toSignIn(server)
        assertEquals(SignInAnswer.IDENTITY_FAULT, m.done { entry.submitSignIn(at(), alice, strong) })
        assertFalse(assertNotNull(d.snapshot.earlierAccount, "offered").confirming)
        m.askToForgetEarlierAccount()
        val confirm = assertNotNull(d.snapshot.earlierAccount)
        assertTrue(confirm.confirming)
        return Road(server, phone, d, m, u, confirm)
    }

    /** What the phone draws for [result] under the confirmation [c]: the shared code's sentence with the address. */
    private fun lineOf(c: EarlierAccountKnown, result: ForgetEarlierResult) = UiText.of(assertNotNull(c.lineFor(result), "$result has a line")).shown()

    /** A second start of the app on the same phone: refused under the address, forgets through its own two steps. */
    private fun secondStartForgets(server: FakeInstance, phone: Phone): Pair<EngineAppApi, TrustModel> {
        val second = app(server, phone)
        val m2 = model(second)
        m2.toSignIn(server)
        assertEquals(SignInAnswer.IDENTITY_FAULT, m2.done { entry.submitSignIn(at(), alice, strong) })
        m2.askToForgetEarlierAccount()
        m2.forgetEarlierAccount()
        m2.onSnapshot(second.snapshot)
        assertEquals(ForgetEarlierResult.FORGOTTEN, m2.saidOn(second.snapshot)?.result)
        return second to m2
    }

    private fun Phone.bindingOf(server: FakeInstance): String? = state.get(SessionKeeper.EMAIL_BINDING_PREFIX + server.origin + "|" + alice)

    // ---- done ----

    /** Forgotten: its line in place on the refused sign-in, which stays with no offer; the next sign-in takes V and says so once. */
    @Test
    fun forgottenIsSaidOnTheRefusedSignInWhichStaysWithNoOfferAndTheNextSignInTakesTheNewAccount() = walk {
        val r = road()
        r.m.forgetEarlierAccount()
        r.m.onSnapshot(r.d.snapshot)
        val said = assertNotNull(r.m.saidOn(r.d.snapshot))
        assertEquals(ForgetEarlierResult.FORGOTTEN, said.result)
        assertEquals(lineOf(r.confirm, ForgetEarlierResult.FORGOTTEN), said.text.shown())
        assertEquals(CopyKey.REMADE_ACCOUNT_FORGOTTEN, assertNotNull(r.confirm.lineFor(ForgetEarlierResult.FORGOTTEN)).key)
        r.d.at<EntryScreen.SignIn>()
        assertNull(r.d.snapshot.earlierAccount, "no offer afterwards")
        assertEquals(SignInAnswer.DONE, r.m.done { entry.submitSignIn(at(), alice, strong) })
        assertEquals(AppPhase.UNLOCKED, r.d.snapshot.phase)
        assertEquals(CopyKey.REMADE_ACCOUNT_REMEMBERED, assertNotNull(r.d.snapshot.rememberedNewAccount).line.key)
    }

    // ---- the account the confirmation named is no longer the one this phone ties the address to ----

    /**
     * While the second step was on show, a second start of the app on the phone forgot U and took V (the account the
     * server serves), and signed out. The confirmation: not taken, said in its line; no offer stands afterwards (there is
     * nothing left to confirm), the refused sign-in stays, and it now takes V.
     */
    @Test
    fun aConfirmationAfterTheAddressCameToNameTheServedAccountIsNotTakenSaidAndNoOfferStands() = walk {
        val r = road()
        val (second, m2) = secondStartForgets(r.server, r.phone)
        assertEquals(SignInAnswer.DONE, m2.done { entry.submitSignIn(at(), alice, strong) })
        assertEquals(PlainResult.DONE, m2.done { signOut() })
        val tied = assertNotNull(r.phone.bindingOf(r.server))
        assertEquals(r.server.account(alice).userId, tied.substringBefore('|'), "the address names V")
        assertNull(second.snapshot.earlierAccount)

        r.m.forgetEarlierAccount()
        r.m.onSnapshot(r.d.snapshot)
        val said = assertNotNull(r.m.saidOn(r.d.snapshot))
        assertEquals(ForgetEarlierResult.ADDRESS_NOW_THE_SERVED_ACCOUNT, said.result)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.REMADE_ACCOUNT_FORGET_ADDRESS_NOW_SERVED, ForgetEarlierResult.ADDRESS_NOW_THE_SERVED_ACCOUNT.sentence)
        assertEquals(lineOf(r.confirm, ForgetEarlierResult.ADDRESS_NOW_THE_SERVED_ACCOUNT), said.text.shown())
        assertNull(r.d.snapshot.earlierAccount, "nothing stands to confirm")
        assertEquals(tied, r.phone.bindingOf(r.server), "nothing forgotten")
        r.d.at<EntryScreen.SignIn>()
        assertEquals(SignInAnswer.DONE, r.m.done { entry.submitSignIn(at(), alice, strong) })
        assertEquals(AppPhase.UNLOCKED, r.d.snapshot.phase)
    }

    /**
     * While the second step was on show (naming U), a second start of the app forgot U and took a THIRD account C under the
     * address (made again once more, served for that moment), and signed out; then the server serves V again. The
     * confirmation: not taken (it named U), said in its line; under it the second step again, naming C now, with every
     * line it carries; the person's tap forgets C; the sign-in then takes V.
     */
    @Test
    fun aConfirmationAfterTheAddressCameToNameAThirdAccountIsNotTakenAndTheSecondStepStandsForThatOne() = walk {
        val r = road()
        val v = r.server.accounts.getValue(alice)
        r.server.accounts.remove(alice)
        model(app(r.server)).register(alice)
        val c = r.server.account(alice).userId
        val (_, m2) = secondStartForgets(r.server, r.phone)
        assertEquals(SignInAnswer.DONE, m2.done { entry.submitSignIn(at(), alice, strong) })
        assertEquals(PlainResult.DONE, m2.done { signOut() })
        assertEquals(c, assertNotNull(r.phone.bindingOf(r.server)).substringBefore('|'), "the address names C")
        r.server.accounts[alice] = v

        r.m.forgetEarlierAccount()
        r.m.onSnapshot(r.d.snapshot)
        val said = assertNotNull(r.m.saidOn(r.d.snapshot))
        assertEquals(ForgetEarlierResult.NOT_CONFIRMED, said.result)
        assertEquals(lineOf(r.confirm, ForgetEarlierResult.NOT_CONFIRMED), said.text.shown())
        val again = assertNotNull(r.d.snapshot.earlierAccount, "the second step again, with what holds now")
        assertTrue(again.confirming)
        assertEquals(c, r.phone.bindingOf(r.server)?.substringBefore('|'), "nothing forgotten yet")
        assertEquals(listOf(CopyKey.REMADE_ACCOUNT_CONFIRM, CopyKey.REMADE_ACCOUNT_CONFIRM_ALWAYS), again.confirmLines.map { it.key })

        r.m.forgetEarlierAccount()
        r.m.onSnapshot(r.d.snapshot)
        assertEquals(ForgetEarlierResult.FORGOTTEN, r.m.saidOn(r.d.snapshot)?.result)
        assertNull(r.phone.bindingOf(r.server), "C forgotten")
        assertEquals(SignInAnswer.DONE, r.m.done { entry.submitSignIn(at(), alice, strong) })
        assertEquals(v.userId, r.server.account(alice).userId)
    }

    // ---- it could not be done ----

    /**
     * While the second step was on show, a second start of the app forgot U and took nothing. The confirmation: nothing
     * to forget, said in its line; no offer stands; the sign-in then takes V as on a phone that never knew the address.
     */
    @Test
    fun aConfirmationWhenTheAddressIsNoLongerKnownSaysThereWasNothingToForgetAndNoOfferStands() = walk {
        val r = road()
        secondStartForgets(r.server, r.phone)
        assertNull(r.phone.bindingOf(r.server))

        r.m.forgetEarlierAccount()
        r.m.onSnapshot(r.d.snapshot)
        val said = assertNotNull(r.m.saidOn(r.d.snapshot))
        assertEquals(ForgetEarlierResult.NOTHING_TO_FORGET, said.result)
        assertEquals(lineOf(r.confirm, ForgetEarlierResult.NOTHING_TO_FORGET), said.text.shown())
        assertNull(r.d.snapshot.earlierAccount)
        r.d.at<EntryScreen.SignIn>()
        assertEquals(SignInAnswer.DONE, r.m.done { entry.submitSignIn(at(), alice, strong) })
        assertEquals(AppPhase.UNLOCKED, r.d.snapshot.phase)
    }

    /**
     * The phone's store refuses the write that removes the address's record: the forgetting could not be done. Said as a
     * fault in place; the second step stays on show for the person's next tap; the app tries nothing again by itself;
     * the next tap finishes it.
     */
    @Test
    fun aForgettingTheStoreRefusesIsSaidAsAFaultTheSecondStepStaysAndTheNextTapFinishesIt() = walk {
        val r = road()
        val bindingKey = SessionKeeper.EMAIL_BINDING_PREFIX + r.server.origin + "|" + alice
        r.phone.state.failOn = bindingKey
        r.m.forgetEarlierAccount()
        r.m.onSnapshot(r.d.snapshot)
        assertNull(r.phone.state.failOn, "the refused write was tried")
        val said = assertNotNull(r.m.saidOn(r.d.snapshot), "said in place")
        assertTrue(said.result != ForgetEarlierResult.FORGOTTEN, "not said as forgotten: ${said.result}")
        assertEquals(Placeholder.WENT_WRONG, assertIs<UiText.Ph>(said.text).placeholder)
        assertTrue(assertNotNull(r.d.snapshot.earlierAccount, "the second step stays").confirming)
        assertNotNull(r.phone.bindingOf(r.server), "the address's record stays")
        r.m.tick()
        r.m.returnedToForeground()
        assertNotNull(r.phone.bindingOf(r.server), "nothing tried again by the app")

        r.m.forgetEarlierAccount()
        r.m.onSnapshot(r.d.snapshot)
        assertEquals(ForgetEarlierResult.FORGOTTEN, r.m.saidOn(r.d.snapshot)?.result)
        assertNull(r.phone.bindingOf(r.server))
        assertNull(r.d.snapshot.earlierAccount)
    }

    // ---- what the second step says of changes not sent ----

    /**
     * U's signed changes to a shared vault were never sent (one waits, as the vault's history keeps it; a sign-out keeps
     * it), and no copy of U is kept. The second step never says that every change was sent.
     */
    @Test
    fun theSecondStepNeverSaysEveryChangeWasSentWhereTheEarlierAccountHoldsASignedChangeNeverSent() = walk {
        val r = road { _, phone, u ->
            phone.state.set("ovh.log|$u|v1|pending", "1")
            phone.state.set("ovh.log|$u|pending-index", "v1")
        }
        val keys = r.confirm.confirmLines.map { it.key }
        println("SECOND STEP LINES WITH A SIGNED CHANGE NEVER SENT: $keys keptCopy=${r.confirm.keptCopy} unsent=${r.confirm.unsentChanges}")
        assertFalse(CopyKey.REMADE_ACCOUNT_CONFIRM_COPY_ALL_SENT in keys, "never 'every change was sent': $keys")
        r.m.forgetEarlierAccount()
        r.m.onSnapshot(r.d.snapshot)
        assertEquals(ForgetEarlierResult.FORGOTTEN, r.m.saidOn(r.d.snapshot)?.result)
        println("AFTER THE FORGETTING, THE CHANGE NEVER SENT: ${r.phone.state.get("ovh.log|${r.u}|v1|pending")} index=${r.phone.state.get("ovh.log|${r.u}|pending-index")}")
    }
}
