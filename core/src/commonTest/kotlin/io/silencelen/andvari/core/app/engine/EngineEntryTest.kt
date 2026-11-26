package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.InstanceCardState
import io.silencelen.andvari.core.app.InviteResult
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.KitScanResult
import io.silencelen.andvari.core.app.KitStep
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.PreCutoverStore
import io.silencelen.andvari.core.app.PreCutoverStores
import io.silencelen.andvari.core.app.RegistrationVia
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.client.session.KeptPhase
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The signed-out journey of [EngineAppApi] against the onboarding tests' [FakeInstance]: the fake's flows, on the engine. */
class EngineEntryTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    private class Wiped : PreCutoverStores {
        val wiped = ArrayList<PreCutoverStore>()
        /** Stores that cannot be deleted for now. */
        val stuck = HashSet<PreCutoverStore>()

        override fun wipe(store: PreCutoverStore): Boolean {
            wiped += store
            return store !in stuck
        }
    }

    private class Device(val state: MemoryDeviceState = MemoryDeviceState(), val secure: MemoryDeviceState = MemoryDeviceState(), val stores: Wiped = Wiped())

    private class Env(val server: FakeInstance, val transport: BearerTransport)

    private fun env(server: FakeInstance = FakeInstance(crypto), extra: Map<String, WireClient> = emptyMap()) =
        Env(server, BearerTransport(mapOf(server.origin to server) + extra))

    private fun app(e: Env, d: Device = Device()): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", e.transport, d.state, d.secure, crypto, { e.server.now }, baked = null, storeBuild = false,
            stores = d.stores, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
    ).also { it.start() }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** First screen → "Use your own server" → the typed address → the Trust Gate, confirmed. */
    private suspend fun ownServer(a: EngineAppApi, address: String = "h.example"): EntryScreen.Server {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), address))
        val gate = a.at<EntryScreen.TrustGate>()
        assertEquals(TrustGateWording.TYPED_ADDRESS, gate.prompt.wording)
        assertEquals("https://h.example", gate.prompt.origin)
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(gate))
        return a.at()
    }

    /** Sign-up and registration up to the kit's reveal. */
    private suspend fun register(a: EngineAppApi, email: String = "alice@example.com"): EntryScreen.Kit {
        val server = ownServer(a)
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(server))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), email, true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        val form = a.at<EntryScreen.CreateAccount>()
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(form, NewAccountInput("", "Alice", strong, true)))
        return a.at()
    }

    /** The kit, revealed, read, and typed back. */
    private suspend fun confirmKit(a: EngineAppApi, kit: EntryScreen.Kit) {
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
    }

    @Test fun startRunsTheFirstLaunchWipeOnceThenShowsTheFirstScreen() = runBlocking<Unit> {
        val e = env()
        val d = Device()
        val a = app(e, d)
        assertEquals<List<PreCutoverStore>>(PreCutoverStore.entries.toList(), d.stores.wiped)
        assertEquals(AppPhase.ENTRY, a.snapshot.phase)
        a.at<EntryScreen.FirstRun>()
        val again = app(e, Device(d.state, d.secure, d.stores))
        assertEquals(PreCutoverStore.entries.size, d.stores.wiped.size, "the marker keeps it to once")
        assertEquals(AppPhase.ENTRY, again.snapshot.phase)
        assertTrue(e.server.calls.isEmpty(), "nothing is fetched from a server nobody chose")
    }

    @Test fun signUpByEmailRegistersShowsTheKitAndOpensTheVaultOnlyOnceItIsConfirmed() = runBlocking<Unit> {
        val e = env()
        e.server.powBits = 6
        val a = app(e)
        val seen = ArrayList<AppSnapshot>()
        a.observe { seen += it }
        val server = ownServer(a)
        assertTrue(server.instance.selfNamed, "a typed-address pin: only the server vouches for the name")
        assertEquals("Home", server.instance.name)
        assertEquals(listOf(WireRoute.INSTANCE, WireRoute.CLIENT_POLICY), e.server.calls.distinct(), "nothing but the card and the policy before sign-up")
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(server))
        val email = a.at<EntryScreen.SignUpEmail>()
        assertEquals(SignUpStartResult.INVALID_EMAIL, a.entry.startSignUp(email, "not an address", true))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(email, "alice@example.com", true))
        assertTrue(seen.any { (it.entry as? EntryScreen.SignUpEmail)?.provingWork == true }, "the proof of work shows its progress")
        val code = a.at<EntryScreen.SignUpCode>()
        assertEquals(CodeResult.WRONG_CODE, a.entry.verifySignUpCode(code, "000000"))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(code, "482915"))
        val form = a.at<EntryScreen.CreateAccount>()
        assertEquals(RegistrationVia.EMAIL_CODE, form.via)
        assertEquals("alice@example.com", form.fixedEmail)
        assertNull(form.recovery, "a card without a recovery key offers no choice")
        assertEquals(CreateAccountResult.WEAK_PASSWORD, a.entry.createAccount(form, NewAccountInput("", "Alice", "short", true)))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(form, NewAccountInput("", "Alice", strong, true)))
        val kit = a.at<EntryScreen.Kit>()
        assertEquals(KitReason.FIRST_KIT, kit.kit.reason)
        assertEquals(KitStep.REVEAL, kit.kit.step)
        assertFalse(a.entry.back(), "no way past the kit but the kit")
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        assertEquals(11, doc.groups.size)
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitStep.CONFIRM, confirm.step)
        assertNull(a.kit.kitDocument(confirm), "the secret is readable only on the reveal")
        assertNull(a.kit.kitDocument(kit.kit), "nor from a screen no longer on show")
        assertEquals(3, confirm.groupsToType.size)
        assertEquals(KitConfirmResult.MISMATCH, a.kit.confirmKit(confirm, listOf("aaaa", "bbbb", "cccc")))
        val again = a.at<EntryScreen.Kit>().kit
        assertEquals(1, again.failedTries)
        assertEquals(AppPhase.ENTRY, a.snapshot.phase)
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(again, again.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        val account = assertNotNull(a.snapshot.account)
        assertEquals("alice@example.com", account.email)
        assertEquals(doc.accountId, account.accountId)
        assertFalse(account.operatorAccount)
        assertTrue(e.server.account("alice@example.com").recoveryConfirmed)
        // The confirmation went with the new session's bearer.
        assertTrue(e.transport.bearersFor(WireRoute.RECOVERY_SELF_CONFIRM).single()!!.startsWith("at-"))
        assertIs<InstanceCardState.Ok>(a.snapshot.instance!!.card)
    }

    @Test fun aRestartIsLockedAndTheUnlockScreensPasswordOpensIt() = runBlocking<Unit> {
        val e = env()
        val d = Device()
        val a = app(e, d)
        confirmKit(a, register(a))
        a.close()
        val b = app(e, Device(d.state, d.secure, d.stores))
        assertEquals(AppPhase.LOCKED, b.snapshot.phase)
        assertEquals("https://h.example", b.snapshot.instance!!.label.origin)
        // The lock screen names the account, the instance and its origin (§4.4).
        val locked = assertNotNull(b.snapshot.locked)
        assertEquals("https://h.example", locked.prompt.instance.origin)
        assertNotNull(locked.prompt.title)
        assertEquals(VaultUnlockResult.WRONG_PASSWORD, b.unlock(locked, "wrong password entirely"))
        assertTrue(locked === b.snapshot.locked, "unchanged, the lock screen is the same object in the next snapshot")
        assertEquals(VaultUnlockResult.DONE, b.unlock(locked, strong))
        assertEquals(AppPhase.UNLOCKED, b.snapshot.phase)
        assertNull(b.snapshot.locked)
        assertEquals(VaultUnlockResult.STALE, b.unlock(locked, strong))
        val account = assertNotNull(b.snapshot.account)
        assertFalse(account.serverStopped)
        b.lock()
        assertEquals(AppPhase.LOCKED, b.snapshot.phase)
        assertNull(b.snapshot.account)

        // Sign-out tells the server (best effort) and forgets the session; the server's pin stays. Locked, it takes the
        // person's second confirmation: this device cannot count what was not sent.
        assertEquals(PlainResult.DONE, b.signOutConfirmed(assertNotNull(b.signOutCheck())))
        assertEquals(AppPhase.ENTRY, b.snapshot.phase)
        assertNull(b.at<EntryScreen.FirstRun>().notice)
        assertEquals(KeptPhase.NONE, b.keeper.phase.value)
        assertNotNull(PinStore(d.state).get("https://h.example"))
        assertEquals(PlainResult.STALE, b.signOut())
    }

    /** AppApi's rule: a state that did not change keeps its identity from snapshot to snapshot. */
    @Test fun unchangedStatesKeepTheirIdentityAcrossSnapshots() = runBlocking<Unit> {
        val e = env()
        val a = app(e)
        val first = a.at<EntryScreen.FirstRun>()
        a.entry.openOwnServer(first)
        assertTrue(a.entry.back())
        assertTrue(first === a.snapshot.entry, "back returns the very screen that was left")
        val server = ownServer(a)
        val instance = assertNotNull(a.snapshot.instance)
        assertEquals("https://h.example", instance.label.origin)
        assertEquals(ServerResult.DONE, a.entry.signInHere(server))
        val signIn = a.at<EntryScreen.SignIn>()
        assertTrue(instance === a.snapshot.instance, "the same server on show: the same instance")
        // A refused intent publishes snapshots (busy on, busy off) and changes nothing on show.
        var published = 0
        val watching = a.observe { published++ }
        assertEquals(SignInAnswer.WRONG, a.entry.submitSignIn(signIn, "nobody@h.example", strong))
        watching.close()
        assertTrue(published > 2, "snapshots were published meanwhile")
        assertTrue(signIn === a.snapshot.entry)
        assertTrue(instance === a.snapshot.instance)
        assertTrue(a.entry.back())
        assertTrue(server === a.snapshot.entry)
        assertTrue(instance.card === a.snapshot.instance!!.card)
        assertTrue(instance.label === a.snapshot.instance!!.label)
    }

    @Test fun anOldStoreThatStaysIsTriedAgainAtEveryStartAndToldOnce() = runBlocking<Unit> {
        val e = env()
        val d = Device()
        d.stores.stuck += PreCutoverStore.SAVED_SESSIONS
        val a = app(e, d)
        a.at<EntryScreen.FirstRun>()
        val notice = assertNotNull(a.snapshot.oldData)
        assertEquals(listOf(PreCutoverStore.SAVED_SESSIONS), notice.stores)
        assertTrue(notice.tellNow)
        a.acknowledgeOldData(notice)
        assertFalse(assertNotNull(a.snapshot.oldData).tellNow)
        a.close()
        // The next start tries the store that stayed, and only that one; the person is not told a second time.
        val before = d.stores.wiped.size
        val b = app(e, Device(d.state, d.secure, d.stores))
        assertEquals(listOf(PreCutoverStore.SAVED_SESSIONS), d.stores.wiped.drop(before))
        val again = assertNotNull(b.snapshot.oldData)
        assertFalse(again.tellNow)
        d.stores.stuck.clear()
        assertTrue(b.retryOldDataRemoval(again))
        assertNull(b.snapshot.oldData)
        b.close()
        val c = app(e, Device(d.state, d.secure, d.stores))
        assertNull(c.snapshot.oldData)
        assertEquals(before + 2, d.stores.wiped.size, "once every store is gone, a start deletes nothing")
    }

    @Test fun aForkedServerOpensReadOnlyAndForgettingItReturnsToTheFirstScreen() = runBlocking<Unit> {
        val e = env()
        val d = Device()
        val a = app(e, d)
        confirmKit(a, register(a))
        a.lock()
        val store = PinStore(d.state)
        store.markForked(store.get("https://h.example")!!)
        a.unlock(assertNotNull(a.snapshot.locked), "wrong password entirely")
        assertIs<InstanceCardState.Stopped>(a.snapshot.instance!!.card)
        // A fork stops traffic, not reading: the device's own copy opens, read-only, and nothing is sent.
        val sentBefore = e.transport.bearersFor(WireRoute.RECOVERY_SELF_CONFIRM).size
        assertEquals(VaultUnlockResult.DONE, a.unlock(assertNotNull(a.snapshot.locked), strong))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        assertTrue(assertNotNull(a.snapshot.account).serverStopped)
        assertEquals(sentBefore, e.transport.bearersFor(WireRoute.RECOVERY_SELF_CONFIRM).size)
        assertEquals(PlainResult.DONE, a.instance.forgetServer(assertNotNull(a.snapshot.instance)))
        assertEquals(AppPhase.ENTRY, a.snapshot.phase)
        a.at<EntryScreen.FirstRun>()
        assertNull(a.snapshot.instance)
        assertEquals(KeptPhase.NONE, a.keeper.phase.value)
        assertNull(PinStore(d.state).state("https://h.example").let { it as? io.silencelen.andvari.core.client.pin.PinState.Forked })
    }

    /** A second device of the same account: sign-in from "Already have an account?". */
    private suspend fun signInScreen(b: EngineAppApi): EntryScreen.SignIn {
        b.entry.openSignIn(b.at())
        b.entry.openPasswordSignIn(b.at())
        assertEquals(ServerResult.DONE, b.entry.chooseOwnServer(b.at(), "https://h.example"))
        assertEquals(ServerResult.DONE, b.entry.confirmTrustGate(b.at<EntryScreen.TrustGate>()))
        return b.at()
    }

    @Test fun signInOnAnotherDeviceOpensTheVault() = runBlocking<Unit> {
        val e = env()
        val a = app(e)
        confirmKit(a, register(a))
        val b = app(e)
        val form = signInScreen(b)
        assertNull(form.prompt.email, "the person types the address")
        assertEquals(SignInAnswer.WRONG, b.entry.submitSignIn(form, "alice@example.com", "not it at all"))
        assertEquals(SignInAnswer.DONE, b.entry.submitSignIn(form, "alice@example.com", strong))
        assertEquals(AppPhase.UNLOCKED, b.snapshot.phase)
        assertEquals(a.snapshot.account!!.accountId, b.snapshot.account!!.accountId)
    }

    /** §9.1: a phone refuses the operator account at sign-in, after the password verified, and keeps nothing of it. */
    @Test fun theOperatorAccountIsRefusedAtSignInOnAPhone() = runBlocking<Unit> {
        val e = env()
        val a = app(e)
        confirmKit(a, register(a))
        e.server.operatorUserId = e.server.account("alice@example.com").userId
        val b = app(e)
        val form = signInScreen(b)
        val logouts = e.transport.bearersFor(io.silencelen.andvari.core.model.wire.WireRoute.LOGOUT).size
        assertEquals(SignInAnswer.OPERATOR_NEEDS_COMPUTER, b.entry.submitSignIn(form, "alice@example.com", strong))
        assertNull(b.snapshot.account)
        assertNull(b.keeper.session, "nothing of the account is kept on this phone")
        assertNull(b.keeper.established)
        assertEquals(logouts + 1, e.transport.bearersFor(io.silencelen.andvari.core.model.wire.WireRoute.LOGOUT).size, "the session it opened is ended")
    }

    @Test fun aTwoStepCodeIsAskedAfterThePasswordAndSentWithTheKeysAlreadyDerived() = runBlocking<Unit> {
        val e = env()
        val a = app(e)
        confirmKit(a, register(a))
        e.server.account("alice@example.com").totp = "123456"
        val b = app(e)
        val form = signInScreen(b)
        assertEquals(SignInAnswer.CODE_NEEDED, b.entry.submitSignIn(form, "alice@example.com", strong))
        val withCode = b.at<EntryScreen.SignIn>()
        assertTrue(withCode.codeNeeded)
        // A code the server did not take is said as that, never as a wrong password.
        val refused = b.entry.submitSignInCode(withCode, "000000")
        assertEquals(SignInAnswer.REFUSED_AFTER_CODE, refused)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.SIGN_IN_REFUSED_AFTER_CODE, refused.sentence)
        // The engine drops the derived keys on a wrong code: the screen asks for the password again.
        assertFalse(b.at<EntryScreen.SignIn>().codeNeeded)
        assertEquals(SignInAnswer.STALE, b.entry.submitSignInCode(withCode, "123456"))
        assertEquals(SignInAnswer.CODE_NEEDED, b.entry.submitSignIn(b.at(), "alice@example.com", strong))
        val logins = e.server.calls.count { it == WireRoute.PRELOGIN }
        assertEquals(SignInAnswer.DONE, b.entry.submitSignInCode(b.at(), "123456"))
        assertEquals(logins, e.server.calls.count { it == WireRoute.PRELOGIN }, "the password is not derived again")
        assertEquals(AppPhase.UNLOCKED, b.snapshot.phase)
    }

    /** [inner], except that the next [cut] calls of `POST /auth/login` get no answer and the next [slowDown] are refused as too many. */
    private class LoginCut(val inner: FakeInstance) : WireClient by inner {
        var cut = 0
        var slowDown = 0
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): io.silencelen.andvari.core.client.net.WireResult<T> {
            if (route == WireRoute.LOGIN && cut > 0) {
                cut--
                return io.silencelen.andvari.core.client.net.WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TRANSPORT)
            }
            if (route == WireRoute.LOGIN && slowDown > 0) {
                slowDown--
                return io.silencelen.andvari.core.client.net.WireResult.Refused(429, io.silencelen.andvari.core.model.wire.WireError("rate_limited", "x"), retryAfterSeconds = 5)
            }
            return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
        }
    }

    /**
     * A sign-in's code step is used once, whatever came of it: after a code that got no answer, or one refused as too many,
     * the screen is back at the password, so no further code is refused as stale; the password and a code then sign in.
     * Before: the code screen stayed, and every further code answered STALE.
     */
    @Test fun aCodeStepThatWasUsedGoesBackToThePasswordWhateverItsAnswer() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val cut = LoginCut(server)
        val e = Env(server, BearerTransport(mapOf(server.origin to cut)))
        val a = app(e)
        confirmKit(a, register(a))
        server.account("alice@example.com").totp = "123456"
        val b = app(e)
        for (road in listOf("no answer", "too many")) {
            val form = (b.snapshot.entry as? EntryScreen.SignIn) ?: signInScreen(b)
            assertEquals(SignInAnswer.CODE_NEEDED, b.entry.submitSignIn(form, "alice@example.com", strong), road)
            val withCode = b.at<EntryScreen.SignIn>()
            assertTrue(withCode.codeNeeded, road)
            if (road == "no answer") cut.cut = 1 else cut.slowDown = 1
            val r = b.entry.submitSignInCode(withCode, "123456")
            assertTrue(r != SignInAnswer.DONE && r != SignInAnswer.STALE, "$road: $r")
            assertFalse(b.at<EntryScreen.SignIn>().codeNeeded, "$road: back at the password")
        }
        assertEquals(SignInAnswer.CODE_NEEDED, b.entry.submitSignIn(b.at(), "alice@example.com", strong))
        assertEquals(SignInAnswer.DONE, b.entry.submitSignInCode(b.at(), "123456"))
        assertEquals(AppPhase.UNLOCKED, b.snapshot.phase)
    }

    @Test fun anAccountThatRequiresLinkingSaysSoOnlyAfterThePasswordVerified() = runBlocking<Unit> {
        val e = env()
        val a = app(e)
        confirmKit(a, register(a))
        e.server.account("alice@example.com").requireLink = true
        val b = app(e)
        val form = signInScreen(b)
        assertEquals(SignInAnswer.WRONG, b.entry.submitSignIn(form, "alice@example.com", "not it at all"))
        b.at<EntryScreen.SignIn>()
        assertEquals(SignInAnswer.LINK_REQUIRED, b.entry.submitSignIn(form, "alice@example.com", strong))
        val required = b.at<EntryScreen.LinkRequired>()
        assertEquals("alice@example.com", required.email)
        b.entry.linkInstead(required)
        b.at<EntryScreen.LinkDeviceEntry>()
        assertEquals(KeptPhase.NONE, b.keeper.phase.value)
    }

    @Test fun aSignInThatFindsTheKitNeverSavedMakesANewOneBeforeTheVaultOpens() = runBlocking<Unit> {
        val e = env()
        val a = app(e)
        register(a)
        a.close()
        val b = app(e)
        assertEquals(SignInAnswer.DONE, b.entry.submitSignIn(signInScreen(b), "alice@example.com", strong))
        val kit = b.at<EntryScreen.Kit>()
        assertEquals(KitReason.NEVER_SAVED, kit.kit.reason)
        assertEquals(KitStep.REVEAL, kit.kit.step)
        assertTrue(e.server.calls.contains(WireRoute.RECOVERY_SELF_SETUP), "a fresh kit was committed")
        assertEquals(AppPhase.ENTRY, b.snapshot.phase)
        confirmKit(b, kit)
        assertEquals(AppPhase.UNLOCKED, b.snapshot.phase)
    }

    @Test fun eachScannerTakesItsOwnKindAndStartsNothingForAnother() = runBlocking<Unit> {
        val e = env()
        val a = app(e)
        val kit = register(a)
        val qr = assertNotNull(a.kit.kitDocument(kit.kit)).qrPayload
        val b = app(e)
        b.entry.openInviteEntry(b.at())
        val invites = b.at<EntryScreen.InviteEntry>()
        assertEquals(InviteResult.KIT_NOT_AN_INVITE, b.entry.submitInvite(invites, qr, PayloadSource.SCANNED))
        assertEquals(InviteResult.NOT_AN_INVITE, b.entry.submitInvite(invites, "hello", PayloadSource.PASTED))
        assertEquals(InviteResult.KIT_NOT_AN_INVITE, b.openAppLink(qr))
        b.entry.startOver()
        b.entry.openSignIn(b.at())
        b.entry.openForgot(b.at())
        b.entry.openKitEntry(b.at())
        val kits = b.at<EntryScreen.KitEntry>()
        assertEquals(KitScanResult.NOT_A_KIT, b.entry.submitKit(kits, "https://h.example/l#abc", PayloadSource.PASTED))
        assertEquals(KitScanResult.INVALID_EMAIL, b.entry.submitTypedKit(kits, "nobody", "h.example", "x"))
        assertEquals(KitScanResult.NOT_AN_ADDRESS, b.entry.submitTypedKit(kits, "alice@example.com", "ftp://h", "x"))
        assertEquals(KitScanResult.NOT_A_KIT, b.entry.submitTypedKit(kits, "alice@example.com", "h.example", "not groups"))
    }

    @Test fun anAddressIsCheckedBeforeAnythingIsDialedAndAServerWithoutACardHasNothingToPin() = runBlocking<Unit> {
        val bare = FakeInstance(crypto, origin = "https://bare.example", withCard = false)
        val e = env(extra = mapOf(bare.origin to bare))
        val a = app(e)
        a.entry.openOwnServer(a.at())
        val own = a.at<EntryScreen.OwnServer>()
        assertEquals(ServerResult.NOT_AN_ADDRESS, a.entry.submitServerAddress(own, "http://example.com"))
        assertTrue(e.transport.sent.isEmpty())
        assertEquals(ServerResult.NOT_SET_UP_YET, a.entry.submitServerAddress(own, "bare.example"))
        assertEquals(ServerResult.UNREACHABLE, a.entry.submitServerAddress(own, "nobody.example"))
    }

    @Test fun aServerThatServesAnotherServersCardIsNotPinned() = runBlocking<Unit> {
        // A genuine chain for h.example, served at another address: §2.4 origin_mismatch.
        val copy = FakeInstance(crypto)
        val e = env(extra = mapOf("https://look-alike.example" to copy))
        val a = app(e)
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.OTHER_ADDRESS, a.entry.submitServerAddress(a.at(), "look-alike.example"))
        // The screen says both addresses, whole; nothing was pinned and no instance is on show.
        val mismatch = a.at<EntryScreen.AddressMismatch>()
        assertEquals("https://look-alike.example", mismatch.dialed)
        assertEquals("https://h.example", mismatch.cardNames)
        assertFalse(mismatch.canRecoverThere)
        assertNull(a.snapshot.instance)
        assertEquals(io.silencelen.andvari.core.client.pin.PinState.None, a.trust.pinState("https://look-alike.example"))
        assertTrue(a.entry.back())
        a.at<EntryScreen.OwnServer>()
    }

    @Test fun decliningTheGateSendsNothingAndGoesBack() = runBlocking<Unit> {
        val e = env()
        val a = app(e)
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        a.entry.declineTrustGate(a.at())
        a.at<EntryScreen.OwnServer>()
        assertEquals(listOf(WireRoute.INSTANCE), e.server.calls.distinct())
        assertEquals(io.silencelen.andvari.core.client.pin.PinState.None, a.trust.pinState("https://h.example"))
    }

    @Test fun aStaleScreenDoesNothing() = runBlocking<Unit> {
        val e = env()
        val a = app(e)
        val first = a.at<EntryScreen.FirstRun>()
        a.entry.openOwnServer(first)
        assertEquals(ServerResult.STALE, a.entry.createAccountOnAndvari(first))
        a.entry.startOver()
        assertEquals(ServerResult.FAILED, a.entry.createAccountOnAndvari(a.at()), "no baked instance in this build")
    }
}
