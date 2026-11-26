package io.silencelen.andvari.app.trust

import io.silencelen.andvari.app.autofill.overlayUnlock
import io.silencelen.andvari.core.app.AppApi
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.ForgetEarlierResult
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.KitDocument
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.KitRecoverResult
import io.silencelen.andvari.core.app.KitScanResult
import io.silencelen.andvari.core.app.KitStep
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.RecoveryChangeResult
import io.silencelen.andvari.core.app.ReplacePasswordResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.engine.AppEngine
import io.silencelen.andvari.core.app.engine.EngineAppApi
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * The kit and forgetting walks over the shared code's REAL implementation ([EngineAppApi] over [AppEngine]) and its own
 * test server ([FakeInstance] behind [BearerTransport]), each driven through this app's model ([TrustModel]) as the
 * screens drive it, and read back from what the model draws and from the server. What the fake alone proved before:
 *
 * - a recovery kit shown with a refusal, the lock that wipes it, the notice above the next screen with its reason line and
 *   way out, the notice again at the next start of the app, and its dismissal;
 * - a kit that replaces one shown here and never confirmed says so on its first step only;
 * - the autofill window's unlock makes no kit and sends nothing of one; andvari's own window then locks first, and the
 *   next unlock with the master password shows the fresh kit;
 * - "Forget the earlier account on this device", from the refusal to the notice that the phone remembers the new account.
 *
 * Set-up the screens do not play (another device, a race at the server) goes to the engine's public calls directly.
 */
class SharedTestServerWalksTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val replacement = "a brand new Master password 7"
    private val alice = "alice@example.com"

    /** Runs [meanwhile] once, the first time [route] is called, before the call goes on to [inner]. */
    private class Racing(val inner: FakeInstance, val route: WireRoute) : WireClient by inner {
        var meanwhile: (suspend () -> Unit)? = null
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            if (route == this.route) meanwhile?.let { meanwhile = null; it() }
            return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
        }
    }

    private class Phone(val state: MemoryDeviceState = MemoryDeviceState(), val secure: MemoryDeviceState = MemoryDeviceState())

    private val opened = ArrayList<EngineAppApi>()

    /** An engine of [phone] (a new one is a start of the app on the same phone), talking to [server]. */
    private fun app(server: FakeInstance, phone: Phone = Phone(), via: WireClient = server): EngineAppApi = EngineAppApi(
        AppEngine(
            AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.origin to via)), phone.state, phone.secure, crypto, { server.now },
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

    /** One intent through the model as a screen runs it, to its end: its result. */
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

    /** Through the first screens to a new account's first kit for [email], on show and not confirmed. */
    private fun TrustModel.signUpToKit(email: String) {
        step { entry.openOwnServer(at()) }
        assertEquals(ServerResult.DONE, done { entry.submitServerAddress(at(), "h.example") })
        (api.snapshot.entry as? EntryScreen.TrustGate)?.let { gate -> assertEquals(ServerResult.DONE, done { entry.confirmTrustGate(gate) }) }
        assertEquals(ServerResult.DONE, done { entry.createAccountHere(at()) })
        assertEquals(SignUpStartResult.DONE, done { entry.startSignUp(at(), email, true) })
        assertEquals(CodeResult.DONE, done { entry.verifySignUpCode(at(), "482915") })
        assertEquals(CreateAccountResult.DONE, done { entry.createAccount(at(), NewAccountInput("", "P", strong, true)) })
        api.at<EntryScreen.Kit>()
    }

    /** Type the kit on show back: its document. */
    private fun TrustModel.confirmKit(): KitDocument {
        val reveal = api.at<EntryScreen.Kit>().kit
        val doc = assertNotNull(api.kit.kitDocument(reveal))
        step { kit.proceedToConfirm(reveal) }
        val confirm = api.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, done { kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }) })
        return doc
    }

    private fun TrustModel.register(email: String): KitDocument {
        signUpToKit(email)
        return confirmKit()
    }

    /** From the first screen to the password screen of a sign-in at [server]. */
    private fun TrustModel.toSignIn(server: FakeInstance) {
        step { entry.openSignIn(at()) }
        step { entry.openPasswordSignIn(at()) }
        assertEquals(ServerResult.DONE, done { entry.chooseOwnServer(at(), server.origin) })
        (api.snapshot.entry as? EntryScreen.TrustGate)?.let { gate -> assertEquals(ServerResult.DONE, done { entry.confirmTrustGate(gate) }) }
        api.at<EntryScreen.SignIn>()
    }

    // ---- 1. a kit shown with a refusal, the lock, the notice, its way out, the next start, the dismissal ----

    /**
     * A kit recovery of [alice]'s account (deleted and made again on another device) on this phone, whose commit the server
     * takes while this phone comes to know the EARLIER account under the same address (signed in and out again on the same
     * phone meanwhile, by a second start of the app over the same device state): the phone refuses the session for the
     * identity fault, and the new kit is on show with that refusal.
     */
    private class Road(val server: FakeInstance, val phone: Phone, val d: EngineAppApi, val m: TrustModel, val r: ReplacePasswordResult)

    /** The road up to the new password's answer; [away]: the app left the screen while the commit was out. */
    private fun refusalKitRoad(away: Boolean): Road {
        val server = FakeInstance(crypto)
        model(app(server)).register(alice)
        val earlier = server.accounts.getValue(alice)
        server.accounts.remove(alice)
        val remade = model(app(server)).register(alice)

        val phone = Phone()
        val racing = Racing(server, WireRoute.RECOVERY_SELF_COMMIT)
        val d = app(server, phone, racing)
        val m = model(d)
        m.register("zed@example.com")
        assertEquals(PlainResult.DONE, m.done { signOut() })
        m.step { entry.openSignIn(at()) }
        m.step { entry.openForgot(at()) }
        m.step { entry.openKitEntry(at()) }
        assertEquals(KitScanResult.DONE, m.done { entry.submitKit(at(), remade.qrPayload, PayloadSource.SCANNED) })
        (d.snapshot.entry as? EntryScreen.TrustGate)?.let { gate -> assertEquals(ServerResult.DONE, m.done { entry.confirmTrustGate(gate) }) }
        assertEquals(KitRecoverResult.DONE, m.done { entry.confirmKitRecovery(at()) })
        racing.meanwhile = {
            // The same phone, started a second time, signs in to the EARLIER account (the server serves it for that moment)
            // and out again: only the phone's record of the address remains, tying it to the earlier account.
            val now = server.accounts.getValue(alice)
            server.accounts[alice] = earlier
            try {
                val again = app(server, phone)
                again.start()
                again.entry.openSignIn(again.at())
                again.entry.openPasswordSignIn(again.at())
                assertEquals(ServerResult.DONE, again.entry.chooseOwnServer(again.at(), server.origin))
                (again.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, again.entry.confirmTrustGate(it)) }
                assertEquals(SignInAnswer.DONE, again.entry.submitSignIn(again.at(), alice, strong))
                assertEquals(PlainResult.DONE, again.signOut())
            } finally {
                server.accounts[alice] = now
            }
        }
        if (away) m.wentAway()
        val r = m.done { entry.chooseReplacementPassword(at(), replacement) }
        return Road(server, phone, d, m, r)
    }

    @Test
    fun aKitShownWithARefusalIsWipedByALockSaidAboveTheNextScreenAgainAtTheNextStartAndGoneAtItsDismiss() = walk {
        val road = refusalKitRoad(away = false)
        val server = road.server
        val phone = road.phone
        val d = road.d
        val m = road.m
        val r = road.r
        assertEquals(ReplacePasswordResult.IDENTITY_FAULT_COMMITTED, r, "the commit happened; this phone refused the session")
        assertTrue(WireRoute.RECOVERY_SELF_COMMIT in server.calls)
        val kit = d.at<EntryScreen.Kit>().kit
        val refusal = assertNotNull(kit.notKeptLine, "the kit is on show with its refusal")
        assertEquals(r, assertNotNull(m.kitRefusal.value, "the model holds the refusal that came with the kit").result)
        assertTrue(kitRefusalLines(kit, m.kitRefusal.value).isNotEmpty(), "the screen draws the refusal's lines with the kit")
        assertNotNull(d.kit.kitDocument(kit))

        // The lock wipes it; the next screen (the first screen: nothing is open here) carries the notice above it.
        m.step { lock() }
        assertNull(d.kit.kitDocument(kit), "gone from memory")
        assertIs<EntryScreen.FirstRun>(d.snapshot.entry)
        val notice = assertNotNull(d.snapshot.kitWiped, "said above the next screen")
        assertEquals(alice, notice.email)
        assertEquals(CopyKey.KIT_WIPED_AFTER_RECOVERY_NOT_HERE, notice.line, "never 'on any device': the fault stands here")
        assertEquals(CopyKey.KIT_NOT_HERE_WHY_IDENTITY_FAULT, notice.whyHere, "the reason, never the kit's own line (refusal $refusal)")
        assertFalse(notice.unseen, "it was on the screen")
        assertEquals(listOf(UiText.of(notice.line).shown(), UiText.of(CopyKey.KIT_NOT_HERE_WHY_IDENTITY_FAULT).shown()), kitWipedLines(notice).map { it.shown() })
        // The identity fault has no way out of its own, and names no kept session: the first screen offers none under it
        // (the offer under a kept account's refusal is proved over the fake: KitScreensLeakAndWayOutTest).
        assertNull(notice.wayOut)
        assertNull(notice.namedKept)
        assertNull(kitWipedWayOut(notice, m.saidOn(d.snapshot)?.result, d.snapshot))
        // Nothing but the dismiss takes it: another lock, the background and the return.
        m.step { lock() }
        m.backgrounded()
        m.returnedToForeground()
        m.onSnapshot(d.snapshot)
        assertEquals(notice.line, assertNotNull(d.snapshot.kitWiped).line)
        assertNull(m.wentWrong.value)

        // The app ends without a dismiss: the next start says it again.
        d.close()
        val next = app(server, phone)
        val nm = model(next)
        val again = assertNotNull(next.snapshot.kitWiped, "said again at the next start")
        assertEquals(notice.line, again.line)
        assertEquals(notice.whyHere, again.whyHere)
        assertEquals(alice, again.email)
        // The dismissal, from the app's Close, takes it; a later start says nothing.
        nm.dismissKitWiped(again)
        nm.onSnapshot(next.snapshot)
        assertNull(next.snapshot.kitWiped)
        next.close()
        assertNull(model(app(server, phone)).api.snapshot.kitWiped, "dismissed: a later start says nothing")
    }

    // ---- 2. a kit that replaces one shown before ----

    @Test
    fun aKitThatReplacesOneShownHereSaysSoFirstOnItsFirstStepAndNoLongerWhereItIsTypedBack() = walk {
        val server = FakeInstance(crypto)
        val a = app(server)
        val m = model(a)
        m.signUpToKit(alice)
        assertNull(kitVoidLine(a.at<EntryScreen.Kit>().kit), "the first kit replaces none")
        // A lock takes the first kit before it was typed back; the next unlock's kit says, first, that the earlier is void.
        m.step { lock() }
        assertEquals(AppPhase.LOCKED, a.snapshot.phase)
        assertEquals(VaultUnlockResult.DONE, m.done { unlock(assertNotNull(snapshot.locked), strong) })
        val next = a.at<EntryScreen.Kit>().kit
        assertEquals(KitReason.NEVER_SAVED, next.reason)
        assertEquals(KitStep.REVEAL, next.step)
        assertEquals(UiText.of(CopyKey.KIT_EARLIER_NOT_CONFIRMED_VOID).shown(), assertNotNull(kitVoidLine(next)).shown())
        m.step { kit.proceedToConfirm(next) }
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitStep.CONFIRM, confirm.step)
        assertNull(kitVoidLine(confirm), "not where it is typed back")
        m.step { kit.showKitAgain(a.at<EntryScreen.Kit>().kit) }
        assertNotNull(kitVoidLine(a.at<EntryScreen.Kit>().kit), "the reveal again says it again")
        m.confirmKit()
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        assertTrue(server.account(alice).recoveryConfirmed, "the server holds the kit that was typed back")
        assertNull(m.wentWrong.value)
    }

    // ---- 3. the unlock for filling ----

    @Test
    fun theAutofillWindowsUnlockMakesNoKitAndSendsNothingOfOneTheAppLocksFirstAndItsUnlockShowsTheFreshKit() = walk {
        val server = FakeInstance(crypto)
        val a = app(server)
        val m = model(a)
        m.register(alice)
        // A kit made in Settings and never confirmed, then a lock: the account's kit is not confirmed.
        assertEquals(RecoveryChangeResult.DONE, a.recovery.makeKit(strong))
        m.onSnapshot(a.snapshot)
        m.step { lock() }
        val account = server.account(alice)
        assertFalse(account.recoveryConfirmed)
        val piece = account.pieceId
        val sentBefore = server.calls.size

        // The autofill window's unlock, as the window runs it.
        assertEquals(VaultUnlockResult.DONE, overlayUnlock(a, assertNotNull(a.snapshot.locked), strong))
        m.onSnapshot(a.snapshot)
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase, "the vault is open for filling")
        assertNull(a.snapshot.entry, "no kit in the journey")
        assertNull(assertNotNull(a.snapshot.account).kit, "no kit in Settings")
        assertEquals(piece, account.pieceId, "the server's kit was not replaced")
        val sent = server.calls.drop(sentBefore)
        assertTrue(sent.none { it.name.startsWith("RECOVERY") }, "nothing about a kit was sent: $sent")
        assertTrue(assertNotNull(a.snapshot.account).kitDueAtOpening)

        // andvari's own window comes on show: it locks first.
        m.openedAsTheApp()
        m.onSnapshot(a.snapshot)
        assertEquals(AppPhase.LOCKED, a.snapshot.phase)
        // The next unlock with the master password shows the fresh kit; only now is the server's kit replaced.
        assertEquals(VaultUnlockResult.DONE, m.done { unlock(assertNotNull(snapshot.locked), strong) })
        assertEquals(KitReason.NEVER_SAVED, a.at<EntryScreen.Kit>().kit.reason)
        assertTrue(piece != account.pieceId)
        m.confirmKit()
        assertTrue(account.recoveryConfirmed)
        assertFalse(assertNotNull(a.snapshot.account).kitDueAtOpening)
        // With nothing due, the app's opening locks nothing.
        m.openedAsTheApp()
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        assertNull(m.wentWrong.value)
    }

    // ---- 4. "Forget the earlier account on this device" ----

    @Test
    fun anAccountMadeAgainUnderAnAddressThisPhoneKnewIsRefusedOfferedForgottenAtTheSecondStepAndRemembered() = walk {
        val server = FakeInstance(crypto)
        val d = app(server)
        val m = model(d)
        m.register(alice)
        val earlierId = server.account(alice).userId
        assertEquals(PlainResult.DONE, m.done { signOut() })
        // Deleted at the server and made again under the same address on another device: a new account id.
        server.accounts.remove(alice)
        model(app(server)).register(alice)
        assertTrue(server.account(alice).userId != earlierId)

        m.toSignIn(server)
        assertEquals(SignInAnswer.IDENTITY_FAULT, m.done { entry.submitSignIn(at(), alice, strong) })
        assertEquals(SignInAnswer.IDENTITY_FAULT, m.saidOn(d.snapshot)?.result, "the refusal is said in place")
        val offer = assertNotNull(d.snapshot.earlierAccount, "the offer")
        assertFalse(offer.confirming)
        // The refusal with both possibilities, each a sentence of its own, and how to tell.
        assertEquals(
            listOf(UiText.of(offer.refusal), UiText.of(offer.ifRemade), UiText.of(offer.ifServer), UiText.of(offer.howToTell)).map { it.shown() },
            earlierAccountLines(offer).drop(1).map { it.shown() },
        )
        val sent = server.calls.size

        // The second step; a lock takes it back, and nothing was forgotten.
        m.askToForgetEarlierAccount()
        assertTrue(assertNotNull(d.snapshot.earlierAccount).confirming)
        m.step { lock() }
        assertFalse(assertNotNull(d.snapshot.earlierAccount, "the offer stays").confirming, "the lock took the second step back")
        m.forgetEarlierAccount()
        assertNotNull(d.snapshot.earlierAccount, "no call without the second step on show")

        // The person's own two taps: forgotten, said in place; nothing was sent.
        m.askToForgetEarlierAccount()
        val confirm = assertNotNull(d.snapshot.earlierAccount)
        assertTrue(confirm.confirming)
        m.forgetEarlierAccount()
        m.onSnapshot(d.snapshot)
        assertNull(d.snapshot.earlierAccount)
        assertEquals(ForgetEarlierResult.FORGOTTEN, m.saidOn(d.snapshot)?.result)
        assertEquals(UiText.of(assertNotNull(confirm.lineFor(ForgetEarlierResult.FORGOTTEN))).shown(), m.saidOn(d.snapshot)?.text?.shown())
        assertEquals(sent, server.calls.size, "nothing was sent to the server")

        // The sign-in again opens the new account, with the notice that this phone now remembers it, until dismissed.
        assertEquals(SignInAnswer.DONE, m.done { entry.submitSignIn(at(), alice, strong) })
        assertEquals(AppPhase.UNLOCKED, d.snapshot.phase)
        val remembered = assertNotNull(d.snapshot.rememberedNewAccount)
        assertEquals(CopyKey.REMADE_ACCOUNT_REMEMBERED, remembered.line.key)
        m.dismissNewAccountRemembered(remembered)
        assertNull(d.snapshot.rememberedNewAccount)
        assertNull(m.wentWrong.value)
    }

    // ---- what the app interface's later set hands the app ----

    /**
     * The app left the screen while the commit was out: the app tells the shared code ([AppApi.wentAway]) as it marks
     * itself away, the kit that arrives meanwhile is locked away before any frame, and the notice says the kit was NEVER
     * shown, with its reason line. Before, the app never told the shared code, which then said "the kit that was on the
     * screen".
     */
    @Test
    fun aKitThatArrivesWhileTheAppIsAwayIsLockedAwayAndSaidAsNeverShown() = walk {
        val road = refusalKitRoad(away = true)
        val d = road.d
        val m = road.m
        assertEquals(ReplacePasswordResult.IDENTITY_FAULT_COMMITTED, road.r)
        if (d.snapshot.entry is EntryScreen.Kit) m.step { lock() }
        assertTrue(d.snapshot.entry !is EntryScreen.Kit, "no kit at the return")
        val notice = assertNotNull(d.snapshot.kitWiped)
        assertTrue(notice.unseen, "said as never shown")
        assertEquals(CopyKey.KIT_WIPED_UNSEEN_AFTER_RECOVERY_NOT_HERE, notice.line)
        assertEquals(CopyKey.KIT_NOT_HERE_WHY_IDENTITY_FAULT, notice.whyHere)
        assertEquals(listOf(UiText.of(notice.line).shown(), UiText.of(CopyKey.KIT_NOT_HERE_WHY_IDENTITY_FAULT).shown()), kitWipedLines(notice).map { it.shown() })
        m.returnedToForeground()
        assertTrue(assertNotNull(d.snapshot.kitWiped).unseen, "the return changes nothing of it")
    }

    private fun deletable(server: FakeInstance) {
        server.override[WireRoute.ACCOUNT_DELETE_PREVIEW] = WireResult.Ok(
            """{"blockers":[],"deletedVaults":[],"leftVaults":[],"memberships":[],"totpRequired":false}""", 200)
    }

    private fun TrustModel.deleteAccount(): io.silencelen.andvari.core.app.DeletionResult {
        assertEquals(PlainResult.DONE, done { settings.openDeletion() })
        val screen = assertNotNull(assertNotNull(api.snapshot.account).deletion)
        var result: io.silencelen.andvari.core.app.DeletionResult? = null
        runBlocking { runIn(DELETION_SECTION, { settings.deleteAccount(screen, alice, strong, null) }, { deletionWords(it, 0) }) { result = it; deletionAnswered(it) }.join() }
        onSnapshot(api.snapshot)
        return assertNotNull(result)
    }

    /** A confirmed deletion: the line as it comes, the first launch, and the server is not offered from memory. */
    @Test
    fun aConfirmedDeletionLandsOnTheFirstLaunchWithItsLineAndNothingOffersItsServerFromMemory() = walk {
        val server = FakeInstance(crypto)
        val d = app(server)
        val m = model(d)
        m.register(alice)
        deletable(server)
        server.override[WireRoute.ACCOUNT_DELETE] = WireResult.Ok("""{"deletedAt":1}""", 200)
        assertEquals(io.silencelen.andvari.core.app.DeletionResult.DONE, m.deleteAccount())
        val first = d.at<EntryScreen.FirstRun>()
        val notice = assertNotNull(first.accountDeleted)
        assertTrue(notice.serverForgotten)
        assertEquals(CopyKey.ACCOUNT_DELETED_SERVER_FORGOTTEN, notice.line.key)
        assertEquals(UiText.of(notice.line).shown(), assertNotNull(accountDeletedLine(first)).shown(), "the line as it comes")
        assertNull(d.snapshot.instance, "no server is current")
        assertNull(d.snapshot.keptSignedOut)
        m.step { entry.dismissNotice(first) }
        // Using the server again starts as on a new phone: its address typed, its Trust Gate.
        m.step { entry.openOwnServer(at()) }
        assertEquals(ServerResult.DONE, m.done { entry.submitServerAddress(at(), "h.example") })
        d.at<EntryScreen.TrustGate>()
    }

    /**
     * A deletion whose answer was lost: the offer to forget the account on this phone, its second step with the
     * confirmation and the count of changes not sent, closed at a lock; a check object of before the lock is never
     * confirmed; nothing is called by the app itself; the person's own confirmation forgets it and lands on the first
     * screen, with nothing said of a forgotten server.
     */
    @Test
    fun afterADeletionOfUnknownOutcomeTheForgettingIsOfferedConfirmedOnlyByThePersonAndClosedAtALock() = walk {
        val server = FakeInstance(crypto)
        val d = app(server)
        val m = model(d)
        m.register(alice)
        deletable(server)
        server.override[WireRoute.ACCOUNT_DELETE] = WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TRANSPORT)
        assertEquals(io.silencelen.andvari.core.app.DeletionResult.OUTCOME_UNKNOWN, m.deleteAccount())
        assertTrue(assertNotNull(assertNotNull(d.snapshot.account).deletion).outcomeUnknown)
        val check = assertNotNull(m.forgetUnknownCheck(), "the offer on the deletion screen")
        assertEquals(emptyList(), forgetUnknownLines(check, confirming = false), "the offer is its button alone")
        assertNull(m.forgetUnknownAsked.value)
        fun ends() = server.calls.count { it == WireRoute.END_SESSION }

        // The second step: the confirmation, then what goes of the changes not sent.
        m.askToForgetUnknownDeletion()
        assertSame(check, m.forgetUnknownAsked.value)
        assertEquals(listOf(check.confirmLine, check.unsentLine).map { UiText.of(it).shown() }, forgetUnknownLines(check, confirming = true).map { it.shown() })
        assertEquals(CopyKey.DELETION_UNKNOWN_FORGET_CONFIRM, check.confirmLine.key)

        // A lock closes it; the lock screen has a new check (the copy cannot be counted there), offered again.
        m.step { lock() }
        assertNull(m.forgetUnknownAsked.value, "the lock closed the second step")
        assertTrue(assertNotNull(d.snapshot.locked).deletionOutcomeUnknown)
        val locked = assertNotNull(m.forgetUnknownCheck())
        assertTrue(locked !== check)
        assertEquals(CopyKey.DELETION_UNKNOWN_FORGET_UNSENT_CANNOT_TELL, locked.unsentLine.key)
        m.forgetUnknownDeletion()
        m.tick()
        m.backgrounded()
        m.returnedToForeground()
        assertEquals(0, ends(), "nothing without the second step on show, nothing by the app itself")
        assertNotNull(d.snapshot.locked)

        // The person's own two taps.
        m.askToForgetUnknownDeletion()
        assertSame(locked, m.forgetUnknownAsked.value)
        m.forgetUnknownDeletion()
        m.onSnapshot(d.snapshot)
        assertEquals(AppPhase.ENTRY, d.snapshot.phase)
        d.at<EntryScreen.FirstRun>()
        assertNull(m.saidOn(d.snapshot), "nothing said of a forgotten server: it is kept")
        assertNull(m.forgetUnknownAsked.value)
        assertNull(m.forgetUnknownCheck())
        assertEquals(1, ends(), "the session's end, once")
        m.forgetUnknownDeletion()
        assertEquals(1, ends(), "never again")
    }
}
