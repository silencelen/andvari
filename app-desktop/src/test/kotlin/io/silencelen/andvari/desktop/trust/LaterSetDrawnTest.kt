package io.silencelen.andvari.desktop.trust

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEvent
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.unit.Density
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.DesktopAppApi
import io.silencelen.andvari.core.app.DeviceLinkHost
import io.silencelen.andvari.core.app.DeviceLinkHostEnd
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitScreen
import io.silencelen.andvari.core.app.LinkDeviceEnd
import io.silencelen.andvari.core.app.LinkPasswordResult
import io.silencelen.andvari.core.app.OperatorResult
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ProofResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.Trouble
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.client.session.Establishing
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * What the app interface's later set hands the desktop, drawn: the forgetting after a deletion whose outcome is not known,
 * the end of a device link (too many requests, an earlier account, a refused code or password), the operator's refused
 * policy, the window leaving the screen and its return, a session this computer could not confirm, the kit's filled
 * warning, and a confirmed deletion's line. Over the fake, by key.
 */
class LaterSetDrawnTest {
    private val dir = "src/main/kotlin/io/silencelen/andvari/desktop/trust/"
    private fun body(file: String, head: String) = File(dir + file).readText().substringAfter(head).substringBefore("\n}\n")
    private val pw = FakeScenes.PASSWORD

    private fun model(api: DesktopAppApi, clock: () -> Long = { 0L }): TrustModel =
        TrustModel(api, CoroutineScope(Dispatchers.Unconfined), clock).also { it.onSnapshot(api.snapshot) }

    private inline fun <reified T : EntryScreen> on(api: FakeDesktopAppApi): T = assertIs<T>(api.snapshot.entry)

    /** The window's entry screens, redrawn from the snapshot as it changes, with the focus walk in [log]. */
    @OptIn(androidx.compose.ui.InternalComposeUiApi::class)
    private class Walk(api: FakeDesktopAppApi, m: TrustModel) {
        val log = ArrayList<String>()
        private var t = 0L
        private val scene = ImageComposeScene(600, 3000, Density(1f)) {
            CompositionLocalProvider(LocalFocusLog provides log) {
                MaterialTheme {
                    Surface {
                        val s: AppSnapshot by api.snapshots.collectAsState()
                        m.said.collectAsState().value
                        s.entry?.let { EntryScreens(m, s, it) }
                    }
                }
            }
        }

        init {
            scene.render(t)
        }

        private fun press(key: Key) {
            scene.sendKeyEvent(KeyEvent(key, KeyEventType.KeyDown))
            scene.sendKeyEvent(KeyEvent(key, KeyEventType.KeyUp))
            repeat(2) {
                t += 50_000_000L
                scene.render(t)
            }
        }

        fun tabUntil(words: String, most: Int = 80) {
            repeat(most) {
                if (log.lastOrNull() == words) return
                press(Key.Tab)
            }
            assertEquals(words, log.lastOrNull(), log.toString())
        }

        fun enter() = press(Key.Enter)

        fun close() = scene.close()
    }

    // ---- a deletion whose outcome is not known: forgetting the account on this computer ----

    private fun unlocked(clock: () -> Long = { 0L }): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(FakeScene.LOCKED)
        val m = model(api, clock)
        m.run({ unlock(assertNotNull(snapshot.locked), pw) })
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        return api to m
    }

    /** Settings › Delete account, sent, its answer lost: the deletion's screen says it cannot tell. */
    private fun unknownOutcome(): Pair<FakeDesktopAppApi, TrustModel> {
        val (api, m) = unlocked()
        m.run({ settings.openDeletion() })
        api.script.deletionAnswerLost = true
        m.deleteAccount(assertNotNull(api.snapshot.account?.deletion), FakeScenes.EMAIL, pw, null)
        m.onSnapshot(api.snapshot)
        assertTrue(assertNotNull(api.snapshot.account?.deletion).outcomeUnknown)
        return api to m
    }

    @Test
    fun theForgettingIsOfferedInTwoStepsAndOnlyThePersonsSecondClickCallsIt() {
        val (api, m) = unknownOutcome()
        val check = assertNotNull(m.forgetUnknownCheck(), "offered on the deletion's screen")
        assertNull(m.forgetUnknownAsked.value, "the first step: the offer alone")
        // Nothing is forgotten without the second step on show.
        assertNull(m.forgetAfterUnknownDeletion(check))
        assertNotNull(api.snapshot.account, "nothing forgotten")
        m.askToForgetAfterUnknownDeletion(check)
        assertSame(check, m.forgetUnknownAsked.value)
        // The second step: the confirmation, then the line about changes not sent, each the shared code's.
        assertEquals(listOf(check.confirmLine.key, check.unsentLine.key), listOf(CopyKey.DELETION_UNKNOWN_FORGET_CONFIRM, check.unsentLine.key))
        assertEquals(listOf(UiText.of(check.confirmLine).shown(), UiText.of(check.unsentLine).shown()), forgetUnknownConfirmLines(check).map { it.shown() })
        assertTrue(check.unsentLine.key.name.startsWith("DELETION_UNKNOWN_FORGET_"))
        // Cancel: back to the offer, nothing forgotten.
        m.keepAfterUnknownDeletion()
        assertNull(m.forgetUnknownAsked.value)
        assertNull(m.forgetAfterUnknownDeletion(check), "the step closed: nothing is sent")
        assertNotNull(api.snapshot.account)
        // A lock closes the second step; the lock screen offers the first step again.
        m.askToForgetAfterUnknownDeletion(check)
        m.lockNow()
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        assertNull(m.forgetUnknownAsked.value, "a lock takes the confirmation back")
        val onLock = assertNotNull(m.forgetUnknownCheck(), "the lock screen offers it")
        assertNull(m.forgetAfterUnknownDeletion(onLock), "never from a step left open over a lock")
        // On the lock screen, both steps, and the person's own confirmation forgets the account here.
        m.askToForgetAfterUnknownDeletion(onLock)
        assertNotNull(m.forgetAfterUnknownDeletion(onLock))
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.ENTRY, api.snapshot.phase, "the first screen")
        assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
        assertNull(api.snapshot.keptSignedOut, "the account is gone from this computer")
        assertNull(m.forgetUnknownCheck())
        assertNull(m.forgetUnknownAsked.value)
        assertNull(m.saidOn(api.snapshot), "done says nothing of its own here; the first screen is the answer")
        // Drawn on all three screens, by the one composable; Cancel first on the second step, and neither step a Main button.
        assertTrue(body("SettingsScreens.kt", "internal fun DeleteAccountSection(").contains("ForgetUnknownDeletionOffer(model, s)"))
        assertTrue(body("AccountScreens.kt", "internal fun LockScreen(").contains("ForgetUnknownDeletionOffer(model, s)"))
        assertTrue(body("EntryScreens.kt", "internal fun FirstRunScreen(").contains("ForgetUnknownDeletionOffer(model, s)"))
        val drawn = body("EarlierAccountOffer.kt", "internal fun ForgetUnknownDeletionOffer(")
        assertTrue(drawn.indexOf("Second(UiText.of(CopyKey.CANCEL)") in 0 until drawn.indexOf("Second(UiText.ph(Placeholder.FORGET_UNKNOWN_CONFIRM)"))
        assertFalse(Regex("""\bMain\(|FocusRequester|requestFocus|onKeyEvent|onPreviewKeyEvent""").containsMatchIn(drawn))
    }

    /** A new offer object (the shared code's after a lock, or a changed count) closes the second step, which is read again. */
    @Test
    fun aNewOfferObjectClosesTheSecondStepAndANewOneIsReadAgain() {
        val (api, m) = unknownOutcome()
        val check = assertNotNull(m.forgetUnknownCheck())
        val changed = rebuilt(check, "unsentChanges" to 3)
        assertNotEquals<Any>(check, changed)
        val swapped = object : DesktopAppApi by api {
            var offer = check
            override fun forgetAfterUnknownDeletionCheck() = offer
        }
        val m2 = model(swapped)
        m2.askToForgetAfterUnknownDeletion(check)
        assertSame(check, m2.forgetUnknownAsked.value)
        swapped.offer = changed
        m2.onSnapshot(swapped.snapshot)
        assertNull(m2.forgetUnknownAsked.value, "the step closes: the offer is another object now")
        assertNull(m2.forgetAfterUnknownDeletion(check), "the old confirmation sends nothing")
        assertNull(m2.forgetAfterUnknownDeletion(changed), "nor the new one without its own second step")
        assertNotNull(api.snapshot.account)
        assertEquals(CopyKey.DELETION_UNKNOWN_FORGET_UNSENT, changed.unsentLine.key)
        m2.askToForgetAfterUnknownDeletion(changed)
        assertEquals(UiText.of(changed.unsentLine).shown(), forgetUnknownConfirmLines(changed)[1].shown())
        assertSame(changed, m2.forgetUnknownAsked.value)
        assertSame(check, m.forgetUnknownCheck(), "the fake's own offer is unchanged")
    }

    /** The keyboard reaches both steps; Enter on the offer shows the second step, and further Enters forget nothing. */
    @Test
    fun enterOnTheOfferNeverPassesTheSecondStep() {
        val (api, m) = unlocked()
        m.run({ settings.openDeletion() })
        api.script.deletionAnswerLost = true
        api.script.deletionHappenedAnyway = true
        m.deleteAccount(assertNotNull(api.snapshot.account?.deletion), FakeScenes.EMAIL, pw, null)
        m.checkDeletion(assertNotNull(api.snapshot.account?.deletion))
        m.onSnapshot(api.snapshot)
        assertTrue(assertNotNull(api.snapshot.locked).deletionOutcomeUnknown)
        m.signInAgain()
        m.onSnapshot(api.snapshot)
        val first = on<EntryScreen.FirstRun>(api)
        assertNotNull(first.deletionOutcomeUnknown, "the first screen says it cannot tell")
        val check = assertNotNull(m.forgetUnknownCheck(), "and offers the forgetting there")
        val walk = Walk(api, m)
        try {
            walk.tabUntil(UiText.of(check.offerLine).shown())
            walk.enter()
            assertSame(check, m.forgetUnknownAsked.value, "Enter on the offer shows the second step")
            walk.enter()
            walk.enter()
            assertNotNull(api.snapshot.keptSignedOut, "Enter again forgets nothing")
            assertSame(check, m.forgetUnknownAsked.value)
            walk.tabUntil(UiText.ph(Placeholder.FORGET_UNKNOWN_CONFIRM).shown())
            walk.enter()
            assertNull(api.snapshot.keptSignedOut, "forgotten by the person's own press on the second step")
            assertNull(m.forgetUnknownCheck())
        } finally {
            walk.close()
        }
    }

    // ---- a confirmed deletion ----

    @Test
    fun aConfirmedDeletionSaysItsLineAndNothingOffersItsServerFromMemory() {
        val (api, m) = unlocked()
        m.run({ settings.openDeletion() })
        m.deleteAccount(assertNotNull(api.snapshot.account?.deletion), FakeScenes.EMAIL, pw, null)
        m.onSnapshot(api.snapshot)
        val s = api.snapshot
        val notice = assertNotNull(m.accountDeletedNotice())
        assertEquals(CopyKey.ACCOUNT_DELETED_SERVER_FORGOTTEN, notice.line.key)
        // The server is not offered from the app's memory: no account kept, no attached server, no choice naming it.
        assertNull(s.keptSignedOut)
        assertNull(io.silencelen.andvari.desktop.attachedOrigin(s))
        val origin = notice.instance.origin
        assertTrue(firstRunChoices(on(api)).none { it.label.shown().contains(origin) || it.line?.shown()?.contains(origin) == true })
        // Where another account keeps the server known, the line says so, as the shared code hands it.
        val kept = rebuilt(notice, "serverForgotten" to false)
        assertEquals(CopyKey.ACCOUNT_DELETED_SERVER_KEPT, kept.line.key)
        assertTrue(body("EntryScreens.kt", "internal fun FirstRunScreen(").contains("Say(UiText.of(deleted.line))"))
    }

    // ---- a device link ----

    /** A device link that ended over an earlier account known here offers the forgetting on its end, by the same code. */
    @Test
    fun aLinkThatEndedOverAnEarlierAccountOffersTheForgettingOnItsEnd() {
        val api = FakeScenes.desktopAt(FakeScene.FIRST_RUN)
        val m = model(api)
        val eve = api.script.publicInstance.addAccount("eve@example.com", pw)
        api.script.earlierAccountKnown = true
        api.script.keeperIdentityFault = true
        m.act { entry.openSignIn(on(api)) }
        m.act { entry.openLinkDevice(on(api)) }
        m.run({ entry.submitDeviceLink(on(api), api.script.deviceLinkFrom(eve, "MacBook"), PayloadSource.PASTED) })
        api.script.otherDeviceAnswers()
        api.script.otherDeviceApproves()
        m.onSnapshot(api.snapshot)
        on<EntryScreen.LinkDeviceEnded>(api)
        val offer = assertNotNull(api.snapshot.earlierAccount, "the shared code hands the offer on the link's end")
        val walk = Walk(api, m)
        try {
            walk.tabUntil(UiText.of(offer.forgetLabel).shown())
            walk.enter()
            assertTrue(assertNotNull(api.snapshot.earlierAccount).confirming, "its second step, on the link's end")
        } finally {
            walk.close()
        }
        assertTrue(body("LinkAndRecoveryScreens.kt", "internal fun LinkDeviceEndedScreen(").contains("EarlierAccountOffer(model, s)"))
        val all = File(dir).listFiles().orEmpty().filter { it.name.endsWith(".kt") }.sumOf { Regex("""fun EarlierAccountOffer\(""").findAll(it.readText()).count() }
        assertEquals(1, all, "no second copy of the offer")
    }

    /** A password the server refuses at a link: its sentence on the link's password window, the field emptied; never "wrong password". */
    @Test
    fun aRefusedProofAtALinkSaysTheSharedCodesSentenceOnThePasswordWindow() {
        val text = assertNotNull(UiText.forResult(LinkPasswordResult.PROOF_REFUSED, 0))
        assertEquals(UiText.of(CopyKey.LINK_PROOF_REFUSED_TYPE_CURRENT).shown(), text.shown())
        assertNotEquals(UiText.forResult(LinkPasswordResult.WRONG, 0)?.shown(), text.shown(), "never the wrong password's line")
        val screen = body("LinkAndRecoveryScreens.kt", "internal fun LinkDevicePasswordScreen(")
        assertTrue(screen.contains("model.run({ entry.submitLinkPassword(screen, typed) }) { password = \"\" }"), "the field is emptied")
        assertTrue(screen.contains("SaidHere(model, s)"), "said on the window it was answered on, which stays")
    }

    @Test
    fun aLinkEndedForTooManyRequestsSaysItsOwnLineWithTheWait() {
        val line = linkDeviceEndLine(LinkDeviceEnd.TOO_MANY, 42)
        // The wait as a length of time a person reads (the desktop's one helper for waits), never a bare number of seconds.
        assertEquals(UiText.filled(CopyKey.DEVICE_LINK_TOO_MANY, waitText(42).shown()).shown(), line.shown())
        assertEquals(UiText.filled(CopyKey.DEVICE_LINK_TOO_MANY, waitText(0).shown()).shown(), linkDeviceEndLine(LinkDeviceEnd.TOO_MANY, 0).shown())
        // On the computer that shows the link: the ended link's own line in place of the outcome's.
        val api = FakeScenes.desktopAt(FakeScene.VAULTS)
        val m = model(api)
        m.run({ devices.startDeviceLink() })
        api.script.newerLinkMadeElsewhere()
        val ended = assertIs<DeviceLinkHost.Ended>(api.snapshot.account?.deviceLink)
        assertEquals(deviceLinkEndLine(ended.outcome).shown(), deviceLinkHostEndText(ended, 7).shown(), "no line of its own: the outcome's")
        val tooMany = rebuilt(ended, "outcome" to DeviceLinkHostEnd.DID_NOT_CHECK_OUT, "line" to CopyKey.DEVICE_LINK_HOST_TOO_MANY)
        assertEquals(UiText.filled(CopyKey.DEVICE_LINK_HOST_TOO_MANY, waitText(7).shown()).shown(), deviceLinkHostEndText(tooMany, 7).shown())
        assertNotEquals(deviceLinkEndLine(DeviceLinkHostEnd.DID_NOT_CHECK_OUT).shown(), deviceLinkHostEndText(tooMany, 7).shown(), "never 'a check failed'")
        assertTrue(body("SettingsScreens.kt", "internal fun DeviceLinkHostView(").contains("Say(deviceLinkHostEndText(host,"))
        // The start of a link, the digits and the approval refused as too many: the too-many line with the wait, never
        // unreachable and never the line without wording.
        for (r in listOf<io.silencelen.andvari.core.app.IntentResult>(PlainResult.RATE_LIMITED, io.silencelen.andvari.core.app.DigitsResult.RATE_LIMITED, ProofResult.RATE_LIMITED)) {
            val said = assertIs<UiText.Ph>(if (r is ProofResult) deviceLinkApproveLine(r, 30) else UiText.forResult(r, 30))
            assertEquals(Placeholder.TROUBLE_TOO_MANY, said.placeholder, "$r")
            assertTrue(said.args.contains(waitText(30).shown()), "$r")
            assertEquals(Trouble.RATE_LIMITED, r.trouble)
        }
    }

    // ---- a sign-in's code step ----

    @Test
    fun aSignInsCodeAnsweredReturnsToThePasswordByItselfAndNothingOffersAnotherCode() {
        val api = FakeScenes.desktopAt(FakeScene.SIGN_IN_CODE_NEEDED)
        val m = model(api)
        m.run({ entry.submitSignInCode(on(api), "000000") })
        assertSame(SignInAnswer.REFUSED_AFTER_CODE, m.saidOn(api.snapshot)?.result)
        assertFalse(on<EntryScreen.SignIn>(api).codeNeeded, "the shared code's window is back at the password")
        assertFalse(signInAsksCode(on(api), codeSpent = false), "the window asks for the password")
        m.run({ entry.submitSignIn(on(api), FakeScenes.EMAIL, pw) })
        assertTrue(on<EntryScreen.SignIn>(api).codeNeeded)
        api.script.keeperRefuses = Establishing.KEPT_COPY_DAMAGED
        val ada = assertNotNull(api.script.publicInstance.accounts.values.firstOrNull { it.email == FakeScenes.EMAIL })
        var answer: SignInAnswer? = null
        m.run({ entry.submitSignInCode(on(api), assertNotNull(ada.twoStepCode)) }) { answer = it }
        assertSame(SignInAnswer.KEPT_COPY_DAMAGED, answer)
        // The fake leaves its screen asking for a code after the keeper's own refusal; the
        // window asks for the password all the same, so nothing offers another code there.
        assertFalse(signInAsksCode(on(api), codeSpent = codeStepSpent(assertNotNull(answer))))
    }

    // ---- the operator's console ----

    @Test
    fun aRefusedPolicySaysWhyBesideThePolicyUntilAStoredSave() {
        val api = FakeScenes.desktopAt(FakeScene.OPERATOR_CONSOLE)
        val m = model(api)
        val op = m.operator
        val read = assertNotNull(assertNotNull(api.operatorApi.console).policy)
        assertNull(policyRefusalText(assertNotNull(api.operatorApi.console)))
        op.savePolicy(read, PolicyTyped.of(read.copy(kdfParams = read.kdfParams.copy(memBytes = 4096))), pw)
        assertEquals(OperatorResult.BAD_POLICY, op.answerAt(OperatorModel.Area.POLICY)?.result)
        val console = assertNotNull(api.operatorApi.console)
        val why = assertNotNull(console.policyRefusal)
        assertEquals(CopyKey.OPERATOR_POLICY_KDF_TOO_WEAK, why.key)
        assertEquals(UiText.of(why).shown(), assertNotNull(policyRefusalText(console)).shown())
        op.savePolicy(read, PolicyTyped.of(read.copy(autoLockSeconds = 120)), pw)
        assertEquals(OperatorResult.DONE, op.answerAt(OperatorModel.Area.POLICY)?.result)
        assertNull(policyRefusalText(assertNotNull(api.operatorApi.console)), "a stored save clears it")
        assertTrue(body("OperatorScreens.kt", "private fun PolicySection(").contains("policyRefusalText(c)?.let { Say(it,"))
    }

    // ---- the window leaves the screen, and comes back ----

    /** Records the two lifecycle calls and every lock, in order. */
    private class Calls(val fake: FakeDesktopAppApi) : DesktopAppApi by fake {
        val log = ArrayList<String>()
        override fun lock() {
            log += "lock"
            fake.lock()
        }
        override fun wentAway() {
            log += "away"
            fake.wentAway()
        }
        override fun returnedToForeground() {
            log += "back"
            fake.returnedToForeground()
        }
    }

    @Test
    fun theWindowGoingAwayIsToldAndAtItsReturnADueLockComesFirst() {
        var now = 0L
        val api = Calls(FakeScenes.desktopAt(FakeScene.VAULTS))
        val m = model(api) { now }
        m.wentAway()
        now += m.autoLockMs() + 1
        m.cameBack()
        assertEquals(listOf("away", "lock", "back"), api.log, "lock first, then the shared code hears the app is back")
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        // No lock due: only the return.
        api.log.clear()
        m.wentAway()
        m.cameBack()
        assertEquals(listOf("away", "back"), api.log)
        val main = File("src/main/kotlin/io/silencelen/andvari/desktop/Main.kt").readText()
        assertTrue(main.contains("override fun windowIconified(e: WindowEvent?) { model?.wentAway() }"))
        assertTrue(main.contains("override fun componentHidden(e: java.awt.event.ComponentEvent?) { model?.wentAway() }"))
        assertTrue(main.contains("override fun windowDeiconified(e: WindowEvent?) { model?.cameBack() }"))
    }

    /** A kit made while the window was away and wiped before it came back is drawn with its own lines (never "on the screen"). */
    @Test
    fun aKitWipedBeforeItWasEverShownIsDrawnWithItsOwnLines() {
        for (away in listOf(true, false)) {
            val api = FakeScenes.desktopAt(FakeScene.FIRST_RUN)
            val m = model(api)
            val dee = api.script.publicInstance.addAccount("dee@example.com", pw)
            m.act { entry.openSignIn(on(api)) }
            m.act { entry.openForgot(on(api)) }
            m.act { entry.openKitEntry(on(api)) }
            m.run({ entry.submitKit(on(api), api.script.kitOf(dee), PayloadSource.PASTED) })
            m.run({ entry.confirmKitRecovery(on(api)) })
            val replace = on<EntryScreen.ReplacePassword>(api)
            api.script.refusedAfterCommit = "some_other_reason"
            if (away) m.wentAway()
            m.run({ entry.chooseReplacementPassword(replace, "a new master password 2") })
            assertNotNull(on<EntryScreen.Kit>(api).kit.notKeptLine)
            m.lockNow()
            m.cameBack()
            m.onSnapshot(api.snapshot)
            val notice = assertNotNull(api.snapshot.kitWiped, "away=$away")
            assertEquals(away, notice.unseen, "away=$away")
            assertEquals(away, notice.line.name.startsWith("KIT_WIPED_UNSEEN_"), "away=$away")
            assertEquals(UiText.of(notice.line).shown(), kitWipedLines(notice).first().shown(), "the notice's own line first")
        }
    }

    // ---- a session this computer could not confirm ----

    @Test
    fun aSessionNotConfirmedIsSaidAsThatEndNeverAsTheServers() {
        val api = FakeScenes.desktopAt(FakeScene.LOCKED)
        val s = api.snapshot
        val locked = assertNotNull(s.locked)
        assertEquals(UiText.ph(Placeholder.SIGNED_OUT_BY_SERVER).shown(), serverEndText(rebuilt(s, "locked" to rebuilt(locked, "signedOutByServer" to true))).shown())
        // The lock screen.
        val notConfirmed = rebuilt(s, "locked" to rebuilt(locked, "signedOutByServer" to true, "sessionNotConfirmed" to true))
        assertEquals(UiText.of(CopyKey.SESSION_NOT_CONFIRMED).shown(), serverEndText(notConfirmed).shown())
        // An opened copy.
        val (open, _) = unlocked()
        val account = assertNotNull(open.snapshot.account)
        val copy = rebuilt(open.snapshot, "account" to rebuilt(account, "signedOutByServer" to true, "sessionNotConfirmed" to true, "endLine" to CopyKey.SESSION_NOT_CONFIRMED_COPY_OPEN))
        assertEquals(UiText.of(CopyKey.SESSION_NOT_CONFIRMED_COPY_OPEN).shown(), serverEndText(copy).shown())
        assertTrue(body("AccountScreens.kt", "internal fun SignedOutByServerCard(").contains("Say(serverEndText(s),"))
        // The first screen: the shared code's line, once, with its dismiss.
        val first = body("EntryScreens.kt", "internal fun FirstRunScreen(")
        assertTrue(first.contains("if (screen.sessionNotConfirmed) {") && first.contains("Say(UiText.of(CopyKey.SESSION_NOT_CONFIRMED))"))
        // The kept account named above a refusal's way out: never "which its server signed out", the shared code's line beside it.
        val ended = FakeScenes.desktopAt(FakeScene.VAULTS)
        val em = model(ended)
        ended.script.sessionEndedByServer()
        em.signInAgain()
        val entry = ended.snapshot
        assertEquals(listOf(keptAccountLine(assertNotNull(entry.keptSignedOut)).shown()), keptAccountNamed(entry).map { it.shown() })
        // A session this computer could not confirm, as the stand-in plays it: the account named, then the shared code's
        // line for that end beside a sign-out, as handed.
        val unconfirmedApi = FakeScenes.desktopAt(FakeScene.VAULTS)
        val nm = model(unconfirmedApi)
        unconfirmedApi.script.sessionNotConfirmed()
        nm.signInAgain()
        val unconfirmed = unconfirmedApi.snapshot
        assertTrue(unconfirmed.keptSignedOutNotConfirmed)
        val handed = assertNotNull(unconfirmed.keptSignedOutSignOutFirstLine)
        assertEquals(CopyKey.SESSION_NOT_CONFIRMED_SIGN_OUT_FIRST, handed)
        val lines = keptAccountNamed(unconfirmed)
        assertEquals(2, lines.size, lines.map { it.shown() }.toString())
        assertEquals(Placeholder.KEPT_ACCOUNT_NOT_CONFIRMED_SIGN_OUT_FIRST, assertIs<UiText.Ph>(lines[0]).placeholder)
        assertEquals(UiText.of(handed).shown(), lines[1].shown())
        // The shared code's other line for that end tells the person to sign in again: never beside "sign out of it first".
        assertFalse(lines.any { it.shown() == UiText.of(CopyKey.SESSION_NOT_CONFIRMED).shown() })
        assertFalse(lines.any { it.shown() == keptAccountLine(assertNotNull(unconfirmed.keptSignedOut)).shown() })
    }

    // ---- a kit's warning ----

    @Test
    fun theShortKitWarningIsDrawnFromTheKitsFilledLine() {
        val api = FakeScenes.desktopAt(FakeScene.FIRST_RUN)
        val m = model(api)
        val dee = api.script.publicInstance.addAccount("dee@example.com", pw)
        m.act { entry.openSignIn(on(api)) }
        m.act { entry.openForgot(on(api)) }
        m.act { entry.openKitEntry(on(api)) }
        m.run({ entry.submitKit(on(api), api.script.kitOf(dee), PayloadSource.PASTED) })
        m.run({ entry.confirmKitRecovery(on(api)) })
        m.run({ entry.chooseReplacementPassword(on(api), "a new master password 2") })
        val kit: KitScreen = on<EntryScreen.Kit>(api).kit
        val short = rebuilt(kit, "idleLockAfterMs" to 20_000L, "idleWarnBeforeMs" to 20_000L, "idleWarningLine" to CopyKey.KIT_IDLE_WARNING_SHORT)
        assertEquals(UiText.of(assertNotNull(short.idleWarning)).shown(), kitIdleWarningText(short, CopyKey.KIT_IDLE_WARNING_SHORT).shown())
        assertEquals(UiText.filled(CopyKey.KIT_IDLE_WARNING_SHORT, "20").shown(), kitIdleWarningText(short, CopyKey.KIT_IDLE_WARNING_SHORT).shown())
        val long = assertNotNull(kit.idleWarningLine)
        assertEquals(UiText.of(assertNotNull(kit.idleWarning)).shown(), kitIdleWarningText(kit, long).shown())
        assertTrue(body("KitScreens.kt", "internal fun KitScreenView(").contains("KitIdleWarningLine(kitIdleWarningText(kit, it))"))
    }
}
