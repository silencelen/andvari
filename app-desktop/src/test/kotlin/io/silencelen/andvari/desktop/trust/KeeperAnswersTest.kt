package io.silencelen.andvari.desktop.trust

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.ImageComposeScene
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.unit.Density
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.KeptStops
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.KitRecoverResult
import io.silencelen.andvari.core.app.KitStep
import io.silencelen.andvari.core.app.LinkDeviceEnd
import io.silencelen.andvari.core.app.LinkPasswordResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.ReplacePasswordResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.fake.FakeAccount
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.client.onboard.AccountOpen
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.client.session.Establishing
import io.silencelen.andvari.desktop.pointerOnlyMoved
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
 * The check of 2026-11-17 (property 5): every result the shared code hands a window after the session keeper refused, or
 * after a change was committed and its session refused, is drawn as itself, and nothing is dropped when the result moves
 * the person to another window. Walked on the shared code's fake, as the other walks are.
 */
class KeeperAnswersTest {
    private val pw = FakeScenes.PASSWORD
    private val newPw = "a brand new master password"
    private val dir = "src/main/kotlin/io/silencelen/andvari/desktop/trust/"
    private fun body(file: String, head: String) = File(dir + file).readText().substringAfter(head).substringBefore("\n}\n")

    private fun at(scene: FakeScene): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(scene)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        m.onSnapshot(api.snapshot)
        return api to m
    }

    /** Ada signed in, her server ended the session, and "Sign in again" opened the journey: her copy is kept here. */
    private fun keptAda(): Pair<FakeDesktopAppApi, TrustModel> {
        val (api, m) = at(FakeScene.VAULTS)
        api.script.sessionEndedByServer()
        m.signInAgain()
        m.onSnapshot(api.snapshot)
        assertNotNull(api.snapshot.keptSignedOut)
        return api to m
    }

    private inline fun <reified T : EntryScreen> on(api: FakeDesktopAppApi): T = assertIs<T>(api.snapshot.entry)

    private fun ada(api: FakeDesktopAppApi): FakeAccount = assertNotNull(api.script.publicInstance.accounts.values.firstOrNull { it.email == FakeScenes.EMAIL })

    private fun draw(m: TrustModel, api: FakeDesktopAppApi) {
        val s = api.snapshot
        val scene = ImageComposeScene(480, 1400, Density(1f)) { MaterialTheme { Surface { s.entry?.let { EntryScreens(m, s, it) } } } }
        try {
            scene.render()
        } finally {
            scene.close()
        }
    }

    /** From the first screen to the new password of a kit recovery of [who]. */
    private fun toNewPassword(api: FakeDesktopAppApi, m: TrustModel, who: FakeAccount): EntryScreen.ReplacePassword {
        m.act { entry.openSignIn(on(api)) }
        m.act { entry.openForgot(on(api)) }
        m.act { entry.openKitEntry(on(api)) }
        m.run({ entry.submitKit(on(api), api.script.kitOf(who), PayloadSource.PASTED) })
        m.run({ entry.confirmKitRecovery(on(api)) })
        return on(api)
    }

    /**
     * The kit on show is one this computer did not keep: its lines are drawn on the reveal and on the confirm step, the
     * answer is not a bar a later step clears, and only typing it back ends it; then the first screen says the answer
     * again, with its way out. Returns what the first screen said.
     */
    private fun kitKeptUntilTypedBack(api: FakeDesktopAppApi, m: TrustModel, expected: IntentResult, line: CopyKey): TrustModel.Said {
        val shown = on<EntryScreen.Kit>(api).kit
        assertEquals(line, shown.notKeptLine)
        assertEquals(KitStep.REVEAL, shown.step)
        assertNull(m.saidOn(api.snapshot), "the answer stays with the kit, not in a bar that the next step clears")
        assertSame(expected, assertNotNull(m.kitResultOn(api.snapshot), "the answer is kept with the kit").result)
        val lines = notKeptKitLines(shown, m.kitResultOn(api.snapshot), api.snapshot)
        assertEquals(UiText.of(line).shown(), lines.first().shown(), "the shared code's line first")
        assertEquals(UiText.of(assertNotNull(shown.notKeptHoldsLine, "the shared code's line for how long it holds")).shown(), lines[1].shown(), "beside it, how long the kit holds")
        assertEquals(lines.size, lines.map { it.shown() }.distinct().size, "nothing said twice")
        draw(m, api)
        val groups = assertNotNull(api.kit.kitDocument(shown)).groups
        m.act { kit.proceedToConfirm(shown) }
        val confirm = on<EntryScreen.Kit>(api).kit
        assertEquals(KitStep.CONFIRM, confirm.step)
        assertEquals(lines.map { it.shown() }, notKeptKitLines(confirm, m.kitResultOn(api.snapshot), api.snapshot).map { it.shown() }, "the same on the confirm step")
        draw(m, api)
        // A wrong entry keeps the kit and its lines.
        m.run({ kit.confirmKit(confirm, confirm.groupsToType.map { "ZZZZ" }) })
        assertNotNull(m.kitResultOn(api.snapshot), "a wrong entry keeps the kit")
        val again = on<EntryScreen.Kit>(api).kit
        val typed = again.groupsToType.map { groups[it - 1] }
        m.run({ kit.confirmKit(again, typed) })
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
        on<EntryScreen.FirstRun>(api)
        val said = assertNotNull(m.saidOn(api.snapshot), "the answer is said again on the first screen, with its way out")
        assertSame(expected, said.result)
        // In the shared code's line for that moment, never the answer's own sentence, which says to save a kit now gone.
        val why = assertNotNull(KeptStops.lineWithoutKit(expected), "$expected")
        assertEquals(UiText.of(why).shown(), said.text.shown(), "$expected")
        for (gone in listOfNotNull(expected.sentence, line)) assertNotEquals(UiText.of(gone).shown(), said.text.shown(), "$expected")
        val way = wayOutOf(said.result, said.text, api.snapshot)
        if (way != null) assertTrue(way.lines.none { l -> listOfNotNull(expected.sentence, line).any { UiText.of(it).shown() == l.shown() } }, "$expected")
        draw(m, api)
        return said
    }

    @Test
    fun aRecoveryCommittedAndThenRefusedHereShowsItsOwnSentenceAndTheKitUntilItIsTypedBack() {
        for ((reason, expected) in listOf(
            Establishing.ANOTHER_SESSION_KEPT to ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT,
            AccountOpen.SELF_IDENTITY_MISMATCH to ReplacePasswordResult.IDENTITY_FAULT_COMMITTED,
            WireOnboarding.SERVER_KEYS_NOT_KNOWN_HERE to ReplacePasswordResult.SERVER_KEYS_NOT_KNOWN_HERE_COMMITTED,
            Establishing.OPERATOR_ACCOUNT_HELD to ReplacePasswordResult.OPERATOR_ACCOUNT_HELD_COMMITTED,
            Establishing.KEPT_COPY_DAMAGED to ReplacePasswordResult.KEPT_COPY_DAMAGED_COMMITTED,
            "some_other_reason" to ReplacePasswordResult.COMMITTED_NOT_KEPT,
        )) {
            val (api, m) = at(FakeScene.FIRST_RUN)
            val dee = api.script.publicInstance.addAccount("dee@example.com", pw)
            val replace = toNewPassword(api, m, dee)
            api.script.refusedAfterCommit = reason
            m.run({ entry.chooseReplacementPassword(replace, newPw) })
            val line = if (expected === ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT) CopyKey.KIT_RECOVERED_NOT_KEPT else assertNotNull(expected.sentence)
            val said = kitKeptUntilTypedBack(api, m, expected, line)
            // No account is kept here: the first screen says the answer's own words, and offers no sign-out.
            assertNull(wayOutOf(said.result, said.text, api.snapshot), reason)
        }
    }

    @Test
    fun aRegistrationMadeAndThenRefusedHereShowsItsKitUntilItIsTypedBack() {
        val (api, m) = at(FakeScene.CREATE_ACCOUNT)
        api.script.anotherAccountTakenDuringCommit = true
        m.run({ entry.createAccount(on(api), NewAccountInput("cy@example.com", "Cy", newPw, false)) })
        kitKeptUntilTypedBack(api, m, CreateAccountResult.ACCOUNT_MADE_NOT_KEPT, CopyKey.KIT_REGISTERED_NOT_KEPT)
    }

    /**
     * The account was made and a fault of its identity refused its session here: its own sentence with the kit; on the
     * first screen once the kit was typed back, the shared code's reason line for it in place of that sentence.
     */
    @Test
    fun aRegistrationMadeAndRefusedForItsIdentityShowsItsSentenceWithTheKit() {
        val (api, m) = at(FakeScene.CREATE_ACCOUNT)
        api.script.refusedAfterCommit = AccountOpen.SELF_IDENTITY_MISMATCH
        m.run({ entry.createAccount(on(api), NewAccountInput("cy@example.com", "Cy", newPw, false)) })
        val said = kitKeptUntilTypedBack(api, m, CreateAccountResult.ACCOUNT_MADE_IDENTITY_FAULT, CopyKey.KIT_REGISTERED_IDENTITY_FAULT)
        assertEquals(UiText.of(CopyKey.KIT_NOT_HERE_WHY_IDENTITY_FAULT).shown(), said.text.shown())
        assertNull(wayOutOf(said.result, said.text, api.snapshot), "nothing to sign out or remove here")
    }

    /**
     * A recovery committed while another account is kept here: with the kit, the kept account named and the shared code's
     * sentence for the commit; once the kit was typed back, the first screen offers the kept account's sign-out with the
     * shared code's reason line, never the commit's sentence or the kit's line again.
     */
    @Test
    fun aRecoveryCommittedBesideAKeptAccountSaysTheSharedCodesLinesWithTheKitAndAfterIt() {
        val (api, m) = keptAda()
        val replace = toNewPassword(api, m, ada(api))
        api.script.refusedAfterCommit = Establishing.ANOTHER_SESSION_KEPT
        m.run({ entry.chooseReplacementPassword(replace, newPw) })
        val withKit = notKeptKitLines(on<EntryScreen.Kit>(api).kit, m.kitResultOn(api.snapshot), api.snapshot).map { it.shown() }
        assertTrue(withKit.contains(UiText.of(assertNotNull(ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT.sentence)).shown()), "the shared code's sentence with the kit")
        val said = kitKeptUntilTypedBack(api, m, ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT, CopyKey.KIT_RECOVERED_NOT_KEPT)
        val way = assertIs<WayOut.SignOutKept>(wayOutOf(said.result, said.text, api.snapshot))
        assertEquals(
            listOf(keptAccountLine(way.kept).shown(), UiText.of(CopyKey.KIT_NOT_HERE_WHY_ANOTHER_KEPT).shown()), way.lines.map { it.shown() },
            "the kept account named, and why",
        )
    }

    /**
     * Ada's kept copy is damaged and she recovers her account: the commit goes through and the copy refuses the session.
     * The kit is kept until typed back, with no removal offered beside it (the removal is a sign-out, which would take the
     * kit unsaid); the first screen then offers the removal, which says first that this computer cannot count what was
     * not sent, and only its second confirmation removes the copy.
     */
    @Test
    fun aDamagedCopyOffersItsRemovalOnlyOnceTheKitWasTypedBack() {
        val (api, m) = keptAda()
        val replace = toNewPassword(api, m, ada(api))
        api.script.refusedAfterCommit = Establishing.KEPT_COPY_DAMAGED
        m.run({ entry.chooseReplacementPassword(replace, newPw) })
        assertTrue(showsNotKeptKit(api.snapshot))
        assertIs<WayOut.RemoveDamagedCopy>(wayOutOf(ReplacePasswordResult.KEPT_COPY_DAMAGED_COMMITTED, null, api.snapshot))
        val said = kitKeptUntilTypedBack(api, m, ReplacePasswordResult.KEPT_COPY_DAMAGED_COMMITTED, CopyKey.RECOVERY_COMMITTED_KEPT_COPY_DAMAGED)
        removedAfterTwoConfirmations(api, m, said)
        // The kit screen draws the lines only; SaidHere offers the way out nowhere a kept kit is on show.
        assertTrue(body("TrustUi.kt", "internal fun SaidHere(").contains("KeptAccountRefusal(model, s, way, offered = !showsNotKeptKit(s))"))
        assertFalse(body("KitScreens.kt", "internal fun KitScreenView(").contains("KeptAccountRefusal("))
    }

    private fun removedAfterTwoConfirmations(api: FakeDesktopAppApi, m: TrustModel, said: TrustModel.Said) {
        val way = assertIs<WayOut.RemoveDamagedCopy>(wayOutOf(said.result, said.text, api.snapshot))
        assertEquals(Placeholder.KEPT_COPY_REMOVE, assertIs<UiText.Ph>(way.button).placeholder)
        assertEquals(FakeScenes.EMAIL, way.kept.email)
        val ask = SignOutAsk(m, SignOutAct.SignOut) {}
        assertEquals(CopyKey.SIGN_OUT_UNSENT_UNKNOWN, ask.check?.line?.key)
        ask.proceed()
        assertTrue(ask.second)
        assertNotNull(api.snapshot.keptSignedOut, "the first confirmation removes nothing")
        ask.confirmLoss()
        assertNull(api.snapshot.keptSignedOut, "the damaged copy is gone")
        on<EntryScreen.FirstRun>(api)
    }

    /** A damaged copy at a sign-in, at a kit's check and at a device link: its sentence and its removal, in view. */
    @Test
    fun aDamagedCopyIsSaidAsItselfWithItsRemovalWhereverItStops() {
        // The sign-in: said on its screen.
        run {
            val (api, m) = keptAda()
            api.script.keeperRefuses = Establishing.KEPT_COPY_DAMAGED
            m.act { entry.openSignIn(on(api)) }
            m.act { entry.openPasswordSignIn(on(api)) }
            m.run({ entry.choosePublicInstance(on(api)) })
            m.run({ entry.submitSignIn(on(api), FakeScenes.EMAIL, pw) })
            val said = assertNotNull(m.saidOn(api.snapshot))
            assertSame(SignInAnswer.KEPT_COPY_DAMAGED, said.result)
            val way = assertIs<WayOut.RemoveDamagedCopy>(wayOutOf(said.result, said.text, api.snapshot))
            assertEquals(listOf(UiText.of(CopyKey.KEPT_COPY_DAMAGED).shown()), way.lines.map { it.shown() })
            draw(m, api)
            api.script.keeperRefuses = null
            removedAfterTwoConfirmations(api, m, said)
        }
        // The kit's check: the shared code goes back to where the kit is handed in, and the answer is said there.
        run {
            val (api, m) = keptAda()
            api.script.keeperRefuses = Establishing.KEPT_COPY_DAMAGED
            m.act { entry.openSignIn(on(api)) }
            m.act { entry.openForgot(on(api)) }
            m.act { entry.openKitEntry(on(api)) }
            m.run({ entry.submitKit(on(api), api.script.kitOf(ada(api)), PayloadSource.PASTED) })
            val asked = m.placeOf(api.snapshot)
            m.run({ entry.confirmKitRecovery(on(api)) })
            val said = assertNotNull(m.saidOn(api.snapshot), "said where the person now is")
            assertSame(KitRecoverResult.KEPT_COPY_DAMAGED, said.result)
            assertTrue(asked != m.placeOf(api.snapshot) || api.snapshot.entry is EntryScreen.KitRecover)
            assertIs<WayOut.RemoveDamagedCopy>(wayOutOf(said.result, said.text, api.snapshot))
            draw(m, api)
        }
        // A device link: the window that says how it ended offers the removal.
        run {
            val (api, m) = keptAda()
            api.script.keeperRefuses = Establishing.KEPT_COPY_DAMAGED
            m.act { entry.openSignIn(on(api)) }
            m.act { entry.openLinkDevice(on(api)) }
            m.run({ entry.submitDeviceLink(on(api), api.script.deviceLinkFrom(ada(api), "MacBook"), PayloadSource.PASTED) })
            api.script.otherDeviceAnswers()
            api.script.otherDeviceApproves()
            if (api.snapshot.entry is EntryScreen.LinkDevicePassword) m.run({ entry.submitLinkPassword(on(api), pw) })
            val ended = on<EntryScreen.LinkDeviceEnded>(api)
            assertEquals(LinkDeviceEnd.KEPT_COPY_DAMAGED, ended.outcome)
            assertIs<WayOut.RemoveDamagedCopy>(linkEndWayOut(ended, api.snapshot))
            assertTrue(body("LinkAndRecoveryScreens.kt", "internal fun LinkDeviceEndedScreen(").contains("linkEndWayOut(screen, s)?.let { KeptAccountRefusal(model, s, it) }"))
            draw(m, api)
        }
    }

    /** An operator's account held here: its own sentence, and never a sign-out (the desktop never holds one to remove). */
    @Test
    fun anOperatorsAccountHeldHereIsSaidAsThatAndNeverOffersASignOut() {
        val (api, m) = keptAda()
        api.script.keeperRefuses = Establishing.OPERATOR_ACCOUNT_HELD
        m.act { entry.openSignIn(on(api)) }
        m.act { entry.openPasswordSignIn(on(api)) }
        m.run({ entry.choosePublicInstance(on(api)) })
        m.run({ entry.submitSignIn(on(api), FakeScenes.EMAIL, pw) })
        val said = assertNotNull(m.saidOn(api.snapshot))
        assertSame(SignInAnswer.OPERATOR_ACCOUNT_HELD, said.result)
        assertEquals(UiText.of(CopyKey.OPERATOR_ACCOUNT_HELD_HERE).shown(), assertNotNull(said.text).shown())
        assertNull(wayOutOf(said.result, said.text, api.snapshot), "never a sign-out")
        for (r in listOf(SignInAnswer.OPERATOR_ACCOUNT_HELD, LinkPasswordResult.OPERATOR_ACCOUNT_HELD, KitRecoverResult.OPERATOR_ACCOUNT_HELD, ReplacePasswordResult.OPERATOR_ACCOUNT_HELD, ReplacePasswordResult.OPERATOR_ACCOUNT_HELD_COMMITTED, ReplacePasswordResult.NOT_THE_KEPT_ACCOUNT)) {
            assertNull(wayOutOf(r, null, api.snapshot), r.toString())
            assertTrue(isKeeperAnswer(r), r.toString())
        }
        // Where a first screen does show one held here (a phone's case), its removal is offered behind a confirmation.
        val first = body("EntryScreens.kt", "internal fun FirstRunScreen(")
        assertTrue(first.contains("screen.heldAsOperator?.let") && first.contains("HeldOperatorRemoval(model, s, held)"))
        val removal = body("EntryScreens.kt", "private fun HeldOperatorRemoval(")
        assertTrue(removal.contains("held.removeLine") && removal.contains("entry.removeHeldOperatorAccount(held)") && removal.contains("asking = true"))
    }

    /**
     * The request for the operator's help: each stop the shared code puts on its screen is said in place of the stage's
     * line, with its own way out and no other (the check found the request's screen unchanged).
     */
    @Test
    fun theRequestForTheOperatorsHelpSaysEachStopInPlaceOfItsStage() {
        val day = 86_400_000L
        for ((reason, key) in listOf(
            Establishing.OPERATOR_ACCOUNT_HELD to CopyKey.OPERATOR_ACCOUNT_HELD_HERE,
            Establishing.KEPT_COPY_DAMAGED to CopyKey.KEPT_COPY_DAMAGED,
        )) {
            val (api, m) = at(FakeScene.OPERATOR_HELP_HOLDING)
            api.script.advance(7 * day)
            assertTrue(api.script.operatorAnswers(forged = false))
            api.script.keeperRefuses = reason
            m.run({ entry.refreshOperatorHelp(on(api)) })
            val help = on<EntryScreen.OperatorHelp>(api)
            assertEquals(key, operatorHelpStop(help))
            assertNull(operatorHelpWayOut(help, api.snapshot), "no account is kept here to act on")
            // The act is the shared code's (one cause, one way out): the damaged copy's removal; nothing for the held
            // operator account here (the first screen offers its removal).
            val act = if (reason == Establishing.KEPT_COPY_DAMAGED) io.silencelen.andvari.core.app.KeptWayOut.REMOVE_THIS_COPY else io.silencelen.andvari.core.app.KeptWayOut.REMOVE_HELD_OPERATOR_ACCOUNT
            assertEquals(act, help.wayOut)
            draw(m, api)
        }
        val screen = body("LinkAndRecoveryScreens.kt", "internal fun OperatorHelpScreen(")
        assertTrue(screen.contains("val stop = operatorHelpStop(screen)") && screen.contains("operatorHelpWayOut(screen, s)?.let { KeptAccountRefusal(model, s, it) }"))
        assertTrue(screen.indexOf("Say(operatorHelpStageLine(screen))") in 0 until screen.indexOf("Say(UiText.of(stop)"), "the stop in place of the stage's line")
        // With an account kept, the way out is exactly the shared code's act for the screen's stop.
        val keptSnap = keptAda().first.snapshot
        for ((reason, want) in listOf(Establishing.KEPT_COPY_DAMAGED to WayOut.RemoveDamagedCopy::class, Establishing.OPERATOR_ACCOUNT_HELD to null)) {
            val (api, m) = at(FakeScene.OPERATOR_HELP_HOLDING)
            api.script.advance(7 * day)
            assertTrue(api.script.operatorAnswers(forged = false))
            api.script.keeperRefuses = reason
            m.run({ entry.refreshOperatorHelp(on(api)) })
            val way = operatorHelpWayOut(on(api), keptSnap)
            if (want == null) assertNull(way, "$reason") else assertTrue(want.isInstance(way), "$reason")
        }
    }

    /**
     * A refusal after the two-step code is said as itself, never as a wrong password. On a refusal that leaves the screen
     * asking for a code although the step's password is used up (the keeper's own refusal after the code, here), the
     * desktop asks for the password again rather than a code that could only be refused as stale; the password typed
     * again asks for a new code, which goes through.
     */
    @Test
    fun aCodeThatUsedUpTheStepAsksForThePasswordAgainNotAnotherCode() {
        val (api, m) = at(FakeScene.SIGN_IN_CODE_NEEDED)
        val ada = ada(api)
        // A wrong code: its own sentence, back to the password.
        m.run({ entry.submitSignInCode(on(api), "000000") })
        val refused = assertNotNull(m.saidOn(api.snapshot))
        assertSame(SignInAnswer.REFUSED_AFTER_CODE, refused.result)
        assertEquals(UiText.of(CopyKey.SIGN_IN_REFUSED_AFTER_CODE).shown(), assertNotNull(refused.text).shown())
        assertTrue(codeStepSpent(SignInAnswer.REFUSED_AFTER_CODE))
        assertFalse(signInAsksCode(on(api), codeSpent = true))
        // The password again, then a code the keeper refuses after it: the step is used up.
        m.run({ entry.submitSignIn(on(api), FakeScenes.EMAIL, pw) })
        assertTrue(on<EntryScreen.SignIn>(api).codeNeeded)
        api.script.keeperRefuses = Establishing.KEPT_COPY_DAMAGED
        var answer: SignInAnswer? = null
        m.run({ entry.submitSignInCode(on(api), assertNotNull(ada.twoStepCode)) }) { answer = it }
        assertSame(SignInAnswer.KEPT_COPY_DAMAGED, answer)
        assertTrue(codeStepSpent(assertNotNull(answer)))
        assertFalse(signInAsksCode(on(api), codeSpent = true), "the password is asked, whatever the screen still says")
        api.script.keeperRefuses = null
        // The password typed again on that same screen asks for a new code, which goes through.
        var again: SignInAnswer? = null
        m.run({ entry.submitSignIn(on(api), FakeScenes.EMAIL, pw) }) { again = it }
        assertSame(SignInAnswer.CODE_NEEDED, again)
        assertFalse(codeStepSpent(SignInAnswer.CODE_NEEDED))
        m.run({ entry.submitSignInCode(on(api), assertNotNull(ada.twoStepCode)) })
        assertFalse(api.snapshot.entry is EntryScreen.SignIn, "signed in")
        val screen = body("AccountEntryScreens.kt", "internal fun SignInScreen(")
        assertTrue(screen.contains("if (!signInAsksCode(screen, codeSpent))") && screen.contains("codeSpent = codeStepSpent(it)"))
    }

    /**
     * A code the server refused at a device link's pickup while the link's time runs leaves the link open: the shared
     * code's own sentence (never "wrong password", never the link's end), the password window again with its code field
     * emptied, and the password and the current code typed again go through. (Until the app interface's later set, such
     * a refusal ended the link with [LinkDeviceEnd.REFUSED_AFTER_CODE].)
     */
    @Test
    fun aDeviceLinkRefusedAfterItsCodeEndsWithItsOwnSentence() {
        val (api, m) = at(FakeScene.FIRST_RUN)
        val eve = api.script.publicInstance.addAccount("eve@example.com", pw)
        eve.twoStepCode = "135790"
        m.act { entry.openSignIn(on(api)) }
        m.act { entry.openLinkDevice(on(api)) }
        m.run({ entry.submitDeviceLink(on(api), api.script.deviceLinkFrom(eve, "MacBook"), PayloadSource.PASTED) })
        api.script.otherDeviceAnswers()
        api.script.otherDeviceApproves()
        m.run({ entry.submitLinkPassword(on(api), pw) })
        assertTrue(on<EntryScreen.LinkDevicePassword>(api).codeNeeded)
        var answer: LinkPasswordResult? = null
        m.run({ entry.submitLinkCode(on(api), "000000") }) { answer = it }
        assertSame(LinkPasswordResult.CODE_REFUSED_LINK_STAYS, answer)
        // The link stays: its password window, at the password, with the shared code's sentence under it.
        assertFalse(on<EntryScreen.LinkDevicePassword>(api).codeNeeded, "the password window again, not another code")
        val said = assertNotNull(m.saidOn(api.snapshot), "said on the link's password window")
        assertEquals(UiText.of(CopyKey.DEVICE_LINK_CODE_REFUSED_LINK_STAYS).shown(), assertNotNull(said.text).shown())
        assertFalse(said.text.shown() == UiText.of(CopyKey.DEVICE_LINK_REFUSED_AFTER_CODE).shown())
        draw(m, api)
        // The password and the current code again: the link goes through.
        m.run({ entry.submitLinkPassword(on(api), pw) })
        assertTrue(on<EntryScreen.LinkDevicePassword>(api).codeNeeded)
        m.run({ entry.submitLinkCode(on(api), "135790") })
        assertFalse(api.snapshot.entry is EntryScreen.LinkDevicePassword || api.snapshot.entry is EntryScreen.LinkDeviceEnded, "linked")
        // The window empties the code it sent, whatever the answer (the field the person typed into).
        val screen = body("LinkAndRecoveryScreens.kt", "internal fun LinkDevicePasswordScreen(")
        assertTrue(screen.contains("model.run({ entry.submitLinkCode(screen, code.trim()) }) { code = \"\" }"))
    }

    /** The fake, with each call of [lock] counted: the fake has no wipe of its own to show that the lock came. */
    private class CountedLocks(val fake: FakeDesktopAppApi) : io.silencelen.andvari.core.app.DesktopAppApi by fake {
        var locks = 0
        override fun lock() {
            locks++
            fake.lock()
        }
    }

    /**
     * The rules of 2026-11-17 (a kit of a committed change never survives a lock; the kit screen's idle limit): on a kit
     * shown with this computer's refusal the shared code sets the limit ([io.silencelen.andvari.core.app.KitScreen.idleLockAfterMs])
     * and the warning ([io.silencelen.andvari.core.app.KitScreen.idleWarningLine], [io.silencelen.andvari.core.app.KitScreen.idleWarnBeforeMs]
     * before it). The desktop counts on its one idle clock from the moment the kit comes on show; a click or a key starts
     * the count again and puts the warning away at once; a pointer that only moves does not; a step from the reveal to the
     * confirm keeps counting; at the limit the desktop calls the lock, and the answer kept with the kit goes with it.
     */
    @Test
    fun aKitThisComputerDidNotKeepIsLockedAtTheSharedCodesIdleLimitWithItsWarningFirst() {
        var now = 0L
        val fake = FakeScenes.desktopAt(FakeScene.FIRST_RUN)
        val api = CountedLocks(fake)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { now })
        // The operating system's signals (the taskbar's attention, the alert sound): counted here, as the window's own would be called.
        var signals = 0
        m.kitWarningSignal = KitWarningSignal { signals++ }
        val dee = fake.script.publicInstance.addAccount("dee@example.com", pw)
        val replace = toNewPassword(fake, m, dee)
        fake.script.refusedAfterCommit = Establishing.KEPT_COPY_DAMAGED
        // The window ticks once a second (a tick ten seconds late would lock at once: the computer slept).
        fun tickTo(t: Long) {
            while (now < t) {
                now += 1_000L
                m.tick()
            }
        }
        // Four minutes pass on the new password's screen without a touch: the kit's count starts when it comes on show,
        // not at the last touch before it.
        tickTo(240_000L)
        m.run({ entry.chooseReplacementPassword(replace, newPw) })
        val shown = assertNotNull(kitIdleLimitOf(fake.snapshot), "the shared code's limit is on this kit")
        val limit = assertNotNull(shown.idleLockAfterMs)
        val warnFrom = limit - assertNotNull(shown.idleWarnBeforeMs)
        val warning = assertNotNull(shown.idleWarningLine)
        assertNull(fake.snapshot.account, "no account is open")
        val shownAt = now + 1_000L
        tickTo(shownAt + warnFrom - 1_000L)
        assertNull(m.kitIdleWarning.value)
        assertEquals(0, api.locks)
        assertEquals(0, signals, "nothing is asked before the warning")
        tickTo(shownAt + warnFrom)
        assertEquals(warning, m.kitIdleWarning.value, "the shared code's line, its own time before the limit")
        assertEquals(1, signals, "asked the moment the warning comes")
        // The kit's screen draws the line, and the line takes the focus (the window has it here).
        assertEquals(listOf(UiText.of(warning).shown()), drawnFocus(m, fake), "the warning line, and only it, took the focus")
        // A pointer that only moves over the window is not the person being there.
        m.touched(moved = true)
        assertEquals(warning, m.kitIdleWarning.value)
        // The step to the confirm is the same kit on show: the count goes on.
        m.act { kit.proceedToConfirm(on<EntryScreen.Kit>(fake).kit) }
        assertEquals(KitStep.CONFIRM, on<EntryScreen.Kit>(fake).kit.step)
        tickTo(shownAt + limit - 1_000L)
        assertEquals(0, api.locks, "not before the limit")
        assertNotNull(m.kitResultOn(fake.snapshot), "kept until the limit")
        assertEquals(1, signals, "not again at every tick while the warning stays")
        // A click at the last second: the warning goes at once, and the count starts again.
        m.touched()
        val clickedAt = now
        assertNull(m.kitIdleWarning.value, "a click puts the warning away")
        tickTo(clickedAt + warnFrom - 1_000L)
        assertEquals(1, signals)
        tickTo(clickedAt + warnFrom)
        assertEquals(warning, m.kitIdleWarning.value)
        assertEquals(2, signals, "a new warning after the touch is asked again")
        tickTo(clickedAt + limit - 1_000L)
        assertEquals(0, api.locks)
        tickTo(clickedAt + limit)
        assertEquals(1, api.locks, "the limit locks")
        assertNull(m.kitIdleWarning.value)
        assertEquals(2, signals, "the lock itself asks nothing")
        assertNull(m.kitResultOn(fake.snapshot), "the lock takes the kit's answer with it")
        // The fake's lock now wipes such a kit as the engine's does, and sets the notice that says so.
        assertFalse(showsNotKeptKit(fake.snapshot), "the lock wiped the kit")
        assertNotNull(fake.snapshot.kitWiped, "and the screen it leaves says so")
        // A key counts as the click does (the window's key preview), and a pointer that only moves is told apart.
        val main = File("src/main/kotlin/io/silencelen/andvari/desktop/Main.kt").readText()
        assertTrue(main.contains("onPreviewKeyEvent = {\n            model?.touched()"))
        assertTrue(main.contains("model?.touched(moved = pointerOnlyMoved(e.type))"))
        assertTrue(pointerOnlyMoved(androidx.compose.ui.input.pointer.PointerEventType.Move))
        assertFalse(pointerOnlyMoved(androidx.compose.ui.input.pointer.PointerEventType.Press))
        assertFalse(pointerOnlyMoved(androidx.compose.ui.input.pointer.PointerEventType.Release))
        assertFalse(pointerOnlyMoved(androidx.compose.ui.input.pointer.PointerEventType.Scroll))
    }

    private class WindowFocus(override val isWindowFocused: Boolean) : androidx.compose.ui.platform.WindowInfo

    /** The words of each marked control the focus reached while the entry screen on show was drawn, the window focused. */
    private fun drawnFocus(m: TrustModel, api: FakeDesktopAppApi): List<String> {
        val s = api.snapshot
        val log = ArrayList<String>()
        val scene = ImageComposeScene(480, 1400, Density(1f)) {
            CompositionLocalProvider(LocalFocusLog provides log, androidx.compose.ui.platform.LocalWindowInfo provides WindowFocus(true)) {
                MaterialTheme { Surface { s.entry?.let { EntryScreens(m, s, it) } } }
            }
        }
        try {
            scene.render(0L)
            scene.render(50_000_000L)
        } finally {
            scene.close()
        }
        return log
    }

    /**
     * An ordinary kit in the journey (its account's keys are open) has its limit and its warning from the kit itself, as
     * every kit the shared code makes now does (replaces the rule that such a kit had no limit and no warning of its own):
     * the warning at its own time before the limit, the operating system asked once, a moving pointer not counted, and the
     * lock at the kit's limit.
     */
    @Test
    fun anOrdinaryKitLocksAtItsOwnLimitWithItsWarningFirst() {
        var now = 0L
        val fake = FakeScenes.desktopAt(FakeScene.CREATE_ACCOUNT)
        val api = CountedLocks(fake)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { now })
        var signals = 0
        m.kitWarningSignal = KitWarningSignal { signals++ }
        m.run({ entry.createAccount(on(fake), NewAccountInput("cy@example.com", "Cy", newPw, false)) })
        val kit = on<EntryScreen.Kit>(fake).kit
        assertNull(kit.notKeptLine)
        assertSame(kit, kitIdleLimitOf(fake.snapshot), "the kit carries its own limit")
        val limit = assertNotNull(kit.idleLockAfterMs)
        val warnFrom = limit - assertNotNull(kit.idleWarnBeforeMs)
        val warning = assertNotNull(kit.idleWarningLine)
        assertTrue(warnFrom > 0, "a five-minute kit warns before its limit, not from the start")
        assertTrue(m.lockable())
        // The first tick with the kit on show starts its count.
        now += 1_000L
        m.tick()
        val shownAt = now
        while (now < shownAt + warnFrom - 1_000L) {
            now += 1_000L
            m.tick()
            assertNull(m.kitIdleWarning.value)
            if (now == shownAt + warnFrom / 2) m.touched(moved = true)
        }
        assertEquals(0, signals)
        now += 1_000L
        m.tick()
        assertEquals(warning, m.kitIdleWarning.value, "the kit's own warning, its own time before the limit")
        assertEquals(1, signals, "the operating system asked once, the moment the warning comes")
        while (now < shownAt + limit - 1_000L) {
            now += 1_000L
            m.tick()
        }
        assertEquals(0, api.locks, "a moving pointer did not start the count again")
        assertEquals(1, signals, "not again while the warning stays")
        now += 1_000L
        m.tick()
        assertEquals(1, api.locks, "the kit's limit, counted from its showing")
        assertEquals(1, signals, "the lock itself asks nothing")
    }

    /** Each committed recovery the keeper refused is one of its answers, so it is said where the person is. */
    @Test
    fun everyCommittedRefusalIsAKeeperAnswer() {
        for (r in ReplacePasswordResult.entries.filter { it.name.endsWith("_COMMITTED") || it.name == "COMMITTED_NOT_KEPT" }) assertTrue(isKeeperAnswer(r), r.name)
        assertTrue(isKeeperAnswer(CreateAccountResult.ACCOUNT_MADE_NOT_KEPT))
        assertFalse(isKeeperAnswer(KitConfirmResult.DONE))
        assertFalse(isKeeperAnswer(SignInAnswer.WRONG))
    }
}
