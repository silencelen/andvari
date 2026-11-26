package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.LinkDeviceEnd
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.ReplacePasswordResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Every result the shared code can now hand a screen is drawn as itself (check A17, property 5): a recovery or a
 * registration the server took while this phone refused the session shows its sentence and its new kit until the kit is
 * typed back, then says it again on the first screen; a stop before the commit is said where the person lands; each of
 * the keeper's own reasons offers its own way out; a two-step code the shared code already used gives way to the way
 * back; and the side that answered a link is offered the comparison.
 */
class RefusalsDrawnTest {
    private val newPassword = "a brand new master password"
    private val damaged = "kept_copy_damaged"
    private val held = "operator_account_held"

    private fun at(scene: FakeScene, clock: () -> Long = { 0L }): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, clock)
        m.onSnapshot(api.snapshot)
        return api to m
    }

    private inline fun <reified S : EntryScreen> FakeAppApi.on(): S = assertIs<S>(snapshot.entry)

    private fun TrustModel.go(api: FakeAppApi, block: suspend io.silencelen.andvari.core.app.AppApi.() -> io.silencelen.andvari.core.app.IntentResult) {
        run(block)
        onSnapshot(api.snapshot)
    }

    /** The screen on show, of the kind [S], handed to the intent [block] as the screens do. */
    private inline fun <reified S : EntryScreen> TrustModel.on(api: FakeAppApi, crossinline block: suspend io.silencelen.andvari.core.app.AppApi.(S) -> io.silencelen.andvari.core.app.IntentResult) {
        val screen = api.on<S>()
        go(api) { block(screen) }
    }

    private fun TrustModel.choose(api: FakeAppApi, password: String) =
        on<EntryScreen.ReplacePassword>(api) { entry.chooseReplacementPassword(it, password) }

    /** Types the kit on show back, as the confirm step asks, through the model; the journey then leaves the kit. */
    private fun typeBack(api: FakeAppApi, m: TrustModel) {
        val reveal = api.on<EntryScreen.Kit>().kit
        val doc = assertNotNull(api.kit.kitDocument(reveal))
        m.act { kit.proceedToConfirm(reveal) }
        m.onSnapshot(api.snapshot)
        val confirm = api.on<EntryScreen.Kit>().kit
        assertNotNull(m.kitRefusal.value ?: Unit, "the refusal stays beside the kit on its confirm step")
        assertEquals(kitRefusalLines(reveal, m.kitRefusal.value).map { it.shown() }, kitRefusalLines(confirm, m.kitRefusal.value).map { it.shown() }, "the same lines on every step")
        m.go(api) { kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }) }
    }

    @Test
    fun aRecoveryCommittedAndRefusedHereShowsItsSentenceAndKitUntilTypedBackThenSaysItOnTheFirstScreen() {
        val cases = listOf(
            "self_identity_mismatch" to ReplacePasswordResult.IDENTITY_FAULT_COMMITTED,
            "server_keys_not_known_here" to ReplacePasswordResult.SERVER_KEYS_NOT_KNOWN_HERE_COMMITTED,
        )
        for ((reason, expected) in cases) {
            val (api, m) = at(FakeScene.REPLACE_PASSWORD)
            api.script.refusedAfterCommit = reason
            m.choose(api, newPassword)
            val kit = api.on<EntryScreen.Kit>().kit
            assertEquals(KitReason.AFTER_RECOVERY, kit.reason)
            val refusal = assertNotNull(m.kitRefusal.value, reason)
            assertEquals(expected, refusal.result)
            val lines = kitRefusalLines(kit, refusal)
            // The result's own sentence is the kit's line here: said once, with how long the kit holds.
            val holds = UiText.of(assertNotNull(kit.notKeptHoldsLine, "the shared code's line for how long the kit holds")).shown()
            assertEquals(listOf(UiText.of(assertNotNull(expected.sentence)).shown(), holds), lines.map { it.shown() }, "how long the kit holds, last")
            assertNull(m.saidOn(api.snapshot), "nothing under the kit's top, so no way out is offered over the kit")
            assertNotNull(api.kit.kitDocument(kit), "the new kit is on show")

            typeBack(api, m)
            assertIs<EntryScreen.FirstRun>(api.snapshot.entry, reason)
            assertEquals(AppPhase.ENTRY, api.snapshot.phase, "nothing of the account opens here")
            val said = assertNotNull(m.saidOn(api.snapshot), "the first screen says it again: $reason")
            assertEquals(expected, said.result)
            // No kit is left: the shared code's reason line in place of the sentence that says to save the kit now.
            val why = assertNotNull(io.silencelen.andvari.core.app.KeptStops.lineWithoutKit(expected), reason)
            assertEquals(UiText.of(why).shown(), said.text.shown())
            assertNull(m.kitRefusal.value)
        }
    }

    @Test
    fun aRecoveryWhoseSessionAnotherAccountTookShowsTheKeptAccountsWordsBesideTheKit() {
        val (api, m) = at(FakeScene.REPLACE_PASSWORD)
        api.script.anotherAccountTakenDuringCommit = true
        m.choose(api, newPassword)
        val kit = api.on<EntryScreen.Kit>().kit
        assertEquals(CopyKey.KIT_RECOVERED_NOT_KEPT, kit.notKeptLine)
        val refusal = assertNotNull(m.kitRefusal.value)
        assertEquals(ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT, refusal.result)
        assertEquals(Placeholder.KEPT_ACCOUNT_PASSWORD_IN_FORCE, assertIs<UiText.Ph>(refusal.text).placeholder, "the new password is in force, said beside the kit")
        val lines = kitRefusalLines(kit, refusal).map { it.shown() }
        assertEquals(UiText.of(CopyKey.KIT_RECOVERED_NOT_KEPT).shown(), lines.first())
        assertEquals(3, lines.size)
        typeBack(api, m)
        val said = assertNotNull(m.saidOn(api.snapshot))
        // No kit is left: the shared code's reason line, not the result's sentence (which says to save the kit now).
        assertEquals(UiText.of(CopyKey.KIT_NOT_HERE_WHY_ANOTHER_KEPT).shown(), said.text.shown())
        assertEquals(io.silencelen.andvari.core.app.KeptStops.lineWithoutKit(assertNotNull(said.result)),CopyKey.KIT_NOT_HERE_WHY_ANOTHER_KEPT)
        assertEquals(WayOut.KEPT_SIGN_OUT, wayOutFor(said.result), "the first screen offers the kept account's sign-out where one is kept")
    }

    @Test
    fun aRegistrationTheServerTookWhileThisPhoneRefusedTheSessionShowsItsFirstKit() {
        val (api, m) = at(FakeScene.CREATE_ACCOUNT)
        api.script.anotherAccountTakenDuringCommit = true
        m.on<EntryScreen.CreateAccount>(api) { entry.createAccount(it, NewAccountInput("", "Ada", newPassword, true)) }
        val kit = api.on<EntryScreen.Kit>().kit
        assertEquals(KitReason.FIRST_KIT, kit.reason)
        val refusal = assertNotNull(m.kitRefusal.value)
        assertEquals(CreateAccountResult.ACCOUNT_MADE_NOT_KEPT, refusal.result)
        assertNull(refusal.text, "its sentence is the kit's line: said once")
        assertEquals(UiText.of(CopyKey.KIT_REGISTERED_NOT_KEPT).shown(), kitRefusalLines(kit, refusal).first().shown())
        typeBack(api, m)
        val said = assertNotNull(m.saidOn(api.snapshot))
        assertEquals(CreateAccountResult.ACCOUNT_MADE_NOT_KEPT, said.result)
        assertEquals(UiText.of(CopyKey.KIT_NOT_HERE_WHY_ANOTHER_KEPT).shown(), said.text.shown(), "the reason line once the kit is typed back")
        assertEquals(WayOut.KEPT_SIGN_OUT, wayOutFor(CreateAccountResult.ACCOUNT_MADE_NOT_KEPT))
    }

    @Test
    fun aKitWithNoRefusalHasNoLinesAndTheKitScreenDrawsThem() {
        val (api, m) = at(FakeScene.KIT_REVEAL)
        assertTrue(kitRefusalLines(api.on<EntryScreen.Kit>().kit, m.kitRefusal.value).isEmpty())
        val src = File("src/main/kotlin/io/silencelen/andvari/app/trust/KitScreens.kt").readText()
        assertTrue(src.contains("for (line in kitRefusalLines(kit, refusal)) Say(line,"), "the kit screen draws them on every step")
    }


    @Test
    fun aRecoveryStoppedBeforeItsCommitIsSaidWhereThePersonLands() {
        val (api, m) = at(FakeScene.REPLACE_PASSWORD)
        api.script.anotherAccountTakenBeforeCommit = true
        m.choose(api, newPassword)
        assertTrue(api.snapshot.entry !is EntryScreen.ReplacePassword && api.snapshot.entry !is EntryScreen.Kit)
        val said = assertNotNull(m.saidOn(api.snapshot), "said on the screen the person is back on")
        assertEquals(ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT_NOT_COMMITTED, said.result)
        assertEquals(UiText.of(CopyKey.RECOVERY_ANOTHER_ACCOUNT_KEPT).shown(), said.text.shown())

        // After the operator's help: the request's screen says it itself, in place of its stage, with the sign-out.
        val (help, hm) = at(FakeScene.REPLACE_PASSWORD_AFTER_HELP)
        help.script.anotherAccountTakenBeforeCommit = true
        hm.choose(help, newPassword)
        val screen = help.on<EntryScreen.OperatorHelp>()
        assertNull(hm.saidOn(help.snapshot), "not said twice")
        val stop = assertNotNull(operatorHelpStop(screen))
        assertEquals(CopyKey.ASSIST_ANOTHER_ACCOUNT_KEPT, stop.line)
        assertEquals(WayOut.KEPT_SIGN_OUT, stop.way)
    }

    @Test
    fun theRequestsScreenSaysEachOfTheKeepersReasonsWithItsOwnWayOut() {
        for ((reason, way) in listOf(held to WayOut.HELD_OPERATOR_REMOVAL, damaged to WayOut.COPY_REMOVAL)) {
            val (api, m) = at(FakeScene.OPERATOR_HELP_HOLDING)
            api.script.advance(7L * 24 * 60 * 60 * 1000)
            assertTrue(api.script.operatorAnswers(forged = false))
            api.script.keeperRefuses = reason
            m.on<EntryScreen.OperatorHelp>(api) { entry.refreshOperatorHelp(it) }
            val stop = assertNotNull(operatorHelpStop(api.on()), reason)
            assertEquals(if (reason == held) CopyKey.OPERATOR_ACCOUNT_HELD_HERE else CopyKey.KEPT_COPY_DAMAGED, stop.line)
            assertEquals(way, stop.way)
        }
        val src = File("src/main/kotlin/io/silencelen/andvari/app/trust/LinkAndRecoveryScreens.kt").readText()
        assertTrue(src.contains("val stop = operatorHelpStop(screen)") && src.contains("WayOutOffer(model, s, stop.way)"))
    }

    @Test
    fun anAnswerNamingAnotherAccountAndTheIdentityFaultOfferNoSignOut() {
        assertNull(wayOutFor(ReplacePasswordResult.NOT_THE_KEPT_ACCOUNT))
        assertNull(wayOutFor(ReplacePasswordResult.IDENTITY_FAULT))
        assertNull(wayOutFor(ReplacePasswordResult.IDENTITY_FAULT_COMMITTED))
        assertNull(wayOutFor(SignInAnswer.REFUSED_AFTER_CODE))
        assertTrue(movesWithPerson(ReplacePasswordResult.NOT_THE_KEPT_ACCOUNT))
    }

    /** A damaged copy: its sentence, and the removal of that copy, which says first that it cannot count (its copy is shut). */
    @Test
    fun aDamagedCopyOffersItsRemovalBehindTheCountAndAConfirmation() {
        val (api, m) = at(FakeScene.VAULTS)
        api.script.sessionEndedByServer()
        api.signInAgain(assertNotNull(api.snapshot.locked))
        val kept = assertNotNull(api.snapshot.keptSignedOut)
        api.entry.openSignIn(api.on())
        api.entry.openPasswordSignIn(api.on())
        assertEquals(ServerResult.DONE, runBlocking { api.entry.choosePublicInstance(api.on()) })
        api.script.keeperRefuses = damaged
        m.on<EntryScreen.SignIn>(api) { entry.submitSignIn(it, FakeScenes.EMAIL, FakeScenes.PASSWORD) }
        val said = assertNotNull(m.saidOn(api.snapshot))
        assertEquals(SignInAnswer.KEPT_COPY_DAMAGED, said.result)
        assertEquals(UiText.of(CopyKey.KEPT_COPY_DAMAGED).shown(), said.text.shown())
        assertEquals(WayOut.COPY_REMOVAL, wayOutFor(said.result))
        assertFalse(offersKeptSignOut(api.snapshot, said.result), "a removal, never 'another account is kept'")
        assertEquals(Placeholder.COPY_REMOVE_WARNING, assertIs<UiText.Ph>(copyRemovalWarning(kept)).placeholder)
        val ask = m.signOutAsk()
        ask.open()
        assertEquals(CopyKey.SIGN_OUT_UNSENT_UNKNOWN, assertNotNull(ask.check?.line).key, "it says first that it cannot count")
        ask.confirm()
        assertNotNull(api.snapshot.keptSignedOut, "the first confirmation removes nothing")
        ask.confirm()
        assertNull(api.snapshot.keptSignedOut)
        assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
        for (r in listOf(ReplacePasswordResult.KEPT_COPY_DAMAGED, ReplacePasswordResult.KEPT_COPY_DAMAGED_COMMITTED, io.silencelen.andvari.core.app.KitRecoverResult.KEPT_COPY_DAMAGED)) {
            assertEquals(WayOut.COPY_REMOVAL, wayOutFor(r), r.toString())
        }
        assertEquals(WayOut.COPY_REMOVAL, wayOutFor(LinkDeviceEnd.KEPT_COPY_DAMAGED))
        assertTrue(File("src/main/kotlin/io/silencelen/andvari/app/trust/TrustUi.kt").readText().contains("WayOutOffer(model, s, wayOutFor(said.result))"))
    }

    @Test
    fun aHeldOperatorAccountIsSaidAsItselfAndItsRemovalIsOnTheFirstScreen() {
        val (api, m) = at(FakeScene.SIGN_IN)
        api.script.publicInstance.addAccount("ada@example.com", newPassword)
        api.script.keeperRefuses = held
        m.on<EntryScreen.SignIn>(api) { entry.submitSignIn(it, "ada@example.com", newPassword) }
        val said = assertNotNull(m.saidOn(api.snapshot))
        assertEquals(SignInAnswer.OPERATOR_ACCOUNT_HELD, said.result)
        assertEquals(UiText.of(CopyKey.OPERATOR_ACCOUNT_HELD_HERE).shown(), said.text.shown())
        assertEquals(WayOut.HELD_OPERATOR_REMOVAL, wayOutFor(said.result))
        assertTrue(offersHeldRemoval(api.snapshot))
        m.askRemoveHeldOperator()
        m.onSnapshot(api.snapshot)
        assertIs<EntryScreen.FirstRun>(api.snapshot.entry, "the removal is on the first screen, behind its confirmation")
        assertFalse(offersHeldRemoval(api.snapshot), "the first screen's card offers it there")
        assertEquals(WayOut.HELD_OPERATOR_REMOVAL, wayOutFor(LinkDeviceEnd.OPERATOR_ACCOUNT_HELD))
        assertTrue(File("src/main/kotlin/io/silencelen/andvari/app/trust/EntryScreens.kt").readText().contains("model.removeHeldAsked.collectAsState()"))
    }

    /** The check's loop: a code step whose code the shared code used gives way to the way back, never a field that cannot work. */
    @Test
    fun aTwoStepCodeAnsweredWithAStopGivesWayToTheWayBackInsteadOfALoopOfStaleCodes() {
        val (api, m) = at(FakeScene.SIGN_IN_CODE_NEEDED)
        assertTrue(api.on<EntryScreen.SignIn>().codeNeeded)
        api.script.keeperRefuses = damaged
        m.submitSignInCode(api.on(), "654321")
        m.onSnapshot(api.snapshot)
        val said = assertNotNull(m.saidOn(api.snapshot))
        assertEquals(SignInAnswer.KEPT_COPY_DAMAGED, said.result)
        if (api.on<EntryScreen.SignIn>().codeNeeded) {
            assertTrue(m.signInCodeSpent.value, "the code field gives way")
            // What a second code would meet: the shared code's step is spent.
            api.script.keeperRefuses = null
            assertEquals(SignInAnswer.STALE, runBlocking { api.entry.submitSignInCode(api.on(), "654321") })
            m.act { entry.back() }
            m.onSnapshot(api.snapshot)
            assertFalse(m.signInCodeSpent.value)
        }
        val src = File("src/main/kotlin/io/silencelen/andvari/app/trust/AccountEntryScreens.kt").readText()
        assertTrue(src.contains("model.signInCodeSpent.collectAsState().value") && src.contains("model.submitSignInCode(screen, code.trim())"))

        // A refused code: its own sentence, back at the password, never the wrong-password line.
        val (wrong, wm) = at(FakeScene.SIGN_IN_CODE_NEEDED)
        wm.submitSignInCode(wrong.on(), "000000")
        wm.onSnapshot(wrong.snapshot)
        val refused = assertNotNull(wm.saidOn(wrong.snapshot))
        assertEquals(SignInAnswer.REFUSED_AFTER_CODE, refused.result)
        assertEquals(UiText.of(CopyKey.SIGN_IN_REFUSED_AFTER_CODE).shown(), refused.text.shown())
        assertFalse(wrong.on<EntryScreen.SignIn>().codeNeeded, "back at the password")
        assertFalse(wm.signInCodeSpent.value)
    }

    @Test
    fun theSideThatAnsweredALinkIsOfferedTheComparisonWhereTheSharedCodeSaysSo() {
        val (api, m) = at(FakeScene.VAULTS)
        val me = assertNotNull(api.script.publicInstance.accounts[FakeScenes.EMAIL])
        val cy = me.contacts.first { it.label == "Cy" }
        cy.codesReady = false
        cy.compared = false
        cy.revealWaiting = true
        m.go(api) { contacts.openContacts() }
        val row = assertNotNull(api.snapshot.account?.contacts).contacts.first { it.label == "Cy" }
        assertFalse(row.codesReady)
        assertTrue(row.canCompare)
        assertTrue(offersCompare(row), "the answerer can open the comparison, which waits for the other side's code")
        val src = File("src/main/kotlin/io/silencelen/andvari/app/trust/PeopleScreens.kt").readText()
        assertTrue(src.contains("if (offersCompare(c)) Second("))
        assertFalse(src.contains("c.codesReady && !c.compared"))
    }
}
