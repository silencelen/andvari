package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.OpenedInvite
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
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
 * No copy on this computer is deleted over changes that were not sent without the person being told how many (the
 * rule of 2026-11-17). Each place that signs out (Settings, the lock screen, an account its server signed out and
 * this computer kept, in the journey and above its open vault, and the invitation for another server, whose switch
 * signs out), in each state: changes waiting, sent first or not, locked (this computer cannot tell), nothing waiting.
 * Lines are named by their keys, so these hold whatever their words are.
 */
class SignOutOverUnsentTest {
    private class At(val api: FakeDesktopAppApi, val m: TrustModel) {
        var closed = 0
        fun ask(): SignOutAsk = SignOutAsk(m, SignOutAct.SignOut) { closed++ }
        fun switch(): SignOutAsk = SignOutAsk(m, SignOutAct.Switch(assertIs<OpenedInvite.OtherInstance>(api.snapshot.account?.opened))) { closed++ }
    }

    private fun at(scene: FakeScene): At {
        val api = FakeScenes.desktopAt(scene)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        m.onSnapshot(api.snapshot)
        return At(api, m)
    }

    /** A login saved while the server does not answer: it waits on this computer. */
    private fun At.savedOffline(name: String) {
        val c = assertNotNull(api.fakeContent)
        c.setOffline(true)
        assertEquals(ActionResult.Ok, runBlocking { c.saveLogin(null, LoginInput(name, "me", "pw-$name", listOf("https://$name.test"), "", "", false), null) })
    }

    private fun At.online() = assertNotNull(api.fakeContent).setOffline(false)

    private fun shownAs(key: CopyKey) = UiText.of(key).shown()

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/$name").readText()
    private fun body(text: String, head: String) = text.substringAfter(head).substringBefore("\n}\n")

    // ---- Settings (the vault open) ----

    @Test
    fun settingsWithNothingWaitingSignsOutAsBefore() {
        val a = at(FakeScene.VAULTS)
        val ask = a.ask()
        assertEquals(0, assertNotNull(ask.check).unsentChanges)
        assertNull(ask.line, "no line when nothing waits")
        assertNull(ask.sendFirstLabel)
        ask.proceed()
        assertFalse(ask.second, "no second confirmation")
        assertEquals(AppPhase.ENTRY, a.api.snapshot.phase)
        assertEquals(1, a.closed)
    }

    @Test
    fun settingsWithChangesWaitingSaysHowManyAndOnlyTheSecondConfirmationSignsOut() {
        val a = at(FakeScene.VAULTS)
        a.savedOffline("Bank")
        a.savedOffline("Shop")
        val ask = a.ask()
        val line = assertNotNull(assertNotNull(ask.check).line)
        assertEquals(CopyKey.SIGN_OUT_UNSENT_LOST, line.key)
        assertEquals(listOf("2"), line.values, "how many are lost")
        assertEquals(UiText.of(line).shown(), assertNotNull(ask.line).shown())
        assertEquals(shownAs(CopyKey.SIGN_OUT_SEND_FIRST), assertNotNull(ask.sendFirstLabel).shown())

        ask.proceed()
        assertTrue(ask.second, "Sign out opens the second confirmation")
        assertEquals(AppPhase.UNLOCKED, a.api.snapshot.phase, "the first confirmation signs nothing out")
        assertEquals(0, a.closed)

        ask.confirmLoss()
        assertEquals(AppPhase.ENTRY, a.api.snapshot.phase)
        assertEquals(1, a.closed)
    }

    @Test
    fun sendingFirstThatFailsSaysSoKeepsEverythingAndStillAsksTwice() {
        val a = at(FakeScene.VAULTS)
        a.savedOffline("Bank")
        val ask = a.ask()
        ask.proceed()
        assertTrue(ask.second)
        ask.sendFirst()
        assertFalse(ask.second, "back to the first confirmation, with the new check")
        assertEquals(shownAs(CopyKey.SIGN_OUT_SEND_FIRST_FAILED), assertNotNull(ask.said).shown())
        assertEquals(1, assertNotNull(ask.check).unsentChanges)
        assertEquals(AppPhase.UNLOCKED, a.api.snapshot.phase)
        ask.proceed()
        assertTrue(ask.second, "still the second confirmation")
        assertEquals(AppPhase.UNLOCKED, a.api.snapshot.phase)
    }

    @Test
    fun sendingFirstThatWorksReadsTheCheckAgainAndThenSignsOutAsBefore() {
        val a = at(FakeScene.VAULTS)
        a.savedOffline("Bank")
        val ask = a.ask()
        a.online()
        ask.sendFirst()
        assertNull(ask.said, "everything was sent")
        assertEquals(0, assertNotNull(ask.check).unsentChanges)
        assertNull(ask.line)
        ask.proceed()
        assertFalse(ask.second)
        assertEquals(AppPhase.ENTRY, a.api.snapshot.phase)
    }

    @Test
    fun aCheckThatNoLongerHoldsIsShownAgainAndNothingIsDeleted() {
        val a = at(FakeScene.VAULTS)
        a.savedOffline("Bank")
        val ask = a.ask()
        ask.proceed()
        a.savedOffline("Mail")
        // The second confirmation was given for one change; two wait now.
        ask.confirmLoss()
        assertEquals(AppPhase.UNLOCKED, a.api.snapshot.phase, "not signed out")
        assertFalse(ask.second)
        assertEquals(listOf("2"), assertNotNull(assertNotNull(ask.check).line).values, "the new count")
        assertEquals(shownAs(CopyKey.UNSENT_NOT_CONFIRMED), assertNotNull(ask.said).shown())
        assertNull(a.m.saidOn(a.api.snapshot), "said in the confirmation, not on the page")
        assertEquals(0, a.closed)
    }

    // ---- the lock screen ----

    @Test
    fun theLockScreenSaysThisComputerCannotTellOffersNoSendingAndStillAsksTwice() {
        val a = at(FakeScene.VAULTS)
        a.savedOffline("Bank")
        a.api.lock()
        a.m.onSnapshot(a.api.snapshot)
        assertEquals(AppPhase.LOCKED, a.api.snapshot.phase)
        val ask = a.ask()
        val check = assertNotNull(ask.check)
        assertNull(check.unsentChanges)
        assertEquals(CopyKey.SIGN_OUT_UNSENT_UNKNOWN, check.line?.key)
        assertNull(ask.sendFirstLabel, "nothing can be sent while locked")
        ask.proceed()
        assertTrue(ask.second)
        assertEquals(AppPhase.LOCKED, a.api.snapshot.phase)
        ask.confirmLoss()
        assertEquals(AppPhase.ENTRY, a.api.snapshot.phase)
        assertEquals(1, a.closed)
    }

    @Test
    fun aLockWhileTheConfirmationIsOpenTurnsItsLineIntoCannotTell() {
        val a = at(FakeScene.VAULTS)
        a.savedOffline("Bank")
        val ask = a.ask()
        assertEquals(CopyKey.SIGN_OUT_UNSENT_LOST, ask.check?.line?.key)
        a.api.lock()
        ask.reread()
        assertEquals(CopyKey.SIGN_OUT_UNSENT_UNKNOWN, ask.check?.line?.key)
        assertNull(ask.sendFirstLabel)
    }

    // ---- an account its server signed out, kept on this computer ----

    @Test
    fun aKeptAccountOnTheLockScreenCannotBeCountedAndAboveItsOpenCopySaysHowManyAndCannotSendThem() {
        val a = at(FakeScene.VAULTS)
        a.savedOffline("Bank")
        a.api.script.sessionEndedByServer()
        a.m.onSnapshot(a.api.snapshot)
        // The server's end, on the lock screen (its card offers Sign out there): this computer cannot tell.
        assertEquals(AppPhase.LOCKED, a.api.snapshot.phase)
        val onLock = a.ask()
        assertEquals(CopyKey.SIGN_OUT_UNSENT_UNKNOWN, onLock.check?.line?.key)
        assertNull(onLock.sendFirstLabel)
        // The copy opened read-only, a change made while nothing answers: it is counted, and cannot be sent.
        a.m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        a.m.onSnapshot(a.api.snapshot)
        assertTrue(a.api.snapshot.account?.signedOutByServer == true)
        val ask = a.ask()
        assertEquals(CopyKey.SIGN_OUT_UNSENT_LOST, ask.check?.line?.key)
        assertEquals(listOf("1"), ask.check?.line?.values)
        assertNull(ask.sendFirstLabel, "the server ended the session: nothing can be sent")
        ask.proceed()
        assertTrue(ask.second)
        ask.confirmLoss()
        assertEquals(AppPhase.ENTRY, a.api.snapshot.phase)
        assertNull(a.api.snapshot.keptSignedOut)
    }

    @Test
    fun aKeptAccountInTheJourneyCannotBeCountedAndIsSignedOutOnlyByTheSecondConfirmation() {
        val a = at(FakeScene.VAULTS)
        a.api.script.sessionEndedByServer()
        a.m.signInAgain()
        assertEquals(AppPhase.ENTRY, a.api.snapshot.phase)
        assertNotNull(a.api.snapshot.keptSignedOut)
        val ask = a.ask()
        assertTrue(assertNotNull(ask.check).needsConfirmation)
        assertEquals(CopyKey.SIGN_OUT_UNSENT_UNKNOWN, ask.check?.line?.key)
        assertNull(ask.sendFirstLabel)
        ask.proceed()
        assertNotNull(a.api.snapshot.keptSignedOut, "the first confirmation deletes nothing")
        ask.confirmLoss()
        assertNull(a.api.snapshot.keptSignedOut)
        assertIs<EntryScreen.FirstRun>(a.api.snapshot.entry)
    }

    // ---- the invitation for another server ----

    @Test
    fun theSwitchWithNothingWaitingGoesAsBefore() {
        val a = at(FakeScene.OPENED_OTHER_INSTANCE)
        val other = assertIs<OpenedInvite.OtherInstance>(a.api.snapshot.account?.opened).inviteInstance.origin
        val ask = a.switch()
        assertNull(ask.line)
        ask.proceed()
        assertFalse(ask.second)
        assertEquals(AppPhase.ENTRY, a.api.snapshot.phase)
        assertEquals(other, a.api.snapshot.instance?.label?.origin)
    }

    @Test
    fun theSwitchOverChangesWaitingSaysHowManySendsFirstAndGoesOnlyOnTheSecondConfirmation() {
        val a = at(FakeScene.OPENED_OTHER_INSTANCE)
        a.savedOffline("Bank")
        val ask = a.switch()
        assertEquals(CopyKey.SIGN_OUT_UNSENT_LOST, ask.check?.line?.key)
        assertEquals(listOf("1"), ask.check?.line?.values)
        assertNotNull(ask.sendFirstLabel)
        ask.proceed()
        assertTrue(ask.second)
        // The second confirmation's way out goes back to the window; the invitation stays.
        ask.back()
        assertFalse(ask.second)
        assertIs<OpenedInvite.OtherInstance>(a.api.snapshot.account?.opened)
        ask.sendFirst()
        assertEquals(shownAs(CopyKey.SIGN_OUT_SEND_FIRST_FAILED), assertNotNull(ask.said).shown())
        ask.proceed()
        ask.confirmLoss()
        assertEquals(AppPhase.ENTRY, a.api.snapshot.phase, "switched over what was lost")
    }

    @Test
    fun theSwitchAfterSendingFirstNeedsNoSecondConfirmation() {
        val a = at(FakeScene.OPENED_OTHER_INSTANCE)
        a.savedOffline("Bank")
        val ask = a.switch()
        a.online()
        ask.sendFirst()
        assertNull(ask.line)
        ask.proceed()
        assertFalse(ask.second)
        assertEquals(AppPhase.ENTRY, a.api.snapshot.phase)
    }

    @Test
    fun aSwitchCheckThatNoLongerHoldsIsShownAgainInTheWindow() {
        val a = at(FakeScene.OPENED_OTHER_INSTANCE)
        a.savedOffline("Bank")
        val ask = a.switch()
        ask.proceed()
        a.savedOffline("Mail")
        ask.confirmLoss()
        assertEquals(AppPhase.UNLOCKED, a.api.snapshot.phase)
        assertEquals(listOf("2"), ask.check?.line?.values)
        // The person asked to switch servers: the line of the switch, never the sign-out's "you're still signed in".
        assertEquals(UiText.ph(Placeholder.SWITCH_UNSENT_NOT_CONFIRMED).shown(), assertNotNull(ask.said).shown())
        assertIs<OpenedInvite.OtherInstance>(a.api.snapshot.account?.opened, "the window stays")
    }

    @Test
    fun theSwitchsLineSaysWhatTheSharedCodeKnowsOfLinkedDevices() {
        val a = at(FakeScene.OPENED_OTHER_INSTANCE)
        fun line() = assertIs<OpenedInvite.OtherInstance>(a.api.snapshot.account?.opened).signOutLine.key
        assertEquals(CopyKey.OTHER_INSTANCE_SIGNS_OUT_LINK_UNKNOWN, line(), "the server serves no read of it")
        a.m.run({ devices.setRequireLink(true, FakeScenes.PASSWORD) })
        assertEquals(CopyKey.OTHER_INSTANCE_SIGNS_OUT_LINK_REQUIRED, line())
        a.m.run({ devices.setRequireLink(false, FakeScenes.PASSWORD) })
        assertEquals(CopyKey.OTHER_INSTANCE_SIGNS_OUT, line())
    }

    @Test
    fun eachConfirmationDrawsInEveryState() {
        val waiting = at(FakeScene.OPENED_OTHER_INSTANCE).also { it.savedOffline("Bank") }
        val locked = at(FakeScene.VAULTS).also { it.api.lock() }
        val plain = at(FakeScene.VAULTS)
        val opened = assertIs<OpenedInvite.OtherInstance>(waiting.api.snapshot.account?.opened)
        val screens = listOf<@androidx.compose.runtime.Composable () -> Unit>(
            { SignOutQuestion(waiting.m, null, waiting.api.snapshot) {} },
            { SignOutQuestion(locked.m, null, locked.api.snapshot) {} },
            { SignOutQuestion(plain.m, null, plain.api.snapshot) {} },
            { SecondConfirmation(waiting.ask().also { it.proceed() }, waiting.api.snapshot) {} },
            { SecondConfirmation(waiting.switch().also { it.proceed() }, waiting.api.snapshot) {} },
            { OtherInstanceWindow(waiting.m, waiting.api.snapshot, opened) },
        )
        for (screen in screens) {
            val image = androidx.compose.ui.ImageComposeScene(480, 760, androidx.compose.ui.unit.Density(1f)) {
                androidx.compose.material3.MaterialTheme { androidx.compose.material3.Surface { screen() } }
            }
            try {
                image.render()
            } finally {
                image.close()
            }
        }
    }

    // ---- every place asks through the same confirmation, the way out first ----

    @Test
    fun everyPlaceThatSignsOutAsksThroughTheCheckWithTheWayOutFirst() {
        val accounts = src("AccountScreens.kt")
        assertTrue(body(accounts, "internal fun SignOutButton(").contains("SignOutQuestion(model, null, s)"), "Settings, the lock screen, the server's end above the vault")
        assertTrue(body(src("KeptAccountRefusal.kt"), "internal fun KeptAccountRefusal(").contains("SignOutQuestion(model, way.kept, s)"), "the kept account, and its damaged copy")
        val question = body(src("KeptAccountRefusal.kt"), "internal fun SignOutQuestion(")
        assertTrue(question.contains("SignOutAsk(model, SignOutAct.SignOut, close)") && question.contains("LaunchedEffect(s) { ask.reread() }"), question)
        assertTrue(question.contains("if (ask.second) return SecondConfirmation(ask, s, close)"))
        assertTrue(question.contains("UnsentLines(ask)") && question.contains("ask.proceed()"))
        assertFalse(question.contains("model.signOut()"), "nothing signs out but the check's way")
        assertTrue(question.contains("ConfirmationButtons(UiText.ph(Placeholder.STAY_SIGNED_IN), close, ask, s, UiText.ph(Placeholder.SIGN_OUT))"), question)
        assertFalse(question.contains("dismissButton"), "no second button slot the dialog could stack above the way out")

        val window = body(src("LinksScreens.kt"), "internal fun OtherInstanceWindow(")
        assertTrue(window.contains("SignOutAsk(model, SignOutAct.Switch(opened))") && window.contains("LaunchedEffect(s) { ask.reread() }"), window)
        assertTrue(window.contains("UnsentLines(ask)") && window.contains("ask.proceed()"))
        assertFalse(window.contains("links.switchInstance(opened)"), "the switch goes only through the check")
        assertTrue(window.indexOf("Say(opened.signOutLine") < window.indexOf("UnsentLines(ask)"))
        assertFalse(window.contains("dismissButton"))

        // One row, in order: the way out, sending first, the main action (seen on the display: the dialog's own two
        // slots stacked the main action above the way out once a label wrapped).
        val unsent = src("SignOutOverUnsent.kt")
        val row = body(unsent, "internal fun ConfirmationButtons(")
        assertTrue(row.contains("Row("), row)
        assertTrue(row.indexOf("DialogButton(wayOut") < row.indexOf("ask.sendFirst()") && row.indexOf("ask.sendFirst()") < row.indexOf("DialogButton(main"), row)
        val second = body(unsent, "internal fun SecondConfirmation(")
        assertTrue(second.contains("ConfirmationButtons(") && second.contains("ask.confirmLoss()") && !second.contains("dismissButton"), second)
        assertTrue(second.contains("close, null, s,"), "the second confirmation does not offer sending first again")
    }
}
