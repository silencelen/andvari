package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.OpenedInvite
import io.silencelen.andvari.core.app.SendFirstResult
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
 * No copy on this phone is deleted over changes that were not sent without the person being told how many (rule of
 * 2026-11-17), at every place the phone signs out: Settings, the lock screen, the account its server signed out and the
 * phone kept, and the switch to another server's invitation. Each place, each state, against the fake's switches.
 */
class SignOutUnsentTest {
    private fun at(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(api.snapshot)
        return api to m
    }

    /** A login saved while the server does not answer: one change waits on this phone. */
    private fun FakeAppApi.offlineSave(name: String) {
        val c = assertNotNull(fakeContent)
        c.setOffline(true)
        assertEquals(ActionResult.Ok, runBlocking { c.saveLogin(null, LoginInput(name, "me", "pw-$name", listOf("https://$name.test"), "", "", false), null) })
    }

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    // ---- Settings (unlocked) ----

    @Test
    fun settingsWithNothingWaitingSignsOutAsToday() {
        val (api, m) = at(FakeScene.VAULTS)
        val ask = m.signOutAsk()
        ask.open()
        assertEquals(SignOutAsk.Step.FIRST, ask.step)
        val check = assertNotNull(ask.check)
        assertEquals(0, check.unsentChanges)
        assertNull(check.line, "no line about changes")
        assertNull(check.sendFirstLabel, "nothing to send first")
        ask.confirm()
        assertEquals(AppPhase.ENTRY, api.snapshot.phase, "one confirmation signs out")
        assertEquals(SignOutAsk.Step.CLOSED, ask.step)
    }

    @Test
    fun settingsWithChangesWaitingSaysHowManyAndOnlyTheSecondConfirmationSignsOut() {
        val (api, m) = at(FakeScene.VAULTS)
        api.offlineSave("Bank")
        api.offlineSave("Shop")
        val ask = m.signOutAsk()
        ask.open()
        val line = assertNotNull(ask.check?.line, "the line says how many are lost")
        assertEquals(CopyKey.SIGN_OUT_UNSENT_LOST, line.key)
        assertEquals(listOf("2"), line.values)
        assertEquals(CopyKey.SIGN_OUT_SEND_FIRST, ask.check?.sendFirstLabel?.key, "it offers to send them first")
        ask.confirm()
        assertEquals(SignOutAsk.Step.SECOND, ask.step)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase, "the first confirmation deletes nothing")
        ask.close()
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase, "backing out deletes nothing")

        ask.open()
        ask.confirm()
        ask.confirm()
        assertEquals(AppPhase.ENTRY, api.snapshot.phase, "the second confirmation signs out")
    }

    @Test
    fun sendingFirstThatFailsKeepsEverythingAndStillAsks() {
        val (api, m) = at(FakeScene.VAULTS)
        api.offlineSave("Bank")
        val ask = m.signOutAsk()
        ask.open()
        ask.sendFirst()
        assertEquals(SendFirstResult.NOT_ALL_SENT, ask.sendAnswer)
        assertEquals(CopyKey.SIGN_OUT_SEND_FIRST_FAILED, SendFirstResult.NOT_ALL_SENT.sentence, "said in the confirmation by its sentence")
        assertNotNull(sendAnswerWords(ask.sendAnswer))
        assertEquals(1, ask.check?.unsentChanges, "the check is read again")
        assertEquals(SignOutAsk.Step.FIRST, ask.step)
        assertFalse(ask.sending)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        ask.confirm()
        assertEquals(SignOutAsk.Step.SECOND, ask.step, "still asked twice")
    }

    @Test
    fun sendingFirstThatSucceedsLetsTheOneConfirmationSignOut() {
        val (api, m) = at(FakeScene.VAULTS)
        api.offlineSave("Bank")
        val ask = m.signOutAsk()
        ask.open()
        assertTrue(ask.asksTwice)
        assertNotNull(api.fakeContent).setOffline(false)
        ask.sendFirst()
        assertNull(ask.sendAnswer, "nothing to say: everything was sent")
        assertEquals(0, ask.check?.unsentChanges)
        assertNull(ask.check?.line)
        assertFalse(ask.asksTwice)
        ask.confirm()
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
    }

    @Test
    fun aCheckThatNoLongerHoldsDeletesNothingAndOpensTheConfirmationAgainWithTheNewCount() {
        val (api, m) = at(FakeScene.VAULTS)
        api.offlineSave("Bank")
        val ask = m.signOutAsk()
        ask.open()
        ask.confirm()
        assertEquals(SignOutAsk.Step.SECOND, ask.step)
        api.offlineSave("Mail")
        ask.confirm()
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase, "the shared code refused a check that no longer holds")
        assertEquals(SignOutAsk.Step.FIRST, ask.step, "the first confirmation again")
        assertEquals(listOf("2"), ask.check?.line?.values)
        assertNull(m.said.value, "the confirmation itself says it; nothing else under the screen")
    }

    @Test
    fun aChangeMadeBeforeAOneStepConfirmationIsCaughtTheSameWay() {
        val (api, m) = at(FakeScene.VAULTS)
        val ask = m.signOutAsk()
        ask.open()
        assertFalse(ask.asksTwice)
        api.offlineSave("Bank")
        ask.confirm()
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase, "signOut() refused: a change waits now")
        assertEquals(SignOutAsk.Step.FIRST, ask.step)
        assertEquals(CopyKey.SIGN_OUT_UNSENT_LOST, ask.check?.line?.key)
    }

    // ---- The lock screen ----

    @Test
    fun theLockScreenSaysThisPhoneCannotTellAndStillAsksTwice() {
        val (api, m) = at(FakeScene.VAULTS)
        api.offlineSave("Bank")
        api.lock()
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        val ask = m.signOutAsk()
        ask.open()
        val check = assertNotNull(ask.check)
        assertNull(check.unsentChanges)
        assertEquals(CopyKey.SIGN_OUT_UNSENT_UNKNOWN, check.line?.key)
        assertNull(check.sendFirstLabel, "nothing can be sent while locked")
        ask.sendFirst()
        assertNull(ask.sendAnswer, "send first is not offered, so it does nothing")
        ask.confirm()
        assertEquals(SignOutAsk.Step.SECOND, ask.step)
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        ask.confirm()
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
    }

    @Test
    fun settingsAndTheLockScreenAskThroughTheOneConfirmation() {
        val body = src("AccountScreens.kt").substringAfter("internal fun SignOutButton(").substringBefore("\n}\n")
        assertTrue("model.signOutAsk()" in body && "SignOutConfirm(ask, s," in body)
        assertTrue("signOut()" !in body, "no place calls the sign-out itself")
        assertEquals(2, Regex("SignOutButton\\(model, s\\)").findAll(src("AccountScreens.kt")).count(), "the lock screen and Settings")
        val confirm = src("SignOutConfirm.kt")
        val first = confirm.substringAfter("SignOutAsk.Step.FIRST -> AlertDialog(").substringBefore("SignOutAsk.Step.SECOND ->")
        assertTrue("UnsentLines(ask, s)" in first, "the first confirmation shows the line and send first")
        val second = confirm.substringAfter("internal fun SecondSignOutConfirm(")
        assertTrue("UiText.of(line)" in second && "Placeholder.SIGN_OUT_ALL_THE_SAME" in second && "Placeholder.SWITCH_ALL_THE_SAME" in second)
        // No screen signs out or switches around the confirmation.
        for (f in File("src/main/kotlin/io/silencelen/andvari/app/trust").listFiles()!!.filter { it.name != "TrustModel.kt" }) {
            val code = f.readText()
            assertFalse(Regex("""\{\s*signOut\(\)\s*\}""").containsMatchIn(code), f.name)
            assertFalse("links.switchInstance" in code, f.name)
        }
    }

    // ---- The account its server signed out, kept on this phone ----

    @Test
    fun theKeptAccountCannotBeCountedSoItsSignOutSaysSoAndAsksTwice() {
        val (api, m) = at(FakeScene.VAULTS)
        api.offlineSave("Bank")
        api.script.sessionEndedByServer()
        api.signInAgain(assertNotNull(api.snapshot.locked))
        assertNotNull(api.snapshot.keptSignedOut)
        val ask = m.signOutAsk()
        ask.open()
        assertEquals(CopyKey.SIGN_OUT_UNSENT_UNKNOWN, ask.check?.line?.key)
        assertNull(ask.check?.sendFirstLabel)
        ask.confirm()
        assertEquals(SignOutAsk.Step.SECOND, ask.step)
        ask.close()
        assertNotNull(api.snapshot.keptSignedOut, "backing out keeps the copy")
        ask.open()
        ask.confirm()
        ask.confirm()
        assertNull(api.snapshot.keptSignedOut)
        assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
    }

    // ---- The switch to another server's invitation ----

    @Test
    fun theSwitchWithNothingWaitingGoesAtOnce() {
        val (api, m) = at(FakeScene.OPENED_OTHER_INSTANCE)
        val opened = assertIs<OpenedInvite.OtherInstance>(assertNotNull(api.snapshot.account).opened)
        val ask = m.switchAsk(opened).also { it.open() }
        assertNull(ask.check?.line)
        ask.confirm()
        assertNull(api.snapshot.account, "switched: signed out here")
        assertNotNull(api.snapshot.entry)
    }

    @Test
    fun theSwitchOverChangesWaitingSaysHowManySendsFirstAndAsksASecondTime() {
        val (api, m) = at(FakeScene.OPENED_OTHER_INSTANCE)
        val opened = assertIs<OpenedInvite.OtherInstance>(assertNotNull(api.snapshot.account).opened)
        assertEquals(CopyKey.OTHER_INSTANCE_SIGNS_OUT_LINK_UNKNOWN, opened.signOutLine.key, "the fake's account: whether linking is required is not known")
        api.offlineSave("Bank")
        val ask = m.switchAsk(opened).also { it.open() }
        assertEquals(CopyKey.SIGN_OUT_UNSENT_LOST, ask.check?.line?.key)
        assertEquals(listOf("1"), ask.check?.line?.values)

        ask.sendFirst()
        assertEquals(SendFirstResult.NOT_ALL_SENT, ask.sendAnswer, "still offline")
        ask.confirm()
        assertEquals(SignOutAsk.Step.SECOND, ask.step)
        assertNotNull(api.snapshot.account, "the switch's screen is the first confirmation; nothing is signed out yet")
        ask.back()
        assertEquals(SignOutAsk.Step.FIRST, ask.step, "back to the switch's screen")
        assertNotNull(api.snapshot.account)

        ask.confirm()
        ask.confirm()
        assertNull(api.snapshot.account, "the second confirmation switches")
        assertNotNull(api.snapshot.entry)
    }

    @Test
    fun theSwitchAfterSendingFirstNeedsNoSecondConfirmation() {
        val (api, m) = at(FakeScene.OPENED_OTHER_INSTANCE)
        val opened = assertIs<OpenedInvite.OtherInstance>(assertNotNull(api.snapshot.account).opened)
        api.offlineSave("Bank")
        val ask = m.switchAsk(opened).also { it.open() }
        assertNotNull(api.fakeContent).setOffline(false)
        ask.sendFirst()
        assertFalse(ask.asksTwice)
        ask.confirm()
        assertNull(api.snapshot.account)
    }
}
