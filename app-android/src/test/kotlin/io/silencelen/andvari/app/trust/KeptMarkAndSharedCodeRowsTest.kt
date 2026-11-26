package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppApi
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.LinkDeviceEnd
import io.silencelen.andvari.core.app.LinkPasswordResult
import io.silencelen.andvari.core.app.ReplacePasswordResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
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
import kotlin.test.assertTrue

/**
 * What the app interface's later set hands the app, over the fake where it plays it (the real engine's walks are in
 * [SharedTestServerWalksTest]): the call that tells the shared code the app left the screen, and the order at the return;
 * a session this phone could not confirm, said as that end; the kept account's words for it; the warning drawn from the
 * kit's filled line; a link's refused proof and its too-many end.
 */
class KeptMarkAndSharedCodeRowsTest {
    private fun main(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/$name").readText()

    /** The fake, every call of the three lifecycle calls recorded in order. */
    private class Recording(private val inner: AppApi) : AppApi by inner {
        val calls = ArrayList<String>()
        override fun wentAway() {
            calls += "away"
            inner.wentAway()
        }
        override fun lock() {
            calls += "lock"
            inner.lock()
        }
        override fun returnedToForeground() {
            calls += "back"
            inner.returnedToForeground()
        }
    }

    private fun at(scene: FakeScene, clock: () -> Long = { 0L }): Triple<FakeAppApi, Recording, TrustModel> {
        val fake = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        val api = Recording(fake)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, clock)
        m.onSnapshot(api.snapshot)
        return Triple(fake, api, m)
    }

    /** An unlock of an account whose kit was never saved: the kit in the journey, under the clock at its own limit. */
    private fun kitOnShow(fake: FakeAppApi, api: Recording, m: TrustModel): Long {
        fake.script.publicInstance.accounts.values.first().kitSaved = false
        m.touched()
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        m.onSnapshot(api.snapshot)
        assertEquals(KitReason.NEVER_SAVED, assertIs<EntryScreen.Kit>(api.snapshot.entry).kit.reason)
        return assertNotNull(assertIs<EntryScreen.Kit>(api.snapshot.entry).kit.idleLockAfterMs)
    }

    // ---- the app away, and the order at its return ----

    @Test
    fun everyRoadAwayTellsTheSharedCodeAndTheBackgroundTellsItBeforeItsLock() {
        val (_, api, m) = at(FakeScene.VAULTS)
        // The print screen and an autofill window closing: TrustApp calls model.wentAway() for both.
        m.wentAway()
        assertEquals(listOf("away"), api.calls)
        m.returnedToForeground()
        assertEquals(listOf("away", "back"), api.calls, "nothing due: no lock at the return")
        api.calls.clear()
        // The background that locks: told first, then the lock.
        m.backgrounded()
        assertEquals(listOf("away", "lock"), api.calls)
        // In the app's lifecycle: every stop that does not lock goes through model.wentAway(), the one that locks through
        // backgrounded(); the return through returnedToForeground().
        val app = main("trust/TrustApp.kt").lines().joinToString("\n") { it.substringBefore("//") }
        assertTrue("if (stop != ProcessStop.LOCK) model.wentAway()" in app)
        assertTrue("ProcessStop.LOCK -> model.backgrounded()" in app)
        assertTrue("model.returnedToForeground()" in app)
        val model = main("trust/TrustModel.kt")
        assertTrue("contained { api.wentAway() }" in model.substringAfter("fun wentAway() = contained {").substringBefore("\n    }\n"))
        assertTrue("contained { api.wentAway() }" in model.substringAfter("private fun backgroundedNow() {").substringBefore("\n    }\n"))
    }

    @Test
    fun atTheReturnALockThatFellDueIsMadeBeforeTheSharedCodeIsToldTheAppIsBack() {
        var now = 0L
        val (fake, api, m) = at(FakeScene.LOCKED) { now }
        val limit = kitOnShow(fake, api, m)
        api.calls.clear()
        m.wentAway()
        // The kit's limit passes while the app is away (the phone asleep, behind the print screen).
        now = limit
        m.returnedToForeground()
        assertEquals(listOf("away", "lock", "back"), api.calls, "lock first, then back: a kit never drawn is not said as seen")
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)

        // Before the limit, the return locks nothing.
        val (fake2, api2, m2) = at(FakeScene.LOCKED) { now }
        now = 0L
        kitOnShow(fake2, api2, m2)
        api2.calls.clear()
        m2.wentAway()
        now = 1_000L
        m2.returnedToForeground()
        assertEquals(listOf("away", "back"), api2.calls)
        assertIs<EntryScreen.Kit>(api2.snapshot.entry)
    }

    // ---- the warning from the kit's filled line ----

    @Test
    fun theShortWarningIsDrawnFromTheKitsFilledLineWithItsLimitNeverTheBareKey() {
        var now = 0L
        val (fake, api, m) = at(FakeScene.LOCKED) { now }
        fake.script.publicInstance.autoLockSeconds = 20
        kitOnShow(fake, api, m)
        val kit = assertIs<EntryScreen.Kit>(api.snapshot.entry).kit
        assertEquals(20_000L, kit.idleLockAfterMs)
        assertEquals(CopyKey.KIT_IDLE_WARNING_SHORT, kit.idleWarningLine)
        val filled = assertNotNull(kit.idleWarning)
        assertEquals(listOf("20"), filled.values, "the slot names the limit")
        m.tick()
        val drawn = assertNotNull(m.kitIdleWarning.value, "warned from the start: no thirty seconds are left")
        assertEquals(filled.key, drawn.key)
        assertEquals(filled.values, drawn.values, "the filled line, never the bare key")
        assertEquals(UiText.of(filled).shown(), UiText.of(drawn).shown())
        assertTrue("model.kitIdleWarning.collectAsState().value?.let { Say(UiText.of(it)" in main("trust/KitScreens.kt"))
    }

    // ---- a session this phone could not confirm with its server ----

    @Test
    fun aSessionThisPhoneCouldNotConfirmIsSaidAsThatEndOnTheLockScreenTheFirstScreenAndBesideTheKeptAccount() {
        val (fake, api, _) = at(FakeScene.LOCKED)
        fake.script.sessionEndedByServer()
        val byServer = assertNotNull(api.snapshot.locked)
        assertTrue(byServer.signedOutByServer)
        assertEquals(UiText.ph(Placeholder.SIGNED_OUT_BY_SERVER).shown(), assertNotNull(lockEndLine(byServer)).shown(), "the server's end")
        // The fake does not play the end where no try of a refresh was left: the shared code's own screen, its field set.
        val notConfirmed = StandIns.rebuilt(byServer, "sessionNotConfirmed" to true)
        assertEquals(CopyKey.SESSION_NOT_CONFIRMED, notConfirmed.endLine)
        assertEquals(UiText.of(CopyKey.SESSION_NOT_CONFIRMED).shown(), assertNotNull(lockEndLine(notConfirmed)).shown(), "never 'signed out by its server'")
        val lock = main("trust/AccountScreens.kt").substringAfter("internal fun LockScreen(").substringBefore("\n}\n")
        assertTrue("lockEndLine(locked, signOutWayOutStands(s))?.let" in lock)
        assertFalse("Placeholder.SIGNED_OUT_BY_SERVER)" in lock, "the server's line only through lockEndLine")
        assertTrue("if (locked.signedOutByServer) {\n            Second(UiText.ph(Placeholder.SIGN_IN_AGAIN)" in lock, "the buttons stay as for the server's end")
        // The open copy: its own line in place of the server's.
        assertTrue("model.openedSignedOutByServer(s) -> account.endLine?.let { UiText.of(it) } ?: UiText.ph(Placeholder.SIGNED_OUT_BY_SERVER_OPEN)" in main("trust/AccountScreens.kt"))

        // The first screen after "Sign in again": the shared code's notice is empty, its own field set.
        val first = assertIs<EntryScreen.FirstRun>(FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.FIRST_RUN).snapshot.entry)
        assertNull(sessionNotConfirmedLine(first))
        val after = StandIns.rebuilt(first, "sessionNotConfirmed" to true)
        assertNull(after.notice)
        assertEquals(UiText.of(CopyKey.SESSION_NOT_CONFIRMED).shown(), assertNotNull(sessionNotConfirmedLine(after)).shown())
        val screen = main("trust/EntryScreens.kt").substringAfter("internal fun FirstRunScreen(").substringBefore("\n}\n")
        assertTrue("sessionNotConfirmedLine(screen, signOutWayOutStands(s))?.let { line ->\n            Say(line)\n            Quieter(UiText.ph(Placeholder.DISMISS)) { model.act { entry.dismissNotice(screen) } }" in screen)

        // Beside the kept account on the first screen: its words never say its server signed it out.
        val kept = fake.snapshot.keptSignedOut
        assertEquals(Placeholder.KEPT_ACCOUNT_SIGN_OUT_FIRST, (keptAccountWords(SignUpStartResult.ANOTHER_ACCOUNT_KEPT, kept) as UiText.Ph).placeholder)
        assertEquals(Placeholder.KEPT_ACCOUNT_SIGN_OUT_FIRST_NOT_CONFIRMED, (keptAccountWords(SignUpStartResult.ANOTHER_ACCOUNT_KEPT, kept, notConfirmed = true) as UiText.Ph).placeholder)
        assertEquals(Placeholder.KEPT_ACCOUNT_PASSWORD_IN_FORCE_NOT_CONFIRMED, (keptAccountWords(ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT, kept, notConfirmed = true) as UiText.Ph).placeholder)
        assertTrue("keptAccountWords(r, s.keptSignedOut, s.keptSignedOutNotConfirmed)" in main("trust/TrustModel.kt"))
    }

    // ---- a device link ----

    @Test
    fun aRefusedProofAtALinkKeepsItsPasswordScreenEmptiesTheFieldAndSaysTheSharedCodesSentence() {
        val said = assertNotNull(UiText.forResult(LinkPasswordResult.PROOF_REFUSED, 0))
        assertEquals(UiText.of(CopyKey.LINK_PROOF_REFUSED_TYPE_CURRENT).shown(), said.shown())
        assertTrue(said.shown() != assertNotNull(UiText.forResult(LinkPasswordResult.WRONG, 0)).shown(), "never the wrong password's words")
        val code = assertNotNull(UiText.forResult(LinkPasswordResult.CODE_REFUSED_LINK_STAYS, 0))
        assertEquals(UiText.of(CopyKey.DEVICE_LINK_CODE_REFUSED_LINK_STAYS).shown(), code.shown())
        // The screen is the shared code's (it stays for PROOF_REFUSED); the field is emptied at every answer.
        val screen = main("trust/LinkAndRecoveryScreens.kt").substringAfter("internal fun LinkDevicePasswordScreen(").substringBefore("\n}\n")
        assertTrue("model.run({ entry.submitLinkPassword(screen, typed) }) { password = \"\" }" in screen)
        assertTrue("SaidHere(model, s)" in screen)
    }

    /** A wait in seconds is said as a length of time, never shorter than asked, and as "a while" where none was named. */
    @Test
    fun aWaitInSecondsIsSaidAsALengthOfTime() {
        fun said(seconds: Int): Pair<Placeholder, List<String>> = assertIs<UiText.Ph>(OutcomeWords.waitLength(seconds)).let { it.placeholder to it.args }
        assertEquals(Placeholder.WAIT_A_WHILE to emptyList(), said(0))
        assertEquals(Placeholder.WAIT_ONE_SECOND to emptyList(), said(1))
        assertEquals(Placeholder.WAIT_SECONDS to listOf("42"), said(42))
        assertEquals(Placeholder.WAIT_ONE_MINUTE to emptyList(), said(60))
        assertEquals(Placeholder.WAIT_MINUTES to listOf("2"), said(61), "rounded up: never shorter than the server asked")
        assertEquals(Placeholder.WAIT_MINUTES to listOf("15"), said(900))
        assertEquals(Placeholder.WAIT_ONE_HOUR to emptyList(), said(3600))
        assertEquals(Placeholder.WAIT_HOURS to listOf("3"), said(7201))
        assertEquals(Placeholder.WAIT_HOURS to listOf("24"), said(86_400))
        // The raw number of seconds is never put into the link's line by itself.
        assertNotEquals(UiText.of(CopyKey.DEVICE_LINK_TOO_MANY, "900").shown(), OutcomeWords.linkDeviceEnd(LinkDeviceEnd.TOO_MANY, 900).shown())
    }

    @Test
    fun aLinkEndedAsTooManySaysTheWaitAndTheShowingPhoneSaysItsOwnLine() {
        // The wait as a length of time a person reads ([OutcomeWords.waitLength]), "a while" where none was named.
        val wait42 = OutcomeWords.waitLength(42).shown()
        assertEquals(UiText.of(CopyKey.DEVICE_LINK_TOO_MANY, wait42).shown(), OutcomeWords.linkDeviceEnd(LinkDeviceEnd.TOO_MANY, 42).shown())
        assertEquals(
            UiText.of(CopyKey.DEVICE_LINK_TOO_MANY, UiText.ph(Placeholder.WAIT_A_WHILE).shown()).shown(),
            OutcomeWords.linkDeviceEnd(LinkDeviceEnd.TOO_MANY, 0).shown(),
            "no wait named: a while",
        )
        assertEquals(
            UiText.of(CopyKey.DEVICE_LINK_HOST_TOO_MANY, wait42).shown(),
            assertNotNull(OutcomeWords.tooManyLine(CopyKey.DEVICE_LINK_HOST_TOO_MANY, tooMany = true, retryAfterSeconds = 42)).shown(),
        )
        val ended = main("trust/LinkAndRecoveryScreens.kt").substringAfter("internal fun LinkDeviceEndedScreen(").substringBefore("\n}\n")
        assertTrue("OutcomeWords.linkDeviceEnd(screen.outcome, model.api.retryAfterSeconds())" in ended)
        assertTrue("s.earlierAccount?.let { EarlierAccountOffer(model, s, it) }" in ended, "the forgetting's offer where the snapshot hands it")
        val host = main("trust/DevicesScreens.kt")
        assertTrue("for (line in hostEndedLines(host, model.api.retryAfterSeconds())) Say(line)" in host)
        assertTrue("host.line?.let { listOfNotNull(OutcomeWords.tooManyLine(it, tooMany = true, retryAfterSeconds)) } ?: deviceLinkEndLines(host.outcome)" in host)
    }

    // ---- the forgetting after a deletion of unknown outcome, drawn ----

    @Test
    fun theForgettingAfterAnUnknownDeletionIsDrawnWhereTheOutcomeIsUnknownWithTwoButtonsOfOneWeight() {
        val view = main("trust/EarlierAccountScreens.kt").substringAfter("internal fun ForgetUnknownDeletionOffer(").substringBefore("\n}\n")
        assertEquals(3, Regex("Second\\(").findAll(view).count(), "the offer; at the second step two of the same weight")
        assertFalse(Regex("Main\\(|Button\\(|focusRequester|onKeyEvent|BackHandler").containsMatchIn(view), "none default, focused or bound to a key")
        assertTrue("model.forgetUnknownCheck() ?: return" in view, "read at every drawing")
        assertTrue("if (locked.deletionOutcomeUnknown) ForgetUnknownDeletionOffer(model, s)" in main("trust/AccountScreens.kt"))
        assertTrue("if (screen.deletionOutcomeUnknown != null) ForgetUnknownDeletionOffer(model, s)" in main("trust/EntryScreens.kt"))
        assertTrue("ForgetUnknownDeletionOffer(model, s, DELETION_SECTION)" in main("trust/SettingsScreens.kt"))
        val callers = File("src/main/kotlin").walkTopDown().filter { it.isFile && it.extension == "kt" }
            .flatMap { f -> f.readLines().filter { "forgetAfterUnknownDeletion(" in it }.map { f.name } }.toList()
        assertEquals(listOf("TrustModel.kt"), callers, "one line of the model calls it (said in a section or on the screen)")
    }
}
