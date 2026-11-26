package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.NewAccountInput
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
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * A recovery kit that comes on show while the app is away is never drawn at the return, and a kit in the journey is
 * under the lock clock wherever the person is (the system's print screen, after an unlock from the autofill window).
 *
 * P1, P1b: an independent check's probes of the earlier code, which showed a refusal kit that arrived in the background
 * drawn at the return, uncovered, with a fresh count, and an ordinary one locked only at the first tick after it. Both
 * now end with the lock made as the kit arrives, before any frame of it.
 *
 * The fake plays the engine's lock: a kit of a committed change is wiped and the notice follows. The lock is also seen
 * as the app's call of `lock()` ([EngineLike]) and the cover ([RealEngineKitNoticeTest] over the real implementation).
 */
class KitAwayAndLockClockTest {
    private val newPassword = "a brand new master password"

    private fun main(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/$name").readText()

    private fun at(scene: FakeScene, clock: () -> Long): Triple<FakeAppApi, EngineLike, TrustModel> {
        val fake = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        val api = EngineLike(fake)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, clock)
        m.onSnapshot(api.snapshot)
        return Triple(fake, api, m)
    }

    private fun createAccount(api: EngineLike, m: TrustModel) {
        val screen = assertIs<EntryScreen.CreateAccount>(api.snapshot.entry)
        m.run({ entry.createAccount(screen, NewAccountInput("", "Ada", newPassword, true)) })
    }

    // ---- item 1: a kit that arrives while the app is away ----

    @Test
    fun p1_aRefusalKitArrivingWhileTheAppIsAwayIsLockedAsItArrivesNeverDrawnAtTheReturn() {
        var now = 0L
        val (fake, api, m) = at(FakeScene.CREATE_ACCOUNT) { now }
        fake.script.refusedAfterCommit = "self_identity_mismatch"
        // The person tapped Create, then left before the answer came: the answer arrives in the background.
        m.backgrounded()
        assertEquals(0, api.locks, "nothing to lock on the form")
        now = 1_000
        createAccount(api, m)
        // As the engine: the lock wiped the kit of the committed change, and the notice says so.
        assertIs<EntryScreen.FirstRun>(api.snapshot.entry, "the lock took the kit as it arrived")
        val notice = assertNotNull(api.snapshot.kitWiped, "the kit is said gone")
        // The app told the shared code it was away (backgrounded() calls wentAway()): the kit was never on the screen,
        // and the notice says so with the unseen line.
        assertTrue(notice.unseen)
        assertEquals(CopyKey.KIT_WIPED_UNSEEN_AFTER_REGISTRATION_NOT_HERE, notice.line)
        assertEquals(1, api.locks, "locked as it arrived, while the app was away")
        assertTrue(m.kitCovered.value, "and covered, in case the lock leaves it in place")
        assertFalse(m.keepScreenOn.value)

        // An hour later the person comes back: no frame of a kit, only the notice.
        now += 3_600_000
        m.returnedToForeground()
        m.onSnapshot(api.snapshot)
        assertFalse(api.snapshot.entry is EntryScreen.Kit, "no frame of the kit at the return")
        assertEquals(1, api.locks, "the lock came before the return, not at it")
        assertSame(notice, api.snapshot.kitWiped, "the notice stands until its Close")
        // Nothing is left under the clock.
        m.tick()
        assertEquals(1, api.locks)
        assertNull(m.idleLockDueInMs())
    }

    @Test
    fun p1b_anOrdinaryKitArrivingWhileTheAppIsAwayIsLockedAsItArrivesToo() {
        var now = 0L
        val (_, api, m) = at(FakeScene.CREATE_ACCOUNT) { now }
        m.backgrounded()
        createAccount(api, m)
        assertEquals(1, api.locks, "locked as it arrived, not at the first tick after the return")
        val after = api.snapshot
        assertTrue(after.entry !is EntryScreen.Kit || m.kitCovered.value, "taken by the lock, or covered: ${after.entry}")
        assertNull(m.wentWrong.value, "nothing went wrong on the way")
        now += 3_600_000
        m.returnedToForeground()
        m.onSnapshot(api.snapshot)
        assertTrue(api.snapshot.entry !is EntryScreen.Kit || m.kitCovered.value, "no frame of the kit at the return")
    }

    @Test
    fun aKitArrivingInTheForegroundIsShownAndItsCountStartsAtItsArrivalWithoutAnyFrame() {
        var now = 0L
        val (fake, api, m) = at(FakeScene.CREATE_ACCOUNT) { now }
        fake.script.refusedAfterCommit = "self_identity_mismatch"
        now = 200_000
        createAccount(api, m)
        // No composition and no tick has seen it: the arrival is the model's own subscription's.
        val kit = assertIs<EntryScreen.Kit>(api.snapshot.entry).kit
        val limit = assertNotNull(kit.idleLockAfterMs)
        assertEquals(0, api.locks, "a kit arriving while the app is on show is shown")
        assertFalse(m.kitCovered.value)
        assertEquals(limit, m.idleLockDueInMs(), "its count starts at its arrival")
        now += limit
        m.tick()
        assertEquals(1, api.locks)
    }

    @Test
    fun aKitArrivingAfterAnExcursionOrAFillWindowClosedIsLockedAsItArrives() {
        val (fake, api, m) = at(FakeScene.LOCKED) { 0L }
        // The account's kit was never confirmed: the next unlock makes one (KitReason.NEVER_SAVED).
        fake.script.publicInstance.accounts.values.first().kitSaved = false
        m.wentAway()
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        assertEquals(1, api.locks, "the kit that unlock made was locked away at once")
        assertEquals(AppPhase.LOCKED, api.snapshot.phase, "the lock took the kit and its keys")
    }

    // ---- item 2: the lock clock behind the print screen and after an unlock from the autofill window ----

    @Test
    fun aRefusalKitBehindTheSystemsPrintScreenIsLockedAtItsOwnLimit() {
        var now = 0L
        val (fake, api, m) = at(FakeScene.REPLACE_PASSWORD) { now }
        fake.script.anotherAccountTakenDuringCommit = true
        now = 50_000
        m.run({ entry.chooseReplacementPassword(assertIs(snapshot.entry), newPassword) })
        val kit = assertIs<EntryScreen.Kit>(api.snapshot.entry).kit
        val limit = assertNotNull(kit.idleLockAfterMs)
        // Print: the process stops as an excursion; the hard lock is armed for the kit's own limit.
        m.wentAway()
        assertEquals(limit, m.idleLockDueInMs(), "the hard lock's wait: the kit's own limit, from its arrival")
        now += limit / 2
        assertEquals(limit / 2, m.idleLockDueInMs())
        // The hard lock's check, while the person is still in the print screen or has left from there.
        now += limit / 2
        m.tick()
        assertEquals(1, api.locks, "locked while away: the lock wipes the kit and sets the notice")
    }

    @Test
    fun aNeverSavedKitAnUnlockLeavesInTheJourneyIsLockedAtItsOwnLimitByTheAppsClock() {
        var now = 0L
        val (fake, api, m) = at(FakeScene.LOCKED) { now }
        fake.script.publicInstance.accounts.values.first().kitSaved = false
        // An ordinary unlock of an account whose kit was never saved: the kit is in the journey, in memory, under the clock.
        // (The autofill window no longer takes this road: it unlocks for filling and makes no kit; see
        // AutofillUnlockMakesNoKitTest and SharedTestServerWalksTest.)
        m.touched()
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        val kit = assertIs<EntryScreen.Kit>(api.snapshot.entry, "the unlock made a kit in the journey").kit
        assertEquals(KitReason.NEVER_SAVED, kit.reason)
        // Every kit carries its limit and its warning from the shared code; the app's clock runs from these.
        val limit = assertNotNull(kit.idleLockAfterMs, "the ordinary kit has its limit too")
        assertEquals(minOf(limit, 30_000L), kit.idleWarnBeforeMs)
        assertEquals(limit, m.idleLockDueInMs(), "under the lock clock, at the kit's own limit")
        now = limit - 1
        m.tick()
        assertEquals(0, api.locks)
        now = limit
        assertEquals(0L, m.idleLockDueInMs())
        m.tick()
        assertEquals(1, api.locks)
        assertEquals(AppPhase.LOCKED, api.snapshot.phase, "the lock took the kit and its keys")
        assertNull(m.idleLockDueInMs(), "nothing left under the clock")
    }

    @Test
    fun theHardLockWaitsForWhateverIsUnderTheLockClockNotOnlyAnOpenVault() {
        val hard = main("autofill/ContentFillSession.kt").substringAfter("object HardLock {")
        assertTrue("m.idleLockDueInMs()" in hard, "the hard lock's wait is the model's")
        assertFalse("phase == AppPhase.UNLOCKED" in hard, "not only an open vault")
        val app = main("trust/TrustApp.kt").lines().joinToString("\n") { it.substringBefore("//") }
        assertTrue("if (stop != ProcessStop.LOCK) model.wentAway()" in app, "an excursion or a closing fill window is the app away")
        for (branch in listOf("ProcessStop.EXCURSION -> ", "ProcessStop.HOLD_UNTIL_IDLE -> ")) {
            assertTrue("ContentFillSession.HardLock.arm(appContext)" in app.substringAfter(branch).lineSequence().first(), branch)
        }
        // The autofill window's unlock arms it whatever it opened (DONE with a kit and no open vault included).
        val unlock = main("autofill/AutofillUnlockActivity.kt").substringAfter("private suspend fun unlocked(").substringBefore("if (access !is")
        assertTrue("ContentFillSession.HardLock.arm(applicationContext)" in unlock)
    }

    // ---- item 3: the screen stays on while a kit is on show ----

    @Test
    fun theScreenStaysOnWhileAKitIsOnShowUpToItsLimitAndNotOtherwise() {
        var now = 0L
        val (_, api, m) = at(FakeScene.KIT_REVEAL) { now }
        assertTrue(m.keepScreenOn.value, "a kit on show")
        now = m.autoLockMs() - 1
        m.tick()
        assertTrue(m.keepScreenOn.value, "up to its limit")
        m.backgrounded()
        assertFalse(m.keepScreenOn.value, "not in the background, nor covered")
        m.returnedToForeground()
        m.onSnapshot(api.snapshot)
        if (api.snapshot.entry is EntryScreen.Kit) {
            m.uncoverKit()
            m.touched()
            m.tick()
            assertTrue(m.keepScreenOn.value)
        }

        val (_, vaults, vm) = at(FakeScene.VAULTS) { 0L }
        assertEquals(AppPhase.UNLOCKED, vaults.snapshot.phase)
        assertFalse(vm.keepScreenOn.value, "an open vault without a kit never keeps the screen on")
        vm.tick()
        assertFalse(vm.keepScreenOn.value)
    }

    @Test
    fun theRefusalKitKeepsTheScreenOnUntilItsLimitThenLetsGo() {
        var now = 0L
        val (fake, api, m) = at(FakeScene.REPLACE_PASSWORD) { now }
        fake.script.anotherAccountTakenDuringCommit = true
        m.run({ entry.chooseReplacementPassword(assertIs(snapshot.entry), newPassword) })
        val limit = assertNotNull(assertIs<EntryScreen.Kit>(api.snapshot.entry).kit.idleLockAfterMs)
        assertTrue(m.keepScreenOn.value)
        now = limit - 1
        m.tick()
        assertTrue(m.keepScreenOn.value, "the warning's time included")
        now = limit
        m.tick()
        assertEquals(1, api.locks)
        assertFalse(m.keepScreenOn.value, "the limit ends it, not the phone's timeout")
    }

    @Test
    fun onlyTheKitKeepsTheScreenOnAndItsWarningIsAPoliteLiveRegion() {
        val sources = File("src/main/kotlin").walkTopDown().filter { it.isFile && it.extension == "kt" }
            .filter { f -> f.readLines().any { l -> val code = l.substringBefore("//"); "keepScreenOn" in code || "FLAG_KEEP_SCREEN_ON" in code } }
            .map { it.name }.toSet()
        assertEquals(setOf("TrustApp.kt", "TrustModel.kt"), sources, "the app's only place that keeps the screen on")
        val app = main("trust/TrustApp.kt")
        assertTrue("KeepDisplayOn(model.keepScreenOn.collectAsStateWithLifecycle().value)" in app.substringAfter("fun TrustApp(").substringBefore("\n}\n"))
        val keep = app.substringAfter("internal fun KeepDisplayOn(").substringBefore("\n}\n")
        assertTrue("view.keepScreenOn = on" in keep && "onDispose { view.keepScreenOn = false }" in keep, "and it stops when no kit is on show")
        val view = main("trust/KitScreens.kt").substringAfter("internal fun KitScreenView(").substringBefore("\n}\n")
        val warning = view.lines().first { "kitIdleWarning" in it }
        assertTrue("liveRegion = LiveRegionMode.Polite" in warning, "a screen reader says the warning")
    }
}
