package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
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
 * A lock takes a recovery kit shown with a refusal, and the screen says so until the person dismisses it (sections AZ
 * and BL): the shared code's notice above whatever is on show, in every phase, with what stands in the way here; the
 * kit's own idle limit, counted on the app's one timer with the shared code's figures and warning; the kit's line for
 * how long it holds; and the window's protections over all of it.
 *
 * The fake plays the engine's lock (the kit shown with a refusal is wiped and the notice follows): the notices here are
 * the fake's own ([FakeKitNotices]); where one is carried into a scene its walk does not end in, [EngineLike] lays it
 * over that scene's snapshots, and the lock at the limit is seen as the app's call of `lock()`.
 */
class KitWipedAndIdleLimitTest {
    private val newPassword = "a brand new master password"

    private fun main(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/$name").readText()

    private fun at(scene: FakeScene, clock: () -> Long = { 0L }): Triple<FakeAppApi, EngineLike, TrustModel> {
        val fake = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        val api = EngineLike(fake)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, clock)
        m.onSnapshot(api.snapshot)
        return Triple(fake, api, m)
    }

    /** A recovery the server took while another account was kept here meanwhile: its kit on show with the refusal. */
    private fun kitWithRefusal(api: EngineLike, fake: FakeAppApi, m: TrustModel) {
        fake.script.anotherAccountTakenDuringCommit = true
        val screen = assertIs<EntryScreen.ReplacePassword>(api.snapshot.entry)
        m.run({ entry.chooseReplacementPassword(screen, newPassword) })
        m.onSnapshot(api.snapshot)
        assertNotNull(assertIs<EntryScreen.Kit>(api.snapshot.entry).kit.notKeptLine)
    }

    @Test
    fun theNoticeThatAKitIsGoneStandsAboveTheLockScreenTheFirstScreenAndAnOpenVaultUntilTheDismiss() {
        // The lock screen, then (unlocked) the open vault: the same notice, through a lock and an opening.
        val (_, api, m) = at(FakeScene.LOCKED)
        // The notice as the fake's lock makes it, while another account is kept here; carried to the lock screen.
        val notice = FakeKitNotices.afterRecoveryWhileKept()
        assertEquals(CopyKey.KIT_WIPED_AFTER_RECOVERY_NOT_HERE, notice.line)
        assertEquals(CopyKey.KIT_NOT_HERE_WHY_ANOTHER_KEPT, notice.whyHere, "the reason line, never the kit's own")
        api.kitWiped = notice
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        assertEquals(
            listOf(UiText.of(CopyKey.KIT_WIPED_AFTER_RECOVERY_NOT_HERE).shown(), UiText.of(CopyKey.KIT_NOT_HERE_WHY_ANOTHER_KEPT).shown()),
            kitWipedLines(assertNotNull(api.snapshot.kitWiped)).map { it.shown() },
            "the line, then what stands in the way here",
        )
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        assertSame(notice, api.snapshot.kitWiped, "an opening does not take it")
        m.tick()
        m.act { lock() }
        m.onSnapshot(api.snapshot)
        m.backgrounded()
        assertSame(notice, api.snapshot.kitWiped, "nor a lock, nor the background")
        assertTrue(api.dismissed.isEmpty(), "the app never dismisses it by itself")
        m.dismissKitWiped(notice)
        assertEquals(listOf(notice), api.dismissed, "the dismiss hands back the very notice on show")
        assertNull(api.snapshot.kitWiped)

        // The first screen: the plain line where nothing stands in the way here (no second line).
        val (registering, first, fm) = at(FakeScene.CREATE_ACCOUNT)
        val plain = FakeKitNotices.afterRegistration(registering)
        first.refresh()
        fm.onSnapshot(first.snapshot)
        assertIs<EntryScreen.FirstRun>(first.snapshot.entry)
        assertSame(plain, first.snapshot.kitWiped, "the fake's own notice, after its lock")
        assertNull(plain.whyHere)
        assertEquals(listOf(UiText.of(CopyKey.KIT_WIPED_AFTER_REGISTRATION).shown()), kitWipedLines(plain).map { it.shown() })
        fm.dismissKitWiped(plain)
        assertEquals(listOf(plain), first.dismissed)
        assertNull(first.snapshot.kitWiped, "the fake's dismiss took it")

        // Drawn above the phase's screen, outside the choice of screen, so in every phase (and at a start, which the
        // shared code turns into the same notice); the dismiss is its only way out.
        val root = main("trust/TrustApp.kt").substringAfter("fun TrustApp(").substringBefore("\n}\n")
        val drawn = root.indexOf("s.kitWiped?.let { KitWipedNoticeView(model, it) }")
        assertTrue(drawn > 0 && drawn < root.indexOf("when (s.phase)"), "above whatever screen is on show")
        val view = main("trust/TrustApp.kt").substringAfter("internal fun KitWipedNoticeView(").substringBefore("\n}\n")
        assertTrue("Say(UiText.Plain(notice.email)" in view && "kitWipedLines(notice)" in view && "model.dismissKitWiped(notice)" in view)
        val callers = File("src/main/kotlin").walkTopDown().filter { it.isFile && it.extension == "kt" }
            .flatMap { f -> f.readLines().filter { "dismissKitWiped(" in it }.map { f.name to it.trim() } }.toList()
        assertEquals(
            setOf("TrustApp.kt", "TrustModel.kt"),
            callers.map { it.first }.toSet(),
            "nothing else calls the dismiss: $callers",
        )
    }

    @Test
    fun aKitShownWithARefusalLocksAtTheSharedCodesLimitAfterItsWarningCountedFromWhenItCameOnShow() {
        var now = 0L
        val (fake, api, m) = at(FakeScene.REPLACE_PASSWORD) { now }
        // The person spent a while on the new-password screen before the commit: that time is not the kit's.
        now = 200_000
        kitWithRefusal(api, fake, m)
        val kit = assertIs<EntryScreen.Kit>(api.snapshot.entry).kit
        val limit = assertNotNull(kit.idleLockAfterMs, "the shared code's limit for this kit")
        val warnBefore = assertNotNull(kit.idleWarnBeforeMs)
        val shownAt = now

        now = shownAt + limit - warnBefore - 1
        m.tick()
        assertNull(m.kitIdleWarning.value)
        assertEquals(0, api.locks, "the count starts when the kit came on show")
        now += 1
        m.tick()
        assertEquals(assertNotNull(kit.idleWarningLine), m.kitIdleWarning.value?.key, "the shared code's warning, at its time")

        // The step after the reveal is a new screen object: the count goes on, by "a kit is on show".
        m.act { this.kit.proceedToConfirm(kit) }
        m.onSnapshot(api.snapshot)
        assertIs<EntryScreen.Kit>(api.snapshot.entry)
        m.tick()
        assertNotNull(m.kitIdleWarning.value, "still warned on the confirm step")

        // A touch or a key ends the warning and starts the count again.
        m.touched()
        assertNull(m.kitIdleWarning.value)
        val touchedAt = now
        now = touchedAt + limit - 1
        m.tick()
        assertEquals(0, api.locks)
        now = touchedAt + limit
        m.tick()
        assertEquals(1, api.locks, "at the limit the app locks; the lock wipes the kit and sets the notice")
        assertNull(m.kitIdleWarning.value)
    }

    @Test
    fun anOrdinaryKitHasItsOwnLimitAndWarningAndLocksAtIt() {
        var now = 0L
        val (_, api, m) = at(FakeScene.KIT_REVEAL) { now }
        val kit = assertIs<EntryScreen.Kit>(api.snapshot.entry).kit
        assertNull(kit.notKeptLine)
        // Every kit carries its limit: the lock time of the policy kept for its server, five minutes where none is kept.
        val limit = assertNotNull(kit.idleLockAfterMs, "the shared code's limit, for the ordinary kit too")
        assertEquals(300_000L, limit, "no policy kept for this server")
        assertEquals(minOf(limit, 30_000L), kit.idleWarnBeforeMs, "and its warning, thirty seconds before")
        val line = assertNotNull(kit.idleWarningLine)
        assertTrue(m.locksNow(api.snapshot))
        now = limit - 30_000L - 1
        m.tick()
        assertNull(m.kitIdleWarning.value)
        now += 1
        m.tick()
        assertEquals(line, m.kitIdleWarning.value?.key, "the shared code's warning, at its time")
        now = limit - 1
        m.tick()
        assertEquals(0, api.locks)
        now = limit
        m.tick()
        assertEquals(1, api.locks, "at the kit's own limit the app locks")
        assertNull(m.kitIdleWarning.value)
    }

    @Test
    fun theKitsScreenDrawsTheSharedCodesWarningAndHoldsLineAndTypingCountsAsActivity() {
        val kits = main("trust/KitScreens.kt")
        val view = kits.substringAfter("internal fun KitScreenView(").substringBefore("\n}\n")
        assertTrue("model.kitIdleWarning.collectAsState().value?.let { Say(UiText.of(it)" in view, "the shared code's warning line")
        assertTrue("for (line in kitRefusalLines(kit, refusal)) Say(line," in view)
        assertTrue("kit.notKeptHoldsLine?.let { UiText.of(it) }" in kits.substringAfter("internal fun kitRefusalLines("), "the shared code's holds line")
        assertFalse(File("src/main/kotlin/io/silencelen/andvari/app/trust/UiText.kt").readText().contains("KIT_IDLE_WARNING("), "no warning of the app's own any more")
        // The on-screen keyboard reaches no key event of the window: the kit's fields count their typing themselves.
        val confirm = kits.substringAfter("private fun KitConfirm(").substringBefore("\n}\n")
        assertTrue("model.touched()" in confirm)
        assertTrue("model.touched()" in kits.substringAfter("private fun KitNotMade(").substringBefore("\n}\n"))
    }

    @Test
    fun theNoticeAndTheWarningAreDrawnInTheProtectedWindowNeverInAWindowOfTheirOwn() {
        // The whole window is secure (no screenshots, nothing in the recent-apps picture) and nothing clears it; a
        // dialog or a popup would be a window of its own, without the flag.
        assertTrue(main("MainActivity.kt").contains("window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)"))
        File("src/main/kotlin").walkTopDown().filter { it.isFile && it.extension == "kt" }.forEach {
            assertFalse(it.readText().contains("clearFlags(WindowManager.LayoutParams.FLAG_SECURE)"), it.name)
        }
        val notice = main("trust/TrustApp.kt").substringAfter("internal fun KitWipedNoticeView(").substringBefore("\n}\n")
        val kitView = main("trust/KitScreens.kt").substringAfter("internal fun KitScreenView(").substringBefore("\n}\n")
        for (body in listOf(notice, kitView)) {
            assertFalse("Dialog" in body || "Popup" in body, "drawn in the app's own window")
        }
        // A kit left in the background is covered before anything else of it, the warning included.
        assertTrue(kitView.indexOf("if (covered &&") < kitView.indexOf("kitIdleWarning"))
    }
}
