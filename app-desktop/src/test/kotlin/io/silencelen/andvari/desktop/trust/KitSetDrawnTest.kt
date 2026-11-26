package io.silencelen.andvari.desktop.trust

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.unit.Density
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.DesktopAppApi
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.KeptStops
import io.silencelen.andvari.core.app.KeptWayOut
import io.silencelen.andvari.core.app.KitRecoverResult
import io.silencelen.andvari.core.app.KitScanResult
import io.silencelen.andvari.core.app.KitStep
import io.silencelen.andvari.core.app.LinkPasswordResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.ReplacePasswordResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * The shared code's kit set, as the desktop draws it: every kit's limit and warning from the kit itself (in the journey and
 * in Settings, and from the start of the screen where the limit is short); the line on a kit that replaces one shown here
 * before, first on its first step; and the way out beside a stop from the shared code's own act for it. Walked on the
 * shared code's fake, which makes its kits as the engine does.
 */
class KitSetDrawnTest {
    private val pw = FakeScenes.PASSWORD
    private val dir = "src/main/kotlin/io/silencelen/andvari/desktop/trust/"
    private fun body(file: String, head: String) = File(dir + file).readText().substringAfter(head).substringBefore("\n}\n")

    private class CountedLocks(val fake: FakeDesktopAppApi) : DesktopAppApi by fake {
        var locks = 0
        override fun lock() {
            locks++
            fake.lock()
        }
    }

    private fun draw(m: TrustModel, api: DesktopAppApi) {
        val s = api.snapshot
        val scene = ImageComposeScene(480, 1400, Density(1f)) {
            MaterialTheme { Surface { s.entry?.let { EntryScreens(m, s, it) } } }
        }
        try {
            scene.render()
        } finally {
            scene.close()
        }
    }

    // ---- the warning from the start of a short kit ----

    /**
     * A policy whose lock time is not longer than the warning's: the kit's warning is on show from its first tick, the
     * operating system is asked once, a touch keeps the kit and leaves the warning on show without asking again, and the
     * lock comes at the kit's limit after the last touch. The smallest time a policy gives (one second) warns from the
     * start too.
     */
    @Test
    fun aKitWhoseLimitIsShortWarnsFromTheStartAndAsksTheSystemOnce() {
        for (seconds in listOf(20, 1)) {
            var now = 0L
            val fake = FakeScenes.desktopAt(FakeScene.CREATE_ACCOUNT)
            fake.script.publicInstance.autoLockSeconds = seconds
            val api = CountedLocks(fake)
            val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { now })
            var signals = 0
            m.kitWarningSignal = KitWarningSignal { signals++ }
            val form = assertIs<EntryScreen.CreateAccount>(fake.snapshot.entry)
            m.run({ entry.createAccount(form, NewAccountInput("cy@example.com", "Cy", "a brand new master password", false)) })
            val kit = assertNotNull(kitIdleLimitOf(fake.snapshot), "$seconds s")
            val limit = assertNotNull(kit.idleLockAfterMs)
            assertEquals(seconds * 1000L, limit, "the kit's own limit: the policy's lock time")
            assertTrue(warnsFromStart(kit), "$seconds s: the warning is shown from the start")
            assertEquals(0, signals)
            // The first tick with the kit on show: the warning, and the system asked once.
            now += 1_000L
            m.tick()
            if (seconds == 1) {
                // One second: the first tick both warns and, a second later, locks.
                assertEquals(kit.idleWarningLine, m.kitIdleWarning.value)
                assertEquals(1, signals)
                now += 1_000L
                m.tick()
                assertEquals(1, api.locks, "1 s: the limit locks")
                assertEquals(1, signals)
                continue
            }
            assertEquals(kit.idleWarningLine, m.kitIdleWarning.value, "from the start")
            assertEquals(1, signals, "asked once, as it comes")
            now += 5_000L
            m.tick()
            // A click keeps the kit: the count starts again, the warning stays, and nothing is asked again.
            m.touched()
            val touchedAt = now
            assertEquals(kit.idleWarningLine, m.kitIdleWarning.value, "a touch leaves a warning shown from the start on show")
            while (now < touchedAt + limit - 1_000L) {
                now += 1_000L
                m.tick()
                assertEquals(kit.idleWarningLine, m.kitIdleWarning.value)
            }
            assertEquals(0, api.locks, "the touch kept the kit")
            assertEquals(1, signals, "not asked again at the touch, nor at every tick")
            now += 1_000L
            m.tick()
            assertEquals(1, api.locks, "the limit after the last touch locks")
            assertNull(m.kitIdleWarning.value)
            assertEquals(1, signals, "the lock itself asks nothing")
        }
    }

    // ---- the operating system's signal fails ----

    /**
     * The operating system's signal throws when the warning comes: the failure is logged by its class only, the warning
     * still shows, nothing is said on the screen, and the lock still comes at the kit's limit.
     */
    @Test
    fun aSignalOfTheSystemThatFailsIsLoggedAndTheLockStillComes() {
        var now = 0L
        val fake = FakeScenes.desktopAt(FakeScene.CREATE_ACCOUNT)
        val api = CountedLocks(fake)
        val logged = ArrayList<String>()
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { now }, faultLog = { logged += it })
        var tries = 0
        m.kitWarningSignal = KitWarningSignal {
            tries++
            throw IllegalStateException("the taskbar refused, with words that must not reach the log")
        }
        val form = assertIs<EntryScreen.CreateAccount>(fake.snapshot.entry)
        m.run({ entry.createAccount(form, NewAccountInput("cy@example.com", "Cy", "a brand new master password", false)) })
        val kit = assertNotNull(kitIdleLimitOf(fake.snapshot))
        val limit = assertNotNull(kit.idleLockAfterMs)
        val warnFrom = limit - assertNotNull(kit.idleWarnBeforeMs)
        now += 1_000L
        m.tick()
        val shownAt = now
        while (now < shownAt + warnFrom) {
            now += 1_000L
            m.tick()
        }
        assertEquals(kit.idleWarningLine, m.kitIdleWarning.value, "the warning shows all the same")
        assertEquals(1, tries)
        assertEquals(listOf("kit warning signal :: IllegalStateException"), logged, "logged once, by its class, never its message")
        assertNull(m.said.value, "nothing is said on the screen for it")
        while (now < shownAt + limit) {
            now += 1_000L
            m.tick()
        }
        assertEquals(1, api.locks, "the lock still comes at the kit's limit")
        assertEquals(1, tries, "not asked again")
    }

    // ---- a kit made in Settings ----

    /** The kit made in Settings over the open vault: its own limit and its warning at its own time, then the lock. */
    @Test
    fun aKitMadeInSettingsHasItsOwnLimitAndWarning() {
        var now = 0L
        val fake = FakeScenes.desktopAt(FakeScene.VAULTS)
        val api = CountedLocks(fake)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { now })
        var signals = 0
        m.kitWarningSignal = KitWarningSignal { signals++ }
        m.onSnapshot(fake.snapshot)
        m.run({ recovery.makeKit(pw) })
        val kit = assertNotNull(fake.snapshot.account?.kit, "the kit is on show in Settings")
        assertSame(kit, kitIdleLimitOf(fake.snapshot))
        val limit = assertNotNull(kit.idleLockAfterMs)
        val warnFrom = limit - assertNotNull(kit.idleWarnBeforeMs)
        now += 1_000L
        m.tick()
        val shownAt = now
        while (now < shownAt + warnFrom - 1_000L) {
            now += 1_000L
            m.tick()
            if (now == shownAt + 10_000L) m.touched(moved = true)
        }
        assertNull(m.kitIdleWarning.value)
        assertEquals(0, signals)
        now += 1_000L
        m.tick()
        assertEquals(kit.idleWarningLine, m.kitIdleWarning.value, "the kit's warning, its own time before the limit")
        assertEquals(1, signals)
        while (now < shownAt + limit) {
            now += 1_000L
            m.tick()
        }
        assertEquals(1, api.locks, "the kit's limit locks the vault and takes the kit")
        assertEquals(AppPhase.LOCKED, fake.snapshot.phase)
    }

    // ---- the line on a kit that replaces one shown here before ----

    /**
     * A kit shown and never confirmed, then a lock and an unlock: the fresh kit says on its reveal, first and in the error
     * tone, that the earlier one no longer works; its confirm step does not.
     */
    @Test
    fun aKitThatReplacesOneShownBeforeSaysSoFirstOnItsReveal() {
        val api = FakeScenes.desktopAt(FakeScene.KIT_REVEAL)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }).also { it.onSnapshot(api.snapshot) }
        assertNull(assertIs<EntryScreen.Kit>(api.snapshot.entry).kit.earlierKitVoidLine, "the first kit replaces none")
        m.lockNow()
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        m.run({ unlock(assertNotNull(api.snapshot.locked), pw) })
        val fresh = assertIs<EntryScreen.Kit>(api.snapshot.entry).kit
        assertEquals(KitStep.REVEAL, fresh.step)
        assertEquals(CopyKey.KIT_EARLIER_NOT_CONFIRMED_VOID, fresh.earlierKitVoidLine)
        draw(m, api)
        m.act { kit.proceedToConfirm(fresh) }
        val confirm = assertIs<EntryScreen.Kit>(api.snapshot.entry).kit
        assertEquals(KitStep.CONFIRM, confirm.step)
        assertNull(confirm.earlierKitVoidLine, "only on the first step")
        draw(m, api)
        // Drawn first in the kit's view, before the warning and every other line, in the error tone.
        val view = body("KitScreens.kt", "internal fun KitScreenView(").substringAfter("AuthColumn {")
        val first = view.lines().map { it.trim() }.first { it.isNotEmpty() && !it.startsWith("//") }
        assertEquals("kit.earlierKitVoidLine?.let { Say(UiText.of(it), color = MaterialTheme.colorScheme.error) }", first)
    }

    // ---- the way out beside a stop: the shared code's act ----

    /**
     * Every result of the journey's flows offers exactly the shared code's act for it ([KeptStops.wayOut]) while an account
     * is kept here: the kept account's sign-out, or the removal of this computer's copy; nothing for the held operator
     * account (the first screen offers its removal) or for a result with no act. Nothing at all where no account is kept.
     */
    @Test
    fun theWayOutBesideAStopIsTheSharedCodesActForIt() {
        val api = FakeScenes.desktopAt(FakeScene.VAULTS)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }).also { it.onSnapshot(api.snapshot) }
        api.script.sessionEndedByServer()
        m.signInAgain()
        m.onSnapshot(api.snapshot)
        val s = api.snapshot
        val kept = assertNotNull(s.keptSignedOut)
        val results: List<IntentResult> = SignInAnswer.entries + ReplacePasswordResult.entries + KitRecoverResult.entries + KitScanResult.entries +
            CreateAccountResult.entries + SignUpStartResult.entries + LinkPasswordResult.entries
        var signOuts = 0
        var removals = 0
        for (r in results) {
            val way = wayOutOf(r, null, s)
            when (KeptStops.wayOut(r)) {
                KeptWayOut.SIGN_OUT_KEPT_ACCOUNT -> {
                    assertIs<WayOut.SignOutKept>(way, "$r")
                    assertSame(kept, way.kept)
                    signOuts++
                }
                KeptWayOut.REMOVE_THIS_COPY -> {
                    assertIs<WayOut.RemoveDamagedCopy>(way, "$r")
                    assertEquals(Placeholder.KEPT_COPY_REMOVE, assertIs<UiText.Ph>(way.button).placeholder, "$r: labelled as the copy's removal")
                    removals++
                }
                KeptWayOut.REMOVE_HELD_OPERATOR_ACCOUNT, null -> assertNull(way, "$r")
            }
        }
        assertTrue(signOuts > 0 && removals > 0)
        // A stop whose keys this computer does not know is this computer's own copy in the way: its removal.
        assertIs<WayOut.RemoveDamagedCopy>(wayOutOf(SignInAnswer.SERVER_KEYS_NOT_KNOWN_HERE, null, s))
        // No account kept: nothing for any of them.
        val none = FakeScenes.desktopAt(FakeScene.FIRST_RUN).snapshot
        for (r in results) assertNull(wayOutOf(r, null, none), "$r")
    }
}
