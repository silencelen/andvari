package io.silencelen.andvari.desktop

import io.silencelen.andvari.desktop.trust.Placeholder
import io.silencelen.andvari.desktop.trust.UiText
import io.silencelen.andvari.desktop.trust.captureView
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The owner's decision of 2026-11-16: on Windows every window of the app is hidden from screen capture
 * before its first frame, unless the person allowed capture on this computer in Settings; elsewhere nothing pretends.
 * The native call sits behind [CaptureShield], faked here; what this cannot show must be checked on a real Windows
 * computer.
 */
class ScreenCaptureTest {
    /** A pretend Windows: what each window was last set to, and whether the call works. */
    private class FakeShield(var answers: CaptureState = CaptureState.HIDDEN, override val possible: Boolean = true) : CaptureShield<String> {
        val hidden = HashMap<String, Boolean>()
        override fun apply(window: String, hide: Boolean): CaptureState {
            hidden[window] = hide
            return if (!possible) CaptureState.NOT_POSSIBLE_HERE else if (hide) answers else CaptureState.ALLOWED
        }
    }

    private fun placeholderOf(t: UiText) = (t as UiText.Ph).placeholder

    @Test
    fun theSwitchIsOffByDefaultAndIsKeptForThisComputer() {
        val dir = Files.createTempDirectory("andvari-capture").toFile().also { it.deleteOnExit() }
        val store = DesktopSessionStore(dir)
        assertFalse(store.allowScreenCapture, "capture is hidden by default")
        val guard = CaptureGuard(FakeShield(), store.allowScreenCapture) { store.allowScreenCapture = it }
        guard.setAllowed(true)
        assertTrue(DesktopSessionStore(dir).allowScreenCapture, "kept in this computer's prefs.json")
        guard.setAllowed(false)
        assertFalse(DesktopSessionStore(dir).allowScreenCapture)
        // An unreadable file is off.
        File(dir, "prefs.json").writeText("{ not json")
        assertFalse(DesktopSessionStore(dir).allowScreenCapture)
    }

    @Test
    fun everyOpenWindowIsHiddenAtOnceAndTheSwitchAppliesToThemAll() {
        val shield = FakeShield()
        var kept: Boolean? = null
        val guard = CaptureGuard(shield, false) { kept = it }
        guard.register("main")
        guard.register("second")
        assertEquals(mapOf("main" to true, "second" to true), shield.hidden)
        assertEquals(CaptureState.HIDDEN, guard.state.value)
        guard.setAllowed(true)
        assertEquals(mapOf("main" to false, "second" to false), shield.hidden, "at once, on every open window")
        assertEquals(CaptureState.ALLOWED, guard.state.value)
        assertEquals(true, kept)
        // A window opened while capture is allowed is left capturable; turned off again, it is hidden too.
        guard.register("third")
        assertEquals(false, shield.hidden["third"])
        guard.setAllowed(false)
        assertTrue(shield.hidden.values.all { it })
        assertEquals(CaptureState.HIDDEN, guard.state.value)
    }

    @Test
    fun aRefusedCallIsSaidAsNotActiveAndTheOlderWindowsValueAsBlack() {
        val shield = FakeShield(CaptureState.NOT_ACTIVE)
        val guard = CaptureGuard(shield, false) {}
        guard.register("main")
        assertEquals(CaptureState.NOT_ACTIVE, guard.state.value, "the app does not pretend")
        assertEquals(Placeholder.CAPTURE_NOT_ACTIVE, placeholderOf(captureView(guard.state.value, guard.offersSwitch).lines[0]))
        assertTrue(captureView(guard.state.value, true).error)
        // One window refused among others that took it: still not active.
        val mixed = FakeShield()
        val g2 = CaptureGuard(mixed, false) {}
        g2.register("a")
        mixed.answers = CaptureState.NOT_ACTIVE
        g2.register("b")
        assertEquals(CaptureState.NOT_ACTIVE, g2.state.value)
        val old = CaptureGuard(FakeShield(CaptureState.BLACKED_OUT), false) {}
        old.register("main")
        assertEquals(Placeholder.CAPTURE_BLACKED_OUT, placeholderOf(captureView(old.state.value, true).lines[0]))
    }

    @Test
    fun theSettingsSentenceFollowsWhatIsTrueOnEachPlatform() {
        // Windows, hidden: the switch, what is true now, and what turning it on means (this computer only).
        val hidden = captureView(CaptureState.HIDDEN, offersSwitch = true)
        assertTrue(hidden.offersSwitch)
        assertEquals(listOf(Placeholder.CAPTURE_HIDDEN, Placeholder.CAPTURE_SWITCH_MEANS), hidden.lines.map { placeholderOf(it) })
        assertTrue(Placeholder.CAPTURE_SWITCH_MEANS.gloss.contains("this computer only") && Placeholder.CAPTURE_SWITCH_MEANS.gloss.contains("recovery kit"))
        assertEquals(Placeholder.CAPTURE_ALLOWED, placeholderOf(captureView(CaptureState.ALLOWED, true).lines[0]))
        // Linux: one sentence and no switch that would do nothing.
        val linux = CaptureGuard(FakeShield(possible = false), false) {}
        linux.register("main")
        assertEquals(CaptureState.NOT_POSSIBLE_HERE, linux.state.value)
        assertFalse(linux.offersSwitch)
        val view = captureView(linux.state.value, linux.offersSwitch)
        assertFalse(view.offersSwitch)
        assertEquals(listOf(Placeholder.CAPTURE_NOT_POSSIBLE_HERE), view.lines.map { placeholderOf(it) })
        linux.setAllowed(true)
        assertFalse(linux.allowed.value, "nothing to switch there")
        // The guard for this computer picks the platform from the OS's name.
        val dir = Files.createTempDirectory("andvari-capture-os").toFile().also { it.deleteOnExit() }
        assertTrue(CaptureGuard.forThisComputer(DesktopSessionStore(dir), "Windows 11").offersSwitch)
        assertFalse(CaptureGuard.forThisComputer(DesktopSessionStore(dir), "Linux").offersSwitch)
    }

    /** Every window the app opens goes through the one maker that registers it before its first frame. */
    @Test
    fun everyWindowIsMadeInTheOnePlaceThatHidesIt() {
        val main = File("src/main/kotlin/io/silencelen/andvari/desktop/Main.kt").readText()
        val maker = main.substringAfter("private fun ApplicationScope.GuardedWindow(").substringBefore("\n}\n")
        assertTrue("visible = ready," in maker, "shown only once registered")
        assertTrue(maker.indexOf("guard.register(window)") < maker.indexOf("ready = true"))
        assertEquals(1, Regex("""(?<![A-Za-z])Window\(\s*\n?\s*onCloseRequest""").findAll(main).count(), "one Window( call, in the maker")
        assertTrue("GuardedWindow(guard) {" in main && "GuardedWindow(\n        capture," in main)
        // No other window anywhere in the app's sources: no DialogWindow, Frame, JFrame or JDialog of its own.
        val sources = File("src/main/kotlin").walkTopDown().filter { it.name.endsWith(".kt") }.toList()
        for (f in sources) {
            val text = f.readText()
            for (other in listOf("DialogWindow(", "JFrame(", "JDialog(", "Window(onCloseRequest")) assertFalse(other in text, "${f.name}: $other")
            if (f.name != "Main.kt") assertFalse(Regex("""(?<![A-Za-z.])Window\(""").containsMatchIn(text.replace("GuardedWindow(", "")), "${f.name} opens a window of its own")
        }
    }
}
