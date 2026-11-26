package io.silencelen.andvari.desktop

import androidx.compose.runtime.ProvidableCompositionLocal
import androidx.compose.runtime.staticCompositionLocalOf
import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.util.Collections
import java.util.WeakHashMap

/**
 * The owner's decision of 2026-11-16: on Windows, andvari's windows are hidden from screenshots and screen recording
 * (Windows Recall, the Snipping Tool, screen sharing, remote-support tools could otherwise record the recovery kit, a
 * revealed password, a card number or a one-time code while it is on screen), with a switch in Settings to allow
 * capture. Off by default; kept per computer in `prefs.json` ([DesktopSessionStore.allowScreenCapture]), never in the
 * account.
 */
enum class CaptureState {
    /** Windows 10 2004 and later: the window is left out of every capture (`WDA_EXCLUDEFROMCAPTURE`). */
    HIDDEN,

    /** Older Windows: the window shows as black in captures (`WDA_MONITOR`), the only affinity it has. */
    BLACKED_OUT,

    /** The call failed: hiding is not active on this computer, and the Settings line says so. */
    NOT_ACTIVE,

    /** The person allowed capture on this computer (the switch is on). */
    ALLOWED,

    /** This operating system has nothing of the kind (Linux): no switch is shown, one sentence says so. */
    NOT_POSSIBLE_HERE,
}

/** The one native call, behind an interface the tests fake. [W] is the window type (AWT's on the desktop). */
interface CaptureShield<W> {
    /** Whether this operating system can hide a window from capture at all. */
    val possible: Boolean

    /** Hide [window] from capture ([hide]) or let it be captured again; what is now true of it. */
    fun apply(window: W, hide: Boolean): CaptureState
}

/** Windows: `SetWindowDisplayAffinity` through JNA, which the project already has (no new dependency). */
internal object WindowsCaptureShield : CaptureShield<java.awt.Window> {
    private const val WDA_NONE = 0x0
    private const val WDA_MONITOR = 0x1
    private const val WDA_EXCLUDEFROMCAPTURE = 0x11

    @Suppress("FunctionName")
    private interface User32 : Library {
        fun SetWindowDisplayAffinity(hWnd: Pointer, dwAffinity: Int): Boolean
    }

    private val user32: User32? by lazy { runCatching { Native.load("user32", User32::class.java) }.getOrNull() }

    override val possible: Boolean get() = true

    override fun apply(window: java.awt.Window, hide: Boolean): CaptureState {
        val lib = user32 ?: return if (hide) CaptureState.NOT_ACTIVE else CaptureState.ALLOWED
        return runCatching {
            // The window's handle exists once it is displayable; the caller makes it so before its first frame.
            if (!window.isDisplayable) window.addNotify()
            val hwnd = Native.getWindowPointer(window) ?: return@runCatching if (hide) CaptureState.NOT_ACTIVE else CaptureState.ALLOWED
            when {
                !hide -> { lib.SetWindowDisplayAffinity(hwnd, WDA_NONE); CaptureState.ALLOWED }
                lib.SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) -> CaptureState.HIDDEN
                // Before Windows 10 2004 the exclusion value is refused: the older value shows the window as black.
                lib.SetWindowDisplayAffinity(hwnd, WDA_MONITOR) -> CaptureState.BLACKED_OUT
                else -> CaptureState.NOT_ACTIVE
            }
        }.getOrElse { if (hide) CaptureState.NOT_ACTIVE else CaptureState.ALLOWED }
    }
}

/** Linux (and anything else): no such call; nothing pretends. */
internal object NoCaptureShield : CaptureShield<java.awt.Window> {
    override val possible: Boolean get() = false

    override fun apply(window: java.awt.Window, hide: Boolean): CaptureState = CaptureState.NOT_POSSIBLE_HERE
}

/**
 * Every window the app opens is registered here before its first frame ([register], from the app's one window maker,
 * `GuardedWindow`), and the switch ([setAllowed]) applies at once to every open window. [state] is what is true
 * now: the weakest of the open windows', so a window the call failed on is never hidden by another's success.
 */
class CaptureGuard<W>(private val shield: CaptureShield<W>, private val allowedAtStart: Boolean, private val keep: (Boolean) -> Unit) {
    private val windows: MutableSet<W> = Collections.synchronizedSet(Collections.newSetFromMap(WeakHashMap()))
    private val states = Collections.synchronizedMap(WeakHashMap<W, CaptureState>())
    private val allowedFlow = MutableStateFlow(allowedAtStart)
    private val stateFlow = MutableStateFlow(if (!shield.possible) CaptureState.NOT_POSSIBLE_HERE else if (allowedAtStart) CaptureState.ALLOWED else CaptureState.HIDDEN)

    /** Whether the switch "allow screen capture" is on (off by default). */
    val allowed: StateFlow<Boolean> get() = allowedFlow

    /** What is true of capture on this computer now. */
    val state: StateFlow<CaptureState> get() = stateFlow

    /** Whether the Settings page offers the switch: only where hiding is possible at all. */
    val offersSwitch: Boolean get() = shield.possible

    /** A window that exists and has not drawn yet: hidden now, unless capture is allowed. */
    fun register(window: W) {
        windows += window
        states[window] = shield.apply(window, hide = !allowedFlow.value)
        recompute()
    }

    fun unregister(window: W) {
        windows -= window
        states.remove(window)
        recompute()
    }

    /** The switch: kept for this computer and applied to every open window at once. */
    fun setAllowed(allow: Boolean) {
        if (!shield.possible) return
        allowedFlow.value = allow
        runCatching { keep(allow) }
        val open = synchronized(windows) { windows.toList() }
        for (w in open) states[w] = shield.apply(w, hide = !allow)
        recompute()
    }

    private fun recompute() {
        if (!shield.possible) {
            stateFlow.value = CaptureState.NOT_POSSIBLE_HERE
            return
        }
        if (allowedFlow.value) {
            stateFlow.value = CaptureState.ALLOWED
            return
        }
        val now = synchronized(states) { states.values.toList() }
        stateFlow.value = when {
            now.any { it == CaptureState.NOT_ACTIVE || it == CaptureState.ALLOWED } -> CaptureState.NOT_ACTIVE
            now.any { it == CaptureState.BLACKED_OUT } -> CaptureState.BLACKED_OUT
            else -> CaptureState.HIDDEN
        }
    }

    companion object {
        /** The guard for this computer: Windows hides; elsewhere nothing can. */
        fun forThisComputer(store: DesktopSessionStore, os: String = System.getProperty("os.name").orEmpty()): CaptureGuard<java.awt.Window> {
            val shield: CaptureShield<java.awt.Window> = if (os.lowercase().contains("win")) WindowsCaptureShield else NoCaptureShield
            return CaptureGuard(shield, store.allowScreenCapture) { store.allowScreenCapture = it }
        }
    }
}

/** The app's guard, for the Settings page; null outside the app's window (tests, previews). */
val LocalCaptureGuard: ProvidableCompositionLocal<CaptureGuard<*>?> = staticCompositionLocalOf { null }
