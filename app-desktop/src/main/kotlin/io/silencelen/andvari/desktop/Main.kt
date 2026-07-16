package io.silencelen.andvari.desktop

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.KeyShortcut
import androidx.compose.ui.input.key.isCtrlPressed
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.type
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.MenuBar
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import java.awt.event.WindowEvent
import java.awt.event.WindowFocusListener

// Treasury/gold palette — matches the web + Android clients.
// UI-audit 2026-07 (Cut B): full Material3 role coverage, value-identical to Android's
// Theme.kt (which carries the per-pair contrast rationale). The web token-lockstep test
// parses this file — keep the exact hex literals in sync with Theme.kt.
private val Gold = Color(0xFFD0A94A)
private val Ink = Color(0xFFEDE4D0)
private val Bg = Color(0xFF14120E)
private val BgRaised = Color(0xFF1E1B15)

private val DarkColors = darkColorScheme(
    primary = Gold, onPrimary = Color(0xFF1A1509),
    primaryContainer = Color(0xFF4A3A12), onPrimaryContainer = Color(0xFFECD9A0),
    secondary = Color(0xFFE8C66A), onSecondary = Color(0xFF1A1509),
    secondaryContainer = Color(0xFF38311F), onSecondaryContainer = Ink,
    tertiary = Color(0xFF7FA86A), onTertiary = Color(0xFF10200B),
    tertiaryContainer = Color(0xFF2A3A22), onTertiaryContainer = Color(0xFFC8DDB8),
    background = Bg, onBackground = Ink, surface = BgRaised, onSurface = Ink,
    surfaceVariant = Color(0xFF262119), onSurfaceVariant = Color(0xFFA79C85),
    surfaceTint = Gold,
    inverseSurface = Ink, inverseOnSurface = Color(0xFF2C2517), inversePrimary = Color(0xFF9A7420),
    error = Color(0xFFD97F6F), onError = Color(0xFF1A0F0B),
    errorContainer = Color(0xFF4A231C), onErrorContainer = Color(0xFFF2C0B5),
    outline = Color(0xFF80714F), outlineVariant = Color(0xFF38311F), scrim = Color(0xFF000000),
    surfaceBright = Color(0xFF3A332A), surfaceDim = Bg,
    surfaceContainerLowest = Color(0xFF0F0D0A), surfaceContainerLow = Color(0xFF1A1712),
    surfaceContainer = BgRaised, surfaceContainerHigh = Color(0xFF262119),
    surfaceContainerHighest = Color(0xFF2E2820),
)
private val LightColors = lightColorScheme(
    primary = Color(0xFF8F6B16), onPrimary = Color.White,
    primaryContainer = Color(0xFFECDCAE), onPrimaryContainer = Color(0xFF3A2B05),
    secondary = Color(0xFF7D5E14), onSecondary = Color.White,
    secondaryContainer = Color(0xFFECE2C8), onSecondaryContainer = Color(0xFF2C2517),
    tertiary = Color(0xFF4F7A3A), onTertiary = Color.White,
    tertiaryContainer = Color(0xFFD7E6CB), onTertiaryContainer = Color(0xFF1C2F12),
    background = Color(0xFFF4EFE4), onBackground = Color(0xFF2C2517),
    surface = Color(0xFFFBF8F1), onSurface = Color(0xFF2C2517),
    surfaceVariant = Color(0xFFE9E1CF), onSurfaceVariant = Color(0xFF6B6047),
    surfaceTint = Color(0xFF8F6B16),
    inverseSurface = Color(0xFF2C2517), inverseOnSurface = Color(0xFFEDE4D0), inversePrimary = Gold,
    error = Color(0xFFB3402C), onError = Color.White,
    errorContainer = Color(0xFFF6DED7), onErrorContainer = Color(0xFF5C1F12),
    outline = Color(0xFF857857), outlineVariant = Color(0xFFE0D8C5), scrim = Color(0xFF000000),
    surfaceBright = Color(0xFFFBF8F1), surfaceDim = Color(0xFFD8D2C2),
    surfaceContainerLowest = Color.White, surfaceContainerLow = Color(0xFFFBF8F1),
    surfaceContainer = Color(0xFFF4EFE4), surfaceContainerHigh = Color(0xFFEFE9DB),
    surfaceContainerHighest = Color(0xFFE9E1CF),
)
private val AndvariType = Typography(
    headlineMedium = TextStyle(fontFamily = FontFamily.Serif, fontWeight = FontWeight.SemiBold, fontSize = 26.sp),
    titleLarge = TextStyle(fontFamily = FontFamily.Serif, fontWeight = FontWeight.SemiBold, fontSize = 22.sp),
)

/**
 * UI-audit #26: the user's theme override. Auto follows the OS via [isSystemInDarkTheme] — which
 * on Linux desktops routinely reports light regardless of the actual desktop theme, hard-sticking
 * those users in the weaker light scheme; Light/Dark force a side. Persisted as a plain string in
 * DesktopSessionStore prefs ([fromStore] parses leniently so an unknown value degrades to Auto).
 */
enum class ThemeMode(val storeValue: String, val label: String) {
    Auto("auto", "Auto"),
    Light("light", "Light"),
    Dark("dark", "Dark");

    companion object {
        fun fromStore(v: String): ThemeMode = entries.find { it.storeValue == v } ?: Auto
    }
}

@Composable
fun AndvariDesktopTheme(themeMode: ThemeMode = ThemeMode.Auto, content: @Composable () -> Unit) {
    // #26: the override wraps — never replaces — the system signal; the scheme declarations
    // above are untouched (they stay in web token-lockstep).
    val dark = when (themeMode) {
        ThemeMode.Light -> false
        ThemeMode.Dark -> true
        ThemeMode.Auto -> isSystemInDarkTheme()
    }
    MaterialTheme(
        colorScheme = if (dark) DarkColors else LightColors,
        typography = AndvariType,
        content = content,
    )
}

fun main() = application {
    // The state holder must exist before Window's key-event callback references it, so
    // hoist scope+state to the application scope (the window IS the app lifetime here).
    val scope = rememberCoroutineScope()
    val state = remember { DesktopState(scope).also { it.start() } }
    Window(
        onCloseRequest = ::exitApplication,
        title = "andvari",
        state = rememberWindowState(width = 480.dp, height = 720.dp),
        // Every hardware key press counts as user activity for the inactivity auto-lock
        // (spec 01 §8). Window-level preview sees keys regardless of what has focus; never
        // consumes — EXCEPT Ctrl+L (design 2026-07-13 platform-fit §2), the panic lock. This is
        // the ONE authoritative shortcut handler: it consumes the KeyDown so the 'l' never reaches
        // a focused text field, and the menu's KeyShortcut(Key.L, ctrl) is accelerator TEXT only
        // (its onClick calls the same idempotent panicLock()). Every other key still falls through.
        onPreviewKeyEvent = {
            state.touch()
            if (it.type == KeyEventType.KeyDown && it.isCtrlPressed && it.key == Key.L) {
                state.panicLock(); true
            } else false
        },
    ) {
        // design 2026-07-13 platform-fit §2: the desktop command surface. Renders a native/AWT menu
        // on both target formats (Msi + Deb). Shortcuts are DECLARED here for their accelerator text
        // (the discoverability win); handling stays in onPreviewKeyEvent above (Ctrl+L) or the AWT
        // accelerator itself (Ctrl+R/Ctrl+Q) — every onClick calls an idempotent function, so a
        // double-dispatch is harmless.
        MenuBar {
            Menu("Vault") {
                Item("Sync now", shortcut = KeyShortcut(Key.R, ctrl = true), enabled = state.menuSignedIn) { state.refresh() }
                Item("Import passwords…", enabled = state.onVaultScreen) { state.requestImport() }
                Separator()
                Item("Lock", shortcut = KeyShortcut(Key.L, ctrl = true), enabled = state.menuSignedIn) { state.panicLock() }
                // §2 security note: Sign out is destructive and MUST route through a confirm dialog.
                // The only sign-out confirm today is local `remember` state inside the (locked)
                // Unlock screen — there is NO signed-in-reachable confirm (that's the audit's separate
                // "un-confirmed sign-out" finding, not this wave). Per the contract: ship DISABLED
                // rather than a bare state.signOut() (AWT native menu items can't carry a tooltip).
                Item("Sign out…", enabled = false) {}
                Separator()
                Item("Quit", shortcut = KeyShortcut(Key.Q, ctrl = true)) { exitApplication() }
            }
            Menu("Help") {
                Item("Open web vault") { openInBrowser(state.baseUrl) }
                Item("Check for updates") { state.checkForUpdatesNow() }
                Item("About andvari") { state.requestAbout() }
            }
        }
        // Cut I (v2 #9): a hard floor — below ~480×600 the auth card and vault toolbar
        // truncate into unusability; AWT minimumSize is the only enforcement point.
        LaunchedEffect(Unit) { window.minimumSize = java.awt.Dimension(480, 600) }
        // Sync (and enforce the idle lock) whenever the window regains OS focus (spec 03 §6).
        DisposableEffect(Unit) {
            val focus = object : WindowFocusListener {
                override fun windowGainedFocus(e: WindowEvent?) = state.onWindowFocus()
                override fun windowLostFocus(e: WindowEvent?) {}
            }
            window.addWindowFocusListener(focus)
            onDispose { window.removeWindowFocusListener(focus) }
        }
        AndvariDesktopTheme(state.themeMode) {
            Surface {
                // Root pointer interceptor: PointerEventPass.Initial observes every pointer
                // event (press/move/scroll) before children consume it — any of them resets
                // the auto-lock window. Purely observational; nothing is consumed.
                Box(
                    Modifier.fillMaxSize().pointerInput(Unit) {
                        awaitPointerEventScope {
                            while (true) {
                                awaitPointerEvent(PointerEventPass.Initial)
                                state.touch()
                            }
                        }
                    },
                ) { DesktopApp(state) }
            }
        }
    }
}
