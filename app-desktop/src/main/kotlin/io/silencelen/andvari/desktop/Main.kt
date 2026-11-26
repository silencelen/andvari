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
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.MenuBar
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Text
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.desktop.trust.AboutDialog
import io.silencelen.andvari.desktop.trust.DesktopHome
import io.silencelen.andvari.desktop.trust.KitWarningSignal
import io.silencelen.andvari.desktop.trust.WindowKitWarningSignal
import io.silencelen.andvari.desktop.trust.Placeholder
import io.silencelen.andvari.desktop.trust.SingleInstance
import io.silencelen.andvari.desktop.trust.TrustApp
import io.silencelen.andvari.desktop.trust.SensitiveClipboardManager
import io.silencelen.andvari.desktop.trust.TrustModel
import io.silencelen.andvari.desktop.trust.TrustSeam
import io.silencelen.andvari.desktop.trust.UiText
import io.silencelen.andvari.desktop.trust.clipboardSeconds
import io.silencelen.andvari.desktop.trust.ScreenFailedCard
import io.silencelen.andvari.desktop.trust.ScreenFailure
import io.silencelen.andvari.desktop.trust.StateFileScreen
import io.silencelen.andvari.desktop.trust.StateFiles
import io.silencelen.andvari.desktop.trust.updateStatusLines
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.window.ApplicationScope
import androidx.compose.ui.window.LocalWindowExceptionHandlerFactory
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.platform.LocalClipboardManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
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
    // The success green: 4.69 to 1 on the light ground, so that small text in it can be read (4.5 at least).
    tertiary = Color(0xFF4C7538), onTertiary = Color.White,
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

/** The one-instance lock, held for the life of the process. */
@Volatile
private var heldInstance: SingleInstance? = null

/**
 * A second start, or a start that could not make sure it is the first: say so in a plain dialog and stop. Nothing of
 * the app has run yet, so nothing was read or written.
 */
private fun refuseSecondStart(gate: SingleInstance.Gate) {
    val text = when (gate) {
        is SingleInstance.Gate.Failed -> UiText.ph(Placeholder.INSTANCE_CHECK_FAILED, gate.why)
        else -> UiText.ph(Placeholder.ALREADY_OPEN)
    }.shown()
    runCatching { javax.swing.JOptionPane.showMessageDialog(null, text, "andvari", javax.swing.JOptionPane.INFORMATION_MESSAGE) }
    kotlin.system.exitProcess(0)
}

@OptIn(ExperimentalComposeUiApi::class)
fun main() {
    // Note N7: from here on an uncaught error is logged redacted, never printed with its message.
    DesktopDiagnostics.installUncaughtLogging()
    // One andvari per account on this computer, before anything else runs: a second start reads and writes nothing
    // (two instances once spent each other's refresh token and tore device-state.json).
    when (val gate = SingleInstance.acquire(SingleInstance.fileIn(DesktopHome.defaultRoot()))) {
        is SingleInstance.Gate.Acquired -> heldInstance = gate.instance
        else -> return refuseSecondStart(gate)
    }
    // Extract libsodium to a writable temp file and hand core its path BEFORE any crypto touch,
    // sidestepping lazysodium's resource-loader (which dies on a jpackage install under a spaced
    // path like "Program Files"). Must run before the self-check below — the first crypto call.
    NativeSodium.prepare()
    // Audit H81: reclaim the per-launch `%TEMP%\andvari-libsodium-*.dll` orphans 0.26.2/0.26.3
    // left behind (deleteOnExit cannot unlink a DLL JNA still has mapped). After prepare, and it
    // skips the file the property names, so it can never delete the library about to be loaded.
    NativeSodium.sweepLegacyTempExtractions()
    // Field diagnostics BEFORE any UI: confirm the native libsodium layer loads on this machine
    // (the one thing that differs between a fresh install and the dev/CI boxes where it always
    // works) and record the environment. Writes to ~/.andvari-desktop/diagnostic.log; never
    // throws. The sign-in canon flattens a native-crypto failure to the same calm line as every
    // other cause, so without this a field failure has no readable trail.
    // Audit H15: the verdict is HELD, not discarded — a failed load renders the blocking
    // "this is not a password problem" state instead of the password field (applySelfCheck).
    val selfCheck = DesktopDiagnostics.runStartupSelfCheck()
    // The onboarding and trust overhaul: the window runs the new path ([TrustApp] over the app API, built in
    // [TrustSeam]); the old path's state holder and screens are gone. Native crypto that did not load builds no engine
    // at all: the blocking screen shows instead (audit H15).
    val cryptoUnavailable = if (selfCheck is SelfCheck.CryptoUnavailable) CRYPTO_UNAVAILABLE_NOTICE else null
    // What prefs.json keeps across the cut-over: the theme and the update rollback floor (the wipe keeps them).
    val prefs = DesktopSessionStore()
    // The owner's decision of 2026-11-16: every window is hidden from screen capture on Windows unless allowed here.
    val capture = CaptureGuard.forThisComputer(prefs)
    // Nothing that fails at start or in a screen closes the window with a raw message. What
    // failed is logged redacted, the vault is locked, and the window becomes a card with Quit ([ScreenFailedCard]).
    val failure = ScreenFailure()
    val home = if (cryptoUnavailable == null) runCatching { DesktopHome() }.onFailure { failure.caught("opening this computer's files", it) }.getOrNull() else null
    // A state file that does not parse is never read as empty: the engine is not built over it until the person has
    // answered the screen that names it ([StateFileScreen]).
    val damaged = home?.let { StateFiles.damaged(it) }.orEmpty()
    fun build(h: DesktopHome): TrustModel? = runCatching { TrustSeam.model(h) }.onFailure { failure.caught("building the app", it) }.getOrNull()
    val first = if (home != null && damaged.isEmpty()) build(home) else null
    application {
        val failed by failure.failed.collectAsState()
        var damagedNow by remember { mutableStateOf(damaged) }
        var model by remember { mutableStateOf(first) }
        val theme = ThemeMode.fromStore(prefs.themeMode)
        LaunchedEffect(model) {
            val m = model
            failure.onFailure = { m?.lockNow(); clearVaultClipboard() }
        }
        when {
            failed -> PlainWindow(capture, theme) { ScreenFailedCard(DesktopDiagnostics.logFile.absolutePath, ::exitApplication) }
            damagedNow.isNotEmpty() && home != null -> PlainWindow(capture, theme) {
                StateFileScreen(
                    damagedNow,
                    startFresh = {
                        StateFiles.setAside(damagedNow).also { moved ->
                            if (moved) {
                                model = build(home)
                                damagedNow = emptyList()
                            }
                        }
                    },
                    quit = ::exitApplication,
                )
            }
            else -> CompositionLocalProvider(LocalWindowExceptionHandlerFactory provides failure.factory(), LocalCaptureGuard provides capture) {
                AppWindow(model, cryptoUnavailable, prefs, capture)
            }
        }
    }
}

/**
 * The app's one way to open a window (the owner's decision of 2026-11-16): the window exists hidden, is registered
 * with [guard] (on Windows it is excluded from screen capture unless the person allowed it), and is shown only then,
 * so no frame of it is ever drawn uncovered. Every other surface (dialogs, menus) draws inside a window made here.
 */
@Composable
private fun ApplicationScope.GuardedWindow(
    guard: CaptureGuard<java.awt.Window>,
    onPreviewKeyEvent: (androidx.compose.ui.input.key.KeyEvent) -> Boolean = { false },
    onClose: () -> Unit = ::exitApplication,
    content: @Composable androidx.compose.ui.window.FrameWindowScope.() -> Unit,
) {
    var ready by remember { mutableStateOf(false) }
    Window(
        onCloseRequest = onClose,
        title = "andvari",
        // The running window / taskbar icon (jpackage's iconFile only covers the launcher +
        // Start-menu entry). Same brand mark, loaded from resources so it rides every build.
        icon = painterResource("andvari.png"),
        state = rememberWindowState(width = 480.dp, height = 720.dp),
        visible = ready,
        onPreviewKeyEvent = onPreviewKeyEvent,
    ) {
        DisposableEffect(window) {
            guard.register(window)
            ready = true
            onDispose { guard.unregister(window) }
        }
        content()
    }
}

/**
 * A pointer event that is only the pointer moving over the window (or entering or leaving it): no click, no scroll. On a
 * kit with the shared code's idle limit it does not count as the person being there.
 */
internal fun pointerOnlyMoved(type: androidx.compose.ui.input.pointer.PointerEventType): Boolean =
    type == androidx.compose.ui.input.pointer.PointerEventType.Move ||
        type == androidx.compose.ui.input.pointer.PointerEventType.Enter ||
        type == androidx.compose.ui.input.pointer.PointerEventType.Exit

/** A window of its own for what shows instead of the app (a failure, a damaged state file). */
@Composable
private fun ApplicationScope.PlainWindow(guard: CaptureGuard<java.awt.Window>, theme: ThemeMode, content: @Composable () -> Unit) {
    GuardedWindow(guard) {
        AndvariDesktopTheme(theme) { content() }
    }
}

/** The app's window over [model] (null when native crypto did not load: the blocking screen shows). */
@Composable
private fun ApplicationScope.AppWindow(model: TrustModel?, cryptoUnavailable: String?, prefs: DesktopSessionStore, capture: CaptureGuard<java.awt.Window>) {
        val scope = rememberCoroutineScope()
        // start() runs the first-launch wipe (§12.4) and opens what this computer kept, if anything. An unexpected
        // exception there is said on the starting screen as "something went wrong", never a
        // closed app at every start; the menu's Quit stays.
        LaunchedEffect(model) { model?.start() }
        // The idle lock: the API keeps no clock, so the app ticks it once a second.
        LaunchedEffect(model) {
            while (model != null && isActive) {
                delay(1000)
                model.tick()
            }
        }
        val snapshot = model?.snapshots?.collectAsState()?.value
        // The update check: the attached server sets the channel, GitHub's releases are
        // the default; nothing is asked before a server is chosen, and the old address never. The same signed list,
        // verified against the pinned key, with the same rollback floor.
        // Attached: a server this computer holds an account on, never one only on show.
        val attached = attachedOrigin(snapshot)
        var updateReport by remember { mutableStateOf<UpdateReport?>(null) }
        val checkUpdates = {
            val origin = attached
            scope.launch {
                val r = withContext(Dispatchers.IO) { checkForUpdates(origin, prefs.lastAcceptedSeq) }
                recordUpdateReport(prefs, r)
                updateReport = r
            }
        }
        LaunchedEffect(attached) { checkUpdates() }
        val updateAvailable = (updateReport?.check as? UpdateCheck.Available)?.version
        val unlocked = snapshot?.phase == AppPhase.UNLOCKED
        // The theme chooser (UI-audit #26), now in the View menu: kept in prefs.json, which the wipe keeps.
        var theme by remember { mutableStateOf(ThemeMode.fromStore(prefs.themeMode)) }
        var aboutOpen by remember { mutableStateOf(false) }
        // "Open web vault" opens the server on show (its origin, whole), as the old Help menu opened the configured one.
        // A session with no browser opens nothing (openInBrowser fails quietly; the origin is in About and Settings).
        val webVault = snapshot?.instance?.label?.origin
    GuardedWindow(
        capture,
        // Every hardware key press counts as user activity for the inactivity auto-lock
        // (spec 01 §8). Window-level preview sees keys regardless of what has focus; never
        // consumes — EXCEPT Ctrl+L (design 2026-07-13 platform-fit §2), the panic lock. This is
        // the ONE authoritative shortcut handler: it consumes the KeyDown so the 'l' never reaches
        // a focused text field, and the menu's KeyShortcut(Key.L, ctrl) is accelerator TEXT only
        // (its onClick calls the same idempotent panicLock()). Every other key still falls through.
        onPreviewKeyEvent = {
            model?.touched()
            if (it.type == KeyEventType.KeyDown && it.isCtrlPressed && it.key == Key.L) {
                model?.lockNow(); true
            } else false
        },
        // The person's own end of the app: where changes wait in memory only, asked first (TrustModel.askBeforeQuit).
        onClose = { if (model == null) exitApplication() else model.askBeforeQuit() },
    ) {
        DisposableEffect(model) {
            model?.quit = ::exitApplication
            onDispose { model?.quit = {} }
        }
        // design 2026-07-13 platform-fit §2: the desktop command surface. Renders a native/AWT menu
        // on both target formats (Msi + Deb). Shortcuts are DECLARED here for their accelerator text
        // (the discoverability win); handling stays in onPreviewKeyEvent above (Ctrl+L) or the AWT
        // accelerator itself (Ctrl+R/Ctrl+Q) — every onClick calls an idempotent function, so a
        // double-dispatch is harmless.
        // The new path's menu, with the old one's items where the interface offers them (Sign out stays in Settings,
        // behind its confirm).
        MenuBar {
            Menu("Vault") {
                Item("Sync now", shortcut = KeyShortcut(Key.R, ctrl = true), enabled = unlocked) { model?.syncNow() }
                Item("Import passwords…", enabled = unlocked) { model?.requestImport() }
                Separator()
                // The kit on show and a sign-in's code step lock too.
                Item("Lock", shortcut = KeyShortcut(Key.L, ctrl = true), enabled = snapshot != null && model?.lockable(snapshot) == true) { model?.lockNow() }
                Separator()
                Item("Quit", shortcut = KeyShortcut(Key.Q, ctrl = true)) { if (model == null) exitApplication() else model.askBeforeQuit() }
            }
            Menu("View") {
                for (mode in ThemeMode.entries) {
                    RadioButtonItem(mode.label, selected = theme == mode) {
                        theme = mode
                        prefs.themeMode = mode.storeValue
                    }
                }
            }
            Menu("Help") {
                Item("Open web vault", enabled = webVault != null) { webVault?.let { openInBrowser(it) } }
                Item("Check for updates") { checkUpdates() }
                Separator()
                Item("About andvari") { aboutOpen = true }
            }
        }
        // Cut I (v2 #9): a hard floor — below ~480×600 the auth card and vault toolbar
        // truncate into unusability; AWT minimumSize is the only enforcement point.
        LaunchedEffect(Unit) { window.minimumSize = java.awt.Dimension(480, 600) }
        // A kit's idle warning asks the operating system for attention on this window and sounds the alert once.
        DisposableEffect(model) {
            model?.kitWarningSignal = WindowKitWarningSignal(window)
            onDispose { model?.kitWarningSignal = KitWarningSignal.None }
        }
        // Sync (and enforce the idle lock) whenever the window regains OS focus (spec 03 §6).
        DisposableEffect(Unit) {
            val focus = object : WindowFocusListener {
                // A lock that fell due comes first, then the shared code is told the window is the foreground again.
                override fun windowGainedFocus(e: WindowEvent?) {
                    model?.cameBack()
                }
                // Another application in front, with this window still on the screen: nothing of the app left the screen.
                override fun windowLostFocus(e: WindowEvent?) {}
            }
            // Minimised or hidden without a lock: nothing of the app is on show until the window is back.
            val away = object : java.awt.event.WindowAdapter() {
                override fun windowIconified(e: WindowEvent?) { model?.wentAway() }
                override fun windowDeiconified(e: WindowEvent?) { model?.cameBack() }
            }
            val hidden = object : java.awt.event.ComponentAdapter() {
                override fun componentHidden(e: java.awt.event.ComponentEvent?) { model?.wentAway() }
                override fun componentShown(e: java.awt.event.ComponentEvent?) { model?.cameBack() }
            }
            window.addWindowFocusListener(focus)
            window.addWindowListener(away)
            window.addComponentListener(hidden)
            onDispose {
                window.removeWindowFocusListener(focus)
                window.removeWindowListener(away)
                window.removeComponentListener(hidden)
            }
        }
        // Every copy in the window, a text field's own Ctrl+C, Ctrl+X and context menu included, goes through the app's
        // one secret clipboard: marked sensitive, cleared after the policy's window.
        val fieldClipboard = LocalClipboardManager.current
        val sensitiveClipboard = remember(fieldClipboard, model) {
            SensitiveClipboardManager(fieldClipboard, { model?.let { clipboardSeconds(it) } ?: io.silencelen.andvari.core.app.ServerPolicy.DEFAULT_CLIPBOARD_CLEAR_SECONDS })
        }
        CompositionLocalProvider(LocalClipboardManager provides sensitiveClipboard) {
        AndvariDesktopTheme(theme) {
            if (aboutOpen) {
                AboutDialog(webVault, updateAvailable, DesktopDiagnostics.logFile.absolutePath, updateStatusLines(updateReport, prefs.lastUpdateCheck, signedAt = prefs.lastUpdateListSignedAt)) { aboutOpen = false }
            }
            Surface {
                // Root pointer interceptor: PointerEventPass.Initial observes every pointer
                // event (press/move/scroll) before children consume it — any of them resets
                // the auto-lock window, except that a pointer that only moves does not keep a kit
                // with the shared code's idle limit on show (TrustModel.touched). Purely
                // observational; nothing is consumed.
                Column(
                    Modifier.fillMaxSize().pointerInput(Unit) {
                        awaitPointerEventScope {
                            while (true) {
                                val e = awaitPointerEvent(PointerEventPass.Initial)
                                model?.touched(moved = pointerOnlyMoved(e.type))
                            }
                        }
                    },
                ) {
                    // A found update is a soft nudge above whatever screen is showing (the old banner, unchanged).
                    // The banner names the signed list's own address for this platform when it is
                    // https on the publisher's hosts, else the project's GitHub releases page; never the relaying server.
                    (updateReport?.check as? UpdateCheck.Available)?.let { a ->
                        Surface(color = MaterialTheme.colorScheme.secondaryContainer, modifier = Modifier.fillMaxWidth()) {
                            Text(
                                updateBanner(a).shown(),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSecondaryContainer,
                                modifier = Modifier.padding(horizontal = 16.dp, vertical = 6.dp),
                            )
                        }
                    }
                    TrustApp(model, cryptoUnavailable, DesktopDiagnostics.logFile.absolutePath)
                }
            }
        }
        }
    }
}
