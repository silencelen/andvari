package io.silencelen.andvari.app.trust

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.silencelen.andvari.app.AuthColumn
import io.silencelen.andvari.app.Centered
import io.silencelen.andvari.app.ExternalExcursion
import io.silencelen.andvari.app.InProcessOverlays
import io.silencelen.andvari.app.Sigil
import io.silencelen.andvari.app.autofill.ContentFillSession
import io.silencelen.andvari.app.VERSION_LINE
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.EntryScreen

/**
 * The new path's root: one screen per [AppSnapshot.phase] (IF-3 "what a screen author must know" 1). ENTRY shows
 * [AppSnapshot.entry], LOCKED shows [AppSnapshot.locked], UNLOCKED shows [AppSnapshot.account]; exactly one is set.
 */
@Composable
fun TrustApp(model: TrustModel) {
    val s by model.snapshots.collectAsStateWithLifecycle()
    val said by model.said.collectAsStateWithLifecycle()
    LaunchedEffect(s) { model.onSnapshot(s) }
    // Lock-on-background, process-level (an in-app excursion such as rotation or a dialog is not leaving the app).
    val processOwner = androidx.lifecycle.ProcessLifecycleOwner.get()
    val appContext = androidx.compose.ui.platform.LocalContext.current.applicationContext
    DisposableEffect(processOwner) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_STOP -> {
                    val stop = processStop(ExternalExcursion.consume(), InProcessOverlays.lastStopWasOverlay())
                    // Nothing of the app is on show from here on: a kit that comes on show now is locked away as it
                    // arrives (backgrounded() says the same for the stop that locks).
                    if (stop != ProcessStop.LOCK) model.wentAway()
                    when (stop) {
                        ProcessStop.LOCK -> model.backgrounded()
                        // An autofill window closing is not leaving the app: the unlock it made holds for the idle window,
                        // and the hard lock closes it then, the same as when the app was not open at all.
                        ProcessStop.HOLD_UNTIL_IDLE -> ContentFillSession.HardLock.arm(appContext)
                        // An excursion nobody returns from still locks, after the idle window; a kit on show
                        // behind it (the system's print screen) is under the same clock, at its own limit.
                        ProcessStop.EXCURSION -> ContentFillSession.HardLock.arm(appContext)
                    }
                }
                Lifecycle.Event.ON_START -> {
                    ExternalExcursion.clear()
                    // The one lifecycle event the API takes besides lock(): an open vault reads what autofill queued
                    // meanwhile, and the event bell's ladder goes to zero.
                    model.returnedToForeground()
                }
                else -> {}
            }
        }
        processOwner.lifecycle.addObserver(observer)
        onDispose { processOwner.lifecycle.removeObserver(observer) }
    }
    // andvari's own window coming on show (this activity, not the process, which the autofill window shares): a vault
    // opened for filling while a kit is due is locked first, so the next unlock shows the kit.
    val windowOwner = androidx.lifecycle.compose.LocalLifecycleOwner.current
    DisposableEffect(windowOwner) {
        val observer = LifecycleEventObserver { _, event -> if (event == Lifecycle.Event.ON_START) model.openedAsTheApp() }
        windowOwner.lifecycle.addObserver(observer)
        onDispose { windowOwner.lifecycle.removeObserver(observer) }
    }
    @Suppress("UNUSED_EXPRESSION") said // read so a new answer recomposes the screen that shows it
    // A kit on show keeps the phone's screen on up to its own limit ([TrustModel.keepScreenOn]); nothing else does.
    KeepDisplayOn(model.keepScreenOn.collectAsStateWithLifecycle().value)
    Surface(Modifier.fillMaxSize()) {
        Column(Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing)) {
            s.oldData?.let { if (it.tellNow) OldDataNotice(model, it) }
            // A notice above the screen that stays usable, never a wall, as on the desktop.
            if (model.updateNoticeOn(s)) UpdateNotice()
            // A fault the app contained in work that answers nothing in place: said once, closable.
            WentWrongNotice(model)
            // A recovery kit that was on show with a refusal was wiped (a lock by hand, the kit's idle limit, or the app's
            // close): said above whatever is on show, in every phase, until the person dismisses it (section AZ, second
            // point; section BL, first and fourth).
            s.kitWiped?.let { KitWipedNoticeView(model, it) }
            s.rememberedNewAccount?.let { NewAccountRememberedView(model, it) }
            // The server's policy forbids a copy on devices and this phone's copy is gone: the shared code's notice, read
            // from the snapshot only (which gives it only to its own account, or where no session is kept), in every
            // phase, until the person dismisses it.
            s.policyWipe?.let { PolicyWipeNoticeView(model, it) }
            // A sign-in over a copy sealed under another master password: said once above whatever opens, until closed.
            if (s.phase == AppPhase.UNLOCKED) s.account?.signInNotice?.let { SignInNotice(model, it) }
            Box(Modifier.weight(1f)) {
                when (s.phase) {
                    AppPhase.STARTING -> Centered { Sigil() }
                    AppPhase.ENTRY -> s.entry?.let { EntryRouter(model, s, it) }
                    AppPhase.LOCKED -> s.locked?.let { LockScreen(model, s, it) }
                    AppPhase.UNLOCKED -> s.account?.let {
                        AccountShell(model, s, it)
                        // The question for the name a link carries, over whichever screen asked for a link (§6.7).
                        LinkNameDialog(model, s)
                    }
                }
            }
        }
    }
}

/**
 * The window's screen stays on while [on] (a recovery kit on show, up to its own limit), and goes back to the phone's
 * own timeout the moment it is not, or when this leaves the composition. The app's only place that keeps the screen on.
 */
@Composable
internal fun KeepDisplayOn(on: Boolean) {
    val view = androidx.compose.ui.platform.LocalView.current
    DisposableEffect(view, on) {
        view.keepScreenOn = on
        onDispose { view.keepScreenOn = false }
    }
}

/** What the process leaving the foreground does to an open vault ([processStop]). */
internal enum class ProcessStop { LOCK, HOLD_UNTIL_IDLE, EXCURSION }

/**
 * The lock-on-background rule. One behaviour for an unlock made for a fill,
 * whatever the app's state was: when the last activity to stop was one of the autofill windows
 * ([InProcessOverlays.lastStopWasOverlay]), the process stop is that window closing, not the person leaving andvari,
 * so the vault holds for the policy's idle window and the hard lock closes it ([ProcessStop.HOLD_UNTIL_IDLE]). That is
 * what already happens when the app's own screen was never open (no observer exists then). A consumed excursion (a
 * share sheet, a file picker) is not leaving either, but it arms the same hard lock, so a vault left open
 * behind an excursion nobody returns from still locks after the idle window. Anything else locks.
 */
internal fun processStop(excursionConsumed: Boolean, lastStopWasFillWindow: Boolean): ProcessStop = when {
    lastStopWasFillWindow -> ProcessStop.HOLD_UNTIL_IDLE
    excursionConsumed -> ProcessStop.EXCURSION
    else -> ProcessStop.LOCK
}

/** The signed-out journey: one composable per [EntryScreen]. Back leaves for the screen before, where there is one. */
/**
 * Whether Back leaves [screen]. Not on a claimed device link's Waiting and Code screens (the engine's `back()` refuses
 * them too): they advance by themselves and are left only with `startOver()`.
 */
internal fun entryBackLeaves(screen: EntryScreen): Boolean =
    screen !is EntryScreen.LinkDeviceWaiting && screen !is EntryScreen.LinkDeviceCode

/**
 * The app's one way to take Back. Since the app targets Android 16, Back is predictive: the Back key no longer reaches
 * `dispatchKeyEvent`, where every other key counts as activity for the idle lock, and only a registered callback hears
 * it. So a Back the app takes counts as activity here. `TargetSdkPinTest` keeps every screen on this path.
 */
@Composable
internal fun ActiveBackHandler(model: TrustModel, enabled: Boolean = true, onBack: () -> Unit) {
    BackHandler(enabled = enabled) {
        model.touched()
        onBack()
    }
}

@Composable
internal fun EntryRouter(model: TrustModel, s: AppSnapshot, screen: EntryScreen) {
    ActiveBackHandler(model, enabled = screen !is EntryScreen.FirstRun) {
        // A claimed device link (Waiting, Code) is left only with Start over: the system Back does nothing there, and
        // the app does not close under it either.
        if (!entryBackLeaves(screen)) return@ActiveBackHandler
        model.clearSaid()
        model.api.entry.back()
    }
    EntryScreens(model, s, screen)
}

/** A screen whose slice has not landed yet: says so visibly, and offers the way back. */
@Composable
internal fun NotBuilt(model: TrustModel, s: AppSnapshot, what: String) {
    AuthColumn {
        Sigil()
        Gap()
        Say(Placeholder.NOT_BUILT_YET, what)
        SaidHere(model, s)
        Gap()
        Quieter(UiText.ph(Placeholder.BACK), enabled = !s.busy) { model.act { entry.back() } }
        Quieter(UiText.ph(Placeholder.START_OVER), enabled = !s.busy) { model.act { entry.startOver() } }
    }
}

/**
 * An intent at the server on show answered `UPDATE_REQUIRED`: this build is too old for it. A notice above the lock
 * screen or the open vault, which stay as they are: the copy on this device stays readable and is read-only while
 * the state stands (core recomposes the vault with `serverStopped`, so the item screens offer no write), and nothing here offers
 * "Sign out" or "Forget this server" as the way on (those stay where they always are, behind their questions).
 */
@Composable
private fun UpdateNotice() {
    Column(Modifier.windowInsetsPadding(WindowInsets(16, 8, 16, 8))) {
        Say(UiText.ph(Placeholder.UPDATE_REQUIRED), style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.error)
        Text(VERSION_LINE, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/** [TrustModel.wentWrong]: one placeholder line and its Close; nothing of the fault itself is shown. */
@Composable
private fun WentWrongNotice(model: TrustModel) {
    val w by model.wentWrong.collectAsStateWithLifecycle()
    val shown = w ?: return
    Column(Modifier.windowInsetsPadding(WindowInsets(16, 8, 16, 8))) {
        Say(shown.text, color = MaterialTheme.colorScheme.error)
        Quieter(UiText.ph(Placeholder.CLOSE)) { model.dismissWentWrong() }
    }
}

/**
 * After a sign-in, this phone's copy had been sealed under another master password than the one typed, and now follows
 * the server's ([io.silencelen.andvari.core.app.AccountSnapshot.signInNotice]): the shared code's line, once, closable.
 */
@Composable
internal fun SignInNotice(model: TrustModel, line: io.silencelen.andvari.core.app.CopyLine) {
    Column(Modifier.windowInsetsPadding(WindowInsets(16, 8, 16, 8))) {
        Say(line)
        Quieter(UiText.ph(Placeholder.CLOSE)) { model.act { dismissSignInNotice() } }
    }
}

/**
 * [AppSnapshot.kitWiped]: the account the kit was for, the shared code's line that the kit is gone and the change stands,
 * and the refusal's own line where it still stands here ([kitWipedLines]); one dismiss, which is the only thing that
 * takes it away. Drawn in the app's own window, never in a dialog of its own, so the window's protections (no
 * screenshots, nothing in the recent-apps picture) hold for it as for the kit.
 */
@Composable
internal fun KitWipedNoticeView(model: TrustModel, notice: io.silencelen.andvari.core.app.KitWipedNotice) {
    Column(Modifier.windowInsetsPadding(WindowInsets(16, 8, 16, 8))) {
        Say(UiText.Plain(notice.email), style = MaterialTheme.typography.titleSmall)
        kitWipedLines(notice).forEachIndexed { i, line -> Say(line, color = if (i == 0) MaterialTheme.colorScheme.error else androidx.compose.ui.graphics.Color.Unspecified) }
        Quieter(UiText.ph(Placeholder.DISMISS)) { model.dismissKitWiped(notice) }
    }
}

/**
 * [AppSnapshot.policyWipe]: the server's policy forbids a copy of the vault on devices, this phone tried once to send what
 * waited and then removed its copy. Its lines as the shared code hands them ([policyWipeLines]), the first as the
 * warning it is, and one dismiss, the only thing that takes it away. Drawn in the app's own window, as the kit's notice.
 */
@Composable
internal fun PolicyWipeNoticeView(model: TrustModel, notice: io.silencelen.andvari.core.app.PolicyWipeNotice) {
    Column(Modifier.windowInsetsPadding(WindowInsets(16, 8, 16, 8))) {
        policyWipeLines(notice).forEachIndexed { i, line -> Say(line, color = if (i == 0) MaterialTheme.colorScheme.error else androidx.compose.ui.graphics.Color.Unspecified) }
        Quieter(UiText.ph(Placeholder.DISMISS)) { model.dismissPolicyWipe(notice) }
    }
}

/**
 * The notice's lines exactly as the shared code hands them, in its order
 * ([io.silencelen.andvari.core.app.PolicyWipeNotice.lines]: why the copy went and what was lost, those that may or may
 * not have arrived, the moves left half-done). The app words, adds, drops or reorders none of them: a known number is
 * never hidden because the shared code never hides it. Logins the phone caught are not part of the copy and are not here.
 */
internal fun policyWipeLines(notice: io.silencelen.andvari.core.app.PolicyWipeNotice): List<UiText> =
    notice.lines.map { UiText.of(it) }

/** The notice's lines: its [io.silencelen.andvari.core.app.KitWipedNotice.line], then what stands in the way here, if anything. */
internal fun kitWipedLines(notice: io.silencelen.andvari.core.app.KitWipedNotice): List<UiText> =
    listOfNotNull(UiText.of(notice.line), notice.whyHere?.let { UiText.of(it) })

/** §12.4: an old store could not be removed. Tell once, in the approved words (copy page, entry 6), then acknowledge. */
@Composable
private fun OldDataNotice(model: TrustModel, notice: io.silencelen.andvari.core.app.OldDataLeft) {
    Column(Modifier.windowInsetsPadding(WindowInsets(16, 8, 16, 8))) {
        Say(UiText.Plain(Approved.OLD_DATA_NOT_REMOVED_TITLE), style = MaterialTheme.typography.titleSmall)
        Say(UiText.Plain(Approved.OLD_DATA_NOT_REMOVED_BODY))
        Quieter(UiText.Plain(Approved.OLD_DATA_NOT_REMOVED_TRY_AGAIN)) { model.api.retryOldDataRemoval(notice) }
        Quieter(UiText.Plain(Approved.OLD_DATA_NOT_REMOVED_CONTINUE)) { model.api.acknowledgeOldData(notice) }
    }
}
