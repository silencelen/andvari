package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitWipedNotice
import io.silencelen.andvari.core.app.OldDataLeft
import io.silencelen.andvari.core.app.PolicyWipeNotice
import io.silencelen.andvari.desktop.DESKTOP_VERSION
import io.silencelen.andvari.desktop.clearVaultClipboard

/**
 * The new path's root on desktop: one screen per [AppSnapshot.phase] (IF-3 "what a screen author must know" 1).
 * ENTRY shows [AppSnapshot.entry], LOCKED shows [AppSnapshot.locked], UNLOCKED shows [AppSnapshot.account].
 *
 * Before any of them, the states that block everything: native crypto missing on this computer ([cryptoUnavailable],
 * the old app's startup self-check, kept: no password field can help there), and the update wall.
 */
@Composable
fun TrustApp(model: TrustModel?, cryptoUnavailable: String?, diagnosticLogPath: String) {
    if (model == null || cryptoUnavailable != null) {
        CryptoUnavailableScreen(cryptoUnavailable ?: "", diagnosticLogPath)
        return
    }
    val s by model.snapshots.collectAsState()
    val said by model.said.collectAsState()
    LaunchedEffect(s) { model.onSnapshot(s) }
    // A secret copied from the vault does not outlive it: leaving UNLOCKED (lock, sign-out, forget) clears it, as the
    // old app's lock did. Only a value this app put there is cleared (the sensitive clipboard's own rule).
    LaunchedEffect(s.phase) { if (s.phase != AppPhase.UNLOCKED) clearVaultClipboard() }
    @Suppress("UNUSED_EXPRESSION") said // read so a new answer recomposes the screen that shows it
    // Work the vault's screens launch that a lock overtakes is said as the lock (rememberWorkScope).
    val overtook = remember(model) { { model.lockOvertook() } }
    // What the shared code throws in a screen's work, click or drawing is said in place.
    CompositionLocalProvider(LocalLockOvertook provides overtook, LocalFault provides model.fault) { Surface(Modifier.fillMaxSize()) {
        val old = s.oldData
        // The owner's decision (approved entry 6): data an earlier version left that could not be removed blocks
        // nothing. This version never opens it; core tries again at every start; the person is told once, here.
        Column(Modifier.fillMaxSize()) {
            // Above whatever is on show, in every phase, until the person dismisses it (the rule of 2026-11-17).
            KitWipedBar(model, s)
            KitWipedWayOut(model, s)
            NewAccountRememberedBar(model, s)
            PolicyWipeBar(model, s)
            QuitQuestion(model)
            KeepUnknownQuestion(model)
            NoKeyStoreQuestion(model)
            KeptUnopenableNotice(model, s)
            if (old != null && old.tellNow) OldDataNotice(model, old)
            Box(Modifier.weight(1f).escapeGoesBack(model, s)) {
                when (s.phase) {
                    AppPhase.STARTING -> Centered {
                        Sigil()
                        // The current app's loading page: something visibly moves while the start takes seconds.
                        Gap(16)
                        OpeningSpinner()
                        // A start the shared code made throw says so here (the menu's Quit stays).
                        SaidHere(model, s)
                    }
                    AppPhase.ENTRY -> s.entry?.let { EntryScreens(model, s, it) }
                    AppPhase.LOCKED -> s.locked?.let { LockScreen(model, s, it) }
                    AppPhase.UNLOCKED -> s.account?.let { AccountShell(model, s, it) }
                }
            }
        }
    } }
}

/** Escape on a signed-out screen goes back, as the phone's Back does; never on the first screen. */
private fun Modifier.escapeGoesBack(model: TrustModel, s: AppSnapshot): Modifier = onPreviewKeyEvent { e ->
    val screen = s.entry
    if (e.type == KeyEventType.KeyDown && e.key == Key.Escape && s.phase == AppPhase.ENTRY && screen != null && screen !is EntryScreen.FirstRun && !s.busy) {
        model.clearSaid()
        model.quietly { model.api.entry.back() }
        true
    } else {
        false
    }
}

/**
 * The session's server answered `UPDATE_REQUIRED`: this build is too old for it. A notice
 * above the lock screen or the open vault, never a wall. The vault stays open and readable from this computer's copy,
 * with nothing saved meanwhile ([LocalSavesHeld]), the standing of a session the server ended; "Forget this server" is
 * offered beside it behind its question, never as the only way on. Signed out, the answer is said in place instead
 * ([UiText.forResult]) and the screen stays usable.
 */
@Composable
internal fun UpdateNotice(model: TrustModel, s: AppSnapshot) {
    if (!model.updateRequiredOn(s)) return
    Column(Modifier.padding(vertical = 8.dp)) {
        Say(Placeholder.UPDATE_REQUIRED, DESKTOP_VERSION)
        s.instance?.let { ForgetServerButton(model, s, it) }
    }
}

/**
 * A recovery kit shown with this computer's refusal was wiped: a lock took it (by hand or at the kit screen's idle
 * limit), or the app was closed with it on show ([AppSnapshot.kitWiped]). Said above whatever is on show, in every phase
 * (the starting screen, the first screen, the lock screen, an open vault), until the person dismisses it; nothing
 * else here takes it away. Inside the app's one window, so the Settings switch for screen capture covers it as it covers
 * the kit.
 */
@Composable
private fun KitWipedBar(model: TrustModel, s: AppSnapshot) {
    val notice = s.kitWiped ?: return
    val drawn = LocalNoticeDrawn.current
    androidx.compose.runtime.SideEffect { drawn(notice, s.phase) }
    Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
        for (line in kitWipedLines(notice)) Say(line)
        Quieter(UiText.ph(Placeholder.DISMISS)) { model.quietly { model.api.dismissKitWiped(notice) } }
    }
}

/**
 * Told each time the notice that a kit was wiped is drawn, with the phase it is drawn above. Nothing listens in the app;
 * a test listens, to see the notice drawn in every phase (the check of 2026-11-18: a test that runs, not one that reads
 * the source).
 */
internal val LocalNoticeDrawn = androidx.compose.runtime.staticCompositionLocalOf<(KitWipedNotice, AppPhase) -> Unit> { { _, _ -> } }

/**
 * Under the notice, where it names what stands in the way on this computer and this computer can act on it, that way
 * out ([kitWipedWayOut]: the kept account's sign-out, behind the usual count and confirmations, only while the account
 * kept is shown to be another than the kit's), without a sign-in tried first (the rule of 2026-11-18). The notice itself keeps only its dismiss. Not
 * drawn where the answer on show offers the same way out already.
 */
@Composable
private fun KitWipedWayOut(model: TrustModel, s: AppSnapshot) {
    val way = kitWipedWayOut(s) ?: return
    model.said.collectAsState().value
    if (model.saidOn(s)?.let { wayOutOf(it.result, it.text, s) } != null) return
    Column(Modifier.padding(horizontal = 16.dp)) { KeptAccountRefusal(model, s, way) }
}

/**
 * What the notice that a kit was wiped says: the shared code's line; where something stands in the way on this
 * computer, the refusal's own line ([KitWipedNotice.whyHere]), which says what; and the account the kit was for.
 */
internal fun kitWipedLines(notice: KitWipedNotice): List<UiText> =
    listOfNotNull(UiText.of(notice.line), notice.whyHere?.let { UiText.of(it) }, UiText.Plain(notice.email))

/**
 * The server's policy forbids a copy of the vault on devices, and this computer's copy is gone after the shared code's one
 * try to send what waited in it ([AppSnapshot.policyWipe]). Said above whatever is on show, in every phase, until the
 * person dismisses it; the shared code decides whose notice is on show (inside an account only its own), and the
 * desktop keeps none of its own: the object on show is the one dismissed.
 */
@Composable
private fun PolicyWipeBar(model: TrustModel, s: AppSnapshot) {
    val notice = s.policyWipe ?: return
    val lines = policyWipeLines(notice)
    val drawn = LocalPolicyWipeDrawn.current
    androidx.compose.runtime.SideEffect { drawn(notice, lines, s.phase) }
    Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
        for (line in lines) Say(line)
        Quieter(UiText.ph(Placeholder.DISMISS)) { model.quietly { model.api.dismissPolicyWipe(notice) } }
    }
}

/** What the notice says, exactly as the shared code hands it: its lines, in order, and nothing else. */
internal fun policyWipeLines(notice: PolicyWipeNotice): List<UiText> = notice.lines.map { UiText.of(it) }

/** Told each time the policy's notice is drawn, with its lines as drawn and the phase. Nothing listens in the app; a test does. */
internal val LocalPolicyWipeDrawn =
    androidx.compose.runtime.staticCompositionLocalOf<(PolicyWipeNotice, List<UiText>, AppPhase) -> Unit> { { _, _, _ -> } }

/**
 * The person asked to quit (the window's close or the menu's Quit) while changes made here wait in memory only, which
 * quitting loses ([TrustModel.askBeforeQuit]): asked first, with the number, or without one where the shared code cannot
 * tell. Staying keeps everything; quitting goes on.
 */
@Composable
private fun QuitQuestion(model: TrustModel) {
    val ask = model.quitAsked.collectAsState().value ?: return
    Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
        Say(quitQuestionLine(ask))
        Quieter(UiText.ph(Placeholder.QUIT_WAITING_STAY)) { model.stayAfterQuestion() }
        Quieter(UiText.ph(Placeholder.QUIT_WAITING_ANYWAY)) { model.quitAfterQuestion() }
    }
}

/** The quit question's line: the number where it is known, otherwise the line without one. */
internal fun quitQuestionLine(ask: QuitAsk): UiText =
    ask.waiting?.let { UiText.ph(Placeholder.QUIT_WAITING, it.toString()) } ?: UiText.ph(Placeholder.QUIT_WAITING_UNKNOWN)

/**
 * The settings file that holds "keep me signed in" could not be read. Nothing kept
 * was read or deleted because of it; the app says so and asks. Either answer keeps the unreadable file under a new name.
 */
@Composable
private fun KeepUnknownQuestion(model: TrustModel) {
    val unknown by model.keepUnknown.collectAsState()
    if (!unknown) return
    Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
        Say(Placeholder.KEEP_UNKNOWN)
        Quieter(UiText.ph(Placeholder.KEEP_UNKNOWN_YES)) { model.answerKeepUnknown(true) }
        Quieter(UiText.ph(Placeholder.KEEP_UNKNOWN_NO)) { model.answerKeepUnknown(false) }
    }
}

/**
 * "Keep me signed in" on a computer with no key store (or one that refused). It says so in
 * plain words, and the person chooses: a file only their account can read, or not kept. Nothing falls back silently.
 */
@Composable
private fun NoKeyStoreQuestion(model: TrustModel) {
    val ask by model.noKeyStoreQuestion.collectAsState()
    if (!ask) return
    Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
        Say(Placeholder.KEEP_NO_KEY_STORE)
        Quieter(UiText.ph(Placeholder.KEEP_NO_KEY_STORE_FILE)) { model.answerNoKeyStore(true) }
        Quieter(UiText.ph(Placeholder.KEEP_NO_KEY_STORE_NOT)) { model.answerNoKeyStore(false) }
    }
}

/**
 * Note N2: the sign-in kept here is wrapped and could not be opened. Unknown, never "nothing kept": the person signs in
 * again, and the file is left as it is. Shown while signed out; it goes once a new sign-in is kept.
 */
@Composable
private fun KeptUnopenableNotice(model: TrustModel, s: AppSnapshot) {
    val unopenable by model.keptUnopenable.collectAsState()
    if (!unopenable || s.phase == AppPhase.UNLOCKED) return
    Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
        Say(Placeholder.KEPT_UNOPENABLE)
    }
}

/**
 * §12.4, approved entry 6: data an earlier version left could not be removed. Told once, over the screen on show:
 * the title, the body, "Try again" and "Continue" ([io.silencelen.andvari.core.app.AppApi.acknowledgeOldData]). After
 * that the title stays as a line in Settings with "Try again" ([OldDataSettingsLine]) until the data is gone.
 */
@Composable
private fun OldDataNotice(model: TrustModel, notice: OldDataLeft) {
    Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
        Say(UiText.approved("OLD_DATA_NOT_REMOVED.title"), style = MaterialTheme.typography.titleSmall)
        Say(UiText.approved("OLD_DATA_NOT_REMOVED.body"))
        Quieter(UiText.approved("OLD_DATA_NOT_REMOVED.button0")) { model.api.retryOldDataRemoval(notice) }
        Quieter(UiText.approved("OLD_DATA_NOT_REMOVED.button1")) { model.api.acknowledgeOldData(notice) }
    }
}

/** What the screens show of [OldDataLeft], as data a test can read: the notice once, then the Settings line. */
internal enum class OldDataShown { NOTHING, NOTICE, SETTINGS_LINE }

internal fun oldDataShown(old: OldDataLeft?): OldDataShown = when {
    old == null -> OldDataShown.NOTHING
    old.tellNow -> OldDataShown.NOTICE
    else -> OldDataShown.SETTINGS_LINE
}

/** The Settings line after the notice: the approved title, with "Try again", until the old data is gone. */
@Composable
internal fun OldDataSettingsLine(model: TrustModel, s: AppSnapshot) {
    val old = s.oldData ?: return
    if (oldDataShown(old) != OldDataShown.SETTINGS_LINE) return
    Say(UiText.approved("OLD_DATA_NOT_REMOVED.title"))
    Quieter(UiText.approved("OLD_DATA_NOT_REMOVED.button0"), enabled = !s.busy) { model.api.retryOldDataRemoval(old) }
}

/**
 * The old app's blocking state when native crypto did not load on this computer (audit H15), carried over: no
 * password field renders, because none could help. The sentence and the log path come from the startup self-check.
 */
@Composable
private fun CryptoUnavailableScreen(message: String, logPath: String) {
    Surface(Modifier.fillMaxSize()) {
        Centered {
            Sigil()
            Gap(16)
            Text("andvari can't start on this computer", style = MaterialTheme.typography.titleMedium)
            Text(message, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, textAlign = TextAlign.Center, modifier = Modifier.widthIn(max = 380.dp).padding(top = 8.dp))
            Gap()
            Text("Diagnostic log", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(logPath, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, textAlign = TextAlign.Center, modifier = Modifier.widthIn(max = 380.dp))
        }
    }
}
