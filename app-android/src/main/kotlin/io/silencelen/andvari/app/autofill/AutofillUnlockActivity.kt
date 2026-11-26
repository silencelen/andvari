package io.silencelen.andvari.app.autofill

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.view.autofill.AutofillManager
import android.view.inputmethod.InlineSuggestionsRequest
import androidx.activity.compose.setContent
import androidx.fragment.app.FragmentActivity
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import io.silencelen.andvari.app.AndvariTheme
import io.silencelen.andvari.app.BrandSigil
import io.silencelen.andvari.app.SigilMark
import io.silencelen.andvari.app.trust.TrustModel
import io.silencelen.andvari.app.trust.TrustSeam
import io.silencelen.andvari.app.trust.UiText
import io.silencelen.andvari.app.trust.quickUnlockWords
import io.silencelen.andvari.core.app.AppApi
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.FastUnlock
import io.silencelen.andvari.core.app.LockedScreen
import io.silencelen.andvari.core.app.QuickUnlockResult
import io.silencelen.andvari.core.app.UnlockForFilling
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.content.VaultContent
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

/**
 * The overlay's unlock with the master password: the shared code's unlock for filling ([UnlockForFilling]), since this
 * window cannot show a recovery kit. For an account whose kit was never confirmed it opens the vault for filling and
 * makes no kit (nothing is sent about one); the kit is left to andvari's own next opening
 * ([io.silencelen.andvari.core.app.AccountSnapshot.kitDueAtOpening], [io.silencelen.andvari.app.trust.TrustModel.openedAsTheApp]).
 * It is also fast: the quiet raise of the account's password-hashing cost is put off to the next full unlock in the
 * app. Where the app interface has no such unlock, [FastUnlock] or the plain unlock.
 */
internal suspend fun overlayUnlock(api: AppApi, locked: LockedScreen, password: String): VaultUnlockResult =
    (api as? UnlockForFilling)?.unlockForFilling(locked, password)
        ?: (api as? FastUnlock)?.unlockPuttingOffReKey(locked, password)
        ?: api.unlock(locked, password)

/**
 * What the unlock window says when an unlock threw: the lock as the lock, anything else as a fault
 * the app contained, in the general line: nothing is open while an unlock fails, so the vault's line ("your other vaults
 * and the rest of andvari still work") would claim what nobody knows. Never the exception's class or message: either
 * can say what it was working on.
 *
 * "The keys are gone" here is not a lock the person could undo by unlocking: the shared code answers a lock or an end
 * that came during the unlock with STALE ([io.silencelen.andvari.core.app.VaultUnlockResult.STALE]), and the throw
 * reaches this window only when the keys the unlock had just opened went before it finished, which the session's end by
 * its server does too ([io.silencelen.andvari.core.client.AccountWipedException]). So [now], the snapshot after the
 * throw, decides: the lock screen of a session the server ended, or no lock screen at all, is that end; otherwise the
 * unlock did not finish and can be tried again. Never "do it again once you've unlocked": the thing to do again was the
 * unlock.
 */
internal fun unlockFaultWords(t: Throwable, now: io.silencelen.andvari.core.app.AppSnapshot): UiText = when {
    !io.silencelen.andvari.app.Overtaken.isLock(t) -> UiText.ph(io.silencelen.andvari.app.trust.Placeholder.WENT_WRONG)
    now.phase == io.silencelen.andvari.core.app.AppPhase.ENTRY || now.locked?.signedOutByServer == true ->
        UiText.ph(io.silencelen.andvari.app.trust.Placeholder.SESSION_ENDED_OVERTOOK)
    else -> UiText.ph(io.silencelen.andvari.app.trust.Placeholder.UNLOCK_NOT_FINISHED)
}

/**
 * Translucent activity for the LOCKED autofill path. The platform launches it from the
 * service's `setAuthentication` PendingIntent (adding, on API 30+, the inline request). It prompts
 * for the master password (or offers quick unlock), unlocks the app's OWN session on the new code
 * ([TrustSeam]'s app API: `unlock` / `quickUnlock`), builds datasets from the vault content's working
 * set ([ContentFill]) for the form the SERVICE parsed and baked into that PendingIntent
 * ([FillBinding]), and returns them via EXTRA_AUTHENTICATION_RESULT.
 *
 * Security review 2026-10 (root cause G): the launch also carries an EXTRA_ASSIST_STRUCTURE, but it
 * arrives through the HOST app's process, which can replace it with one claiming to be a trusted
 * browser on any domain. It is never parsed here — only cross-checked against the baked package, and
 * a disagreement refuses the fill.
 *
 * Single token-holder invariant (binding blocker): this activity opens no session of its own. It
 * unlocks the ONE process-wide app API the main app uses, so the session it opens is the app's, and
 * the main app finds it open; there is never a second token-holder. The session stays open for the
 * policy's idle window only ([ContentFillSession.HardLock]), as it did on the old code.
 */
class AutofillUnlockActivity : FragmentActivity() {

    private var busy by mutableStateOf(false)
    private var errorText by mutableStateOf<String?>(null)

    /** This launch's one-use nonce ([UnlockNonces]); retired when a result is delivered. */
    private var nonce: String? = null

    /** Per-launch diagnostic trace (see AutofillDebugLog) — terminal events only, no values. */
    private val trace = AutofillDebugLog.FillTrace(origin = "unlock")

    private val model: TrustModel by lazy { TrustSeam.model(applicationContext) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // This overlay takes the master password — keep it out of screen recordings/casts
        // (it is already excludeFromRecents, so no thumbnail concern).
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        // Other apps' overlays are hidden while the unlock card is shown (API 31+).
        if (Build.VERSION.SDK_INT >= 31) window.setHideOverlayWindows(true)
        // Touches through another window are dropped here too ([FillWindow]); the window is opaque.
        window.decorView.filterTouchesWhenObscured = true
        // Default result is CANCELED (back / dismiss returns cleanly with no fill).
        setResult(RESULT_CANCELED)

        // Root cause G: identity comes from the service's bake, never from the host-delivered structure.
        val form = FillBinding.resolve(intent)
        if (form == null) {
            trace.finish(applicationContext, AutofillDebugLog.FillReason.BINDING_REFUSED)
            finish(); return
        }
        // Ruling 1: a sender that already delivered a result (or one this process never minted) shows nothing and
        // returns nothing. A cancelled prompt left its nonce live, so the same row can be tried again.
        nonce = UnlockNonces.of(intent)
        if (!UnlockNonces.tokens.isLive(nonce)) {
            trace.finish(applicationContext, AutofillDebugLog.FillReason.BINDING_REFUSED)
            finish(); return
        }
        val inlineRequest = intent.inlineRequest()
        // Quick unlock's prompt is shown over this activity (the main activity attaches itself the same way).
        TrustSeam.keyWrap(applicationContext).attach(this)

        // A cold process started for this fill reads its stored state first (STARTING); wait for it, bounded.
        lifecycleScope.launch {
            withTimeoutOrNull(STARTING_WAIT_MS) { model.api.snapshots.first { it.phase != AppPhase.STARTING } }
            begin(form, inlineRequest)
        }
    }

    override fun onDestroy() {
        runCatching { TrustSeam.keyWrap(applicationContext).detach(this) }
        super.onDestroy()
    }

    private val obscuredTold = BooleanArray(1)

    /** On Android 10 and 11 a touch while the window is partly covered is dropped ([FillWindow]). */
    override fun dispatchTouchEvent(ev: android.view.MotionEvent): Boolean = FillWindow.dispatch(this, ev, obscuredTold) { super.dispatchTouchEvent(it) }

    private fun begin(form: ParsedForm, inlineRequest: InlineSuggestionsRequest?) {
        // Fast path: already unlocked in this process (e.g. the main app unlocked first) — no prompt.
        // The access is read after the idle lock (spec 01 §8): an idle-expired vault was locked
        // there and falls through to the master-password prompt below.
        when (val access = ContentFillSession.access(applicationContext)) {
            is ContentFillSession.Access.Open -> {
                ContentFillSession.HardLock.arm(applicationContext)
                finishFromContent(access.content, form, inlineRequest)
                return
            }
            ContentFillSession.Access.SignedOut -> {
                trace.finish(applicationContext, AutofillDebugLog.FillReason.SIGNED_OUT)
                finish(); return
            }
            ContentFillSession.Access.Locked -> Unit
        }
        val locked = model.api.snapshot.locked
        if (locked == null) { // still starting after the wait, or signed out meanwhile
            trace.finish(applicationContext, AutofillDebugLog.FillReason.SIGNED_OUT)
            finish(); return
        }

        // Cut F review: adjustResize never worked in translucent windows (and is inert under
        // Android 15 edge-to-edge) — insets must be dispatched and consumed in Compose instead,
        // or the IME simply covers the centered card and Unlock stays unreachable.
        androidx.core.view.WindowCompat.setDecorFitsSystemWindows(window, false)
        setContent {
            AndvariTheme {
                UnlockCard(
                    email = locked.prompt.email.orEmpty(),
                    busy = busy,
                    error = errorText,
                    offerBiometricHint = false,
                    notice = fillUnlockNoticeText(locked),
                    onUnlock = { pw -> unlockAndFinish(locked, pw, form, inlineRequest) },
                    onCancel = { finish() },
                )
            }
        }
        // Exclude the whole overlay (incl. the master-password field) from autofill —
        // belt-and-suspenders with the service self-guard.
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS

        // Quick unlock (spec 01 §8 / design §3): over the still-rendered password card, auto-show
        // the prompt when the lock screen offers it. Any failure/cancel leaves the password card in
        // place (never neither, design §5).
        if (locked.quickUnlock) tryQuickUnlock(locked, form, inlineRequest)
    }

    /** The app's quick unlock, over the password card; a refusal says why in the API's words, a cancel says nothing. */
    private fun tryQuickUnlock(locked: LockedScreen, form: ParsedForm, inlineRequest: InlineSuggestionsRequest?) {
        if (busy) return
        lifecycleScope.launch {
            val r = runCatching { model.api.quickUnlock(locked) }.getOrElse { t ->
                recordException(t)
                errorText = unlockFaultWords(t, model.api.snapshot).shown()
                return@launch
            }
            if (r == QuickUnlockResult.DONE) {
                unlocked(form, inlineRequest)
            } else {
                quickUnlockWords(r, model.api.retryAfterSeconds())?.let { errorText = it.shown() }
            }
        }
    }

    private fun unlockAndFinish(
        locked: LockedScreen,
        password: String,
        form: ParsedForm,
        inlineRequest: InlineSuggestionsRequest?,
    ) {
        if (busy) return
        busy = true
        errorText = null
        lifecycleScope.launch {
            val r = runCatching { overlayUnlock(model.api, locked, password) }.getOrElse { t ->
                recordException(t)
                busy = false
                errorText = unlockFaultWords(t, model.api.snapshot).shown()
                return@launch
            }
            if (r == VaultUnlockResult.DONE) {
                unlocked(form, inlineRequest)
            } else {
                busy = false
                // The API's own sentence for what it answered (a wrong password, a blocked server, ...).
                errorText = (UiText.forResult(r, model.api.retryAfterSeconds()) ?: UiText.ph(io.silencelen.andvari.app.trust.Placeholder.REFUSAL)).shown()
            }
        }
    }

    /** The session is open: the person just acted, the idle window starts now, and the hard lock is armed for it. */
    private suspend fun unlocked(form: ParsedForm, inlineRequest: InlineSuggestionsRequest?) {
        busy = true
        model.touched()
        // This window opened the vault, so its own close (and the chooser's or a confirm's after it)
        // is not the person leaving andvari: the vault holds for the idle window. The fast path never says so.
        io.silencelen.andvari.app.InProcessOverlays.noteVaultOpenedByFillWindow()
        ContentFillSession.HardLock.arm(applicationContext)
        val access = ContentFillSession.access(applicationContext)
        if (access !is ContentFillSession.Access.Open) {
            // DONE but no open vault to fill from (the unlock for filling opens one even where the kit was never
            // confirmed; this stays for an app interface without it): nothing is offered.
            trace.finish(applicationContext, AutofillDebugLog.FillReason.SIGNED_OUT)
            finishWithResponse(null)
            return
        }
        // The first sync after the unlock, bounded, so the fill offers the vault and not an empty list.
        ContentFillSession.ready(access.content)
        finishFromContent(access.content, form, inlineRequest)
    }

    private fun finishFromContent(content: VaultContent, form: ParsedForm, inlineRequest: InlineSuggestionsRequest?) {
        // Any throwable building the response must degrade to CANCELED, never crash the
        // host app's fill flow (an uncaught throw in this callback path kills the process).
        finishAfterUnlock(runCatching {
            val trusted = TrustedBrowsers.isTrusted(this, form.appPackage)
            if (!form.fillable) {
                null
            } else {
                DatasetBuilder.responseForUnlocked(this, form, ContentFill.offersFor(content, form, trusted), inlineRequest, trace) { id -> ContentFill.release(content, id) }
            }
        }.onFailure { recordException(it) }.getOrNull())
    }

    /** Terminal EXCEPTION event for a throw while (re)building datasets; trace records
     *  once, so a later finishFromBuild becomes a no-op instead of mislabeling it.
     *  CLASS name only — exception messages echo their input (never-log rule). */
    private fun recordException(t: Throwable) {
        trace.finish(applicationContext, AutofillDebugLog.FillReason.EXCEPTION, AutofillDebugLog.exceptionDetail(t))
    }

    /**
     * Post-unlock finish. The FillResponse is delivered IMMEDIATELY — this activity is
     * noHistory, so ANY deferral window (screen-off, home, a call) can cancel the
     * coroutine and silently drop the response, incl. the "Open andvari" fallback row;
     * correctness of delivery beats an acknowledgement card. The no-match acknowledgement
     * is therefore a Toast (fires-and-forgets past finish(), gates nothing) and is shown
     * ONLY for a KNOWN no-match (counts computed, zero credential datasets, no exception
     * recorded) — an internal error must never masquerade as "no login matches".
     */
    private fun finishAfterUnlock(response: android.service.autofill.FillResponse?) {
        val knownNoMatch = trace.datasetCount == 0 && trace.loginItemCount >= 0
        trace.finishFromBuild(applicationContext)
        if (knownNoMatch) {
            runCatching {
                android.widget.Toast.makeText(
                    applicationContext,
                    "Unlocked — no saved login matches this app or site",
                    android.widget.Toast.LENGTH_SHORT,
                ).show()
            }
        }
        finishWithResponse(response)
    }

    private fun finishWithResponse(response: android.service.autofill.FillResponse?) {
        // Ruling 1: the sender is used up by its first result. Retired before anything is set, and only the call that
        // retires it may deliver: a second launch racing this one gets nothing.
        if (!UnlockNonces.tokens.retire(nonce)) {
            setResult(RESULT_CANCELED)
            finish()
            return
        }
        if (response != null) {
            setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response))
        } else {
            setResult(RESULT_CANCELED) // unlocked, but nothing matched this form
        }
        finish()
    }

    @Suppress("DEPRECATION")
    private fun Intent.inlineRequest(): InlineSuggestionsRequest? {
        if (Build.VERSION.SDK_INT < 30) return null
        return if (Build.VERSION.SDK_INT >= 33) {
            getParcelableExtra(AutofillManager.EXTRA_INLINE_SUGGESTIONS_REQUEST, InlineSuggestionsRequest::class.java)
        } else {
            getParcelableExtra(AutofillManager.EXTRA_INLINE_SUGGESTIONS_REQUEST)
        }
    }

    private companion object {
        /** How long a cold process may take to read its stored state before the fill gives up. */
        const val STARTING_WAIT_MS = 5_000L
    }
}

/**
 * The fill unlock's notice: under a session the server ended ([LockedScreen.signedOutByServer]) the password opens this
 * device's copy read-only, a fill may come from it, and nothing is saved (design §4.4); the card says so before the
 * person types. Under a server policy that forbids keeping data on the phone there is no copy to fill from: the shared
 * code's line that the account's keys are kept at the server ([LockedScreen.keysAtServerLine]) stands there instead, as
 * handed. Null for an ordinary lock.
 */
internal fun fillUnlockNotice(locked: LockedScreen): UiText? = when {
    locked.keysAtServerLine != null -> io.silencelen.andvari.app.trust.lockKeysAtServerLine(locked)
    locked.signedOutByServer -> UiText.ph(io.silencelen.andvari.app.trust.Placeholder.FILL_FROM_COPY)
    else -> null
}

/**
 * Above the fill unlock's notice, where the account's keys are kept at the server and the session has ended: the shared
 * code's line for that end ([LockedScreen.endLine]), as the lock screen says it, so the person reads before typing that
 * nothing opens here until they sign in again. Null otherwise (the notice alone says the rest).
 */
internal fun fillUnlockEndLine(locked: LockedScreen): UiText? =
    locked.endLine?.takeIf { locked.keysAtServerLine != null }?.let { UiText.of(it) }

/** What the fill unlock's card says above the field: [fillUnlockEndLine], then [fillUnlockNotice], one per line; null for an ordinary lock. */
internal fun fillUnlockNoticeText(locked: LockedScreen): String? =
    listOfNotNull(fillUnlockEndLine(locked), fillUnlockNotice(locked)).takeIf { it.isNotEmpty() }?.joinToString("\n") { it.shown() }

@androidx.compose.runtime.Composable
internal fun UnlockCard(
    email: String,
    busy: Boolean,
    error: String?,
    /**
     * This device COULD use a fingerprint here but has not enrolled (design §7.1). The overlay
     * cannot enroll — enrollment needs the UVK and the vault is locked at this exact moment — so
     * the line NAMES where the switch is rather than pretending to be a button.
     *
     * It matters most right here: since lock-on-background, this overlay is where the user feels
     * the cost of not having biometrics, and it was the one screen that never mentioned they were
     * a possibility.
     */
    offerBiometricHint: Boolean,
    /** What the card says above the field, when the session is not an ordinary one ([fillUnlockNotice]). */
    notice: String?,
    onUnlock: (String) -> Unit,
    onCancel: () -> Unit,
) {
    var password by remember { mutableStateOf("") }
    // Cut F (v2 #5): scrollable — the centered fixed card left Unlock unreachable with the
    // IME open in landscape / split-screen / half-fold.
    Column(
        Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing).verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                // #25: geometry, not the raw ᛅ codepoint — this overlay renders over arbitrary
                // apps, exactly where a tofu box would undercut the anti-spoof brand signal.
                SigilMark(BrandSigil, 40.dp)
                Text("Unlock andvari", style = MaterialTheme.typography.titleLarge)
                Text(email, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (notice != null) {
                    Spacer(Modifier.height(8.dp))
                    Text(notice, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error, textAlign = TextAlign.Center)
                }
                Spacer(Modifier.height(16.dp))
                // a11yand-07: this overlay is a ONE-field password form rendered over another
                // app — reaching the Unlock button is the whole interaction, so the IME's Done
                // must submit it (same gate as the button), not merely close the keyboard.
                val submit = { if (password.isNotBlank() && !busy) onUnlock(password) }
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("Master password") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    visualTransformation = PasswordVisualTransformation(),
                    // Cut E (v2 #4): declare the secret to the IME — no suggestion strip, no
                    // personal-dictionary learning of the master password.
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false, imeAction = ImeAction.Done),
                    keyboardActions = KeyboardActions(onDone = { submit() }),
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                )
                if (error != null) {
                    Spacer(Modifier.height(8.dp))
                    // a11yand-15: the main app routes every error through ErrorBar/InlineError, both
                    // of which announce; these overlay activities were outside that sweep, so a
                    // TalkBack user who mistypes their master password mid-fill heard NOTHING.
                    // Assertive, like ErrorBar — this is the service's most consequential error.
                    Text(error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Assertive })
                }
                Spacer(Modifier.height(16.dp))
                Button(
                    onClick = { onUnlock(password) },
                    enabled = password.isNotBlank() && !busy,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    // a11yand-08: name the busy spinner with the button's action (see PrimaryButton).
                    if (busy) CircularProgressIndicator(Modifier.height(18.dp).semantics { contentDescription = "Unlock"; stateDescription = "working" }, strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                    else Text("Unlock")
                }
                TextButton(onClick = onCancel, enabled = !busy) { Text("Cancel") }
                if (offerBiometricHint) {
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "Tip: turn on fingerprint unlock in andvari's settings and this becomes a touch.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                    )
                }
            }
        }
    }
}
