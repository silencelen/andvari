package io.silencelen.andvari.app.autofill

import android.app.assist.AssistStructure
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import io.silencelen.andvari.app.AndvariTheme
import io.silencelen.andvari.app.BrandSigil
import io.silencelen.andvari.app.QuickUnlock
import io.silencelen.andvari.app.Session
import io.silencelen.andvari.app.SessionStore
import io.silencelen.andvari.app.SigilMark
import io.silencelen.andvari.app.VaultSession
import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.HouseholdCopy
import io.silencelen.andvari.core.crypto.CryptoException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException

/**
 * Translucent activity for the LOCKED autofill path. The platform launches it from the
 * service's `setAuthentication` PendingIntent, injecting EXTRA_ASSIST_STRUCTURE (and, on
 * API 30+, the inline request). It prompts for the master password, unlocks the vault into
 * [VaultSession], rebuilds datasets exactly as the service would, and returns them via
 * EXTRA_AUTHENTICATION_RESULT.
 *
 * Single token-holder invariant (binding blocker): the api is built EXACTLY like
 * AndvariViewModel.newApi — with an HttpClient engine AND the SessionStore.updateTokens
 * persistence callback — and bound into VaultSession so the main app reuses the SAME
 * token-holder. Building a token-carrying api without the onTokens callback would rotate
 * the refresh token in memory only; the next main-app unlock would reuse the consumed token
 * and revoke the whole device. If a session is already bound (a race), we reuse it and never
 * mint a second token-holder.
 */
class AutofillUnlockActivity : FragmentActivity() {

    private var busy by mutableStateOf(false)
    private var errorText by mutableStateOf<String?>(null)

    /** Per-launch diagnostic trace (see AutofillDebugLog) — terminal events only, no values. */
    private val trace = AutofillDebugLog.FillTrace(origin = "unlock")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // This overlay takes the master password — keep it out of screen recordings/casts
        // (it is already excludeFromRecents, so no thumbnail concern).
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        // Default result is CANCELED (back / dismiss returns cleanly with no fill).
        setResult(RESULT_CANCELED)

        val structure = intent.assistStructure()
        if (structure == null) {
            trace.finish(applicationContext, AutofillDebugLog.FillReason.NO_STRUCTURE)
            finish(); return
        }
        val inlineRequest = intent.inlineRequest()

        // Cold-process safety: arm the auto-lock gate with the persisted policy window
        // before consulting it (this activity never fetches policy itself).
        VaultSession.setAutoLockSeconds(SessionStore(applicationContext).autoLockSeconds)

        // Fast path: already unlocked in this process (e.g. the main app unlocked first) —
        // reuse it, build datasets immediately, no password prompt, no second token-holder.
        // getIfFresh enforces the inactivity window (spec 01 §8): an idle-expired vault is
        // locked and falls through to the master-password prompt below.
        VaultSession.getIfFresh()?.let { unlocked ->
            // F12: (re)arm the autofill-process hard-lock — this serve may be the last thing
            // that ever looks at the session in this process (no-op when auto-lock is off).
            AutofillHardLock.arm()
            // Any throwable building the response must degrade to CANCELED, never crash the
            // host app's fill flow (an uncaught throw in this callback path kills the process).
            finishAfterUnlock(runCatching {
                DatasetBuilder.responseForUnlocked(this, structure, unlocked.engine.items(), inlineRequest, trace)
            }.onFailure { recordException(it) }.getOrNull())
            return
        }

        val store = SessionStore(applicationContext)
        val session = store.load()
        if (session == null || session.accessToken.isEmpty()) { // signed out
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
                    email = session.email,
                    busy = busy,
                    error = errorText,
                    onUnlock = { pw -> unlockAndFinish(store, session, pw, structure, inlineRequest) },
                    onCancel = { finish() },
                )
            }
        }
        // Exclude the whole overlay (incl. the master-password field) from autofill —
        // belt-and-suspenders with the service self-guard.
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS

        // Quick unlock (spec 01 §8 / design §3): over the still-rendered password card, auto-show
        // the BiometricPrompt when eligible + enrolled + within the 30-day window. Any
        // failure/cancel leaves the password card in place (never neither, design §5).
        val dir = applicationContext.noBackupFilesDir
        if (QuickUnlock.isEligible(applicationContext, store) &&
            QuickUnlock.isEnrolled(dir, session.userId) &&
            QuickUnlock.isFresh(store, session.userId)
        ) {
            tryBiometricUnlock(store, session, structure, inlineRequest)
        }
    }

    /** Recover the UVK behind a BiometricPrompt, then unlock via the UVK path and finish exactly
     *  like the password path. Never crashes the fill callback (runCatching rails). */
    private fun tryBiometricUnlock(
        store: SessionStore,
        session: Session,
        structure: AssistStructure,
        inlineRequest: InlineSuggestionsRequest?,
    ) {
        if (busy) return
        lifecycleScope.launch {
            when (val r = QuickUnlock.recoverUvk(this@AutofillUnlockActivity, applicationContext.noBackupFilesDir, session.userId)) {
                is QuickUnlock.Recover.Ok -> {
                    busy = true
                    errorText = null
                    val result = runCatching {
                        withContext(Dispatchers.IO) { AutofillUnlock.unlockWithUvk(this@AutofillUnlockActivity, store, session, r.uvk) }
                    }
                    result.onSuccess { unlocked ->
                        finishAfterUnlock(runCatching {
                            DatasetBuilder.responseForUnlocked(
                                this@AutofillUnlockActivity, structure, unlocked.engine.items(), inlineRequest, trace,
                            )
                        }.onFailure { recordException(it) }.getOrNull())
                    }.onFailure { t ->
                        busy = false
                        // design §5: a stale/foreign UVK (identity SEED won't open) wipes the blob;
                        // an identityPub MISMATCH is a hard fault — keep the blob (evidence), banner.
                        if (t is CryptoException && !isIdentityMismatch(t)) {
                            QuickUnlock.wipe(applicationContext.noBackupFilesDir, session.userId)
                        }
                        errorText = friendly(t)
                    }
                }
                // Card is already on screen; surface the mapped reason (wipe-class events already
                // deleted the blob inside recoverUvk).
                is QuickUnlock.Recover.Fallback -> r.reason?.let { errorText = it }
                is QuickUnlock.Recover.Wiped -> errorText = r.reason
            }
        }
    }

    private fun isIdentityMismatch(t: Throwable): Boolean =
        t.message?.contains("identity key mismatch") == true

    private fun unlockAndFinish(
        store: SessionStore,
        session: Session,
        password: String,
        structure: AssistStructure,
        inlineRequest: InlineSuggestionsRequest?,
    ) {
        if (busy) return
        busy = true
        errorText = null
        lifecycleScope.launch {
            val result = runCatching {
                withContext(Dispatchers.IO) { AutofillUnlock.unlock(this@AutofillUnlockActivity, store, session, password) }
            }
            result.onSuccess { unlocked ->
                // Rebuild datasets exactly as the service would, from the durable cache.
                // Any throwable here degrades to CANCELED rather than crashing the host app.
                finishAfterUnlock(runCatching {
                    DatasetBuilder.responseForUnlocked(
                        this@AutofillUnlockActivity, structure, unlocked.engine.items(), inlineRequest, trace,
                    )
                }.onFailure { recordException(it) }.getOrNull())
            }.onFailure { t ->
                busy = false
                errorText = friendly(t)
            }
        }
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
        if (response != null) {
            setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response))
        } else {
            setResult(RESULT_CANCELED) // unlocked, but nothing matched this form
        }
        finish()
    }

    /** #23: this overlay pre-maps its two lane-specific contexts — it renders inside ANOTHER
     *  app (so a dead session must say "open andvari"), and [AutofillUnlock.unlock] only
     *  throws IO when there are NO cached keys — then delegates everything else to the shared
     *  household canon. Never the exception's raw message (the old `t.message ?: …`). */
    private fun friendly(t: Throwable): String = when {
        t is ApiException && t.status == 401 -> HouseholdCopy.SESSION_EXPIRED_AUTOFILL
        t is IOException -> HouseholdCopy.UNLOCK_OFFLINE_NO_KEYS
        else -> HouseholdCopy.forUnlockError(t)
    }

    @Suppress("DEPRECATION")
    private fun Intent.assistStructure(): AssistStructure? =
        if (Build.VERSION.SDK_INT >= 33) {
            getParcelableExtra(AutofillManager.EXTRA_ASSIST_STRUCTURE, AssistStructure::class.java)
        } else {
            getParcelableExtra(AutofillManager.EXTRA_ASSIST_STRUCTURE)
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
}

@androidx.compose.runtime.Composable
private fun UnlockCard(
    email: String,
    busy: Boolean,
    error: String?,
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
                Spacer(Modifier.height(16.dp))
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("Master password") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    visualTransformation = PasswordVisualTransformation(),
                    // Cut E (v2 #4): declare the secret to the IME — no suggestion strip, no
                    // personal-dictionary learning of the master password.
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false),
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                )
                if (error != null) {
                    Spacer(Modifier.height(8.dp))
                    Text(error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
                Spacer(Modifier.height(16.dp))
                Button(
                    onClick = { onUnlock(password) },
                    enabled = password.isNotBlank() && !busy,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    if (busy) CircularProgressIndicator(Modifier.height(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                    else Text("Unlock")
                }
                TextButton(onClick = onCancel, enabled = !busy) { Text("Cancel") }
            }
        }
    }
}
