package io.silencelen.andvari.app.autofill

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillManager
import android.view.inputmethod.InlineSuggestionsRequest
import io.silencelen.andvari.app.SessionStore
import io.silencelen.andvari.app.VaultSession
import io.silencelen.andvari.core.client.autofill.BrowserCertPins
import java.util.concurrent.atomic.AtomicInteger

/**
 * Fill-only AutofillService (spec design §4). The whole fill path is synchronous and
 * in-memory: matched credentials come from the already-decrypted [VaultSession] working
 * set (durable offline cache), so there is no network and no suspend work in a callback.
 *
 * Safety rails (binding):
 * - The entire onFillRequest body is wrapped in runCatching → onSuccess(null): a thrown
 *   exception in an autofill callback crashes the whole app process, so a lock race or any
 *   other failure must degrade to "no suggestions", never a crash.
 * - Self-guard: never fill our own screens (no recursion, no master-password capture).
 * - Signed-out device (no session / empty token): return null, not a dead-end unlock row.
 * - Never logs field values, item names, or URIs.
 *
 * Diagnostics: every formerly-silent exit records a terminal-reason event via
 * [AutofillDebugLog] (last-request summary always; the 50-event ring buffer only while
 * the Settings → Autofill status "Debug autofill (24h)" toggle is armed). All recording
 * is throw-proof and value-free — it can never break a fill or leak vault material.
 */
class AndvariAutofillService : AutofillService() {

    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
        val trace = AutofillDebugLog.FillTrace(origin = "service")
        val response = runCatching { handleFill(request, trace) }
            .onFailure { t ->
                // CLASS name only — exception messages routinely echo their input
                // (URIs, JSON, view content) and must never reach the log (never-log rule).
                trace.finish(applicationContext, AutofillDebugLog.FillReason.EXCEPTION, AutofillDebugLog.exceptionDetail(t))
            }
            .getOrNull()
        // onSuccess(null) is the correct "no suggestions" reply; a failure degrades to it too.
        callback.onSuccess(response)
    }

    private fun handleFill(request: FillRequest, trace: AutofillDebugLog.FillTrace): FillResponse? {
        val ctx = applicationContext
        val structure = request.fillContexts.lastOrNull()?.structure
            ?: return null.also { trace.finish(ctx, AutofillDebugLog.FillReason.NO_STRUCTURE) }
        val appPackage = structure.activityComponent?.packageName
            ?: return null.also { trace.finish(ctx, AutofillDebugLog.FillReason.NO_STRUCTURE) }
        trace.pkg = appPackage

        // Self-guard: never offer suggestions inside andvari itself (our unlock/sign-in UI).
        if (appPackage == packageName) {
            trace.finish(ctx, AutofillDebugLog.FillReason.SELF_FILL)
            return null
        }

        // No auth row for a signed-out device (e.g. after revocation) — the unlock activity
        // would have no email/tokens to work with (a dead end inside another app's fill flow).
        val store = SessionStore(applicationContext)
        val session = store.load()
        if (session == null || session.accessToken.isEmpty()) {
            trace.finish(ctx, AutofillDebugLog.FillReason.SIGNED_OUT)
            return null
        }

        // Belt-and-suspenders: make sure the process-wide auto-lock gate carries the
        // last-known policy window even if no other component set it in this process.
        VaultSession.setAutoLockSeconds(store.autoLockSeconds)

        val form = StructureParser.parse(structure)
        trace.setForm(form)
        trace.setTrust(ctx, form)
        if (!form.fillable) {
            trace.finish(ctx, AutofillDebugLog.FillReason.NO_FIELDS)
            return null // no login field and no PAN-anchored card form — a card-only checkout proceeds
        }

        val inlineRequest: InlineSuggestionsRequest? =
            if (Build.VERSION.SDK_INT >= 30) request.inlineSuggestionsRequest else null
        trace.inline = inlineRequest != null

        // Snapshot the session ONCE; a concurrent lock() cannot NPE this reference, at worst
        // it makes the in-memory read slightly stale. getIfFresh enforces the inactivity
        // auto-lock (spec 01 §8): an idle-expired vault is locked here and the user gets
        // the unlock row instead of a silent credential fill.
        val trusted = TrustedBrowsers.isTrusted(this, appPackage)
        val unlocked = VaultSession.getIfFresh()
        return if (unlocked == null) {
            lockedResponse(form, inlineRequest, trusted).also { trace.finish(ctx, AutofillDebugLog.FillReason.LOCKED_ROW_SHOWN) }
        } else {
            DatasetBuilder.buildUnlockedResponse(
                this, unlocked.engine.items(), form, trusted, inlineRequest, trace,
            ).also { trace.finishFromBuild(ctx) }
        }
    }

    /** Locked: an authentication row that launches the translucent unlock activity. */
    @Suppress("DEPRECATION") // setAuthentication(RemoteViews[, InlinePresentation]) works API 29-35
    private fun lockedResponse(form: ParsedForm, inlineRequest: InlineSuggestionsRequest?, trusted: Boolean): FillResponse {
        // allIds covers login AND card fields, so unlock-and-refill works from a card-only checkout.
        val ids = form.allIds.toTypedArray()
        // FLAG_MUTABLE lets the platform inject EXTRA_ASSIST_STRUCTURE + inline specs into the
        // launch intent; the flag constant only exists from API 31, and pre-31 PendingIntents
        // are mutable by default (no FLAG_IMMUTABLE), so the behavior is the same either way.
        val flags = if (Build.VERSION.SDK_INT >= 31) {
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_CANCEL_CURRENT
        } else {
            PendingIntent.FLAG_CANCEL_CURRENT
        }
        val pi = PendingIntent.getActivity(
            this, nextRequestCode(), Intent(this, AutofillUnlockActivity::class.java), flags,
        )
        val menu = DatasetBuilder.lockedPresentation(this, "Unlock andvari")
        val inline = if (Build.VERSION.SDK_INT >= 30) DatasetBuilder.lockedInline(this, inlineRequest) else null
        val b = FillResponse.Builder()
        if (inline != null) {
            b.setAuthentication(ids, pi.intentSender, menu, inline)
        } else {
            b.setAuthentication(ids, pi.intentSender, menu)
        }
        // Same trust rule as the unlocked path: no save prompt in an untrusted known browser (a saved
        // web login couldn't fill there). Native apps + trusted browsers get it.
        if (form.appPackage !in BrowserCertPins.TABLE || trusted) DatasetBuilder.saveInfoFor(form)?.let { b.setSaveInfo(it) }
        return b.build()
    }

    /**
     * "Save to andvari?" — the platform calls this when the user submits credentials in a form we
     * set [android.service.autofill.SaveInfo] on. We hand the submitted structure to
     * [SaveConfirmActivity] (via the IntentSender the framework launches after dismissing the save
     * UI), which reads the typed values, unlocks the vault if needed, confirms with the user, and
     * creates the login. runCatching so a failure degrades to a clean onSuccess() — a throw in this
     * callback would crash the host app's process (never-crash rail).
     */
    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val launched = runCatching {
            val structure = request.fillContexts.lastOrNull()?.structure ?: return@runCatching false
            val intent = Intent(this, SaveConfirmActivity::class.java)
                .putExtra(AutofillManager.EXTRA_ASSIST_STRUCTURE, structure)
            // IMMUTABLE (least privilege): unlike the fill-auth PI, the save PI already carries the
            // structure and the framework injects nothing into the save IntentSender.
            val flags = PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_CANCEL_CURRENT
            val pi = PendingIntent.getActivity(this, nextRequestCode(), intent, flags)
            callback.onSuccess(pi.intentSender) // framework launches the confirm activity after the save UI dismisses
            true
        }.getOrDefault(false)
        if (!launched) runCatching { callback.onSuccess() } // couldn't stage the activity → clean no-op, never a crash
    }

    private companion object {
        private val requestCounter = AtomicInteger(1)
        fun nextRequestCode(): Int = requestCounter.getAndIncrement()
    }
}
