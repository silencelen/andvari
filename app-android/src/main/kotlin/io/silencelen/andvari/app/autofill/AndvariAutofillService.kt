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
import android.view.inputmethod.InlineSuggestionsRequest
import io.silencelen.andvari.app.SessionStore
import io.silencelen.andvari.app.VaultSession
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
 */
class AndvariAutofillService : AutofillService() {

    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
        val response = runCatching { handleFill(request) }.getOrNull()
        // onSuccess(null) is the correct "no suggestions" reply; a failure degrades to it too.
        callback.onSuccess(response)
    }

    private fun handleFill(request: FillRequest): FillResponse? {
        val structure = request.fillContexts.lastOrNull()?.structure ?: return null
        val appPackage = structure.activityComponent?.packageName ?: return null

        // Self-guard: never offer suggestions inside andvari itself (our unlock/sign-in UI).
        if (appPackage == packageName) return null

        // No auth row for a signed-out device (e.g. after revocation) — the unlock activity
        // would have no email/tokens to work with (a dead end inside another app's fill flow).
        val store = SessionStore(applicationContext)
        val session = store.load()
        if (session == null || session.accessToken.isEmpty()) return null

        // Belt-and-suspenders: make sure the process-wide auto-lock gate carries the
        // last-known policy window even if no other component set it in this process.
        VaultSession.setAutoLockSeconds(store.autoLockSeconds)

        val form = StructureParser.parse(structure)
        if (form.fields.isEmpty()) return null // no username/password field classified

        val inlineRequest: InlineSuggestionsRequest? =
            if (Build.VERSION.SDK_INT >= 30) request.inlineSuggestionsRequest else null

        // Snapshot the session ONCE; a concurrent lock() cannot NPE this reference, at worst
        // it makes the in-memory read slightly stale. getIfFresh enforces the inactivity
        // auto-lock (spec 01 §8): an idle-expired vault is locked here and the user gets
        // the unlock row instead of a silent credential fill.
        val unlocked = VaultSession.getIfFresh()
        return if (unlocked == null) {
            lockedResponse(form, inlineRequest)
        } else {
            DatasetBuilder.buildUnlockedResponse(
                this, unlocked.engine.items(), form, TrustedBrowsers.isTrusted(this, appPackage), inlineRequest,
            )
        }
    }

    /** Locked: an authentication row that launches the translucent unlock activity. */
    @Suppress("DEPRECATION") // setAuthentication(RemoteViews[, InlinePresentation]) works API 29-35
    private fun lockedResponse(form: ParsedForm, inlineRequest: InlineSuggestionsRequest?): FillResponse {
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
        return b.build()
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        // Fill-only: no SaveInfo is ever set, so this should never fire. Reply cleanly.
        callback.onSuccess()
    }

    private companion object {
        private val requestCounter = AtomicInteger(1)
        fun nextRequestCode(): Int = requestCounter.getAndIncrement()
    }
}
