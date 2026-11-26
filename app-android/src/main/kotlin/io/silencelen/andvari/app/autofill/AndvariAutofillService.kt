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
import io.silencelen.andvari.app.trust.Placeholder
import io.silencelen.andvari.app.trust.TrustSeam
import io.silencelen.andvari.app.trust.UiText
import io.silencelen.andvari.core.client.autofill.BrowserCertPins
import java.util.concurrent.atomic.AtomicInteger

/**
 * Fill-only AutofillService (spec design §4). The whole fill path is synchronous and
 * in-memory: matched credentials come from the app's own session on the new code, the vault
 * content's working set ([ContentFillSession], [ContentFill]), so there is no network and no
 * suspend work in a callback. A save is sealed and queued for the app ([AutofillSave]), on the new code too.
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
        // onSuccess(null) is the correct "no suggestions" reply; a failure degrades to it too. Its time is the time of
        // the offer that the platform's record of a pick, read at the next request, is about.
        FillPicks.replied(System.currentTimeMillis())
        callback.onSuccess(response)
    }

    private fun handleFill(request: FillRequest, trace: AutofillDebugLog.FillTrace): FillResponse? {
        val ctx = applicationContext
        val fillContext = request.fillContexts.lastOrNull()
        val structure = fillContext?.structure
            ?: return null.also { trace.finish(ctx, AutofillDebugLog.FillReason.NO_STRUCTURE) }
        val appPackage = structure.activityComponent?.packageName
            ?: return null.also { trace.finish(ctx, AutofillDebugLog.FillReason.NO_STRUCTURE) }
        trace.pkg = appPackage

        // Self-guard: never offer suggestions inside andvari itself (our unlock/sign-in UI).
        if (appPackage == packageName) {
            trace.finish(ctx, AutofillDebugLog.FillReason.SELF_FILL)
            return null
        }

        // The new code: the app's own session (ContentFillSession), after its idle lock had its say.
        // No auth row for a signed-out device (e.g. after revocation): the unlock activity would have
        // no account to unlock (a dead end inside another app's fill flow).
        val access = ContentFillSession.access(ctx)
        if (access is ContentFillSession.Access.SignedOut) {
            trace.finish(ctx, AutofillDebugLog.FillReason.SIGNED_OUT)
            return null
        }
        // What the person picked from the last response, by the platform's own record: one use for each row picked
        // (those rows were read without recording). The platform clears its record at every reply, a form with no
        // field included, so it is read here, before any reply. Locked: the pick is not recorded (nothing is open).
        if (access is ContentFillSession.Access.Open) {
            runCatching { ContentFill.recordPicked(access.content, FillPicks.picked(FillPicks.eventsOf(fillEventHistory)), FillPicks.lastReplyAtMs) }
        }

        // The focused view comes from the system's FillContext (security review 2026-10): card values
        // are planned for that field's frame only (ParsedForm.cardFillFrame).
        val form = StructureParser.parse(structure, fillContext.focusedId)
        trace.setForm(form)
        trace.setTrust(ctx, form)
        if (!form.fillable) {
            trace.finish(ctx, AutofillDebugLog.FillReason.NO_FIELDS)
            return null // no login field and no PAN-anchored card form — a card-only checkout proceeds
        }

        val inlineRequest: InlineSuggestionsRequest? =
            if (Build.VERSION.SDK_INT >= 30) request.inlineSuggestionsRequest else null
        trace.inline = inlineRequest != null

        // The access was read ONCE above, after the idle lock (spec 01 §8): an idle-expired vault
        // was locked there and the user gets the unlock row instead of a silent credential fill.
        // Only the content's working set is read: never a vault that is not accepted, frozen or failed.
        val trusted = TrustedBrowsers.isTrusted(this, appPackage)
        return if (access !is ContentFillSession.Access.Open) {
            lockedResponse(form, inlineRequest, trusted).also { trace.finish(ctx, AutofillDebugLog.FillReason.LOCKED_ROW_SHOWN) }
        } else {
            // F12: in the background nothing else observes idle expiry; (re)arm the delayed
            // hard-lock so the vault this serve read does not stay open past the policy window.
            ContentFillSession.HardLock.arm(ctx)
            // Offers, not releases: an item's values are asked for only for a row that must carry them.
            val content = access.content
            DatasetBuilder.buildUnlockedResponse(
                this, ContentFill.offersFor(content, form, trusted), form, trusted, inlineRequest, trace, throughApp = false,
                release = { id -> ContentFill.release(content, id) },
            ).also { trace.finishFromBuild(ctx) }
        }
    }

    /** Locked: an authentication row that launches the translucent unlock activity. */
    @Suppress("DEPRECATION") // setAuthentication(RemoteViews[, InlinePresentation]) works API 29-35
    private fun lockedResponse(form: ParsedForm, inlineRequest: InlineSuggestionsRequest?, trusted: Boolean): FillResponse {
        // allIds covers login AND card fields, so unlock-and-refill works from a card-only checkout.
        val ids = form.allIds.toTypedArray()
        // FLAG_MUTABLE lets the platform add the inline specs (and its EXTRA_ASSIST_STRUCTURE) to the
        // launch intent; the flag constant only exists from API 31, and pre-31 PendingIntents
        // are mutable by default (no FLAG_IMMUTABLE), so the behavior is the same either way.
        // Root cause G (security review 2026-10): that fill-in is delivered through the HOST app, so
        // nothing in it may say who is asking. The form THIS request parsed — package, field ids,
        // frame domains — is baked into the base intent, which a fill-in cannot override, and the
        // unlock activity fills from the bake alone (FillBinding / AutofillAuthGate).
        val flags = if (Build.VERSION.SDK_INT >= 31) {
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_CANCEL_CURRENT
        } else {
            PendingIntent.FLAG_CANCEL_CURRENT
        }
        // Android review 1, ruling 1: a nonce in the base intent, retired when the unlock delivers a result, so the
        // requesting app cannot fire the same sender again for a second result (UnlockNonces).
        val pi = PendingIntent.getActivity(
            this, nextRequestCode(), FillBinding.bake(UnlockNonces.bake(Intent(this, AutofillUnlockActivity::class.java)), form), flags,
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
        // Only while saving runs on the new code and the session takes saves (DatasetBuilder.offersSave).
        if (DatasetBuilder.offersSave(form.appPackage, trusted, AutofillSave.takesSaves(this), DatasetBuilder.isWebPage(form))) DatasetBuilder.saveInfoFor(form)?.let { b.setSaveInfo(it) }
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
        // The new code (AutofillSave): the submitted login is sealed to the account's published key and queued for the
        // app, which saves or lists it at the next unlock or return to the foreground. No vault is opened here and
        // nothing is written to one. runCatching: a throw in this callback would crash the process (never-crash rail).
        val outcome = runCatching {
            val structure = request.fillContexts.lastOrNull()?.structure ?: return@runCatching null
            val raw = SaveExtractor.extract(structure)
            if (raw.appPackage == packageName) return@runCatching null // never our own screens
            // An untrusted caller's domain claim never names the capture (the fill's rule): androidapp://<pkg> instead.
            val verifiedBrowser = TrustedBrowsers.isTrusted(this, raw.appPackage)
            val creds = launderUntrustedCapture(raw, verifiedBrowser)
            AutofillSave.capture(TrustSeam.saveQueue(this), TrustSeam.crypto(this), creds, verifiedBrowser, AutofillSave.session(this), System.currentTimeMillis())
        }.getOrNull()
        runCatching { callback.onSuccess() }
        outcome?.let { o -> runCatching { android.widget.Toast.makeText(applicationContext, saveWords(o).shown(), android.widget.Toast.LENGTH_SHORT).show() } }
    }

    private companion object {
        private val requestCounter = AtomicInteger(1)
        fun nextRequestCode(): Int = requestCounter.getAndIncrement()
    }
}

/** What the person is told after "Save to andvari?" (a toast: the save UI has gone, and nothing else is on screen). */
internal fun saveWords(o: AutofillSave.Outcome): UiText = when (o) {
    AutofillSave.Outcome.QUEUED -> UiText.ph(Placeholder.SAVE_QUEUED)
    AutofillSave.Outcome.NOT_SIGNED_IN -> UiText.ph(Placeholder.SAVE_NOT_SIGNED_IN)
    AutofillSave.Outcome.NOT_NOW -> UiText.ph(Placeholder.SAVE_NOT_NOW)
    AutofillSave.Outcome.REFUSED -> UiText.ph(Placeholder.SAVE_REFUSED)
}
