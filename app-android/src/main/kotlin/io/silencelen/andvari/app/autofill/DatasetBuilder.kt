package io.silencelen.andvari.app.autofill

import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.service.autofill.InlinePresentation
import android.service.autofill.Presentations
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.view.inputmethod.InlineSuggestionsRequest
import android.widget.RemoteViews
import android.widget.inline.InlinePresentationSpec
import androidx.annotation.RequiresApi
import androidx.autofill.inline.UiVersions
import androidx.autofill.inline.v1.InlineSuggestionUi
import com.silencelen.andvari.R
import io.silencelen.andvari.app.MainActivity
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.autofill.FieldKind
import io.silencelen.andvari.core.client.autofill.FillTarget
import io.silencelen.andvari.core.client.autofill.UriMatch

/**
 * Turns matched vault items into a [FillResponse]. Matching is PER FIELD: each field's
 * [FillTarget] embeds that field's own frame domain (only when the requesting package is a
 * trusted browser — otherwise null → androidapp:// package matching only), so one frame's
 * domain can never fill another frame's field. Provides a dropdown (RemoteViews) menu
 * presentation always, plus an inline presentation when an InlineSuggestionsRequest is
 * present (API 30+). Item plaintext is read only from the already-decrypted VaultItems.
 */
object DatasetBuilder {
    const val MAX_DATASETS = 10

    /** Parse [structure], gate the browser trust, and build the unlocked response (or null). */
    fun responseForUnlocked(
        context: Context,
        structure: AssistStructure,
        items: List<VaultItem>,
        inlineRequest: InlineSuggestionsRequest?,
        trace: AutofillDebugLog.FillTrace? = null,
    ): FillResponse? {
        val form = StructureParser.parse(structure)
        trace?.pkg = form.appPackage.ifEmpty { null }
        trace?.setForm(form)
        trace?.setTrust(context, form)
        trace?.inline = inlineRequest != null
        if (form.fields.isEmpty()) return null
        return buildUnlockedResponse(context, items, form, TrustedBrowsers.isTrusted(context, form.appPackage), inlineRequest, trace)
    }

    fun buildUnlockedResponse(
        context: Context,
        items: List<VaultItem>,
        form: ParsedForm,
        trusted: Boolean,
        inlineRequest: InlineSuggestionsRequest?,
        trace: AutofillDebugLog.FillTrace? = null,
    ): FillResponse? {
        val datasets = buildDatasets(context, items, form, trusted, inlineRequest)
        trace?.let { annotate(it, items, form, trusted, datasets.size) }
        if (datasets.isEmpty()) {
            // Honest failure (never absolute silence): the form HAS fillable login fields
            // (form.fields is USERNAME/PASSWORD only — the gate that keeps this row off
            // every plain text box), so offer a single "Open andvari" row instead of
            // vanishing. Bitwarden/1Password convention; tapping launches the app.
            val fallback = openAppDataset(context, form, inlineRequest) ?: return null
            val response = runCatching { FillResponse.Builder().addDataset(fallback).build() }.getOrNull()
            // Only a DELIVERED row justifies the confident NO_URI_MATCH label downstream
            // (finishFromBuild); a failed build must read as UNKNOWN, not "no match".
            trace?.fallbackRowShown = response != null
            return response
        }
        val b = FillResponse.Builder()
        datasets.forEach { b.addDataset(it) }
        return b.build()
    }

    /**
     * Diagnostic counts for the Autofill-status screen (counts only — never names/values;
     * see AutofillDebugLog). Per-field counting mirrors [buildDatasets]' REAL fillability
     * rule — the item must carry a credential of the field's KIND (username for USERNAME
     * fields, password for PASSWORD) AND match that field's own target — so the screen
     * can't contradict what actually filled. The only deliberate difference: these are
     * RAW candidate counts, not capped at [MAX_DATASETS] (FieldSummary documents that).
     */
    private fun annotate(
        trace: AutofillDebugLog.FillTrace,
        items: List<VaultItem>,
        form: ParsedForm,
        trusted: Boolean,
        datasetCount: Int,
    ) {
        runCatching {
            trace.datasetCount = datasetCount
            val logins = items.mapNotNull { item ->
                if (item.doc.type != "login") return@mapNotNull null
                val login = item.doc.login ?: return@mapNotNull null
                if (login.username.isNullOrEmpty() && login.password.isNullOrEmpty()) return@mapNotNull null
                login
            }
            trace.loginItemCount = logins.size
            trace.setMatchCounts(
                form.fields.map { f ->
                    logins.count { login ->
                        val hasCred = when (f.kind) {
                            FieldKind.USERNAME -> !login.username.isNullOrEmpty()
                            FieldKind.PASSWORD -> !login.password.isNullOrEmpty()
                            else -> false
                        }
                        hasCred && UriMatch.matchLogins(login.uris, targetFor(f, form, trusted))
                    }
                },
            )
        }
    }

    private fun buildDatasets(
        context: Context,
        items: List<VaultItem>,
        form: ParsedForm,
        trusted: Boolean,
        inlineRequest: InlineSuggestionsRequest?,
    ): List<Dataset> {
        val specs = inlineSpecs(inlineRequest)
        val maxInline = if (Build.VERSION.SDK_INT >= 30 && inlineRequest != null) inlineRequest.maxSuggestionCount else 0
        val out = ArrayList<Dataset>()
        for (item in items) {
            if (out.size >= MAX_DATASETS) break
            if (item.doc.type != "login") continue
            val login = item.doc.login ?: continue
            val username = login.username?.takeIf { it.isNotEmpty() }
            val password = login.password?.takeIf { it.isNotEmpty() }
            if (username == null && password == null) continue

            // Per-field matching: a field is fillable by this item only when the item matches
            // THAT field's own target (which carries the field's frame domain).
            val userFields = if (username != null) {
                form.fields.filter { it.kind == FieldKind.USERNAME && UriMatch.matchLogins(login.uris, targetFor(it, form, trusted)) }
            } else emptyList()
            val passFields = if (password != null) {
                form.fields.filter { it.kind == FieldKind.PASSWORD && UriMatch.matchLogins(login.uris, targetFor(it, form, trusted)) }
            } else emptyList()
            if (userFields.isEmpty() && passFields.isEmpty()) continue

            val spec = specForIndex(specs, out.size, maxInline)
            val dataset = buildDataset(context, item, username, password, userFields, passFields, spec)
            if (dataset != null) out.add(dataset)
        }
        return out
    }

    private fun targetFor(field: ParsedField, form: ParsedForm, trusted: Boolean): FillTarget =
        FillTarget(webHost = if (trusted) field.webDomain else null, packageName = form.appPackage)

    private fun buildDataset(
        context: Context,
        item: VaultItem,
        username: String?,
        password: String?,
        userFields: List<ParsedField>,
        passFields: List<ParsedField>,
        inlineSpec: InlinePresentationSpec?,
    ): Dataset? {
        val label = item.doc.name.ifBlank { username ?: "login" }
        val menu = presentationRow(context, label, username)
        val inline = if (inlineSpec != null) buildInline(context, label, username, inlineSpec) else null
        return if (Build.VERSION.SDK_INT >= 33) {
            buildDataset33(username, password, userFields, passFields, menu, inline)
        } else {
            buildDatasetLegacy(username, password, userFields, passFields, menu, inline)
        }
    }

    @RequiresApi(33)
    @Suppress("DEPRECATION") // 2-arg setValue is the companion to the Presentations constructor
    private fun buildDataset33(
        username: String?,
        password: String?,
        userFields: List<ParsedField>,
        passFields: List<ParsedField>,
        menu: RemoteViews,
        inline: InlinePresentation?,
    ): Dataset? {
        val presBuilder = Presentations.Builder().setMenuPresentation(menu)
        if (inline != null) presBuilder.setInlinePresentation(inline)
        // Dataset-wide presentations (menu + inline) via the constructor; there is no
        // setValue(id, value, Presentations) overload — values use the 2-arg setValue.
        val b = Dataset.Builder(presBuilder.build())
        var any = false
        if (username != null) for (f in userFields) { b.setValue(f.id, AutofillValue.forText(username)); any = true }
        if (password != null) for (f in passFields) { b.setValue(f.id, AutofillValue.forText(password)); any = true }
        if (!any) return null
        return runCatching { b.build() }.getOrNull()
    }

    @Suppress("DEPRECATION") // RemoteViews/inline setValue overloads deprecated at 33; guarded above
    private fun buildDatasetLegacy(
        username: String?,
        password: String?,
        userFields: List<ParsedField>,
        passFields: List<ParsedField>,
        menu: RemoteViews,
        inlinePresentation: InlinePresentation?,
    ): Dataset? {
        val b = Dataset.Builder(menu) // dataset-wide menu presentation (API 26+)
        val values = ArrayList<Pair<AutofillId, String>>()
        if (username != null) userFields.forEach { values.add(it.id to username) }
        if (password != null) passFields.forEach { values.add(it.id to password) }
        if (values.isEmpty()) return null
        val useInline = Build.VERSION.SDK_INT >= 30 && inlinePresentation != null
        for ((id, value) in values) {
            val av = AutofillValue.forText(value)
            if (useInline) b.setValue(id, av, menu, inlinePresentation!!) else b.setValue(id, av)
        }
        return runCatching { b.build() }.getOrNull()
    }

    // ---- no-match fallback row ----

    /**
     * The always-present "Open andvari" row for a login form with ZERO matching items.
     * A dataset with `setAuthentication` and null values fills nothing — tapping launches
     * MainActivity so the user can add/inspect the login instead of concluding autofill
     * is broken. Built under runCatching: a failure degrades to the old null response.
     */
    @Suppress("DEPRECATION") // legacy setValue overloads pre-33, as in buildDatasetLegacy
    private fun openAppDataset(context: Context, form: ParsedForm, inlineRequest: InlineSuggestionsRequest?): Dataset? =
        runCatching {
            val title = "Open andvari"
            val subtitle = "No match for this app or site"
            val menu = presentationRow(context, title, subtitle)
            val spec = inlineSpecs(inlineRequest).firstOrNull()
            val inline = if (Build.VERSION.SDK_INT >= 30 && spec != null) buildInline(context, title, subtitle, spec) else null
            // FLAG_MUTABLE for the same reason as the locked auth row: the platform injects
            // fill extras into an authentication IntentSender's launch intent.
            val flags = if (Build.VERSION.SDK_INT >= 31) {
                PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            } else {
                PendingIntent.FLAG_UPDATE_CURRENT
            }
            // NEW_TASK is required: dataset-auth IntentSenders fire from the BROWSER's
            // activity (startIntentSenderForResult), so without it MainActivity would be
            // pushed onto the browser's task stack. NEW_TASK routes it to andvari's own
            // task (bringing an existing one forward — deliberately no CLEAR_TASK, which
            // would destroy whatever the user had open in the app).
            val launch = Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            val pi = PendingIntent.getActivity(context, OPEN_APP_REQUEST_CODE, launch, flags)
            val b = if (Build.VERSION.SDK_INT >= 33) {
                val pres = Presentations.Builder().setMenuPresentation(menu)
                if (inline != null) pres.setInlinePresentation(inline)
                Dataset.Builder(pres.build())
            } else {
                Dataset.Builder(menu)
            }
            // Null values: the dataset must reference at least one field id to be shown,
            // but fills nothing — the tap only fires the authentication intent.
            for (f in form.fields) {
                when {
                    Build.VERSION.SDK_INT >= 33 -> b.setValue(f.id, null)
                    Build.VERSION.SDK_INT >= 30 && inline != null -> b.setValue(f.id, null, menu, inline)
                    else -> b.setValue(f.id, null)
                }
            }
            b.setAuthentication(pi.intentSender)
            b.build()
        }.getOrNull()

    private const val OPEN_APP_REQUEST_CODE = 0x0AFD // stable id; intent is always identical

    // ---- locked-path presentations ----

    /** Menu presentation for the "Unlock andvari" authentication row. */
    fun lockedPresentation(context: Context, title: String): RemoteViews =
        presentationRow(context, title, "Tap to unlock your vault")

    /** Inline presentation for the locked auth row (API 30+ and an inline request present). */
    fun lockedInline(context: Context, inlineRequest: InlineSuggestionsRequest?): InlinePresentation? {
        if (Build.VERSION.SDK_INT < 30 || inlineRequest == null) return null
        val spec = inlineSpecs(inlineRequest).firstOrNull() ?: return null
        return buildInline(context, "Unlock andvari", "Tap to unlock your vault", spec)
    }

    // ---- helpers ----

    private fun presentationRow(context: Context, title: String, subtitle: String?): RemoteViews {
        val rv = RemoteViews(context.packageName, R.layout.autofill_dataset)
        rv.setTextViewText(R.id.andvari_autofill_title, title)
        rv.setTextViewText(R.id.andvari_autofill_subtitle, subtitle ?: "")
        return rv
    }

    private fun inlineSpecs(req: InlineSuggestionsRequest?): List<InlinePresentationSpec> =
        if (Build.VERSION.SDK_INT >= 30 && req != null) req.inlinePresentationSpecs else emptyList()

    private fun specForIndex(specs: List<InlinePresentationSpec>, index: Int, max: Int): InlinePresentationSpec? {
        if (specs.isEmpty()) return null
        if (max > 0 && index >= max) return null // honor maxSuggestionCount
        return specs[minOf(index, specs.size - 1)] // reuse the last spec for overflow (platform convention)
    }

    @RequiresApi(30)
    private fun buildInline(context: Context, title: String, subtitle: String?, spec: InlinePresentationSpec): InlinePresentation? =
        runCatching {
            if (!UiVersions.getVersions(spec.style).contains(UiVersions.INLINE_UI_VERSION_1)) return null
            val attribution = PendingIntent.getActivity(
                context, 0, Intent(context, MainActivity::class.java),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
            val builder = InlineSuggestionUi.newContentBuilder(attribution).setTitle(title)
            if (!subtitle.isNullOrEmpty()) builder.setSubtitle(subtitle)
            builder.setStartIcon(Icon.createWithResource(context, R.drawable.ic_autofill))
            InlinePresentation(builder.build().slice, spec, false)
        }.getOrNull()
}
