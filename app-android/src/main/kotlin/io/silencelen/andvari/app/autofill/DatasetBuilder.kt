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
import android.service.autofill.SaveInfo
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
import io.silencelen.andvari.app.browserLabel
import io.silencelen.andvari.core.client.autofill.BrowserCertPins
import io.silencelen.andvari.core.client.autofill.CardFill
import io.silencelen.andvari.core.client.autofill.FieldKind
import io.silencelen.andvari.core.client.autofill.FillTarget
import io.silencelen.andvari.core.client.autofill.UriMatch

/**
 * Turns matched vault items into a [FillResponse]. LOGIN matching is PER FIELD: each field's
 * [FillTarget] embeds that field's own frame domain (only when the requesting package is a
 * trusted browser — otherwise null → androidapp:// package matching only), so one frame's
 * domain can never fill another frame's field. CARD datasets (0.7.0) are appended after the
 * login datasets under the same [MAX_DATASETS] cap — with [loginDatasetCap]'s [U20] headroom
 * so login rows can't consume every slot on a card-eligible form: every `type=="card"` item is offered
 * (deliberately NOT UriMatch-bound — wallet posture), values planned by the pure core
 * [CardFill.plan] (frame-cluster zero-fill + type-pinning), gated by an EXPLICIT browser-trust
 * check (a known-but-untrusted browser gets ZERO card datasets). Provides a dropdown
 * (RemoteViews) menu presentation always, plus an inline presentation when an
 * InlineSuggestionsRequest is present (API 30+). Item plaintext is read only from the
 * already-decrypted VaultItems; card presentations show brand + last4 + expiry ONLY.
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
        if (!form.fillable) return null // no login fields and no PAN-anchored card form
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
        // Only offer "Save to andvari?" where the saved login could actually FILL later: a native app
        // (matches by package) or a TRUSTED browser. In an UNTRUSTED known browser the fill path nulls
        // the web host, so a saved `https://host` login would never match there — a dead item. Skipping
        // save keeps save/fill symmetric: the user trusts the browser once, then both work.
        val offerSave = form.appPackage !in BrowserCertPins.TABLE || trusted
        if (datasets.isEmpty()) {
            // Honest failure (never absolute silence): the form HAS fillable fields —
            // classified USERNAME/PASSWORD or CC_* fields only, the gate that keeps this
            // row off every plain text box — so offer a single "Open andvari" row instead
            // of vanishing. Bitwarden/1Password convention; tapping launches the app.
            // A known-untrusted browser (== !offerSave) gets the "Trust {browser}" onboarding row
            // instead of the generic "Open andvari" — surfaces the one-tap fix where the wall is.
            val fallback = (if (!offerSave) trustBrowserDataset(context, form, inlineRequest) else openAppDataset(context, form, inlineRequest)) ?: return null
            val rb = FillResponse.Builder().addDataset(fallback)
            if (offerSave) saveInfoFor(form)?.let { rb.setSaveInfo(it) } // offer save even when nothing matched
            val response = runCatching { rb.build() }.getOrNull()
            // Only a DELIVERED row justifies the confident NO_URI_MATCH label downstream
            // (finishFromBuild); a failed build must read as UNKNOWN, not "no match".
            trace?.fallbackRowShown = response != null
            return response
        }
        val b = FillResponse.Builder()
        datasets.forEach { b.addDataset(it) }
        if (offerSave) saveInfoFor(form)?.let { b.setSaveInfo(it) }
        return b.build()
    }

    /**
     * SaveInfo for "Save to andvari?" — the login rule is unchanged: watch the form's username +
     * password fields, REQUIRE a password (SAVE_DATA_TYPE_PASSWORD [+USERNAME]). 0.7.0 cards: any
     * classified cc field ids are added as OPTIONAL ids so the platform hands their values to
     * onSaveRequest alongside the login trigger; a form with NO password field but WITH a
     * CC_NUMBER instead uses the number field(s) as the required trigger with
     * SAVE_DATA_TYPE_CREDIT_CARD — card-only checkouts offer save too. Null when the form has
     * neither (nothing worth saving). Set on EVERY FillResponse (match, no-match fallback, and
     * the locked auth row) so save is offered regardless of the fill outcome.
     */
    fun saveInfoFor(form: ParsedForm): SaveInfo? {
        val pw = form.fields.filter { it.kind == FieldKind.PASSWORD }
        val ccNumber = form.ccFields.filter { it.kind == FieldKind.CC_NUMBER }
        if (pw.isEmpty() && ccNumber.isEmpty()) return null
        val user = form.fields.filter { it.kind == FieldKind.USERNAME }
        var type = 0
        if (pw.isNotEmpty()) type = SaveInfo.SAVE_DATA_TYPE_PASSWORD or (if (user.isNotEmpty()) SaveInfo.SAVE_DATA_TYPE_USERNAME else 0)
        if (ccNumber.isNotEmpty()) type = type or SaveInfo.SAVE_DATA_TYPE_CREDIT_CARD
        // Required ids trigger the save UI; the rest of the cc fields ride along as optional so
        // the submitted structure carries expiry/name/CSC values for the extractor.
        // Card-only forms: the design contract is CC_NUMBER as the SOLE required id — the
        // platform shows the save UI only once EVERY required view changed, so requiring every
        // PAN-ish field (a membership/rewards input can still classify CC_NUMBER — the [T10]
        // gift guard's suppressor vocabulary is deliberately narrow and hint claims are always
        // honored) would silently suppress the prompt whenever one stays empty. Pick the anchor
        // of the RICHEST frame cluster (the real payment block has expiry/CVV siblings; a lone
        // membership input doesn't), tree order on ties. Residual platform limit (no OR
        // semantics): a user who fills only a DIFFERENT PAN field gets no prompt — accepted.
        val requiredCc = ccNumber.maxByOrNull { anchor -> form.ccFields.count { it.webDomain == anchor.webDomain } }
        val required = (if (pw.isNotEmpty()) user + pw else listOfNotNull(requiredCc)).map { it.id }
        val optional = form.ccFields.map { it.id }.filterNot { it in required }
        return runCatching {
            val b = SaveInfo.Builder(type, required.toTypedArray())
            if (optional.isNotEmpty()) b.setOptionalIds(optional.toTypedArray())
            b.build()
        }.getOrNull()
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
        // [U20] headroom: count the card datasets this form can actually yield BEFORE the login
        // loop, so a login-heavy vault can't fill every slot and shut cards out of their own
        // checkout. Zero buildable cards → cap stays MAX_DATASETS (logins are never starved
        // for cards that don't exist); the counting rail degrades to exactly that.
        val loginCap = loginDatasetCap(runCatching { countBuildableCardDatasets(items, form, trusted) }.getOrDefault(0))
        val out = ArrayList<Dataset>()
        for (item in items) {
            if (out.size >= loginCap) break
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
        // Card datasets ride AFTER the login datasets, under the same cap. runCatching rail:
        // a card-path failure degrades to "login datasets only", never a lost fill.
        runCatching { appendCardDatasets(context, items, form, trusted, specs, maxInline, out) }
        return out
    }

    /**
     * Card datasets (0.7.0): one per `type=="card"` item whose [CardFill.plan] fills anything on
     * this form. Cards are deliberately NOT UriMatch-bound (wallet posture — any checkout in a
     * trusted surface may summon the card list), which is exactly why the browser-trust gate must
     * be EXPLICIT here: the login path's UriMatch would have nulled an untrusted browser's web
     * host, but cards never consult it. A KNOWN browser that is not trusted gets ZERO card
     * datasets; native apps (not in the pin table) and trusted browsers pass. The hostile-iframe
     * zero-fill + LIST/TEXT type-pinning live in core (CardFill.plan, vector-tested).
     */
    private fun appendCardDatasets(
        context: Context,
        items: List<VaultItem>,
        form: ParsedForm,
        trusted: Boolean,
        specs: List<InlinePresentationSpec>,
        maxInline: Int,
        out: MutableList<Dataset>,
    ) {
        if (form.ccFields.isEmpty()) return
        if (form.appPackage in BrowserCertPins.TABLE && !trusted) return // explicit trust gate
        val ccFields = ccFillFields(form)
        for (item in items) {
            if (out.size >= MAX_DATASETS) break
            if (item.doc.type != "card") continue
            val card = item.doc.card ?: continue
            // Per-item rail: one malformed card degrades to a skip, not a dead response.
            runCatching {
                val plan = CardFill.plan(ccFields, card)
                if (plan.isEmpty()) return@runCatching
                val spec = specForIndex(specs, out.size, maxInline)
                buildCardDataset(context, item, form, plan, spec)?.let { out.add(it) }
            }
        }
    }

    private fun ccFillFields(form: ParsedForm): List<CardFill.CcField> = form.ccFields.mapIndexed { i, f ->
        CardFill.CcField(index = i, kind = f.kind, frameDomain = f.webDomain, autofillType = f.autofillType, options = f.options, maxLength = f.maxLength)
    }

    /**
     * [U20] pre-count for the headroom cap: how many card datasets [appendCardDatasets] would
     * build — same eligibility gates (classified cc fields + explicit browser trust) and the
     * same per-item test (a non-empty [CardFill.plan]), WITHOUT constructing framework
     * Datasets. Deliberately uncapped: the caller's `min(builtCards, 3)` does the clamping.
     */
    private fun countBuildableCardDatasets(items: List<VaultItem>, form: ParsedForm, trusted: Boolean): Int {
        if (form.ccFields.isEmpty()) return 0
        if (form.appPackage in BrowserCertPins.TABLE && !trusted) return 0
        val ccFields = ccFillFields(form)
        return items.count { item ->
            item.doc.type == "card" && item.doc.card?.let { card ->
                runCatching { CardFill.plan(ccFields, card).isNotEmpty() }.getOrDefault(false)
            } == true
        }
    }

    /**
     * [U20] the pure headroom rule (unit-tested — framework Datasets can't be constructed in a
     * JVM test, so the cap must stand alone): login rows on a card-eligible form leave room
     * for up to 3 card rows. The reserve never trims below what cards will consume (cards
     * append under [MAX_DATASETS] after logins, so ≥ min(builtCards, 3) slots remain) and a
     * zero-card form keeps the full [MAX_DATASETS] for logins.
     */
    internal fun loginDatasetCap(builtCards: Int): Int = MAX_DATASETS - minOf(builtCards, 3)

    /**
     * One card dataset. Presentation: [CardFill.presentationLine] — brand + masked last4
     * (+ expiry when composable) ONLY, never a full PAN or any CVV (test-pinned in core) —
     * with the item name as the subtitle. HAZARD guard (type-pinned 1:1): forList on a TEXT
     * node or forText on a LIST node crashes/no-ops the fill, so [CardFill.Value] is mapped
     * MECHANICALLY — Text→forText, ListIndex→forList — never improvised.
     */
    @Suppress("DEPRECATION") // 2-arg setValue at 33 (Presentations ctor companion) + legacy overloads pre-33
    private fun buildCardDataset(
        context: Context,
        item: VaultItem,
        form: ParsedForm,
        plan: List<CardFill.Planned>,
        inlineSpec: InlinePresentationSpec?,
    ): Dataset? {
        val title = CardFill.presentationLine(item.doc)
        val subtitle = item.doc.name.takeIf { it.isNotBlank() }
        val menu = presentationRow(context, title, subtitle)
        val inline = if (inlineSpec != null) buildInline(context, title, subtitle, inlineSpec) else null
        val values = plan.mapNotNull { p ->
            val f = form.ccFields.getOrNull(p.index) ?: return@mapNotNull null
            f.id to when (val v = p.value) {
                is CardFill.Value.Text -> AutofillValue.forText(v.text)
                is CardFill.Value.ListIndex -> AutofillValue.forList(v.index)
                is CardFill.Value.DateMs -> AutofillValue.forDate(v.ms)
            }
        }
        if (values.isEmpty()) return null
        return if (Build.VERSION.SDK_INT >= 33) {
            val presBuilder = Presentations.Builder().setMenuPresentation(menu)
            if (inline != null) presBuilder.setInlinePresentation(inline)
            val b = Dataset.Builder(presBuilder.build())
            for ((id, av) in values) b.setValue(id, av)
            runCatching { b.build() }.getOrNull()
        } else {
            val b = Dataset.Builder(menu) // dataset-wide menu presentation (API 26+)
            val useInline = Build.VERSION.SDK_INT >= 30 && inline != null
            for ((id, av) in values) {
                if (useInline) b.setValue(id, av, menu, inline!!) else b.setValue(id, av)
            }
            runCatching { b.build() }.getOrNull()
        }
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
            for (f in form.fields + form.ccFields) { // cc ids too, or a card-only form shows nothing
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

    /**
     * "Trust {browser} to fill here" row — shown INSTEAD of "Open andvari" when the caller is a
     * KNOWN browser andvari hasn't been trusted in yet (so nothing web can fill/save there). Tapping
     * launches [TrustBrowserActivity], which captures the browser's real on-device signing digest
     * and (with a confirm) approves it — surfacing the one-time trust step exactly where the user
     * hits the wall instead of buried in Settings. Same dataset-auth mechanics as [openAppDataset].
     */
    @Suppress("DEPRECATION")
    private fun trustBrowserDataset(context: Context, form: ParsedForm, inlineRequest: InlineSuggestionsRequest?): Dataset? =
        runCatching {
            val title = "Trust ${browserLabel(form.appPackage)} to fill here"
            val subtitle = "Tap to let andvari fill & save in this browser"
            val menu = presentationRow(context, title, subtitle)
            val spec = inlineSpecs(inlineRequest).firstOrNull()
            val inline = if (Build.VERSION.SDK_INT >= 30 && spec != null) buildInline(context, title, subtitle, spec) else null
            // MUTABLE so the platform injects EXTRA_ASSIST_STRUCTURE into the launch intent (as for
            // openAppDataset) — after trusting, the activity re-runs the fill and returns it, so the
            // dropdown updates in place instead of waiting for a page reload. Per-pkg request code so
            // concurrent browsers don't share one PendingIntent's extras.
            val flags = if (Build.VERSION.SDK_INT >= 31) {
                PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_CANCEL_CURRENT
            } else {
                PendingIntent.FLAG_CANCEL_CURRENT
            }
            val launch = Intent(context, TrustBrowserActivity::class.java)
                .putExtra(TrustBrowserActivity.EXTRA_PKG, form.appPackage)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) // fires from the browser's task; route to andvari's
            val pi = PendingIntent.getActivity(context, form.appPackage.hashCode(), launch, flags)
            val b = if (Build.VERSION.SDK_INT >= 33) {
                val pres = Presentations.Builder().setMenuPresentation(menu)
                if (inline != null) pres.setInlinePresentation(inline)
                Dataset.Builder(pres.build())
            } else {
                Dataset.Builder(menu)
            }
            for (f in form.fields + form.ccFields) { // cc ids too, or a card-only form shows nothing
                when {
                    Build.VERSION.SDK_INT >= 33 -> b.setValue(f.id, null)
                    Build.VERSION.SDK_INT >= 30 && inline != null -> b.setValue(f.id, null, menu, inline)
                    else -> b.setValue(f.id, null)
                }
            }
            b.setAuthentication(pi.intentSender)
            b.build()
        }.getOrNull()

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
