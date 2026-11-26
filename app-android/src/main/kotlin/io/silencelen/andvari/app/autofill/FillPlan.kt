package io.silencelen.andvari.app.autofill

import io.silencelen.andvari.app.trust.Placeholder
import io.silencelen.andvari.app.trust.UiText
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.autofill.AppFillGate
import io.silencelen.andvari.core.client.autofill.BrowserCertPins
import io.silencelen.andvari.core.client.autofill.CardFill
import io.silencelen.andvari.core.client.autofill.FieldKind
import io.silencelen.andvari.core.client.autofill.FillTarget
import io.silencelen.andvari.core.client.autofill.SavedUri
import io.silencelen.andvari.core.client.autofill.UriMatch

/**
 * One row of a fill response, as a plain value: what it shows and exactly which values ride it. [DatasetBuilder]
 * turns each into a platform `Dataset` mechanically, so what a response (or an authentication result) holds is
 * decided here, by pure functions a JVM test calls ([FillPlan.rows]).
 */
sealed interface FillRow<I> {
    val itemId: String
    val title: String
    val subtitle: String?

    /** A login whose user name and password ride the row: one pick fills. */
    data class Login<I>(override val itemId: String, override val title: String, override val subtitle: String?, val values: List<Pair<I, String>>) : FillRow<I>

    /**
     * A login row with no value: its tap opens the app-fill confirm, which returns this login only. [pageDomain] is
     * set when the row fills an app's login into a web page shown inside that app, a page that is not one of the
     * login's own sites: the confirm names that page, is shown every time, and remembers
     * nothing.
     */
    data class LoginConfirm<I>(
        override val itemId: String,
        override val title: String,
        override val subtitle: String?,
        val fieldIds: List<I>,
        val pageDomain: String? = null,
    ) : FillRow<I>

    /** A card whose values ride the row: only in a verified browser (the wallet posture). */
    data class Card<I>(override val itemId: String, override val title: String, override val subtitle: String?, val values: List<Pair<I, CardFill.Value>>) : FillRow<I>

    /** A card row with no value: its tap opens the card confirm in andvari's own window, which returns this card only. */
    data class CardConfirm<I>(override val itemId: String, override val title: String, override val subtitle: String?, val fieldIds: List<I>) : FillRow<I>

    /**
     * A row that names nothing and carries nothing, for a result that passes through
     * an app that is not a verified browser. Its tap opens andvari's own chooser of [kind] ([FillChooserActivity]),
     * where the person picks the item, and the confirm (when the item needs one) is shown there. Its words are the
     * same whatever the vault holds: no name, no user name, no count.
     */
    data class Choose<I>(val kind: ChooserKind, val fieldIds: List<I>) : FillRow<I> {
        override val itemId: String get() = ""
        override val title: String get() = FillPlan.chooseTitle(kind)
        override val subtitle: String? get() = null
    }
}

/** What a [FillRow.Choose] opens a chooser of. */
enum class ChooserKind { LOGINS, CARDS }

/**
 * The fill rules (Android review 1, ruling 1). One fact decides them: whatever an authentication activity returns
 * travels through the requesting app's own process, which can read every value in it without the person picking
 * anything. So a value rides a row only where the requesting app is entitled to it, and the same rows serve the
 * service's direct response and the unlock's result:
 *
 * - **A verified browser** (a known browser whose signer is pinned or approved on this device): the earlier design
 *   stands. Web logins match the frame each field is in, and a card is a row with its values (one pick fills).
 * - **A known browser that is not verified**: web domains do not count, and no card is offered at all.
 * - **Every other app**: a login fills at once only when the app-fill gate says SILENT (a vetted app's own logins);
 *   any other verdict gives a row without values that leads to the app-fill confirm. A card is ALWAYS a row without
 *   values that leads to the card confirm: an app is never remembered for cards, and SILENT does not apply to them.
 * - **Everywhere**, card rows are offered only when the field in focus is itself a card field
 *   ([FormOf.cardFillFrame]), and only the focused field's frame is planned.
 */
internal object FillPlan {
    /** Who is asking, as ruling 1 sorts it. */
    sealed interface Asker {
        data object VerifiedBrowser : Asker
        data object UnverifiedBrowser : Asker
        data class App(val verdict: AppFillGate.Verdict) : Asker
    }

    /**
     * [trusted] is the live browser trust ([TrustedBrowsers.isTrusted]); [verdict] the app-fill gate's verdict, null
     * for a known browser. A package outside the browser table with no verdict is treated as an app that must confirm.
     */
    fun asker(appPackage: String, trusted: Boolean, verdict: AppFillGate.Verdict?): Asker = when {
        appPackage in BrowserCertPins.TABLE -> if (trusted) Asker.VerifiedBrowser else Asker.UnverifiedBrowser
        else -> Asker.App(verdict ?: AppFillGate.Verdict.CONFIRM)
    }

    const val CONFIRM_APP_SUBTITLE = "Tap to confirm this app"
    const val CONFIRM_SIGNER_CHANGED_SUBTITLE = "This app's signer changed — tap to check"
    const val CONFIRM_CARD_SUBTITLE = "Tap to confirm this card in andvari"

    /**
     * The rows for [form], logins first, cards after them, under [maxRows] with the card headroom ([loginRowCap]).
     *
     * [items] may be offers ([ContentFill.offersFor]: no secret, [ContentFill.UNRELEASED] for a password): the values of
     * an item are asked for with [release] only for a row that carries them ([FillRow.Login], [FillRow.Card]), and only
     * once that row is certain. A row without values ([FillRow.LoginConfirm], [FillRow.CardConfirm]) releases nothing.
     * By default the items hold their own values (the JVM tests pass whole items).
     */
    fun <I> rows(
        items: List<VaultItem>,
        form: FormOf<I>,
        asker: Asker,
        maxRows: Int = DatasetBuilder.MAX_DATASETS,
        release: (String) -> VaultItem? = { id -> items.firstOrNull { it.itemId == id } },
    ): List<FillRow<I>> {
        val trusted = asker == Asker.VerifiedBrowser
        // The card headroom is counted on the offers, so no card is released before it is certain to be shown.
        val cardOffers = if (form.ccFields.isNotEmpty() && asker != Asker.UnverifiedBrowser && form.cardFillFrame != null) items.count { it.doc.type == "card" } else 0
        val out = ArrayList<FillRow<I>>()
        val loginCap = minOf(maxRows, loginRowCap(cardOffers, maxRows))
        // Only in an app (never a browser, verified or not), the web page the focused field is on.
        val page = if (asker is Asker.App) focusedPage(form) else null
        for (item in items) {
            if (out.size >= loginCap) break
            if (item.doc.type != "login") continue
            val login = item.doc.login ?: continue
            val username = login.username?.takeIf { it.isNotEmpty() }
            val password = login.password?.takeIf { it.isNotEmpty() }
            if (username == null && password == null) continue
            // Per-field matching: a field is fillable by this item only when the item matches THAT field's own target
            // (which carries the field's frame domain).
            val userFields = if (username != null) {
                form.fields.filter { it.kind == FieldKind.USERNAME && fieldMatches(login.uris, it, form, trusted) }
            } else emptyList()
            val passFields = if (password != null) {
                fillPasswordFields(form).filter { fieldMatches(login.uris, it, form, trusted) }
            } else emptyList()
            val title = item.doc.name.ifBlank { username ?: "login" }
            // The page in focus, when the login matches it only by the app's package: a confirm that names the page,
            // whatever the gate's verdict (an app is never remembered for a page), with this login's fields on it.
            val pageFields = page?.let { d -> appLoginFields(login.uris, username, password, form, d) }.orEmpty()
            if (page != null && pageFields.any { it.webDomain == page && fieldFit(login.uris, it, form, false) == Fit.PAGE }) {
                out += FillRow.LoginConfirm(item.itemId, title, pageSubtitle(page), pageFields.map { it.id }, pageDomain = page)
                continue
            }
            if (userFields.isEmpty() && passFields.isEmpty()) continue
            out += if (asker is Asker.App && asker.verdict != AppFillGate.Verdict.SILENT) {
                val subtitle = if (asker.verdict == AppFillGate.Verdict.CONFIRM_SIGNER_CHANGED) CONFIRM_SIGNER_CHANGED_SUBTITLE else CONFIRM_APP_SUBTITLE
                FillRow.LoginConfirm(item.itemId, title, subtitle, (userFields + passFields).map { it.id })
            } else {
                // A row the platform fills on a pick: its values are asked for now, for this login only.
                val real = release(item.itemId)?.doc?.login ?: continue
                val u = real.username?.takeIf { it.isNotEmpty() }
                val p = real.password?.takeIf { it.isNotEmpty() }
                val values = (if (u != null) userFields.map { it.id to u } else emptyList()) + (if (p != null) passFields.map { it.id to p } else emptyList())
                if (values.isEmpty()) continue
                FillRow.Login(item.itemId, title, username, values)
            }
        }
        if (out.size < maxRows) out += runCatching { cardRows(items, form, asker, release, limit = maxRows - out.size) }.getOrDefault(emptyList())
        return out
    }

    /** The generic row's words (marked placeholders: the owner has approved none for these). */
    fun chooseTitle(kind: ChooserKind): String = when (kind) {
        ChooserKind.LOGINS -> UiText.ph(Placeholder.FILL_CHOOSE_LOGIN).shown()
        ChooserKind.CARDS -> UiText.ph(Placeholder.FILL_CHOOSE_CARD).shown()
    }

    /**
     * The rows of an authentication RESULT,
     * which travels through the requesting app's own process. Nothing that names an item rides it for an app that is
     * not a verified browser: not a login's name, never a user name, not a card's name, not how many there are. Such
     * a result carries at most one generic row for logins and one for cards ([FillRow.Choose]); the choosing happens
     * in andvari's own window. With one generic row there is one way in: the app holds no sender that raises the
     * confirm for an item of its choosing.
     *
     * - A verified browser keeps its rows ([rows]): it is entitled to what its frames match (the wallet posture).
     * - A known browser that is not verified gets nothing here (the service's own fallback, the trust row, stays).
     * - Every other app: one [FillRow.Choose] for logins when any login would be offered, one for cards when any card
     *   would be, each over the field ids those rows would have covered (so the row shows on the same fields).
     *
     * The service's DIRECT response is not a result: it stays with the system until the person picks a row, and only
     * the picked row's sender reaches the app, so it keeps one row per item ([rows]).
     */
    fun <I> resultRows(
        items: List<VaultItem>,
        form: FormOf<I>,
        asker: Asker,
        maxRows: Int = DatasetBuilder.MAX_DATASETS,
        release: (String) -> VaultItem? = { id -> items.firstOrNull { it.itemId == id } },
    ): List<FillRow<I>> = when (asker) {
        Asker.VerifiedBrowser -> rows(items, form, asker, maxRows, release)
        Asker.UnverifiedBrowser -> emptyList()
        is Asker.App -> {
            // Only which fields the rows would cover is wanted here: nothing is released (the offers stand in).
            val all = rows(items, form, asker, Int.MAX_VALUE) { id -> items.firstOrNull { it.itemId == id } }
            val loginIds = all.flatMap { r ->
                when (r) {
                    is FillRow.Login -> r.values.map { it.first }
                    is FillRow.LoginConfirm -> r.fieldIds
                    else -> emptyList()
                }
            }.distinct()
            val cardIds = all.flatMap { r -> if (r is FillRow.CardConfirm) r.fieldIds else emptyList() }.distinct()
            listOfNotNull(
                loginIds.takeIf { it.isNotEmpty() }?.let { FillRow.Choose(ChooserKind.LOGINS, it) },
                cardIds.takeIf { it.isNotEmpty() }?.let { FillRow.Choose(ChooserKind.CARDS, it) },
            )
        }
    }

    /**
     * What andvari's own chooser lists for one generic row: the rows [rows] would offer this app, of [kind] only, with
     * no cap (the chooser is a list in andvari's window, not the platform's dropdown). Only for an app; a browser never
     * gets a generic row.
     */
    fun <I> chooserRows(items: List<VaultItem>, form: FormOf<I>, asker: Asker, kind: ChooserKind): List<FillRow<I>> {
        if (asker !is Asker.App) return emptyList()
        // Nothing is released for the list: the offers stand in, and the chooser asks for the picked item's values only.
        return rows(items, form, asker, Int.MAX_VALUE) { id -> items.firstOrNull { it.itemId == id } }.filter { r ->
            when (kind) {
                ChooserKind.LOGINS -> r is FillRow.Login || r is FillRow.LoginConfirm
                ChooserKind.CARDS -> r is FillRow.CardConfirm
            }
        }
    }

    /** [U20] login rows on a card-eligible form leave room for up to 3 card rows; a form with no card keeps them all. */
    fun loginRowCap(cardRows: Int, maxRows: Int = DatasetBuilder.MAX_DATASETS): Int = maxRows - minOf(cardRows, 3)

    /**
     * The card rows for [form]: none in a known browser that is not verified, none unless the focused field is a card
     * field, and one per card whose plan fills anything in the focused field's frame. Only a verified browser's rows
     * carry the planned values; every other app's rows carry the field ids alone.
     */
    fun <I> cardRows(
        items: List<VaultItem>,
        form: FormOf<I>,
        asker: Asker,
        release: (String) -> VaultItem? = { id -> items.firstOrNull { it.itemId == id } },
        limit: Int = Int.MAX_VALUE,
    ): List<FillRow<I>> {
        if (form.ccFields.isEmpty()) return emptyList()
        if (asker == Asker.UnverifiedBrowser) return emptyList() // explicit trust gate
        val frame = form.cardFillFrame ?: return emptyList() // focus not on a card field: no card at all
        val ccFields = ccFillFields(form)
        // A row without values covers the card fields of the focused frame: which of them a card fills is planned with
        // its values, after the person confirmed it ([cardResult]); offering it reads none.
        val frameIds = form.ccFields.filter { it.webDomain == frame.domain }.map { it.id }
        val out = ArrayList<FillRow<I>>()
        for (item in items) {
            if (out.size >= limit) break
            if (item.doc.type != "card") continue
            if (asker != Asker.VerifiedBrowser) {
                // Its name only: the brand, the last digits and the expiry are shown in andvari's own window.
                if (frameIds.isNotEmpty()) out += FillRow.CardConfirm(item.itemId, item.doc.name.ifBlank { "Card" }, CONFIRM_CARD_SUBTITLE, frameIds)
                continue
            }
            // A verified browser: one pick fills, so the values ride the row and are asked for now, for this card only.
            val released = release(item.itemId) ?: continue
            val card = released.doc.card ?: continue
            // Per-item rail: one malformed card degrades to a skip, not a dead response.
            val plan = runCatching { CardFill.plan(ccFields, card, frame.domain) }.getOrDefault(emptyList())
            val planned = plan.mapNotNull { p -> form.ccFields.getOrNull(p.index)?.let { it.id to p.value } }
            if (planned.isEmpty()) continue
            out += FillRow.Card(item.itemId, CardFill.presentationLine(released.doc), item.doc.name.takeIf { it.isNotBlank() }, planned)
        }
        return out
    }

    /**
     * What the card confirm returns: the values of [item] (one card) for [form]'s focused card frame, and nothing
     * else; null when it is not a card, the focus is not on a card field, or nothing would fill.
     */
    fun <I> cardResult(item: VaultItem, form: FormOf<I>): List<Pair<I, CardFill.Value>>? {
        if (item.doc.type != "card") return null
        val card = item.doc.card ?: return null
        val frame = form.cardFillFrame ?: return null
        val ccFields = ccFillFields(form)
        val plan = CardFill.plan(ccFields, card, frame.domain)
        return plan.mapNotNull { p -> form.ccFields.getOrNull(p.index)?.let { it.id to p.value } }.ifEmpty { null }
    }

    /**
     * What the app-fill confirm returns: [item]'s user name and password for the form's fields, matched exactly as
     * [rows] matches them for an app (package only); null when it no longer matches or carries nothing to fill.
     *
     * [pageDomain] is the page the confirm named ([FillRow.LoginConfirm.pageDomain], baked by the service): the fields
     * on that page which the login matches only by the app's package are released too, and no field on any other page.
     * Without it, a page that is not one of the login's own sites gets nothing.
     */
    fun <I> appLoginResult(item: VaultItem, form: FormOf<I>, pageDomain: String? = null): List<Pair<I, String>>? {
        if (item.doc.type != "login" || form.appPackage in BrowserCertPins.TABLE) return null
        val login = item.doc.login ?: return null
        val username = login.username?.takeIf { it.isNotEmpty() }
        val password = login.password?.takeIf { it.isNotEmpty() }
        val values = appLoginFields(login.uris, username, password, form, pageDomain).map { f ->
            f.id to (if (f.kind == FieldKind.USERNAME) username!! else password!!)
        }
        return values.ifEmpty { null }
    }

    /**
     * An app's fields for one login, as the app-fill confirm releases them: each user-name field (when there is a user
     * name) and each fillable password field (when there is a password) that the login matches directly, plus, on the
     * page [pageDomain] only, those it matches by the package alone ([Fit.PAGE]).
     */
    private fun <I> appLoginFields(uris: List<String>, username: String?, password: String?, form: FormOf<I>, pageDomain: String?): List<FieldOf<I>> {
        fun takes(f: FieldOf<I>): Boolean = when (fieldFit(uris, f, form, false)) {
            Fit.DIRECT -> true
            Fit.PAGE -> pageDomain != null && f.webDomain == pageDomain
            Fit.NONE -> false
        }
        val user = if (username != null) form.fields.filter { it.kind == FieldKind.USERNAME && takes(it) } else emptyList()
        val pass = if (password != null) fillPasswordFields(form).filter { takes(it) } else emptyList()
        return user + pass
    }

    /** The web page the focused field is on, as the requesting app reports it; null on a native screen. */
    fun <I> focusedPage(form: FormOf<I>): String? = form.fields.firstOrNull { it.id == form.focusedId }?.webDomain?.takeIf { it.isNotBlank() }

    /** The page row's second line. The domain is the app's own claim, escaped and bounded like every line it supplies. */
    fun pageSubtitle(pageDomain: String): String = "On the page ${AppFillGate.oneLine(pageDomain) ?: "?"} — tap to confirm"

    /**
     * H21 (audit 2026-09-13): the PASSWORD fields a stored password is written into. Hinted new-password fields stay
     * out whenever a current-password field exists ([NewPasswordSignal.fillablePasswordFields]).
     */
    fun <I> fillPasswordFields(form: FormOf<I>): List<FieldOf<I>> =
        NewPasswordSignal.fillablePasswordFields(form.fields.filter { it.kind == FieldKind.PASSWORD }) { it.isNewPassword }

    /**
     * Whether a login with addresses [uris] may fill [field]. The match is the usual one against the field's target
     * ([targetFor]: its frame's web domain only in a verified browser, the requesting package always), with one more
     * condition (Android review 1, ruling 3): in an app that is not a verified browser, a field that carries a web
     * domain is a web page shown inside that app (an in-app browser, a sign-in web view). An `androidapp://` login
     * matches it only when that domain ALSO matches one of the same login's own web addresses under the usual rule.
     * So an app whose own sign-in screen is a web page keeps working when the login holds both addresses, and the
     * page's claim can only narrow what the package match gives, never widen it (a web login still never fills an
     * app: [targetFor] gives it no web host).
     *
     * The next step is built ([Fit.PAGE]): such a login is offered in an app through the app-fill confirm, with the
     * page's domain named, shown every time and never remembered ([rows], [appLoginResult]); never silently.
     */
    fun <I> fieldMatches(uris: List<String>, field: FieldOf<I>, form: FormOf<I>, trusted: Boolean): Boolean =
        fieldFit(uris, field, form, trusted) == Fit.DIRECT

    /** How a login's addresses fit one field. */
    enum class Fit {
        /** No match: the package (or, in a verified browser, the frame) does not match. */
        NONE,

        /** The usual match, narrowed to the login's own sites: this may fill as the asker's rules allow. */
        DIRECT,

        /**
         * The package matches but the field is on a web page inside the app that is not one of the login's own sites.
         * Only the app-fill confirm that names this page may fill it, every time.
         */
        PAGE,
    }

    fun <I> fieldFit(uris: List<String>, field: FieldOf<I>, form: FormOf<I>, trusted: Boolean): Fit {
        val offered = forScheme(uris, field.webScheme)
        if (!UriMatch.matchLogins(offered, targetFor(field, form, trusted))) return Fit.NONE
        val pageDomain = field.webDomain
        if (trusted) return Fit.DIRECT
        // An HTML field that reports no domain, in an app, is a page of unknown address. It is never
        // filled directly and never matched to the app's own login, not even through the page confirm (it has no page
        // to name).
        if (pageDomain == null) return if (field.isHtml) Fit.NONE else Fit.DIRECT
        val web = offered.filter { UriMatch.parseSavedUri(it) is SavedUri.Web }
        return if (UriMatch.matchLogins(web, FillTarget(webHost = pageDomain, packageName = form.appPackage))) Fit.DIRECT else Fit.PAGE
    }

    /**
     * Core's page rule (FillRules): on a frame that reports `http`, only an address saved
     * as http is a web address that can match (an https login is never offered to the plain-http page of its site,
     * where a hostile network answers). App addresses are kept: they match the package, not the page. A frame that
     * reports no scheme stays as before (a remaining risk).
     */
    fun forScheme(uris: List<String>, scheme: String?): List<String> =
        if (scheme.equals("http", ignoreCase = true)) {
            uris.filter { it.trim().startsWith("http://", ignoreCase = true) || it.trim().startsWith(UriMatch.ANDROID_APP_SCHEME) }
        } else {
            uris
        }

    /** A field's match target: its frame's web domain only in a verified browser, the requesting package always. */
    fun <I> targetFor(field: FieldOf<I>, form: FormOf<I>, trusted: Boolean): FillTarget =
        FillTarget(webHost = if (trusted) field.webDomain else null, packageName = form.appPackage)

    fun <I> ccFillFields(form: FormOf<I>): List<CardFill.CcField> = form.ccFields.mapIndexed { i, f ->
        CardFill.CcField(index = i, kind = f.kind, frameDomain = f.webDomain, autofillType = f.autofillType, options = f.options, maxLength = f.maxLength)
    }
}
