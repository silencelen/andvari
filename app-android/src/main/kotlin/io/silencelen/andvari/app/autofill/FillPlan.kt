package io.silencelen.andvari.app.autofill

import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.autofill.AppFillGate
import io.silencelen.andvari.core.client.autofill.BrowserCertPins
import io.silencelen.andvari.core.client.autofill.CardFill
import io.silencelen.andvari.core.client.autofill.FieldKind
import io.silencelen.andvari.core.client.autofill.FillTarget
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

    /** A login row with no value: its tap opens the app-fill confirm, which returns this login only. */
    data class LoginConfirm<I>(override val itemId: String, override val title: String, override val subtitle: String?, val fieldIds: List<I>) : FillRow<I>

    /** A card whose values ride the row: only in a verified browser (the wallet posture). */
    data class Card<I>(override val itemId: String, override val title: String, override val subtitle: String?, val values: List<Pair<I, CardFill.Value>>) : FillRow<I>

    /** A card row with no value: its tap opens the card confirm in andvari's own window, which returns this card only. */
    data class CardConfirm<I>(override val itemId: String, override val title: String, override val subtitle: String?, val fieldIds: List<I>) : FillRow<I>
}

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

    /** The rows for [form], logins first, cards after them, under [maxRows] with the card headroom ([loginRowCap]). */
    fun <I> rows(items: List<VaultItem>, form: FormOf<I>, asker: Asker, maxRows: Int = DatasetBuilder.MAX_DATASETS): List<FillRow<I>> {
        val trusted = asker == Asker.VerifiedBrowser
        val cards = runCatching { cardRows(items, form, asker) }.getOrDefault(emptyList())
        val out = ArrayList<FillRow<I>>()
        val loginCap = minOf(maxRows, loginRowCap(cards.size, maxRows))
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
                form.fields.filter { it.kind == FieldKind.USERNAME && UriMatch.matchLogins(login.uris, targetFor(it, form, trusted)) }
            } else emptyList()
            val passFields = if (password != null) {
                fillPasswordFields(form).filter { UriMatch.matchLogins(login.uris, targetFor(it, form, trusted)) }
            } else emptyList()
            if (userFields.isEmpty() && passFields.isEmpty()) continue
            val title = item.doc.name.ifBlank { username ?: "login" }
            out += if (asker is Asker.App && asker.verdict != AppFillGate.Verdict.SILENT) {
                val subtitle = if (asker.verdict == AppFillGate.Verdict.CONFIRM_SIGNER_CHANGED) CONFIRM_SIGNER_CHANGED_SUBTITLE else CONFIRM_APP_SUBTITLE
                FillRow.LoginConfirm(item.itemId, title, subtitle, (userFields + passFields).map { it.id })
            } else {
                FillRow.Login(item.itemId, title, username, userFields.map { it.id to username!! } + passFields.map { it.id to password!! })
            }
        }
        for (c in cards) {
            if (out.size >= maxRows) break
            out += c
        }
        return out
    }

    /** [U20] login rows on a card-eligible form leave room for up to 3 card rows; a form with no card keeps them all. */
    fun loginRowCap(cardRows: Int, maxRows: Int = DatasetBuilder.MAX_DATASETS): Int = maxRows - minOf(cardRows, 3)

    /**
     * The card rows for [form]: none in a known browser that is not verified, none unless the focused field is a card
     * field, and one per card whose plan fills anything in the focused field's frame. Only a verified browser's rows
     * carry the planned values; every other app's rows carry the field ids alone.
     */
    fun <I> cardRows(items: List<VaultItem>, form: FormOf<I>, asker: Asker): List<FillRow<I>> {
        if (form.ccFields.isEmpty()) return emptyList()
        if (asker == Asker.UnverifiedBrowser) return emptyList() // explicit trust gate
        val frame = form.cardFillFrame ?: return emptyList() // focus not on a card field: no card at all
        val ccFields = ccFillFields(form)
        val out = ArrayList<FillRow<I>>()
        for (item in items) {
            if (item.doc.type != "card") continue
            val card = item.doc.card ?: continue
            // Per-item rail: one malformed card degrades to a skip, not a dead response.
            val plan = runCatching { CardFill.plan(ccFields, card, frame.domain) }.getOrDefault(emptyList())
            val planned = plan.mapNotNull { p -> form.ccFields.getOrNull(p.index)?.let { it.id to p.value } }
            if (planned.isEmpty()) continue
            out += if (asker == Asker.VerifiedBrowser) {
                FillRow.Card(item.itemId, CardFill.presentationLine(item.doc), item.doc.name.takeIf { it.isNotBlank() }, planned)
            } else {
                // Its name only: the brand, the last digits and the expiry are shown in andvari's own window.
                FillRow.CardConfirm(item.itemId, item.doc.name.ifBlank { "Card" }, CONFIRM_CARD_SUBTITLE, planned.map { it.first })
            }
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
     */
    fun <I> appLoginResult(item: VaultItem, form: FormOf<I>): List<Pair<I, String>>? {
        if (item.doc.type != "login" || form.appPackage in BrowserCertPins.TABLE) return null
        val login = item.doc.login ?: return null
        val username = login.username?.takeIf { it.isNotEmpty() }
        val password = login.password?.takeIf { it.isNotEmpty() }
        val userFields = if (username != null) form.fields.filter { it.kind == FieldKind.USERNAME && UriMatch.matchLogins(login.uris, targetFor(it, form, false)) } else emptyList()
        val passFields = if (password != null) fillPasswordFields(form).filter { UriMatch.matchLogins(login.uris, targetFor(it, form, false)) } else emptyList()
        val values = userFields.map { it.id to username!! } + passFields.map { it.id to password!! }
        return values.ifEmpty { null }
    }

    /**
     * H21 (audit 2026-09-13): the PASSWORD fields a stored password is written into. Hinted new-password fields stay
     * out whenever a current-password field exists ([NewPasswordSignal.fillablePasswordFields]).
     */
    fun <I> fillPasswordFields(form: FormOf<I>): List<FieldOf<I>> =
        NewPasswordSignal.fillablePasswordFields(form.fields.filter { it.kind == FieldKind.PASSWORD }) { it.isNewPassword }

    /** A field's match target: its frame's web domain only in a verified browser, the requesting package always. */
    fun <I> targetFor(field: FieldOf<I>, form: FormOf<I>, trusted: Boolean): FillTarget =
        FillTarget(webHost = if (trusted) field.webDomain else null, packageName = form.appPackage)

    fun <I> ccFillFields(form: FormOf<I>): List<CardFill.CcField> = form.ccFields.mapIndexed { i, f ->
        CardFill.CcField(index = i, kind = f.kind, frameDomain = f.webDomain, autofillType = f.autofillType, options = f.options, maxLength = f.maxLength)
    }
}
