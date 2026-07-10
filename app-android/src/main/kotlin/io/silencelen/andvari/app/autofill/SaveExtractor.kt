package io.silencelen.andvari.app.autofill

import android.app.assist.AssistStructure
import android.view.View
import io.silencelen.andvari.core.client.autofill.CardForm
import io.silencelen.andvari.core.client.autofill.CardNormalize
import io.silencelen.andvari.core.client.autofill.FieldKind
import io.silencelen.andvari.core.client.autofill.FieldSignal

/**
 * Card fields a user typed into a submitted checkout, already CANONICAL (spec 02 CardData
 * forms) via [CardNormalize]: [number] digits-only and Luhn-valid (a [SavedCard] does not
 * exist otherwise), [expMonth] "01".."12", [expYear] 4-digit, [securityCode] digits-only.
 * A field the form didn't carry — or that failed to parse — is null: partial capture beats
 * wrong capture. [webDomain] is the CC_NUMBER field's frame domain (informational only —
 * cards are deliberately not URI-bound).
 */
data class SavedCard(
    val number: String,
    val cardholderName: String?,
    val expMonth: String?,
    val expYear: String?,
    val securityCode: String?,
    val webDomain: String?,
    val appPackage: String,
)

/**
 * Credentials a user typed into a submitted form, for "Save to andvari?". [webDomain] is the
 * password field's frame domain (null for a native app); [appPackage] is the requesting app.
 * [card] (0.7.0, additive) is the checkout's Luhn-valid card capture, when there is one.
 */
data class SavedCredentials(
    val username: String?,
    val password: String?,
    val webDomain: String?,
    val appPackage: String,
    val card: SavedCard? = null,
) {
    /** A login is only worth saving if it has a password. */
    val savable: Boolean get() = !password.isNullOrEmpty()

    /** The URI to store on the new login so it matches next time (spec: web host, else app package). */
    fun uri(): String = webDomain?.let { "https://$it" } ?: "androidapp://$appPackage"

    /** A human title for the saved item: the site host, else a readable app name. */
    fun title(): String = webDomain ?: appPackage.substringAfterLast('.').replaceFirstChar { it.uppercase() }
}

/**
 * Reads the typed values out of a submitted form's AssistStructure — the ONE place the
 * autofill service reads field VALUES (the fill path is value-blind by design). Fields are
 * classified through the exact same path as the fill side ([StructureParser.signalOf] +
 * ONE form-level [CardForm.refine]) so save can never disagree with fill about what a
 * field IS; for card-free forms refine() is bit-identical to the old per-field classify.
 * NEVER logs a value; the result is handed straight to the confirm UI + client-side item
 * encryption. Takes the FIRST value it finds per kind (login forms have one of each; a
 * change-password form's "new password" is the first PASSWORD field).
 *
 * Card capture (0.7.0): CC_* values canonicalize via [CardNormalize] and the capture is
 * REAL only when the number passes the Luhn gate — else it is discarded silently (a phone
 * number or member id must never become a save prompt). PRECEDENCE (design): a Luhn-valid
 * card WINS and the login capture is DISCARDED when the captured password is the captured
 * CSC — a checkout CVV must never overwrite (or save as) a merchant password; otherwise
 * both captures may be returned.
 */
object SaveExtractor {
    private const val MAX_DEPTH = 25

    fun extract(structure: AssistStructure): SavedCredentials {
        val appPackage = structure.activityComponent?.packageName ?: ""

        class Captured(val signal: FieldSignal, val value: String?, val domain: String?)
        val nodes = ArrayList<Captured>()

        fun visit(node: AssistStructure.ViewNode, inheritedDomain: String?, depth: Int) {
            if (depth > MAX_DEPTH) return
            if (node.importantForAutofill == View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS) return
            val nodeDomain = node.webDomain?.takeIf { it.isNotEmpty() } ?: inheritedDomain
            if (node.autofillId != null && node.importantForAutofill != View.IMPORTANT_FOR_AUTOFILL_NO) {
                // Value-less fields are collected too: refine() clusters the WHOLE form by
                // frame, and a CC_NUMBER sibling matters even when this walk sees no text in it.
                nodes.add(Captured(StructureParser.signalOf(node, nodeDomain), textValue(node), nodeDomain))
            }
            for (i in 0 until node.childCount) visit(node.getChildAt(i), nodeDomain, depth + 1)
        }
        for (i in 0 until structure.windowNodeCount) visit(structure.getWindowNodeAt(i).rootViewNode, null, 0)

        // ONE form-level classification — the same classifier path as the fill side.
        val kinds = CardForm.refine(nodes.map { it.signal }).kinds

        var username: String? = null
        var password: String? = null
        var domain: String? = null
        // Raw card captures — first value per kind wins, like the login capture. The ONE
        // exception is CC_NUMBER below: gift/loyalty/membership inputs also classify
        // CC_NUMBER (their names token-match "cardnumber") and typically sit ABOVE the
        // payment block, so a plain first-wins would let a filled gift code displace — or,
        // via the Luhn gate, entirely discard — the real PAN.
        var ccNumber: String? = null
        var ccName: String? = null
        var ccExpMonth: String? = null
        var ccExpYear: String? = null
        var ccExp: String? = null
        var ccCsc: String? = null
        var ccDomain: String? = null

        for ((i, n) in nodes.withIndex()) {
            val value = n.value ?: continue
            when (kinds[i]) {
                FieldKind.PASSWORD -> if (password == null) { password = value; if (domain == null) domain = n.domain }
                FieldKind.USERNAME -> if (username == null) { username = value; if (domain == null) domain = n.domain }
                // Prefer the first LUHN-VALID number: a non-Luhn gift code never displaces a
                // real PAN captured later. Residual (accepted, documented): two Luhn-valid
                // PANs on one form keep first-wins — no value-blind way to rank them.
                FieldKind.CC_NUMBER -> if (ccNumber == null || (!CardNormalize.luhnValid(ccNumber!!) && CardNormalize.luhnValid(value))) { ccNumber = value; ccDomain = n.domain }
                FieldKind.CC_NAME -> if (ccName == null) ccName = value
                FieldKind.CC_EXP_MONTH -> if (ccExpMonth == null) ccExpMonth = value
                FieldKind.CC_EXP_YEAR -> if (ccExpYear == null) ccExpYear = value
                FieldKind.CC_EXP -> if (ccExp == null) ccExp = value
                FieldKind.CC_CSC -> if (ccCsc == null) ccCsc = value
                else -> {}
            }
        }

        // Luhn gate: 12-19 digits, digit-group separators tolerated — anything else means
        // NO card capture at all. Dedicated expiry fields canonicalize via the adapters
        // (digitsOnly first, so spinner labels like "December (12)" / " 2027" normalize
        // too — mirroring CardFill's numeric option matching); a combined CC_EXP value
        // parses via parseExpiry and only backfills what the dedicated fields didn't give.
        val card = ccNumber?.takeIf { CardNormalize.luhnValid(it) }?.let { raw ->
            val combined = ccExp?.let { CardNormalize.parseExpiry(it) }
            SavedCard(
                number = CardNormalize.digitsOnly(raw),
                cardholderName = ccName?.trim()?.takeIf { it.isNotEmpty() },
                expMonth = ccExpMonth?.let { CardNormalize.padMonth(CardNormalize.digitsOnly(it)) } ?: combined?.expMonth,
                expYear = ccExpYear?.let { CardNormalize.yearTo4(CardNormalize.digitsOnly(it)) } ?: combined?.expYear,
                securityCode = ccCsc?.let { CardNormalize.digitsOnly(it) }?.takeIf { it.isNotEmpty() },
                webDomain = ccDomain,
                appPackage = appPackage,
            )
        }

        // CVV precedence (design): the "password" on a checkout whose value IS the card's
        // security code is the CVV mis-signaled, not a merchant password — drop the login
        // capture rather than offer to save/overwrite a stored password with a CVV.
        if (card != null && password != null && (password == ccCsc || password == card.securityCode)) {
            username = null
            password = null
        }
        return SavedCredentials(username, password, domain, appPackage, card)
    }

    /** The field's current text: the typed AutofillValue if present, else the node's own text. */
    private fun textValue(node: AssistStructure.ViewNode): String? {
        val v = node.autofillValue
        val text = if (v != null && v.isText) v.textValue?.toString() else node.text?.toString()
        return text?.takeIf { it.isNotEmpty() }
    }
}
