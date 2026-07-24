package io.silencelen.andvari.core.client.autofill

/** Form-level verdict — drives which fill/save pipeline a consumer runs. */
enum class FormKind { LOGIN, CARD, MIXED }

/** Output of [CardForm.refine]; [kinds] is index-aligned with the input fields. */
data class RefinedForm(val kinds: List<FieldKind>, val formKind: FormKind)

// [X3-A4a] exhaustive `when` (NO `else`) so a new FieldKind is COMPILE-FORCED to decide its
// card-ness here — the silent-skip hazard the design names (adding CC_POSTAL flipped no compile
// check under the old `||` chain). CardKindPartitionTest is the runtime backstop.
val FieldKind.isCardKind: Boolean
    get() = when (this) {
        FieldKind.CC_NUMBER, FieldKind.CC_EXP_MONTH, FieldKind.CC_EXP_YEAR, FieldKind.CC_EXP,
        FieldKind.CC_NAME, FieldKind.CC_CSC, FieldKind.CC_TYPE, FieldKind.CC_POSTAL -> true
        FieldKind.USERNAME, FieldKind.PASSWORD, FieldKind.NONE -> false
    }

/**
 * Form-level card refinement — the pure post-pass over a form's classified fields, shared by all
 * three consumers (Android service, extension, web). Operates only on [FieldSignal]s — no
 * DOM/Android types — so the frame-cluster + demotion rules are vector-tested once
 * (spec/test-vectors/cardform.json).
 */
object CardForm {
    /**
     * Classify [fields] and apply the rules a single field cannot see:
     *  - CSC demotion: a PASSWORD-classified field with declared maxLength ≤ 4 and numeric
     *    inputMode becomes CC_CSC when a CC_NUMBER sits in the SAME frame cluster (fields grouped
     *    by [FieldSignal.frameDomain]; nulls cluster together = native app / main frame). A
     *    cross-frame CC_NUMBER never demotes — a hostile iframe cannot relabel the page's
     *    password field.
     *  - formKind: CARD requires a CC_NUMBER inside ONE frame cluster — the PAN anchor. Card
     *    kinds without a PAN (e.g. two generic expiry fields) NEVER qualify a card form. A
     *    qualifying cluster plus any USERNAME/PASSWORD field → MIXED; everything else → LOGIN,
     *    so card-free forms flow into today's login pipeline unchanged.
     */
    fun refine(fields: List<FieldSignal>): RefinedForm {
        val kinds = fields.map { FieldClassifier.classify(it) }.toMutableList()
        val clusters = fields.indices.groupBy { fields[it].frameDomain }
        for (idxs in clusters.values) {
            if (idxs.none { kinds[it] == FieldKind.CC_NUMBER }) continue
            for (i in idxs) {
                val f = fields[i]
                if (kinds[i] == FieldKind.PASSWORD && (f.maxLength ?: 0) in 1..4 && f.inputMode?.lowercase() == "numeric") {
                    kinds[i] = FieldKind.CC_CSC
                } else if (kinds[i] == FieldKind.NONE && FieldClassifier.postalKind(f) == FieldKind.CC_POSTAL) {
                    // [X3-A1] anchor-gated billing postal: a login-inert postal field (classify →
                    // NONE) is promoted ONLY inside this CC_NUMBER-anchored cluster — a card-free
                    // login form never enters here (login bit-identity). The [X3-A1](ii) >1-postal
                    // fail-close is enforced DOWNSTREAM (CardFill.plan / reveal declared set), not
                    // here — refine just labels every eligible field CC_POSTAL.
                    kinds[i] = FieldKind.CC_POSTAL
                }
            }
        }
        val hasCard = clusters.values.any { idxs -> idxs.any { kinds[it] == FieldKind.CC_NUMBER } }
        val hasLogin = kinds.any { it == FieldKind.USERNAME || it == FieldKind.PASSWORD }
        val formKind = when {
            hasCard && hasLogin -> FormKind.MIXED
            hasCard -> FormKind.CARD
            else -> FormKind.LOGIN
        }
        return RefinedForm(kinds, formKind)
    }
}
