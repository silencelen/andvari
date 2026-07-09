package io.silencelen.andvari.core.client.autofill

/** Form-level verdict — drives which fill/save pipeline a consumer runs. */
enum class FormKind { LOGIN, CARD, MIXED }

/** Output of [CardForm.refine]; [kinds] is index-aligned with the input fields. */
data class RefinedForm(val kinds: List<FieldKind>, val formKind: FormKind)

val FieldKind.isCardKind: Boolean
    get() = this == FieldKind.CC_NUMBER || this == FieldKind.CC_EXP_MONTH || this == FieldKind.CC_EXP_YEAR ||
        this == FieldKind.CC_EXP || this == FieldKind.CC_NAME || this == FieldKind.CC_CSC

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
