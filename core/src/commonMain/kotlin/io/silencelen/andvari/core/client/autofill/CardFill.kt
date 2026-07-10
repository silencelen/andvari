package io.silencelen.andvari.core.client.autofill

import io.silencelen.andvari.core.client.CardData
import io.silencelen.andvari.core.client.CardDisplay
import io.silencelen.andvari.core.client.ItemDoc

/**
 * Pure card fill PLANNING (design 2026-07-09-cards-wallet, "Android fill + save") — decides
 * which classified cc fields receive which values, platform-free. The Android autofill
 * service is the first consumer (it maps [Planned] onto `AutofillValue.forText`/`forList`);
 * the extension's future in-page card fill and web are expected to consume the same plan,
 * which is why the whole safety core lives here in core and not in the service.
 *
 * VALUE-BLIND like the rest of the fill path: this object reads only field METADATA
 * (kind/frame/type/option labels) plus the vault's own [CardData] — never a field's current
 * on-screen value. Option labels of a LIST node are choice metadata, not user input.
 *
 * The three safety rules (each pinned by CardFillTest):
 *  - **Hostile-iframe zero-fill:** fields are clustered by their own [CcField.frameDomain]
 *    (nulls cluster together = native app / main frame) and ONLY clusters that contain a
 *    [FieldKind.CC_NUMBER] field receive ANY value. A lone cc-hinted field in another frame —
 *    the classic embedded-attacker CSC/expiry probe — gets NOTHING.
 *  - **Type-pinning:** an [AUTOFILL_TYPE_TEXT] field only ever gets [Value.Text]; an
 *    [AUTOFILL_TYPE_LIST] field only ever gets [Value.ListIndex] (resolved by NUMERIC option
 *    matching via [CardNormalize] — "1"/"01"/"January (01)" all match month 01, "27"/"2027"
 *    match 2027). No option match, or any other autofillType → the field is SKIPPED.
 *  - **Partial fill beats wrong fill:** a card field that is missing or does not parse to its
 *    canonical form skips its target field rather than guessing — and a value LONGER than the
 *    target's declared max length is never emitted (the platform's LengthFilter would silently
 *    truncate it into a different, wrong value); the one adaptation is 4-digit→2-digit year.
 *
 * Presentations may show brand + last4 + expiry ONLY — [presentationLine] never emits a full
 * PAN or any CVV (test-pinned by substring-absence).
 */
object CardFill {
    // Mirrors android.view.View autofill type constants (pure ints so core stays platform-free).
    const val AUTOFILL_TYPE_TEXT = 1
    const val AUTOFILL_TYPE_LIST = 3

    /** One classified cc field as the platform consumer sees it — metadata only, no values. */
    data class CcField(
        val index: Int,              // caller-side handle; returned in Planned
        val kind: FieldKind,         // one of the CC_* kinds (from CardForm.refine)
        val frameDomain: String?,    // the field's own frame domain (null = native/main frame)
        val autofillType: Int,       // AUTOFILL_TYPE_TEXT | AUTOFILL_TYPE_LIST (others -> field skipped)
        val options: List<String>,   // LIST nodes' choice labels (metadata, not values); empty otherwise
        val maxLength: Int? = null,  // the control's declared capacity (null = undeclared) — the fit-guard input
    )

    /** What to put in a field: text for TEXT nodes, a choice index for LIST nodes — never crossed. */
    sealed interface Value {
        data class Text(val text: String) : Value
        data class ListIndex(val index: Int) : Value
    }

    /** One fill decision, keyed back to the caller's [CcField.index]. */
    data class Planned(val index: Int, val value: Value)

    /**
     * Plan the fill of [fields] from [card] under the safety rules above. Output is
     * deterministic: ordered by [CcField.index].
     */
    fun plan(fields: List<CcField>, card: CardData): List<Planned> {
        val out = ArrayList<Planned>()
        for (cluster in fields.groupBy { it.frameDomain }.values) {
            // Hostile-iframe rule: no CC_NUMBER anchor in this frame cluster → zero fill.
            if (cluster.none { it.kind == FieldKind.CC_NUMBER }) continue
            for (f in cluster) planField(f, card)?.let { out.add(it) }
        }
        return out.sortedBy { it.index }
    }

    private fun planField(f: CcField, card: CardData): Planned? = when (f.autofillType) {
        AUTOFILL_TYPE_TEXT -> textFor(f.kind, card, f.maxLength)?.let { Planned(f.index, Value.Text(it)) }
        AUTOFILL_TYPE_LIST -> listIndexFor(f, card)?.let { Planned(f.index, Value.ListIndex(it)) }
        else -> null // unknown autofillType → skip (type-pinning has no third leg)
    }

    /**
     * Canonical text per kind, or null → skip (missing/unparseable card field never guesses).
     * FIT-GUARD: a value longer than the control's declared [maxLength] is never emitted —
     * the platform's LengthFilter would silently truncate it into a WRONG value ("2027" in a
     * 2-char year box fills "20"). One adaptation exists: a 4-digit year shrinks to its
     * 2-digit form for short year controls; everything else skips (partial beats wrong).
     */
    private fun textFor(kind: FieldKind, card: CardData, maxLength: Int?): String? {
        val raw = when (kind) {
            FieldKind.CC_NUMBER -> CardNormalize.digitsOnly(card.number ?: "").ifEmpty { null }
            FieldKind.CC_NAME -> card.cardholderName?.takeIf { it.isNotBlank() }
            FieldKind.CC_EXP_MONTH -> CardNormalize.padMonth(card.expMonth ?: "")
            FieldKind.CC_EXP_YEAR -> CardNormalize.yearTo4(card.expYear ?: "")
            FieldKind.CC_EXP -> composeExp(card)
            FieldKind.CC_CSC -> card.securityCode?.takeIf { it.isNotBlank() }
            else -> null // non-card kind should never reach a card plan; skip defensively
        } ?: return null
        if (maxLength == null || raw.length <= maxLength) return raw
        if (kind == FieldKind.CC_EXP_YEAR && maxLength >= 2) return CardNormalize.yearTo2(raw)
        return null
    }

    private fun composeExp(card: CardData): String? {
        val m = card.expMonth ?: return null
        val y = card.expYear ?: return null
        return CardNormalize.composeShortExpiry(m, y)
    }

    /**
     * NUMERIC option matching for LIST (select/spinner) nodes — only month and year have a
     * defined numeric matcher; every other kind on a LIST node skips (no guessing a PAN or
     * CVV out of a dropdown). First matching option wins; no match → null → skip.
     */
    private fun listIndexFor(f: CcField, card: CardData): Int? = when (f.kind) {
        FieldKind.CC_EXP_MONTH -> {
            val m = CardNormalize.padMonth(card.expMonth ?: "") ?: return null
            // Two passes: PREFER an option whose whole label parses as the month (pure-numeric
            // "12"/"01" rows — padMonth rejects any other char), so a digit-bearing placeholder
            // ("Month (12)") can never outrank the real row; only then fall back to digit
            // extraction, which is what makes "December (12)" selects fillable at all.
            f.options.indexOfFirst { CardNormalize.padMonth(it) == m }.takeIf { it >= 0 }
                ?: f.options.indexOfFirst { CardNormalize.padMonth(CardNormalize.digitsOnly(it)) == m }.takeIf { it >= 0 }
        }
        FieldKind.CC_EXP_YEAR -> {
            val y = CardNormalize.yearTo4(card.expYear ?: "") ?: return null
            f.options.indexOfFirst { CardNormalize.yearTo4(it) == y }.takeIf { it >= 0 }
                ?: f.options.indexOfFirst { CardNormalize.yearTo4(CardNormalize.digitsOnly(it)) == y }.takeIf { it >= 0 }
        }
        else -> null
    }

    /**
     * Dataset presentation line: "Visa ••4242 · 12/27" — [CardDisplay.subtitle] plus the
     * composed MM/YY when BOTH expiry halves parse; subtitle alone otherwise. Never contains
     * a full PAN or any CVV (the presentation is rendered by the platform outside our
     * process, so this string is the entire leak surface — test-pinned).
     */
    fun presentationLine(doc: ItemDoc): String {
        val subtitle = CardDisplay.subtitle(doc)
        val exp = CardNormalize.composeShortExpiry(doc.card?.expMonth ?: "", doc.card?.expYear ?: "")
        return if (exp != null) "$subtitle · $exp" else subtitle
    }
}
