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
 *    [AUTOFILL_TYPE_LIST] field only ever gets [Value.ListIndex], resolved by [listIndexFor]'s
 *    PASS-MAJOR matching — numeric parses first ("1"/"01"/"January (01)" all match month 01,
 *    "27"/"2027" match 2027), then the [T3] en month-name pass, then the CC_TYPE brand
 *    synonym/contains passes. No option match, or any other autofillType → the field is SKIPPED.
 *  - **Partial fill beats wrong fill:** a card field that is missing or does not parse to its
 *    canonical form skips its target field rather than guessing — and a value LONGER than the
 *    target's declared max length is never emitted (the platform's LengthFilter would silently
 *    truncate it into a different, wrong value). Adaptations are deliberate and enumerated:
 *    the CC_EXP capacity table (MMYY/MM\/YY/MMYYYY/MM\/YYYY keyed on declared maxLength) and
 *    the 4-digit→2-digit year shrink; nothing else reshapes a value to fit.
 *
 * Presentations may show brand + last4 + expiry ONLY — [presentationLine] never emits a full
 * PAN or any CVV (test-pinned by substring-absence).
 */
object CardFill {
    // Mirrors android.view.View autofill type constants (pure ints so core stays platform-free).
    const val AUTOFILL_TYPE_TEXT = 1
    const val AUTOFILL_TYPE_LIST = 3

    // ── Option-matching tables. The NORMATIVE copy lives in spec/test-vectors/cardfill.json
    // "tables" and CardFillVectorTest asserts these EQUAL it ([T14]) — the extension's TS twin
    // carries the same assert against the same file, so a drift on either side reds that side
    // (lockstep by construction, not by review). Keys are CardNormalize.brand outputs.
    internal val BRAND_SYNONYMS: Map<String, List<String>> = mapOf(
        "visa" to listOf("visa", "vi", "v", "001"),
        "mastercard" to listOf("mastercard", "mc", "002"),
        "amex" to listOf("amex", "americanexpress", "ax", "amx", "003"),
        "discover" to listOf("discover", "disc", "di", "004"),
    )
    internal val BRAND_CONTAINS_WORDS: Map<String, List<String>> = mapOf(
        "visa" to listOf("visa"),
        "mastercard" to listOf("mastercard"),
        "amex" to listOf("americanexpress", "amex"),
        "discover" to listOf("discover"),
    )
    internal val MONTH_NAMES: List<String> = listOf(
        "january", "february", "march", "april", "may", "june",
        "july", "august", "september", "october", "november", "december",
    )
    internal val MONTH_ABBREVIATIONS: Map<String, List<String>> = mapOf(
        "01" to listOf("jan"), "02" to listOf("feb"), "03" to listOf("mar"), "04" to listOf("apr"),
        "05" to listOf("may"), "06" to listOf("jun"), "07" to listOf("jul"), "08" to listOf("aug"),
        "09" to listOf("sep", "sept"), "10" to listOf("oct"), "11" to listOf("nov"), "12" to listOf("dec"),
    )

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
            FieldKind.CC_EXP -> composeExp(card, maxLength)
            FieldKind.CC_CSC -> card.securityCode?.takeIf { it.isNotBlank() }
            // The DERIVED brand's display label ("Visa") — never the stored brand field, which
            // is display-only and can be stale ([T9]-adjacent: one derivation everywhere).
            // Unknown IIN → null → the kind is missed, never guessed.
            FieldKind.CC_TYPE -> CardDisplay.brandLabel(CardNormalize.brand(card.number ?: ""))
            else -> null // non-card kind should never reach a card plan; skip defensively
        } ?: return null
        if (maxLength == null || raw.length <= maxLength) return raw
        if (kind == FieldKind.CC_EXP_YEAR && maxLength >= 2) return CardNormalize.yearTo2(raw)
        return null
    }

    /**
     * Combined-expiry adapter for TEXT targets — the declared-capacity table (design §9;
     * the extension's expiryTextFor is the same table plus placeholder branches core has no
     * signal for): 4 → MMYY, 5 → MM/YY, 6 → MMYYYY, 7 → MM/YYYY (the Chromium default),
     * ≤3 → null (no truthful expiry fits — never truncate), null/≥8 → MM/YY. Both halves
     * must parse: a combined target never receives half an expiry. Every emitted form fits
     * its branch by construction; textFor's generic fit-guard stays as the backstop.
     */
    private fun composeExp(card: CardData, maxLength: Int?): String? {
        val m = CardNormalize.padMonth(card.expMonth ?: "") ?: return null
        val y4 = CardNormalize.yearTo4(card.expYear ?: "") ?: return null
        val y2 = y4.substring(2)
        return when {
            maxLength == null || maxLength >= 8 -> "$m/$y2"
            maxLength <= 3 -> null
            maxLength == 4 -> "$m$y2"
            maxLength == 5 -> "$m/$y2"
            maxLength == 6 -> "$m$y4"
            else -> "$m/$y4" // 7
        }
    }

    /**
     * Option matching for LIST (select/spinner) nodes — month/year/combined-expiry/type have
     * defined matchers; every other kind on a LIST node skips (no guessing a PAN or CVV out
     * of a dropdown). PASS-MAJOR ([T2], vector-pinned): each pass scans ALL options in order
     * and the earliest pass with any match wins — option-major would let a digit-bearing
     * placeholder ("Month (12)") outrank the real "12" row. No match → null → skip.
     */
    private fun listIndexFor(f: CcField, card: CardData): Int? = when (f.kind) {
        FieldKind.CC_EXP_MONTH -> {
            val m = CardNormalize.padMonth(card.expMonth ?: "") ?: return null
            // Pass 1 whole-parse (pure-numeric "12"/"01" rows — padMonth rejects any other
            // char), pass 2 digit extraction (what makes "December (12)" selects fillable at
            // all), pass 3 English month names (name-only selects with no digits anywhere).
            f.options.indexOfFirst { CardNormalize.padMonth(it) == m }.takeIf { it >= 0 }
                ?: f.options.indexOfFirst { CardNormalize.padMonth(CardNormalize.digitsOnly(it)) == m }.takeIf { it >= 0 }
                ?: f.options.indexOfFirst { monthNameMatches(it, m) }.takeIf { it >= 0 }
        }
        FieldKind.CC_EXP_YEAR -> {
            val y = CardNormalize.yearTo4(card.expYear ?: "") ?: return null
            f.options.indexOfFirst { CardNormalize.yearTo4(it) == y }.takeIf { it >= 0 }
                ?: f.options.indexOfFirst { CardNormalize.yearTo4(CardNormalize.digitsOnly(it)) == y }.takeIf { it >= 0 }
        }
        FieldKind.CC_EXP -> {
            // Combined-expiry selects ("07/27" rows): the option's digits must equal MMYY or
            // MMYYYY exactly — both halves required, same as the TEXT adapter.
            val m = CardNormalize.padMonth(card.expMonth ?: "") ?: return null
            val y4 = CardNormalize.yearTo4(card.expYear ?: "") ?: return null
            val mmyy = m + y4.substring(2)
            val mmyyyy = m + y4
            f.options.indexOfFirst { CardNormalize.digitsOnly(it).let { d -> d == mmyy || d == mmyyyy } }.takeIf { it >= 0 }
        }
        FieldKind.CC_TYPE -> {
            // [T13]: the extension's value-pass and text-pass FOLDED over the single Android
            // option string — autofillOptions may expose either texts ("Visa") or values
            // ("001"/"VI"), core cannot tell which, so the synonym set carries both. Exact
            // (normalized) match against the derived brand's FULL synonym set first, across
            // ALL options; only then contains-primary-word ("Pay with Visa"). Brand is
            // derived from the number — unknown IIN → null → safe miss.
            val brand = CardNormalize.brand(card.number ?: "") ?: return null
            val synonyms = BRAND_SYNONYMS.getValue(brand)
            val containsWords = BRAND_CONTAINS_WORDS.getValue(brand)
            f.options.indexOfFirst { normalizeTypeOption(it) in synonyms }.takeIf { it >= 0 }
                ?: f.options.indexOfFirst { opt -> normalizeTypeOption(opt).let { n -> containsWords.any { it in n } } }.takeIf { it >= 0 }
        }
        else -> null
    }

    /** [T3] month-name matching: the option's FIRST maximal ASCII-letter run (leading digits/
     *  punctuation skipped, lowercased) must EQUAL the month's full English name or one of its
     *  abbreviations. Prefix matching is FORBIDDEN — fi "marraskuu" starts with "mar" but is
     *  November; equality degrades every localized list to a safe miss, never a wrong month
     *  (pinned by the cardfill.json Marraskuu negative). */
    private fun monthNameMatches(option: String, mm: String): Boolean {
        val run = firstAsciiLetterRun(option) ?: return false
        return run == MONTH_NAMES[mm.toInt() - 1] || run in MONTH_ABBREVIATIONS.getValue(mm)
    }

    private fun firstAsciiLetterRun(s: String): String? {
        // ASCII letters ONLY (mirrors CardNormalize's ASCII-digit rule): "Kesäkuu" yields "kes",
        // which can only fail the equality check — a non-ASCII month name can never half-match.
        fun isAsciiLetter(c: Char) = c in 'a'..'z' || c in 'A'..'Z'
        val start = s.indexOfFirst { isAsciiLetter(it) }
        if (start < 0) return null
        var end = start
        while (end < s.length && isAsciiLetter(s[end])) end++
        return s.substring(start, end).lowercase()
    }

    /** cc-type option normalization ([T13]): lowercase + strip everything but ASCII [a-z0-9] —
     *  "American Express" and "AMERICAN-EXPRESS" both collapse to "americanexpress". */
    private fun normalizeTypeOption(s: String): String = s.lowercase().filter { it in 'a'..'z' || it in '0'..'9' }

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
