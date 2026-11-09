package io.silencelen.andvari.core.client.autofill

import io.silencelen.andvari.core.client.CardData
import io.silencelen.andvari.core.client.ItemDoc
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Executable safety fixtures for [CardFill.plan]/[CardFill.presentationLine] (design
 * 2026-07-09-cards-wallet, "Android fill + save"): hostile-iframe zero-fill, LIST/TEXT
 * type-pinning, unmatched-LIST skip, partial-fill-beats-wrong-fill, and the
 * no-PAN/no-CVV presentation pin. Plain unit tests — no vector file; the vectors for the
 * upstream classify/refine stages live in card.json/cardform.json.
 */
class CardFillTest {
    private val fullCard = CardData(
        cardholderName = "Ada Lovelace",
        number = "4242 4242 4242 4242", // stored canonical is digits-only; spaced here to prove the fill re-canonicalizes
        expMonth = "12",
        expYear = "2027",
        securityCode = "986",
        brand = "visa",
    )

    private fun field(
        index: Int,
        kind: FieldKind,
        frame: String? = null,
        type: Int = CardFill.AUTOFILL_TYPE_TEXT,
        options: List<String> = emptyList(),
        maxLength: Int? = null,
    ) = CardFill.CcField(index, kind, frame, type, options, maxLength)

    private fun List<CardFill.Planned>.at(index: Int): CardFill.Value? = firstOrNull { it.index == index }?.value

    // (a) Hostile-iframe zero-fill: only the frame cluster holding a CC_NUMBER gets values.
    @Test
    fun hostileIframeClusterGetsNothing() {
        val plan = CardFill.plan(
            listOf(
                field(0, FieldKind.CC_NUMBER, frame = "shop.example"),
                field(1, FieldKind.CC_CSC, frame = "shop.example"),
                // Attacker frame: cc-hinted fields but no CC_NUMBER anchor of its own.
                field(2, FieldKind.CC_CSC, frame = "evil.example"),
                field(3, FieldKind.CC_EXP, frame = "evil.example"),
            ),
            fullCard,
            fillFrame = "shop.example",
        )
        assertEquals(listOf(0, 1), plan.map { it.index })
        assertEquals(CardFill.Value.Text("4242424242424242"), plan.at(0))
        assertEquals(CardFill.Value.Text("986"), plan.at(1))
    }

    // Security review 2026-10 (root cause E): the anchor gate alone was not a frame boundary — a
    // third-party iframe that declares a cc-number field of its OWN passed it, and the same dataset
    // wrote the PAN, CSC and expiry into that frame while the user filled the merchant's form. Only
    // the frame holding the field the user is filling (fillFrame) receives anything now.
    @Test
    fun aCrossOriginFrameWithItsOwnPanAnchorGetsNothing() {
        val plan = CardFill.plan(
            listOf(
                field(0, FieldKind.CC_NUMBER, frame = "shop.example"),
                field(1, FieldKind.CC_CSC, frame = "shop.example"),
                // Attacker frame: hidden inputs carrying their OWN cc-number anchor.
                field(2, FieldKind.CC_NUMBER, frame = "evil.example"),
                field(3, FieldKind.CC_CSC, frame = "evil.example"),
                field(4, FieldKind.CC_EXP, frame = "evil.example"),
            ),
            fullCard,
            fillFrame = "shop.example",
        )
        assertEquals(listOf(0, 1), plan.map { it.index })
    }

    // The same rule keeps processor-hosted card frames working: the user taps the card number inside
    // the payment provider's iframe, so that frame is the fill frame and the top page gets nothing.
    @Test
    fun theFocusedProcessorFrameIsTheOnlyOneFilled() {
        val plan = CardFill.plan(
            listOf(
                field(0, FieldKind.CC_NAME, frame = "shop.example"),
                field(1, FieldKind.CC_NUMBER, frame = "shop.example"),
                field(2, FieldKind.CC_NUMBER, frame = "psp.example"),
                field(3, FieldKind.CC_CSC, frame = "psp.example"),
            ),
            fullCard,
            fillFrame = "psp.example",
        )
        assertEquals(listOf(2, 3), plan.map { it.index })
        assertEquals(CardFill.Value.Text("4242424242424242"), plan.at(2))
    }

    // A fill frame holding no field plans nothing (and a frame without its own anchor still gets nothing).
    @Test
    fun aFillFrameWithNoAnchorPlansNothing() {
        val fields = listOf(
            field(0, FieldKind.CC_NUMBER, frame = "shop.example"),
            field(1, FieldKind.CC_CSC, frame = "evil.example"),
        )
        assertTrue(CardFill.plan(fields, fullCard, fillFrame = "other.example").isEmpty())
        assertTrue(CardFill.plan(fields, fullCard, fillFrame = "evil.example").isEmpty())
        assertTrue(CardFill.plan(fields, fullCard, fillFrame = null).isEmpty())
    }

    // (b) LIST fields get ListIndex ONLY, matched numerically across option spellings.
    @Test
    fun listFieldsGetListIndexNeverText() {
        val card = fullCard.copy(expMonth = "01", expYear = "2027")
        val plan = CardFill.plan(
            listOf(
                field(0, FieldKind.CC_NUMBER),
                field(1, FieldKind.CC_EXP_MONTH, type = CardFill.AUTOFILL_TYPE_LIST, options = listOf("MM", "1", "2", "3")),
                field(2, FieldKind.CC_EXP_MONTH, type = CardFill.AUTOFILL_TYPE_LIST, options = listOf("12", "01", "02")),
                field(3, FieldKind.CC_EXP_MONTH, type = CardFill.AUTOFILL_TYPE_LIST, options = listOf("December (12)", "January (01)")),
                field(4, FieldKind.CC_EXP_YEAR, type = CardFill.AUTOFILL_TYPE_LIST, options = listOf("Year", "2026", "2027")),
                field(5, FieldKind.CC_EXP_YEAR, type = CardFill.AUTOFILL_TYPE_LIST, options = listOf("26", "27", "28")),
            ),
            card,
            fillFrame = null,
        )
        assertEquals(CardFill.Value.ListIndex(1), plan.at(1)) // "1" matches month 01
        assertEquals(CardFill.Value.ListIndex(1), plan.at(2)) // "01"
        assertEquals(CardFill.Value.ListIndex(1), plan.at(3)) // "January (01)"
        assertEquals(CardFill.Value.ListIndex(2), plan.at(4)) // "2027"
        assertEquals(CardFill.Value.ListIndex(1), plan.at(5)) // "27" pivots to 2027
        // Type-pinning: no LIST target ever receives Text.
        for (p in plan.filter { it.index != 0 }) assertTrue(p.value is CardFill.Value.ListIndex, "field ${p.index} got ${p.value}")
        assertTrue(plan.at(0) is CardFill.Value.Text)
    }

    // (c) Unmatched LIST options → the field is absent from the plan, not guessed.
    @Test
    fun unmatchedListOptionsSkipTheField() {
        val plan = CardFill.plan(
            listOf(
                field(0, FieldKind.CC_NUMBER),
                field(1, FieldKind.CC_EXP_MONTH, type = CardFill.AUTOFILL_TYPE_LIST, options = listOf("foo", "bar")),
                field(2, FieldKind.CC_EXP_YEAR, type = CardFill.AUTOFILL_TYPE_LIST, options = listOf("1999", "2001")),
            ),
            fullCard,
            fillFrame = null,
        )
        assertEquals(listOf(0), plan.map { it.index })
    }

    // (d) TEXT happy path: every kind fills its canonical form.
    @Test
    fun textFillsCanonicalForms() {
        val card = fullCard.copy(expMonth = "1", expYear = "27") // near-canonical stored values still adapt
        val plan = CardFill.plan(
            listOf(
                field(0, FieldKind.CC_NUMBER),
                field(1, FieldKind.CC_NAME),
                field(2, FieldKind.CC_EXP_MONTH),
                field(3, FieldKind.CC_EXP_YEAR),
                field(4, FieldKind.CC_EXP),
                field(5, FieldKind.CC_CSC),
            ),
            card,
            fillFrame = null,
        )
        assertEquals(CardFill.Value.Text("4242424242424242"), plan.at(0)) // digits-only
        assertEquals(CardFill.Value.Text("Ada Lovelace"), plan.at(1))
        assertEquals(CardFill.Value.Text("01"), plan.at(2)) // padded month
        assertEquals(CardFill.Value.Text("2027"), plan.at(3)) // 4-digit year
        assertEquals(CardFill.Value.Text("01/27"), plan.at(4)) // composed MM/YY
        assertEquals(CardFill.Value.Text("986"), plan.at(5))
        for (p in plan) assertTrue(p.value is CardFill.Value.Text)
    }

    // (e) Missing card fields skip their targets; an empty card plans nothing.
    @Test
    fun missingCardFieldsAreSkipped() {
        val noCvv = fullCard.copy(securityCode = null)
        val plan = CardFill.plan(
            listOf(
                field(0, FieldKind.CC_NUMBER),
                field(1, FieldKind.CC_CSC),
            ),
            noCvv,
            fillFrame = null,
        )
        assertEquals(listOf(0), plan.map { it.index })

        val empty = CardFill.plan(
            listOf(
                field(0, FieldKind.CC_NUMBER),
                field(1, FieldKind.CC_NAME),
                field(2, FieldKind.CC_EXP),
            ),
            CardData(),
            fillFrame = null,
        )
        assertEquals(emptyList(), empty)
    }

    // (f) Presentation pin: brand + last4 + expiry ONLY — never full PAN, never CVV.
    @Test
    fun presentationLineNeverLeaksPanOrCvv() {
        val doc = ItemDoc(type = "card", name = "Personal Visa", card = fullCard)
        val line = CardFill.presentationLine(doc)
        assertEquals("Visa ••4242 · 12/27", line)
        assertFalse("4242424242424242" in line)
        assertFalse(CardNormalize.digitsOnly(line).contains("4242424242424242"))
        assertFalse("986" in line)

        // Partial expiry degrades to subtitle-only — no dangling separator.
        val partial = ItemDoc(type = "card", name = "Personal Visa", card = fullCard.copy(expYear = null))
        assertEquals("Visa ••4242", CardFill.presentationLine(partial))
        val noCard = ItemDoc(type = "card", name = "Empty", card = CardData())
        assertEquals("card", CardFill.presentationLine(noCard))
    }

    // (g) Unknown autofillType skipped; output deterministically ordered by field index.
    @Test
    fun unknownTypeSkippedAndOrderIsByIndex() {
        val plan = CardFill.plan(
            listOf(
                field(5, FieldKind.CC_CSC),
                field(2, FieldKind.CC_NUMBER),
                field(9, FieldKind.CC_NAME, type = 4), // AUTOFILL_TYPE_TOGGLE-ish → skipped
                field(7, FieldKind.CC_EXP, type = 0), // AUTOFILL_TYPE_NONE → skipped
                field(3, FieldKind.CC_EXP_MONTH),
            ),
            fullCard,
            fillFrame = null,
        )
        assertEquals(listOf(2, 3, 5), plan.map { it.index })
    }

    // (i) Fit-guard: a value longer than the control's declared maxLength is never emitted —
    // the platform's LengthFilter would truncate "2027" in a 2-char box into "20", a WRONG
    // year. Adaptations are per-kind tables (year 4→2-digit; combined expiry per the design
    // §9 capacity table — "1227" IS the truthful 4-char form); everything else skips. The
    // table's full branch coverage lives in CardFillVectorTest (cardfill.json expiryText).
    @Test
    fun maxLengthFitGuardAdaptsYearAndSkipsEverythingElse() {
        val plan = CardFill.plan(
            listOf(
                field(0, FieldKind.CC_NUMBER),                       // anchor
                field(1, FieldKind.CC_EXP_YEAR, maxLength = 2),      // adapts: "2027" → "27"
                field(2, FieldKind.CC_EXP_YEAR, maxLength = 4),      // fits: "2027"
                field(3, FieldKind.CC_EXP, maxLength = 4),           // packs MMYY: "1227" (§9 table)
                field(4, FieldKind.CC_NUMBER, maxLength = 12),       // 16-digit PAN can't fit → skip
                field(5, FieldKind.CC_EXP_YEAR, maxLength = 1),      // nothing fits → skip
                field(6, FieldKind.CC_EXP, maxLength = 3),           // no truthful expiry in 3 chars → skip
            ),
            fullCard,
            fillFrame = null,
        )
        assertEquals(CardFill.Value.Text("27"), plan.at(1))
        assertEquals(CardFill.Value.Text("2027"), plan.at(2))
        assertEquals(CardFill.Value.Text("1227"), plan.at(3))
        assertEquals(listOf(0, 1, 2, 3), plan.map { it.index })
    }

    // (j) LIST two-pass: a digit-bearing placeholder row ("Year (e.g. 2026)") never outranks
    // a pure-numeric real row; extraction still rescues label-style selects.
    @Test
    fun listPlaceholderNeverOutranksTheRealOption() {
        val card = fullCard.copy(expMonth = "12", expYear = "2026")
        val plan = CardFill.plan(
            listOf(
                field(0, FieldKind.CC_NUMBER),
                field(1, FieldKind.CC_EXP_YEAR, type = CardFill.AUTOFILL_TYPE_LIST, options = listOf("Year (e.g. 2026)", "2026", "2027")),
                field(2, FieldKind.CC_EXP_MONTH, type = CardFill.AUTOFILL_TYPE_LIST, options = listOf("Month (12)", "12", "01")),
                // No pure-numeric row at all → extraction fallback still fills label selects.
                field(3, FieldKind.CC_EXP_MONTH, type = CardFill.AUTOFILL_TYPE_LIST, options = listOf("November (11)", "December (12)")),
            ),
            card,
            fillFrame = null,
        )
        assertEquals(CardFill.Value.ListIndex(1), plan.at(1))
        assertEquals(CardFill.Value.ListIndex(1), plan.at(2))
        assertEquals(CardFill.Value.ListIndex(1), plan.at(3))
    }

    // (h) Null frame domains cluster together: a native-app form fills when its CC_NUMBER is present.
    @Test
    fun nullDomainsClusterTogetherAndFill() {
        val plan = CardFill.plan(
            listOf(
                field(0, FieldKind.CC_NUMBER, frame = null),
                field(1, FieldKind.CC_EXP, frame = null),
                field(2, FieldKind.CC_CSC, frame = null),
            ),
            fullCard,
            fillFrame = null,
        )
        assertEquals(listOf(0, 1, 2), plan.map { it.index })
        assertEquals(CardFill.Value.Text("12/27"), plan.at(1))
    }
}
