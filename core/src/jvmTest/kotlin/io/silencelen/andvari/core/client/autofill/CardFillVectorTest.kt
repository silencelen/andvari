package io.silencelen.andvari.core.client.autofill

import io.silencelen.andvari.core.client.CardData
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Consumes spec/test-vectors/cardfill.json (design 2026-07-23-card-autofill-tier1 §11) — the
 * select matcher + text-target adapters the extension's TS twin (cardfill.ts) runs against the
 * SAME file. Skipped here by contract, not omission: `tsOnly` cases (placeholder-signal
 * branches — core has no placeholder) and the `selectIndexDom` section (value≠text option
 * pairs — Android exposes ONE string per option). Everything is driven through the public
 * [CardFill.plan] with a same-cluster CC_NUMBER anchor field, never a private shortcut, so the
 * hostile-iframe/type-pinning plumbing is exercised on every vector.
 */
class CardFillVectorTest {
    private val dir = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"))
    private val v: JsonObject = Json.parseToJsonElement(File(dir, "cardfill.json").readText()).jsonObject

    private fun JsonObject.str(k: String): String? = this[k]?.takeIf { it !is JsonNull }?.jsonPrimitive?.content
    private fun JsonObject.int(k: String): Int? = this[k]?.takeIf { it !is JsonNull }?.jsonPrimitive?.int
    private fun JsonObject.strings(k: String): List<String> = getValue(k).jsonArray.map { it.jsonPrimitive.content }
    private fun JsonObject.tsOnly(): Boolean = this["tsOnly"]?.jsonPrimitive?.content == "true"

    /** [T14]/[W13] the compiled-in tables EQUAL the vector's normative copy — drift on either
     *  side (a synonym added in TS but not here, a fold digraph or locale name edited in one
     *  engine) reds that side's gate instead of silently forking the two matchers. The KEY-SET
     *  assert closes the [W13] vacuity hole: a NEW `tables` entry added to the vector without a
     *  Kotlin mirror + a per-table assert below reds here rather than shipping unchecked. */
    @Test
    fun tablesMatchTheNormativeVectorCopy() {
        val t = v.getValue("tables").jsonObject
        assertEquals(t.getValue("synonyms").jsonObject.mapValues { (_, a) -> a.jsonArray.map { it.jsonPrimitive.content } }, CardFill.BRAND_SYNONYMS, "synonyms")
        assertEquals(t.getValue("containsWords").jsonObject.mapValues { (_, a) -> a.jsonArray.map { it.jsonPrimitive.content } }, CardFill.BRAND_CONTAINS_WORDS, "containsWords")
        assertEquals(t.strings("monthNames"), CardFill.MONTH_NAMES, "monthNames")
        assertEquals(t.getValue("monthAbbreviations").jsonObject.mapValues { (_, a) -> a.jsonArray.map { it.jsonPrimitive.content } }, CardFill.MONTH_ABBREVIATIONS, "monthAbbreviations")
        assertEquals(t.getValue("asciiFold").jsonObject.entries.associate { (k, a) -> k.single() to a.jsonPrimitive.content }, FieldClassifier.ASCII_FOLD, "asciiFold")
        assertEquals(t.getValue("monthNamesByLocale").jsonObject.mapValues { (_, a) -> a.jsonArray.map { it.jsonPrimitive.content } }, CardFill.MONTH_NAMES_BY_LOCALE, "monthNamesByLocale")
        assertEquals(
            setOf("synonyms", "containsWords", "monthNames", "monthAbbreviations", "keywords", "asciiFold", "monthNamesByLocale"),
            t.keys,
            "tables key-set (a new vector table needs a Kotlin mirror + a per-table assert above)",
        )
    }

    /** [U8] the keyword groups are an ORDERED array and group order is load-bearing (month/year
     *  before generic exp; the [U1] bare-creditcard group LAST) — so this asserts SEQUENCE
     *  equality: kinds AND order AND contents. A named-key map compare (the [T14] shape above)
     *  would stay silently green across a reorder — the vacuity trap the design names. */
    @Test
    fun keywordGroupsMatchTheNormativeOrderedCopy() {
        val expected = v.getValue("tables").jsonObject.getValue("keywords").jsonArray.map { g ->
            g.jsonObject.let { it.strings("keywords") to vectorFieldKind(it.getValue("kind").jsonPrimitive.content) }
        }
        assertEquals(expected, FieldClassifier.CARD_NAME_KINDS, "tables.keywords sequence")
    }

    /** dateLeg (core-only section, [U8]/§5): DATE-node combined expiry → epoch ms of
     *  (year, month, day 1) UTC — driven through the public plan like every other section,
     *  so the CC_EXP-only + anchor-cluster plumbing is exercised on each vector. */
    @Test
    fun dateLeg() {
        for (case in v.getValue("dateLeg").jsonArray.map { it.jsonObject }) {
            val name = case.getValue("name").jsonPrimitive.content
            val card = CardData(expMonth = case.str("expMonth"), expYear = case.str("expYear"))
            val plan = CardFill.plan(
                listOf(
                    CardFill.CcField(0, FieldKind.CC_NUMBER, null, CardFill.AUTOFILL_TYPE_TEXT, emptyList()),
                    CardFill.CcField(1, FieldKind.CC_EXP, null, CardFill.AUTOFILL_TYPE_DATE, emptyList()),
                    // A month-half on a DATE node must always skip — a date would fabricate the day+year.
                    CardFill.CcField(2, FieldKind.CC_EXP_MONTH, null, CardFill.AUTOFILL_TYPE_DATE, emptyList()),
                ),
                card,
            )
            val expectedMs = case.getValue("expectedMs").jsonPrimitive.long
            assertEquals(CardFill.Value.DateMs(expectedMs), plan.firstOrNull { it.index == 1 }?.value, name)
            assertEquals(null, plan.firstOrNull { it.index == 2 }, "$name: non-CC_EXP kind on a DATE node")
        }
    }

    /** `shared` select cases: options are plain strings = Android's autofillOptions label list;
     *  `expected` is the option index the plan must choose, null = the field must be ABSENT
     *  from the plan (safe miss, never a guess). */
    @Test
    fun selectIndexShared() {
        for (case in v.getValue("selectIndexShared").jsonArray.map { it.jsonObject }) {
            val name = case.getValue("name").jsonPrimitive.content
            val card = CardData(number = case.str("number"), expMonth = case.str("expMonth"), expYear = case.str("expYear"))
            val plan = CardFill.plan(
                listOf(
                    // Anchor only — a missing number leaves it unplanned but still qualifies the cluster.
                    CardFill.CcField(0, FieldKind.CC_NUMBER, null, CardFill.AUTOFILL_TYPE_TEXT, emptyList()),
                    CardFill.CcField(1, vectorFieldKind(case.getValue("kind").jsonPrimitive.content), null, CardFill.AUTOFILL_TYPE_LIST, case.strings("options")),
                ),
                card,
            )
            val got = plan.firstOrNull { it.index == 1 }?.value
            assertEquals(case.int("expected")?.let { CardFill.Value.ListIndex(it) }, got, name)
        }
    }

    private fun runTextSection(section: String, kind: FieldKind) {
        for (case in v.getValue(section).jsonArray.map { it.jsonObject }) {
            if (case.tsOnly()) continue // placeholder-signal branch — extension engine only
            val name = case.getValue("name").jsonPrimitive.content
            val card = CardData(expMonth = case.str("expMonth"), expYear = case.str("expYear"))
            val plan = CardFill.plan(
                listOf(
                    CardFill.CcField(0, FieldKind.CC_NUMBER, null, CardFill.AUTOFILL_TYPE_TEXT, emptyList()),
                    CardFill.CcField(1, kind, null, CardFill.AUTOFILL_TYPE_TEXT, emptyList(), maxLength = case.int("maxLength")),
                ),
                card,
            )
            val got = plan.firstOrNull { it.index == 1 }?.value
            assertEquals(case.str("expected")?.let { CardFill.Value.Text(it) }, got, "$section: $name")
        }
    }

    /** [W2] shared `splitPan`: CardNormalize.splitPanChunks byte-mirrors the extension `splitPan`
     *  — BOTH engines assert the SAME chunk arrays against this section. `boxes` = declared
     *  maxLengths in document order (null = undeclared); `expected` null = no split. */
    @Test
    fun splitPan() {
        for (case in v.getValue("splitPan").jsonArray.map { it.jsonObject }) {
            val name = case.getValue("name").jsonPrimitive.content
            val boxes = case.getValue("boxes").jsonArray.map { if (it is JsonNull) null else it.jsonPrimitive.int }
            val pan = case.getValue("pan").jsonPrimitive.content
            val expected = case["expected"]?.takeIf { it !is JsonNull }?.jsonArray?.map { it.jsonPrimitive.content }
            assertEquals(expected, CardNormalize.splitPanChunks(pan, boxes), name)
        }
    }

    /** [W1] core-only `splitPanPlan`: the CardFill.plan split integration. `clusters` flatten to
     *  CcFields in order (box index = position across ALL clusters' boxes) so the >1-CC_NUMBER-
     *  TEXT-box pre-pass is exercised through the public plan, per cluster and after the anchor
     *  gate. `expectedPlanned` = [{index, text}] for the filled TEXT boxes ONLY; a box absent from
     *  it is SKIPPED (ineligible-fallback suppression or a hostile-frame zero-fill). */
    @Test
    fun splitPanPlan() {
        for (case in v.getValue("splitPanPlan").jsonArray.map { it.jsonObject }) {
            val name = case.getValue("name").jsonPrimitive.content
            val card = CardData(number = case.str("pan"), expMonth = case.str("expMonth"), expYear = case.str("expYear"))
            val fields = ArrayList<CardFill.CcField>()
            var idx = 0
            for (cl in case.getValue("clusters").jsonArray.map { it.jsonObject }) {
                val frame = cl.str("frameDomain")
                for (box in cl.getValue("boxes").jsonArray.map { it.jsonObject }) {
                    fields.add(
                        CardFill.CcField(
                            idx++, vectorFieldKind(box.getValue("kind").jsonPrimitive.content), frame,
                            box.getValue("autofillType").jsonPrimitive.int, emptyList(), maxLength = box.int("maxLength"),
                        ),
                    )
                }
            }
            val expected = case.getValue("expectedPlanned").jsonArray.map { it.jsonObject }
                .map { it.getValue("index").jsonPrimitive.int to it.getValue("text").jsonPrimitive.content }
            val actual = CardFill.plan(fields, card).map { it.index to (it.value as CardFill.Value.Text).text }
            assertEquals(expected, actual, name)
        }
    }

    @Test
    fun expiryText() = runTextSection("expiryText", FieldKind.CC_EXP)

    @Test
    fun yearText() = runTextSection("yearText", FieldKind.CC_EXP_YEAR)

    @Test
    fun monthText() = runTextSection("monthText", FieldKind.CC_EXP_MONTH)
}
