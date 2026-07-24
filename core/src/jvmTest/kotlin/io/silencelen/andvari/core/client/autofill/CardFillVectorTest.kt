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

    /** [T14] the compiled-in tables EQUAL the vector's normative copy — drift on either side
     *  (a synonym added in TS but not here, an abbreviation edited in one engine) reds that
     *  side's gate instead of silently forking the two matchers. */
    @Test
    fun tablesMatchTheNormativeVectorCopy() {
        val t = v.getValue("tables").jsonObject
        assertEquals(t.getValue("synonyms").jsonObject.mapValues { (_, a) -> a.jsonArray.map { it.jsonPrimitive.content } }, CardFill.BRAND_SYNONYMS, "synonyms")
        assertEquals(t.getValue("containsWords").jsonObject.mapValues { (_, a) -> a.jsonArray.map { it.jsonPrimitive.content } }, CardFill.BRAND_CONTAINS_WORDS, "containsWords")
        assertEquals(t.strings("monthNames"), CardFill.MONTH_NAMES, "monthNames")
        assertEquals(t.getValue("monthAbbreviations").jsonObject.mapValues { (_, a) -> a.jsonArray.map { it.jsonPrimitive.content } }, CardFill.MONTH_ABBREVIATIONS, "monthAbbreviations")
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

    @Test
    fun expiryText() = runTextSection("expiryText", FieldKind.CC_EXP)

    @Test
    fun yearText() = runTextSection("yearText", FieldKind.CC_EXP_YEAR)

    @Test
    fun monthText() = runTextSection("monthText", FieldKind.CC_EXP_MONTH)
}
