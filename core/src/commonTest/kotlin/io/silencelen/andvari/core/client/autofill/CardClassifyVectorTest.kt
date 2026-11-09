package io.silencelen.andvari.core.client.autofill

import io.silencelen.andvari.core.readVector
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Card sections of spec/test-vectors/urimatch.json (classifyCard + classifyCardFreeRegression).
 * The frozen "classify" section stays card-free so the fielded web/extension 3-kind classifiers
 * keep passing it; their ports consume these sections once they grow card kinds.
 */
class CardClassifyVectorTest {
    private val v: JsonObject = Json.parseToJsonElement(readVector("urimatch.json")).jsonObject

    @Test
    fun classifyCard() {
        for (case in v.getValue("classifyCard").jsonArray.map { it.jsonObject }) {
            val expected = vectorFieldKind(case.getValue("expected").jsonPrimitive.content)
            assertEquals(expected, FieldClassifier.classify(vectorFieldSignal(case)), "classifyCard $case")
        }
    }

    /** The 0.7.0 gate: card-free verdicts are BIT-IDENTICAL to pre-card classification — replays
     *  the frozen classify section plus the dedicated regression cases; none may pin a card kind. */
    @Test
    fun cardFreeFormsBitIdentical() {
        val cases = v.getValue("classify").jsonArray + v.getValue("classifyCardFreeRegression").jsonArray
        val loginKinds = setOf(FieldKind.USERNAME, FieldKind.PASSWORD, FieldKind.NONE)
        for (case in cases.map { it.jsonObject }) {
            val expected = vectorFieldKind(case.getValue("expected").jsonPrimitive.content)
            assertTrue(expected in loginKinds, "card kind pinned in a card-free section: $case")
            assertEquals(expected, FieldClassifier.classify(vectorFieldSignal(case)), "card-free regression $case")
        }
    }
}
