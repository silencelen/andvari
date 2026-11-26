package io.silencelen.andvari.core.model.wire

import io.silencelen.andvari.core.readVector
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals

/** Grades the wire-side grammar ([WireGrammar]) on `spec/test-vectors/encodings.json`: emailNorm, platform, origin. */
class WireGrammarVectorTest {
    private val doc = Json.parseToJsonElement(readVector("encodings.json")).jsonObject

    @Test fun emailNorm() {
        for (row in doc.getValue("emailNorm").jsonArray.map { it.jsonObject }) {
            val input = row.getValue("input").jsonPrimitive.content
            val expect = row.getValue("expect").jsonObject
            val want = (expect["emailNorm"])?.jsonPrimitive?.content
            assertEquals(expect.getValue("verdict").jsonPrimitive.content == "ok", want != null, "row shape")
            assertEquals(want, WireGrammar.emailNorm(input), row["why"].toString())
        }
    }

    @Test fun platform() {
        for (row in doc.getValue("platform").jsonArray.map { it.jsonObject }) {
            val v = row.getValue("value").jsonPrimitive.content
            assertEquals(row.getValue("valid").jsonPrimitive.boolean, v in WirePlatform.ALL, v)
        }
    }

    @Test fun origin() {
        for (row in doc.getValue("origin").jsonArray.map { it.jsonObject }) {
            val o = row.getValue("origin").jsonPrimitive.content
            assertEquals(row.getValue("valid").jsonPrimitive.boolean, WireGrammar.isOrigin(o), "${row["why"]}: $o")
        }
    }
}
