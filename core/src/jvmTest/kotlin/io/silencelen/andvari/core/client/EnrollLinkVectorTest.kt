package io.silencelen.andvari.core.client

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** Consumes spec/test-vectors/enrolllink.json — the SAME file web/src/enroll/enrolllink.test.ts checks. */
class EnrollLinkVectorTest {
    private val dir = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"))
    private val v: JsonObject = Json.parseToJsonElement(File(dir, "enrolllink.json").readText()).jsonObject

    private fun payload(o: JsonObject) = EnrollPayload(
        v = o.getValue("v").jsonPrimitive.int,
        o = o.getValue("o").jsonPrimitive.content,
        t = o.getValue("t").jsonPrimitive.content,
        e = o.getValue("e").jsonPrimitive.content,
    )

    @Test
    fun roundTrips() {
        for (case in v.getValue("roundTrips").jsonArray.map { it.jsonObject }) {
            val name = case.getValue("name").jsonPrimitive.content
            val o = case.getValue("o").jsonPrimitive.content
            val t = case.getValue("t").jsonPrimitive.content
            val e = case.getValue("e").jsonPrimitive.content
            val link = case.getValue("link").jsonPrimitive.content
            // The pinned link string is byte-exact: compose must reproduce it, and parse
            // must carry o/t/e back verbatim (e in particular is NOT normalized).
            assertEquals(link, EnrollLink.compose(o, t, e), "compose $name")
            assertEquals(EnrollPayload(1, o, t, e), EnrollLink.parse(link), "parse $name")
        }
    }

    @Test
    fun parseRows() {
        for (case in v.getValue("parse").jsonArray.map { it.jsonObject }) {
            val name = case.getValue("name").jsonPrimitive.content
            val input = case.getValue("input").jsonPrimitive.content
            val expected = case.getValue("expected")
            if (expected is JsonNull) {
                assertNull(EnrollLink.parse(input), "parse '$name' must be null")
            } else {
                assertEquals(payload(expected.jsonObject), EnrollLink.parse(input), "parse '$name'")
            }
        }
    }

    @Test
    fun parseIsTotalOnTruncatedLinks() {
        // Belt over the vector rows: parse is TOTAL — every prefix of a real link must
        // return (payload or null) rather than throw, or it is a crash primitive in UI code.
        val link = EnrollLink.compose("https://vault.example", "tok123", "a@example.com")
        for (len in 0..link.length) EnrollLink.parse(link.substring(0, len))
    }
}
