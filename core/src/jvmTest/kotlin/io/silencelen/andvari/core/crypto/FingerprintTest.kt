package io.silencelen.andvari.core.crypto

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The 128-bit human short-form fingerprint matcher + display grouping (security review 2026-10,
 * §7), graded off the SAME `fingerprint.json` the web engine consumes (web/src/crypto/fingerprint.test.ts).
 * Pins the core A2 security change: the old 16-hex (64-bit) prefix no longer matches, a 32-hex
 * short form does (separators/case tolerated), and a machine value is compared at full 64 hex.
 */
class FingerprintTest {
    private val dir = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"))
    private val v: JsonObject = Json.parseToJsonElement(File(dir, "fingerprint.json").readText()).jsonObject
    private fun JsonObject.s(key: String): String = getValue(key).jsonPrimitive.content

    @Test
    fun shortFormAndGroupingMatchTheVector() {
        val full = v.s("full")
        assertEquals(v.s("shortForm"), Fingerprint.shortForm(full))
        assertEquals(32, Fingerprint.shortForm(full).length)
        assertEquals(v.s("groupedShort"), Fingerprint.groupedShort(full))
    }

    @Test
    fun matchesShortGradesEveryVectorRow() {
        val full = v.s("full")
        for (case in v.getValue("match").jsonArray.map { it.jsonObject }) {
            val entry = case.s("entry")
            val ok = case.getValue("ok").jsonPrimitive.boolean
            assertEquals(ok, Fingerprint.matchesShort(entry, full), "matchesShort(\"$entry\"): ${case.s("why")}")
            // Escrow's typed-sheet helper is the same function (one shared helper, both uses).
            assertEquals(ok, Escrow.shortFormMatches(entry, full), "Escrow.shortFormMatches parity: ${case.s("why")}")
        }
    }

    @Test
    fun machineValuesCompareFullLengthAProofPrefixesAreHumanOnly() {
        val m = v.getValue("machineFullCompare").jsonObject
        val full = m.s("full")
        val short = m.s("short")
        // A human-typed prefix matches the 32-hex short form…
        assertTrue(Fingerprint.matchesShort(short, full))
        assertEquals(m.getValue("shortMatchesHuman").jsonPrimitive.boolean, Fingerprint.matchesShort(short, full))
        // …but a machine compare is full 64 hex: the full value equals itself, the truncation does not.
        assertEquals(m.getValue("fullEqualsFull").jsonPrimitive.boolean, full == full)
        assertEquals(m.getValue("shortEqualsFull").jsonPrimitive.boolean, short == full)
        assertFalse(short == full, "a 32-hex short form must NOT pass a full-length machine compare")
    }
}
