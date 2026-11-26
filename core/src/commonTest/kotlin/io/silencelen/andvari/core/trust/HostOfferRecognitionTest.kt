package io.silencelen.andvari.core.trust

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull

/**
 * Design 2026-11-15 §2.4 "Host JSON offer" (VR-15): "printable ASCII and a JSON object with a string
 * `purpose`, else `non_canonical`; a `purpose` other than `setup-offer` and `enrol-offer` is
 * `unknown_format`". What counts as "a JSON object" must not depend on a platform parser: kotlinx reads
 * a bare token such as `abc` as a value, `JSON.parse` does not. These rows pin the edge between the two
 * verdicts; the web twin grades the SAME list (`web/src/crypto/trust/hostoffer.test.ts`).
 */
class HostOfferRecognitionTest {
    private fun verdict(text: String): String = when (val r = StatementCodec.parseHostOffer(text.encodeToByteArray())) {
        is Checked.Ok -> "ok"
        is Checked.Refused -> r.verdict.code
    }

    @Test
    fun recognition_isTheSameOnEveryEngine() {
        val deep = "[".repeat(33) + "]".repeat(33)
        val atTheBound = "[".repeat(31) + "]".repeat(31) // 32 containers open with the object around it
        val rows = listOf(
            """{"purpose":"other"}""" to "unknown_format",
            """ {"purpose":"other"}""" to "unknown_format", // white space is still JSON; the purpose decides
            """{"purpose":"other","x":1e5}""" to "unknown_format",
            """{"purpose":"oth\u0065r"}""" to "unknown_format",
            """{"__proto__":{"purpose":"x"},"purpose":"other"}""" to "unknown_format",
            """{"purpose":"other","x":$atTheBound}""" to "unknown_format",
            """{"purpose":"other","x":abc}""" to "non_canonical", // not JSON: a bare token
            """{"purpose":"other","x":NaN}""" to "non_canonical",
            """{"purpose":"other","x":01}""" to "non_canonical",
            """{"purpose":"other","x":1.}""" to "non_canonical",
            """{"purpose":"other","x":-}""" to "non_canonical",
            """{"purpose":"other",}""" to "non_canonical",
            """{"purpose":"other"}x""" to "non_canonical",
            """{"purpose":"other","x":'y'}""" to "non_canonical",
            """{"purpose":"other","x":$deep}""" to "non_canonical", // deeper than this package reads
            """{"purpose":1}""" to "non_canonical",
            """{"purpose":null}""" to "non_canonical",
            """{"v":2}""" to "non_canonical",
            """{"__proto__":{"purpose":"setup-offer"}}""" to "non_canonical",
            """[{"purpose":"setup-offer"}]""" to "non_canonical",
            """"setup-offer"""" to "non_canonical",
            // A key twice at the top level is non_canonical whichever value comes last.
            """{"purpose":"zzz","purpose":"setup-offer"}""" to "non_canonical",
            """{"purpose":"setup-offer","purpose":"zzz"}""" to "non_canonical",
            """{"purpose":"other","purpose":"other"}""" to "non_canonical",
            """{"purpose":"other","x":1,"x":2}""" to "non_canonical",
            """{"purpose":"other","\u0078":1,"x":2}""" to "non_canonical", // the same key, once escaped
            """{"purpose":"other","x":{"a":1,"a":2}}""" to "unknown_format", // only the top level is judged here
            """{"purpose":"setup-off\u0065r"}""" to "non_canonical", // a host offer by its purpose, never canonical with an escape
            """{"purpose":"setup-offer"}""" to "non_canonical",
            "" to "non_canonical",
        )
        for ((text, expected) in rows) assertEquals(expected, verdict(text), text)
    }

    @Test
    fun strictReader_acceptsExactlyJson() {
        fun parses(text: String) = StrictJson.parse(text) != null
        for (good in listOf("{}", "[]", "0", "-0", "1.5e-3", "\"a\\n\\u00e9\"", "true", "null", " { \"a\" : [ 1 , 2 ] } ", "{\"a\":{\"a\":1}}")) {
            assertEquals(true, parses(good), good)
        }
        for (bad in listOf("", "{", "{]", "{\"a\"}", "{a:1}", "[1,]", "01", "+1", ".5", "1.", "1e", "tru", "nul", "\"a", "\"\\x\"", "\"\t\"", "{} {}", "NaN", "Infinity", "'a'", "{\"a\":1,,\"b\":2}")) {
            assertEquals(false, parses(bad), bad)
        }
        // Compact: no white space outside strings; inside a string it is content.
        assertNull(StrictJson.parse("{\"a\": 1}", compact = true))
        assertNull(StrictJson.parse(" {}", compact = true))
        assertIs<JsonNode.Obj>(StrictJson.parse("{\"a b\":\" \"}", compact = true))
        // A repeated name is kept, in order; the caller decides.
        val twice = assertIs<JsonNode.Obj>(StrictJson.parse("{\"a\":1,\"a\":2}"))
        assertEquals(true, twice.hasRepeatedName)
        assertEquals("2", (twice.last("a") as JsonNode.Num).token)
        // Escapes: only \" and \\ count as plain.
        assertEquals(true, (StrictJson.parse("\"a\\\"b\\\\c\"") as JsonNode.Str).plainEscapes)
        assertEquals(false, (StrictJson.parse("\"a\\u0041\"") as JsonNode.Str).plainEscapes)
        assertEquals("aA/", (StrictJson.parse("\"a\\u0041\\/\"") as JsonNode.Str).value)
    }
}
