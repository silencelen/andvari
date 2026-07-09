package io.silencelen.andvari.core.client.autofill

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals

/** Consumes spec/test-vectors/card.json — the file the web + extension TS CardNormalize ports run too. */
class CardNormalizeVectorTest {
    private val dir = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"))
    private val v: JsonObject = Json.parseToJsonElement(File(dir, "card.json").readText()).jsonObject

    private fun cases(section: String) = v.getValue(section).jsonArray.map { it.jsonObject }
    private fun JsonObject.str(k: String) = getValue(k).let { if (it is JsonNull) null else it.jsonPrimitive.content }

    @Test
    fun digitsOnly() {
        for (c in cases("digitsOnly")) assertEquals(c.str("expected"), CardNormalize.digitsOnly(c.str("raw")!!), "digitsOnly $c")
    }

    @Test
    fun luhn() {
        for (c in cases("luhn")) assertEquals(c.getValue("valid").jsonPrimitive.boolean, CardNormalize.luhnValid(c.str("raw")!!), "luhn $c")
    }

    @Test
    fun brand() {
        for (c in cases("brand")) assertEquals(c.str("expected"), CardNormalize.brand(c.str("raw")!!), "brand $c")
    }

    @Test
    fun parseExpiry() {
        for (c in cases("parseExpiry")) {
            val e = CardNormalize.parseExpiry(c.str("raw")!!)
            assertEquals(c.str("expMonth"), e?.expMonth, "parseExpiry month $c")
            assertEquals(c.str("expYear"), e?.expYear, "parseExpiry year $c")
        }
    }

    @Test
    fun padMonth() {
        for (c in cases("padMonth")) assertEquals(c.str("expected"), CardNormalize.padMonth(c.str("raw")!!), "padMonth $c")
    }

    @Test
    fun yearTo4() {
        for (c in cases("yearTo4")) assertEquals(c.str("expected"), CardNormalize.yearTo4(c.str("raw")!!), "yearTo4 $c")
    }

    @Test
    fun yearTo2() {
        for (c in cases("yearTo2")) assertEquals(c.str("expected"), CardNormalize.yearTo2(c.str("raw")!!), "yearTo2 $c")
    }

    @Test
    fun composeShortExpiry() {
        for (c in cases("composeShortExpiry")) {
            assertEquals(c.str("expected"), CardNormalize.composeShortExpiry(c.str("expMonth")!!, c.str("expYear")!!), "composeShortExpiry $c")
        }
    }
}
