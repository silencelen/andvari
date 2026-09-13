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

/**
 * Consumes spec/test-vectors/urimatch-idna.json — the SAME file the web (vitest) and extension
 * (node --test) mirrors check (H22, 2026-09-13 audit). The `normalize` section pins the A-label
 * OUTPUT, not just a match outcome: three engines that each punycode differently could still
 * agree on `saved == page` when both sides pass through the same buggy encoder, so the bytes
 * themselves are the contract (the expected values come from an independent WHATWG oracle).
 * urimatch.json and urimatch-etld1.json stay byte-frozen and keep passing unchanged.
 */
class UriMatchIdnaVectorTest {
    private val dir = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"))
    private val v: JsonObject = Json.parseToJsonElement(File(dir, "urimatch-idna.json").readText()).jsonObject

    private fun JsonObject.strOrNull(k: String) = getValue(k).let { if (it is JsonNull) null else it.jsonPrimitive.content }

    @Test
    fun normalize() {
        for (case in v.getValue("normalize").jsonArray.map { it.jsonObject }) {
            val input = case.getValue("input").jsonPrimitive.content
            val actual = UriMatch.normalizeHost(input)
            assertEquals(case.strOrNull("expected"), actual, "normalizeHost($input)")
            // Idempotence is load-bearing: the extension pre-normalizes and matches() normalizes
            // again, so a second pass over the A-label must be the identity.
            if (actual != null) assertEquals(actual, UriMatch.normalizeHost(actual), "normalizeHost is idempotent over $input")
        }
    }

    @Test
    fun match() {
        for (case in v.getValue("match").jsonArray.map { it.jsonObject }) {
            val savedRaw = case.getValue("savedUri").jsonPrimitive.content
            val saved = UriMatch.parseSavedUri(savedRaw)
            val target = FillTarget(case.strOrNull("webHost"), case.getValue("packageName").jsonPrimitive.content)
            val actual = saved != null && UriMatch.matches(saved, target)
            assertEquals(case.getValue("expected").jsonPrimitive.boolean, actual, "match $savedRaw @ ${case.strOrNull("webHost")}")
        }
    }
}
