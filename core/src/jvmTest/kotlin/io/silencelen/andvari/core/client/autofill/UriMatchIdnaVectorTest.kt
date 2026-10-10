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
import kotlin.test.assertTrue

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

    /** Security review 2026-10: RFC 1035's label/host length limits applied to the A-label output —
     *  the rule that bounds the punycode encoder and the PSL suffix walk on a planted host. */
    @Test
    fun limits() {
        for (case in v.getValue("limits").jsonArray.map { it.jsonObject }) {
            val input = case.getValue("input").jsonPrimitive.content
            val actual = UriMatch.normalizeHost(input)
            assertEquals(case.strOrNull("expected"), actual, "normalizeHost(${input.take(40)}…)")
            if (actual != null) assertEquals(actual, UriMatch.normalizeHost(actual))
        }
    }

    /** A co-member plants these in a shared login's uris; Android autofill re-runs them on every
     *  fill request and Health on every open. Each took seconds before the fix (O(n²)). */
    @Test
    fun aPlantedPathologicalHost_returnsPromptly() {
        fun fast(label: String, block: () -> Unit) {
            val t = System.nanoTime()
            block()
            val ms = (System.nanoTime() - t) / 1_000_000
            assertTrue(ms < 250, "$label took $ms ms")
        }
        val cjk = buildString { for (i in 0 until 20000) appendCodePoint(0x4e00 + i) }
        // Warm the classes so the first measurement is not JIT/classload time.
        UriMatch.normalizeHost("https://example.com"); Psl.resolve("example.com")
        fast("50k dots then a letter") { UriMatch.normalizeHost("https://" + ".".repeat(50000) + "x") }
        fast("50k trailing dots") { assertEquals("example.com", UriMatch.normalizeHost("https://example.com" + ".".repeat(50000))) }
        fast("20k distinct code points in one label") { assertEquals(null, UriMatch.normalizeHost("https://$cjk.com")) }
        fast("8k labels (PSL suffix walk)") { Psl.resolve("a.".repeat(8000) + "com") }
    }
}
