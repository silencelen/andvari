package io.silencelen.andvari.core.client.autofill

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Consumes spec/test-vectors/urimatch-etld1.json — the SAME file the web (vitest) and
 * extension (node --test) mirrors check, so the three PSL resolvers cannot drift.
 * The 25 original urimatch.json vectors stay byte-frozen and keep passing unchanged —
 * [UriMatchVectorTest] proves that side.
 */
class PslVectorTest {
    private val dir = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"))
    private val v: JsonObject = Json.parseToJsonElement(File(dir, "urimatch-etld1.json").readText()).jsonObject

    /**
     * A6: the drift guard hashes the RUNTIME rule string (after the 48 KB chunk join), not
     * constant-vs-constant — a chunk-boundary bug that dropped or duplicated rules would keep
     * the embedded hash literal intact while corrupting what [Psl] actually loads. Canonical
     * bytes: punycoded rules with `!`/`*.` markers, bytewise-sorted, "\n"-joined, ASCII.
     */
    @Test
    fun snapshotHashMatchesRuntimeData() {
        val expected = v.getValue("snapshotHash").jsonPrimitive.content
        assertEquals(expected, PslData.PSL_SNAPSHOT_HASH, "embedded constant vs vector file")
        val runtime = MessageDigest.getInstance("SHA-256")
            .digest(PslData.joined.toByteArray(Charsets.US_ASCII))
            .joinToString("") { b -> ((b.toInt() and 0xff) + 0x100).toString(16).substring(1) }
        assertEquals(expected, runtime, "sha256 of the chunk-joined runtime rule string")
    }

    @Test
    fun registrable() {
        for (case in v.getValue("registrable").jsonArray.map { it.jsonObject }) {
            val host = case.getValue("host").jsonPrimitive.content
            val actual = Psl.resolve(host)
            val expected = when (case.getValue("kind").jsonPrimitive.content) {
                "registrable" -> PslResult.Registrable(case.getValue("domain").jsonPrimitive.content)
                "public-suffix" -> PslResult.PublicSuffix
                else -> PslResult.Unknown
            }
            assertEquals(expected, actual, "resolve($host)")
        }
    }

    @Test
    fun match() {
        for (case in v.getValue("match").jsonArray.map { it.jsonObject }) {
            val savedRaw = case.getValue("savedUri").jsonPrimitive.content
            val saved = UriMatch.parseSavedUri(savedRaw)
            val target = FillTarget(case.getValue("webHost").jsonPrimitive.content, case.getValue("packageName").jsonPrimitive.content)
            val actual = saved != null && UriMatch.matches(saved, target)
            assertEquals(case.getValue("expected").jsonPrimitive.boolean, actual, "match $savedRaw @ ${target.webHost}")
        }
    }
}
