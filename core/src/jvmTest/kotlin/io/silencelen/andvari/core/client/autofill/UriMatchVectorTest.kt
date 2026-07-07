package io.silencelen.andvari.core.client.autofill

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals

/** Consumes spec/test-vectors/urimatch.json — the SAME file web/src/vault/urimatch.test.ts checks. */
class UriMatchVectorTest {
    private val dir = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"))
    private val v: JsonObject = Json.parseToJsonElement(File(dir, "urimatch.json").readText()).jsonObject

    private fun JsonObject.strOrNull(k: String) = getValue(k).let { if (it is JsonNull) null else it.jsonPrimitive.content }

    @Test
    fun match() {
        for (case in v.getValue("match").jsonArray.map { it.jsonObject }) {
            val saved = UriMatch.parseSavedUri(case.getValue("savedUri").jsonPrimitive.content)
            val target = FillTarget(case.strOrNull("webHost"), case.getValue("packageName").jsonPrimitive.content)
            val actual = saved != null && UriMatch.matches(saved, target)
            assertEquals(case.getValue("expected").jsonPrimitive.boolean, actual, "match ${case.getValue("savedUri").jsonPrimitive.content} @ ${case.strOrNull("webHost")}/${target.packageName}")
        }
    }

    @Test
    fun classify() {
        for (case in v.getValue("classify").jsonArray.map { it.jsonObject }) {
            val sig = FieldSignal(
                hints = case.getValue("hints").jsonArray.map { it.jsonPrimitive.content },
                inputTypeClass = case.getValue("inputTypeClass").jsonPrimitive.int,
                inputTypeVariation = case.getValue("inputTypeVariation").jsonPrimitive.int,
                htmlType = case.strOrNull("htmlType"),
                htmlNameOrId = case.strOrNull("htmlNameOrId"),
            )
            val expected = when (case.getValue("expected").jsonPrimitive.content) {
                "username" -> FieldKind.USERNAME
                "password" -> FieldKind.PASSWORD
                else -> FieldKind.NONE
            }
            assertEquals(expected, FieldClassifier.classify(sig), "classify $sig")
        }
    }
}
