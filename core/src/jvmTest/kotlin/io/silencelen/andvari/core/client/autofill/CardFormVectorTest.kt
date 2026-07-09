package io.silencelen.andvari.core.client.autofill

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals

/** Consumes spec/test-vectors/cardform.json — the form-level refine rules (CSC demotion + frame
 *  clustering + formKind) the web + extension TS ports run against the same file. */
class CardFormVectorTest {
    private val dir = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"))
    private val v: JsonObject = Json.parseToJsonElement(File(dir, "cardform.json").readText()).jsonObject

    @Test
    fun refine() {
        for (case in v.getValue("refine").jsonArray.map { it.jsonObject }) {
            val name = case.getValue("name").jsonPrimitive.content
            val fields = case.getValue("fields").jsonArray.map { it.jsonObject }
            val out = CardForm.refine(fields.map { vectorFieldSignal(it) })
            assertEquals(vectorFormKind(case.getValue("formKind").jsonPrimitive.content), out.formKind, "formKind: $name")
            fields.forEachIndexed { i, f ->
                assertEquals(vectorFieldKind(f.getValue("expected").jsonPrimitive.content), out.kinds[i], "$name — field[$i]")
            }
        }
    }
}
