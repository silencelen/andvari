package io.silencelen.andvari.core.client.pin

import io.silencelen.andvari.core.readVector
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals

/** Grades [PasswordGate] on `spec/test-vectors/passwordgate.json`, row by row. */
class PasswordGateVectorTest {
    private fun str(o: JsonObject, k: String): String? = o[k]?.takeIf { it !is JsonNull }?.jsonPrimitive?.contentOrNull

    @Test fun everyRow() {
        val doc = Json.parseToJsonElement(readVector("passwordgate.json")).jsonObject
        val rows = doc.getValue("rows").jsonArray.map { it.jsonObject }
        for (r in rows) {
            val name = str(r, "name")!!
            val purpose = GatePurpose.entries.single { it.code == str(r, "purpose") }
            val entry = str(r, "entry")?.let { e -> GateEntry.entries.single { it.code == e } }
            val payload = str(r, "payload")?.let { p -> GatePayload.entries.single { it.code == p } }
            val pins = r.getValue("pins").jsonArray.map { it.jsonObject }.map { p ->
                GatePin(str(p, "origin")!!, PinRoot.entries.single { it.code == str(p, "root") }, str(p, "account"))
            }
            val session = (r["session"] as? JsonObject)?.let { GateSession(str(it, "origin")!!, str(it, "account")!!) }
            val input = GateInput(purpose, entry, payload, str(r, "origin")!!, str(r, "account"), pins, session)
            val want = str(r.getValue("expect").jsonObject, "decision")
            assertEquals(want, PasswordGate.decide(input).code, name)
        }
    }
}
