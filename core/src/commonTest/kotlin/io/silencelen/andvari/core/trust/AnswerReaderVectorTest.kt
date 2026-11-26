package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.readVector
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The one shared reader of an answer (spec 04 §7 step 3, "Reading an answer", as corrected on 2026-11-16), graded off
 * `answer-reader.json`, which the independent oracle wrote from the specification text alone: [AnswerToken.read] against
 * every `read` row, [AnswerToken.readFile] against every `readFile` row. A row the code answers otherwise is listed in
 * [KNOWN] and graded in an `@Ignore`d test.
 */
class AnswerReaderVectorTest {
    private val v: JsonObject = Json.parseToJsonElement(readVector("answer-reader.json")).jsonObject
    private fun JsonObject.s(key: String): String = getValue(key).jsonPrimitive.content
    private val request = v.getValue("request").jsonObject

    private fun describe(r: AnswerRead): JsonObject = when (r) {
        is AnswerRead.Ok -> JsonObject(mapOf(
            "verdict" to JsonPrimitive("ok"), "requestId" to JsonPrimitive(r.requestId), "requestKey" to JsonPrimitive(r.requestKey),
            "commitHash" to JsonPrimitive(r.commitHash), "sealed" to JsonPrimitive(r.sealed),
        ))
        is AnswerRead.Refused -> JsonObject(
            mapOf("verdict" to JsonPrimitive(r.refusal.code)) + (r.namedRequest?.let { mapOf("tokenRequestId" to JsonPrimitive(it)) } ?: emptyMap()),
        )
    }

    private fun read(row: JsonObject, table: String): JsonObject {
        val req = row["request"]?.jsonObject ?: request
        return describe(
            if (table == "read") AnswerToken.read(row.s("text"), req.s("requestId"), req.s("rPub"), req.s("email"))
            else AnswerToken.readFile(Bytes.fromB64(row.s("bytesB64")), req.s("requestId"), req.s("rPub"), req.s("email")),
        )
    }

    private fun differences(only: Set<String>? = null): List<String> = listOf("read", "readFile").flatMap { table ->
        v.getValue(table).jsonArray.map { it.jsonObject }.mapNotNull { row ->
            val name = "$table/${row.s("name")}"
            if (only != null && name !in only) return@mapNotNull null
            if (only == null && name in KNOWN) return@mapNotNull null
            val got = read(row, table)
            if (got != row.getValue("expect").jsonObject) "$name: the oracle expects ${row.getValue("expect")}, the code answers $got" else null
        }
    }

    @Test
    fun bareAnswers_theBoundIsTheSame() = assertEquals(v.s("bareMinChars").toInt(), AnswerToken.BARE_MIN_CHARS)

    @Test
    fun everyRow() {
        val d = differences()
        assertTrue(d.isEmpty(), d.joinToString("\n"))
        assertTrue(v.getValue("read").jsonArray.size + v.getValue("readFile").jsonArray.size >= 86)
    }

    private companion object {
        /** Row → finding, for a row the code answers otherwise (graded then in an `@Ignore`d test naming it). None in the specification as corrected on 2026-11-16. */
        val KNOWN: Map<String, String> = mapOf()
    }
}
