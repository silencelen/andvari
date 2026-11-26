package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The `emailNorm` rows of spec/test-vectors/encodings.json (spec 01 §5.5, spec 03 §0.3; the vectors' README
 * gives all of them to the server). Every row is graded against [Grammar.requireEmail], the one function the
 * sign-up (`/signup/start`), sign-in (`/auth/prelogin`, `/auth/login`) and registration (`/auth/register`)
 * routes call on a typed address; a row this test cannot grade fails it.
 */
class EmailNormVectorsTest {
    private val rows: List<JsonObject> = WireJson.json.parseToJsonElement(
        listOf("../spec/test-vectors/encodings.json", "spec/test-vectors/encodings.json").map { File(it) }.first { it.isFile }.readText(),
    ).jsonObject["emailNorm"]!!.jsonArray.map { it.jsonObject }

    private fun JsonObject.s(k: String) = this[k]!!.jsonPrimitive.content

    private fun label(i: Int, r: JsonObject) = "row $i (${r.s("why")})"

    @Test
    fun everyRow_isGraded_againstTheRoutesFunction() {
        assertTrue(rows.isNotEmpty(), "encodings.json has no emailNorm rows")
        var graded = 0
        rows.forEachIndexed { i, r ->
            val input = r.s("input")
            val expect = r["expect"]!!.jsonObject
            when (val verdict = expect.s("verdict")) {
                "ok" -> {
                    assertEquals(expect.s("emailNorm"), Grammar.requireEmail(input), label(i, r))
                    // The normalised address is its own emailNorm: a stored address taken again is the same string.
                    assertEquals(expect.s("emailNorm"), Grammar.requireEmail(expect.s("emailNorm")), label(i, r) + ": idempotent")
                }
                "invalid_email" -> {
                    assertTrue(expect["emailNorm"] == null, label(i, r) + ": a refused row carries no emailNorm")
                    val e = assertFailsWith<ApiException>(label(i, r)) { Grammar.requireEmail(input) }
                    assertEquals(400, e.status, label(i, r))
                    assertEquals(WireErrors.INVALID_EMAIL, e.body.error, label(i, r))
                }
                else -> fail("${label(i, r)}: verdict '$verdict' is not graded by the server")
            }
            graded++
        }
        assertEquals(rows.size, graded, "every emailNorm row is graded")
    }

    /** The same rows through a route: `POST /auth/prelogin` answers 200 for an ok row and `400 invalid_email` otherwise. */
    @Test
    fun everyRow_throughPrelogin() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        rows.forEachIndexed { i, r ->
            val body = buildJsonObject { put("email", r.s("input")) }.toString()
            val resp = client.call(HttpMethod.Post, "/api/v1/auth/prelogin", body)
            if (r["expect"]!!.jsonObject.s("verdict") == "ok") {
                assertEquals(200, resp.status.value, label(i, r) + ": " + resp.bodyAsText())
            } else {
                assertEquals(400, resp.status.value, label(i, r) + ": " + resp.bodyAsText())
                assertEquals(WireErrors.INVALID_EMAIL, resp.errorCode(), label(i, r))
            }
        }
    }
}
