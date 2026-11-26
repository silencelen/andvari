package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.EscrowUpload
import io.silencelen.andvari.core.model.wire.RecoveryRequestCreated
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The server's own checks of an operator's upload (spec 03 §18.6) and of a commit (§18.5), graded by the vector file
 * `spec/test-vectors/recovery-v3.json`: every row of its `fulfil` and `commitCheck` tables is sent to the real routes,
 * in process, with a request fixture (alice@example.org on operator recovery, a verified request past its hold made
 * with the rows' own request key, and the operator's session). Each row's expected wire answer (`expect.wire`, or
 * `200` for `ok`) is compared with the route's status and error code. No row is edited here; a row that differs is
 * reported with both answers.
 *
 * The file is read from the repository's `spec/test-vectors/`, or from the directory `ANDVARI_VECTORS_DIR` names
 * (for a branch the vector file has not reached yet). Without either the test is skipped, saying why.
 */
class RecoveryV3RoutesVectorTest {
    private val email = "alice@example.org"

    private fun vectors(): JsonObject? {
        val candidates = listOfNotNull(
            File("../spec/test-vectors/recovery-v3.json"), File("spec/test-vectors/recovery-v3.json"),
            System.getenv("ANDVARI_VECTORS_DIR")?.let { File(it, "recovery-v3.json") },
        )
        val f = candidates.firstOrNull { it.isFile } ?: return null
        return WireJson.json.parseToJsonElement(f.readText()).jsonObject
    }

    private class Fixture(val c: HttpClient, val s: Services, val clock: MutableClock, val op: Me, val reqId: String, val poll: String)

    private fun token(s: Services, me: Me) = s.db.tx { c -> s.sessions.issue(c, me.userId, me.deviceId, "linux", passwordLogin = true).accessToken }

    private suspend fun fixture(c: HttpClient, s: Services, clock: MutableClock, key: ByteArray, rPub: String): Fixture {
        val op = Flow.finishSetup(c, s)
        val me = Me(email)
        Flow.register(c, s, me, Flow.enrolAuth(s), "operator", Flow.escrow(me, sha256Hex(key)))
        val poll = TestKit.crypto.randomBytes(32)
        val open = """{"email":"$email","rPub":"$rPub","pollHash":"${sha256Hex(poll)}","platform":"android"}"""
        val reqId = WireJson.json.decodeFromString(RecoveryRequestCreated.serializer(), c.call(HttpMethod.Post, "/api/v1/recovery/requests", open).bodyAsText()).requestId
        val code = Flow.codeIn(Flow.sink(s).last { it.first == "recovery_request_code" }.third)
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/verify", """{"code":"$code"}""").status.value)
        clock.advance(Assisted.HOLD_MS)
        return Fixture(c, s, clock, op, reqId, Bytes.toB64(poll))
    }

    private fun expected(row: JsonObject): String {
        val e = row["expect"]!!.jsonObject
        return if (e["verdict"]!!.jsonPrimitive.content == "ok") "200" else e["wire"]!!.jsonPrimitive.content
    }

    private suspend fun answer(r: io.ktor.client.statement.HttpResponse): String =
        if (r.status.value in 200..299) "${r.status.value}" else "${r.status.value} ${r.errorCode()}"

    @Test
    fun everyFulfilAndCommitCheckRow_isAnsweredByTheRoutesAsTheVectorsSay() {
        val v = vectors()
        org.junit.Assume.assumeTrue("recovery-v3.json is not on this branch (and ANDVARI_VECTORS_DIR is not set)", v != null)
        val fulfil = v!!["fulfil"]!!.jsonArray.map { it.jsonObject }
        val commitCheck = v["commitCheck"]!!.jsonArray.map { it.jsonObject }
        val rPubs = fulfil.map { it["row"]!!.jsonObject["rPub"]!!.jsonPrimitive.content }.toSet()
        val emails = fulfil.map { it["row"]!!.jsonObject["emailNorm"]!!.jsonPrimitive.content }.toSet()
        assertEquals(setOf(email), emails, "every fulfil row is for one address, which the fixture holds")
        assertEquals(1, rPubs.size, "every fulfil row is for one request key, which the fixture's request uses")
        val results = ArrayList<Triple<String, String, String>>()
        testApplication {
            val clock = MutableClock()
            val key = TestKit.Identity().curvePub
            val s = TestKit.services(TestKit.config(recoveryKey = key), clock)
            application { andvariModule(s) }
            val f = fixture(client, s, clock, key, rPubs.single())
            // The upload: each row's body, with the operator's right proof added, on the fixture's request.
            for (row in fulfil) {
                val body = JsonObject(row["body"]!!.jsonObject + ("currentAuthKey" to kotlinx.serialization.json.JsonPrimitive(f.op.authKey)))
                f.clock.advance(13_000) // a † route takes 5 a minute per account
                val r = f.c.call(HttpMethod.Post, "/api/v1/admin/recovery-requests/${f.reqId}/fulfil", body.toString(), token(s, f.op))
                results += Triple("fulfil/" + row["name"]!!.jsonPrimitive.content, expected(row), answer(r))
            }
            // The commit: each row's stored hash on the (answered) request, then its value as sent. The row that
            // commits deletes the request, so it runs last.
            val ordered = commitCheck.sortedBy { expected(it) == "200" }
            for (row in ordered) {
                val stored = row["storedCommitHash"]!!.jsonPrimitive.content
                s.db.tx { c -> c.exec("UPDATE recovery_requests SET state='fulfilled', sealed=COALESCE(sealed,'AAAA'), commitHash=? WHERE requestId=?", stored, f.reqId) }
                val commit: JsonElement? = row["commit"]
                val field = if (row.containsKey("commit")) """"commit":${commit.toString()},""" else ""
                val body = """{"pollSecret":"${f.poll}",$field"newAuthKey":"${b32()}","newKdfSalt":"${Bytes.toB64(ByteArray(16) { 5 })}",""" +
                    """"newKdfParams":{"v":1,"alg":"argon2id13","ops":1,"memBytes":8388608},"newWrappedUvk":"AAAA",""" +
                    """"newMemberRecovery":{"recoveryWrappedUvk":"AAAA","recoveryAuthKey":"${b32()}"},"device":{"platform":"ios","name":"x","deviceSecret":"${b32()}"}}"""
                val r = f.c.call(HttpMethod.Post, "/api/v1/recovery/requests/${f.reqId}/commit", body)
                results += Triple("commitCheck/" + row["name"]!!.jsonPrimitive.content, expected(row), answer(r))
            }
        }
        for ((name, want, got) in results) println("VECTOR ${if (want == got) "AGREES" else "DIFFERS"} $name: vector '$want', route '$got'")
        val differ = results.filter { it.second != it.third }
        assertEquals(31, results.size, "every row of both tables was sent")
        assertEquals(emptyList(), differ.map { "${it.first}: vector '${it.second}', route '${it.third}'" })
    }
}
