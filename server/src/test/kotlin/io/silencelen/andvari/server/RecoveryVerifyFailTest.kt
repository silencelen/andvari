package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.RecoveryRequestCreated
import io.silencelen.andvari.core.model.wire.WireJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The code that verifies a recovery request (spec 03 §18.2): a wrong one is refused and recorded, and does nothing else.
 * The route has a bucket per caller address (20 an hour, as the sign-up code's route), and every refused code is
 * audited `recovery_request_verify_fail`, naming the account only when the request is real, so that a decoy (an
 * address with a private-posture account, or with none), an unknown requestId and a malformed one answer exactly like
 * a real request: the same status and body, and an audit row of the same shape. Before, a wrong code was not recorded
 * and the route had no bucket at all.
 */
class RecoveryVerifyFailTest {
    private val post = HttpMethod.Post

    private suspend fun open(c: HttpClient, email: String): String {
        val poll = Bytes.toB64(TestKit.crypto.randomBytes(32))
        val r = c.call(post, "/api/v1/recovery/requests", """{"email":"$email","rPub":"${b32()}","pollHash":"${sha256Hex(Bytes.fromB64(poll))}","platform":"android"}""")
        assertEquals(202, r.status.value, r.bodyAsText())
        return WireJson.json.decodeFromString(RecoveryRequestCreated.serializer(), r.bodyAsText()).requestId
    }

    private fun verify(id: String) = "/api/v1/recovery/requests/$id/verify"

    private fun failRows(s: Services) = s.db.read { c ->
        c.queryAll("SELECT userId,deviceId,ip,meta FROM audit WHERE type='recovery_request_verify_fail' ORDER BY rowid") { r ->
            listOf(r.getString(1), r.getString(2), r.getString(3), r.getString(4))
        }
    }

    private fun stateOf(s: Services, id: String) = s.db.read { it.queryOne("SELECT state,attempts FROM recovery_requests WHERE requestId=?", id) { r -> r.getString(1) to r.getInt(2) } }

    @Test
    fun aWrongCode_isRecorded_andADecoyAnswersExactlyLikeARealRequest() = testApplication {
        val key = TestKit.Identity().curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key))
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Me("me@example.com")
        Flow.register(c, s, me, Flow.enrolAuth(s), "operator", Flow.escrow(me, sha256Hex(key)))
        Flow.member(c, s, "private@example.com")
        Flow.sink(s)
        val real = open(c, me.email)
        val code = Flow.codeIn(Flow.sink(s).last { it.first == "recovery_request_code" }.third)
        val wrong = if (code == "000000") "111111" else "000000"
        val privateDecoy = open(c, "private@example.com")
        val noAccountDecoy = open(c, "nobody@example.com")
        val ids = listOf("real" to real, "private" to privateDecoy, "none" to noAccountDecoy, "unknown" to "AAAAAAAAAAAAAAAAAAAAAA", "malformed" to "not-an-id")
        // One wrong code at each, from one caller address: every answer is the same, byte for byte.
        val answers = ids.map { (name, id) ->
            val r = c.call(post, verify(id), """{"code":"$wrong"}""", ip = "10.9.9.9")
            name to "${r.status.value} ${r.headers["Content-Type"]} ${r.bodyAsText()}"
        }
        assertEquals("400", answers.first().second.substringBefore(' '), answers.first().second)
        for ((name, a) in answers) assertEquals(answers.first().second, a, name)
        // Each is recorded, in the same shape: no device, the caller's address, no detail; the account named only for
        // the real request.
        val rows = failRows(s)
        assertEquals(5, rows.size, rows.toString())
        assertEquals(listOf(me.userId, null, null, null, null), rows.map { it[0] })
        assertTrue(rows.all { it[1] == null && it[3] == null }, rows.toString())
        assertEquals(1, rows.map { it[2] }.toSet().size, rows.toString()); assertTrue(rows[0][2] != null)
        // The wrong code counted on the real request only; the decoys are as they were and still unverifiable.
        assertEquals("unverified" to 1, stateOf(s, real))
        assertEquals("unverified" to 0, stateOf(s, privateDecoy)); assertEquals("unverified" to 0, stateOf(s, noAccountDecoy))
        // The right code still verifies the real request, and writes no fail row.
        val ok = c.call(post, verify(real), """{"code":"$code"}""")
        assertEquals(200, ok.status.value, ok.bodyAsText())
        assertEquals(5, failRows(s).size)
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='recovery_request_verify' AND userId=?", me.userId) })
    }

    @Test
    fun theRouteHasABucketPerCallerAddress_andAnotherAddressIsServed() = testApplication {
        val key = TestKit.Identity().curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key))
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Me("me@example.com")
        Flow.register(c, s, me, Flow.enrolAuth(s), "operator", Flow.escrow(me, sha256Hex(key)))
        Flow.sink(s)
        val real = open(c, me.email)
        val code = Flow.codeIn(Flow.sink(s).last { it.first == "recovery_request_code" }.third)
        // Twenty guesses an hour from one address, at requests that do not exist; the twenty-first is refused by the
        // bucket before anything is looked at, even with the right code for a real request.
        repeat(20) { n ->
            val id = Bytes.toB64(TestKit.crypto.randomBytes(16))
            assertEquals("bad_code", c.call(post, verify(id), """{"code":"123456"}""", ip = "10.8.8.8").errorCode(), "guess ${n + 1}")
        }
        val limited = c.call(post, verify(real), """{"code":"$code"}""", ip = "10.8.8.8")
        assertEquals(429, limited.status.value, limited.bodyAsText()); assertEquals("rate_limited", limited.errorCode())
        assertTrue(limited.headers["Retry-After"] != null)
        assertEquals("unverified" to 0, stateOf(s, real))
        assertEquals(20, failRows(s).size)
        // The owner, from an address of their own, verifies at once.
        val ok = c.call(post, verify(real), """{"code":"$code"}""", ip = "10.7.7.7")
        assertEquals(200, ok.status.value, ok.bodyAsText())
    }
}
