package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.RecoveryRequestCreated
import io.silencelen.andvari.core.model.wire.WireJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Opening an assisted-recovery request (spec 03 §18.1) leaves one audit record of one shape for a real request and for
 * every kind of decoy (an unknown address, a private-posture account, an address over its daily cap), naming the account
 * only for a real one, and the same answer. Before 2026-11-17 only a real request wrote a record, so the records told
 * whether an address has an account that may be recovered this way.
 */
class RecoveryRequestOpenRecordTest {
    private val post = HttpMethod.Post

    private class Fix(val c: HttpClient, val s: Services, val real: Me, val priv: Me)

    private class Opened(val response: HttpResponse, val body: String, val requestId: String, val ip: String)

    private fun app(block: suspend (Fix) -> Unit) = testApplication {
        val key = TestKit.Identity().curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key), MutableClock())
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val real = Me("real@example.com")
        Flow.register(c, s, real, Flow.enrolAuth(s), "operator", Flow.escrow(real, sha256Hex(key)))
        val priv = Flow.member(c, s, "private@example.com")
        Flow.sink(s)
        block(Fix(c, s, real, priv))
    }

    /** One request, from a fresh caller address (the per-IP bucket is not what this test is about; the per-address cap is). */
    private suspend fun open(f: Fix, email: String): Opened {
        val body = """{"email":"$email","rPub":"${b32()}","pollHash":"${sha256Hex(TestKit.crypto.randomBytes(32))}","platform":"android"}"""
        val ip = randomIp()
        val r = f.c.call(post, "/api/v1/recovery/requests", body, ip = ip)
        val text = r.bodyAsText()
        assertEquals(202, r.status.value, text)
        return Opened(r, text, WireJson.json.decodeFromString(RecoveryRequestCreated.serializer(), text).requestId, ip)
    }

    /** Status, headers (without the date) and body, with the request's own id masked: what the caller can compare. */
    private fun shape(o: Opened): String =
        "${o.response.status.value} ${o.response.headers.entries().filter { it.key != "Date" }.sortedBy { it.key }} ${o.body.replace(o.requestId, "<id>")}"

    private fun lastAuditId(s: Services) = s.db.read { c -> c.queryOne("SELECT COALESCE(MAX(id),0) FROM audit") { it.getLong(1) }!! }

    /** The rows the request itself wrote since [after]: (type, userId, deviceId, ip, meta); the outbox worker's own `email_*` rows aside. */
    private fun records(s: Services, after: Long) = s.db.read { c ->
        c.queryAll("SELECT type,userId,deviceId,ip,meta FROM audit WHERE id>? ORDER BY id", after) { r -> listOf(r.getString(1), r.getString(2), r.getString(3), r.getString(4), r.getString(5)) }
    }.filter { !it[0]!!.startsWith("email_") }

    private fun requestRow(s: Services, id: String) = s.db.read { c ->
        c.queryOne("SELECT userId, codeMac IS NOT NULL, state FROM recovery_requests WHERE requestId=?", id) { r -> listOf(r.getString(1), r.getBoolean(2).toString(), r.getString(3)) }
    }

    @Test
    fun openingARequest_leavesOneRecordOfOneShape_forARealRequestAndEveryKindOfDecoy() = app { f ->
        val kinds = listOf(
            "real" to f.real.email,
            "unknown address" to "nobody@example.com",
            "private-posture account" to f.priv.email,
        )
        val shapes = LinkedHashMap<String, String>()
        for ((kind, email) in kinds) {
            val before = lastAuditId(f.s)
            val o = open(f, email)
            shapes[kind] = shape(o)
            val named = if (kind == "real") f.real.userId else null
            assertEquals(listOf(listOf("recovery_request_create", named, null, o.ip, null)), records(f.s, before), kind)
            assertEquals(listOf(named, (kind == "real").toString(), "unverified"), requestRow(f.s, o.requestId), kind)
        }
        // Over the address's daily cap (5), the real account's address gets a decoy, recorded alike and naming no one.
        repeat(4) { open(f, f.real.email) }
        val before = lastAuditId(f.s)
        val over = open(f, f.real.email)
        shapes["over the address's cap"] = shape(over)
        assertEquals(listOf(listOf("recovery_request_create", null, null, over.ip, null)), records(f.s, before))
        assertEquals(listOf(null, "false", "unverified"), requestRow(f.s, over.requestId))
        // The answers are one: status, headers and body (the id aside).
        assertEquals(1, shapes.values.toSet().size, shapes.entries.joinToString("\n"))
        // What is mailed is unchanged: the code to the real address, the notice to the private-posture one, nothing else.
        val mails = Flow.sink(f.s).map { it.first to it.second }
        assertEquals(5, mails.count { it == "recovery_request_code" to f.real.email })
        assertEquals(1, mails.count { it == "recovery_request_private" to f.priv.email })
        assertTrue(mails.none { it.second == "nobody@example.com" }, mails.toString())
    }
}
