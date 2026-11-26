package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.EscrowUpload
import io.silencelen.andvari.core.model.wire.RecoveryRequestCreated
import io.silencelen.andvari.core.model.wire.RecoveryVerifyResponse
import io.silencelen.andvari.core.model.wire.WireJson
import kotlin.test.Test
import kotlin.test.assertEquals

/** Index rows 6, 33, 68, 70 and 72 (spec 03 §12, §14.1, §14.5, §18): the refusals the other files leave. */
class RoutesRecoveryTest {
    /** Each opened request's key, which the upload must carry (spec 03 §18.6). */
    private val rPubs = HashMap<String, String>()

    private val post = HttpMethod.Post
    private fun kdf(ops: Int = 1, mem: Long = 8_388_608) = """{"v":1,"alg":"argon2id13","ops":$ops,"memBytes":$mem}"""
    private val salt16 = Bytes.toB64(ByteArray(16) { 5 })

    private fun reset(params: String = kdf(), salt: String = salt16, kit: Boolean = true) =
        """"newAuthKey":"${b32()}","newKdfSalt":"$salt","newKdfParams":$params,"newWrappedUvk":"AAAA"${if (kit) ""","newMemberRecovery":{"recoveryWrappedUvk":"AAAA","recoveryAuthKey":"${b32()}"}""" else ""},"device":{"platform":"ios","name":"x","deviceSecret":"${b32()}"}"""

    private suspend fun ticket(c: HttpClient, me: Me): String =
        WireJson.json.decodeFromString(
            RecoveryVerifyResponse.serializer(),
            c.call(post, "/api/v1/recovery/self/verify", """{"email":"${me.email}","recoveryAuthKey":"${me.recoveryAuthKey}"}""").bodyAsText(),
        ).recoveryTicket

    @Test
    fun row33_kitCommit_kdfChecks_andAnInactiveAccount() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        suspend fun commit(body: String) = c.call(post, "/api/v1/recovery/self/commit", body)
        suspend fun expect(code: String, rest: String) {
            val r = commit("""{"recoveryTicket":"${ticket(c, me)}",$rest}""")
            assertEquals(400, r.status.value, r.bodyAsText()); assertEquals(code, r.errorCode())
        }
        expect("kdf_too_weak", reset(params = kdf(mem = 4096)))
        expect("kdf_mem_not_kib_multiple", reset(params = kdf(mem = 8_388_609)))
        expect("bad_kdf_salt", reset(salt = Bytes.toB64(ByteArray(8))))
        expect("recovery_required", reset(kit = false))
        // A disabled account is re-enabled by the operator first.
        val t = ticket(c, me)
        s.db.tx { it.exec("UPDATE users SET status='disabled', disabledAt=1 WHERE userId=?", me.userId) }
        val r = commit("""{"recoveryTicket":"$t",${reset()}}""")
        assertEquals(400, r.status.value); assertEquals("recovery_account_not_active", r.errorCode())
        // Each refused commit consumed its ticket.
        assertEquals("invalid_ticket", commit("""{"recoveryTicket":"$t",${reset()}}""").errorCode())
        // None of it changed the credential.
        assertEquals(200, c.call(post, "/api/v1/auth/prelogin", """{"email":"${me.email}"}""").status.value)
        s.db.tx { it.exec("UPDATE users SET status='active', disabledAt=NULL WHERE userId=?", me.userId) }
        assertEquals(200, c.call(post, "/api/v1/auth/login", me.loginBody()).status.value)
    }

    /** One private instance with a recovery key, an operator-posture member, and a request driven to `ready`. */
    private class Assisted(val s: Services, val clock: MutableClock, val op: Me, val me: Me)

    private suspend fun assisted(c: HttpClient, s: Services, clock: MutableClock, key: ByteArray): Assisted {
        val op = Flow.finishSetup(c, s)
        val me = Me("me@example.com")
        Flow.register(c, s, me, Flow.enrolAuth(s), "operator", Flow.escrow(me, sha256Hex(key)))
        Flow.sink(s)
        return Assisted(s, clock, op, me)
    }

    private suspend fun open(c: HttpClient, a: Assisted): Pair<String, String> {
        val poll = TestKit.crypto.randomBytes(32)
        val rPub = b32()
        val reqId = WireJson.json.decodeFromString(
            RecoveryRequestCreated.serializer(),
            c.call(post, "/api/v1/recovery/requests", """{"email":"${a.me.email}","rPub":"$rPub","pollHash":"${sha256Hex(poll)}","platform":"android"}""").bodyAsText(),
        ).requestId
        rPubs[reqId] = rPub
        val code = Flow.codeIn(Flow.sink(a.s).last { it.first == "recovery_request_code" }.third)
        assertEquals(200, c.call(post, "/api/v1/recovery/requests/$reqId/verify", """{"code":"$code"}""").status.value)
        return reqId to Bytes.toB64(poll)
    }

    @Test
    fun row72_assistedCommit_eachRefusal_thenTheCommit() = testApplication {
        val clock = MutableClock()
        val key = TestKit.Identity().curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key), clock)
        application { andvariModule(s) }
        val c = client
        val a = assisted(c, s, clock, key)
        val (reqId, poll) = open(c, a)
        clock.advance(io.silencelen.andvari.server.Assisted.HOLD_MS)
        val opTok = s.db.tx { db -> s.sessions.issue(db, a.op.userId, a.op.deviceId, "linux", passwordLogin = true).accessToken }
        // spec 03 §18.5, §18.6: the commit presents the value whose hash the upload carried.
        val commitValue = TestKit.crypto.randomBytes(32)
        suspend fun commit(secret: String, rest: String) =
            c.call(post, "/api/v1/recovery/requests/$reqId/commit", """{"pollSecret":"$secret","commit":"${Bytes.toB64(commitValue)}",$rest}""")
        // Before the operator's answer: request_state; a wrong poll secret: request_unknown.
        assertEquals("request_state", commit(poll, reset()).errorCode())
        val unknown = commit(b32(), reset())
        assertEquals(404, unknown.status.value); assertEquals("request_unknown", unknown.errorCode())
        assertEquals("request_unknown", c.call(post, "/api/v1/recovery/requests/not-an-id/commit", """{"pollSecret":"$poll",${reset()}}""").errorCode())
        val fulfil = """{"sealed":"${Bytes.toB64(ByteArray(io.silencelen.andvari.core.trust.AnswerToken.sealedBytes(a.me.email)) { 1 })}","requestKey":"${rPubs.getValue(reqId)}",""" +
            """"commitHash":"${io.silencelen.andvari.core.trust.AssistedRecovery.commitHash(TestKit.crypto, commitValue)}","currentAuthKey":"${a.op.authKey}"}"""
        assertEquals(200, c.call(post, "/api/v1/admin/recovery-requests/$reqId/fulfil", fulfil, opTok).status.value)
        for ((code, rest) in listOf(
            "kdf_too_weak" to reset(params = kdf(ops = 0)),
            "kdf_mem_not_kib_multiple" to reset(params = kdf(mem = 8_388_609)),
            "bad_kdf_salt" to reset(salt = Bytes.toB64(ByteArray(65))),
            "recovery_required" to reset(kit = false),
        )) {
            val r = commit(poll, rest)
            assertEquals(400, r.status.value, "$code: ${r.bodyAsText()}"); assertEquals(code, r.errorCode())
        }
        // The refusals left the request ready: the commit still lands, once.
        val ok = commit(poll, reset())
        assertEquals(200, ok.status.value, ok.bodyAsText())
        assertEquals("request_unknown", commit(poll, reset()).errorCode())
    }

    @Test
    fun row70_veto_nonCanonical_andBadStatement() = testApplication {
        val clock = MutableClock()
        val key = TestKit.Identity().curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key), clock)
        application { andvariModule(s) }
        val c = client
        val a = assisted(c, s, clock, key)
        val (reqId, _) = open(c, a)
        val canonical = """{"v":2,"purpose":"recovery-veto","requestId":"$reqId","userId":"${a.me.userId}","issuedAt":1800000000000}"""
        suspend fun veto(st: String) = c.call(post, "/api/v1/recovery/requests/$reqId/veto", """{"statement":"${Bytes.toB64(a.me.identity.frame(10, st))}"}""", a.me.token)
        for ((code, st) in listOf(
            "non_canonical" to canonical.replace("{\"v\"", "{ \"v\""),
            "non_canonical" to canonical.replace(",\"issuedAt\":1800000000000", ""),
            "non_canonical" to canonical.replace("\"issuedAt\":1800000000000", "\"issuedAt\":\"1800000000000\""),
            "bad_statement" to canonical.replace("\"v\":2", "\"v\":3"),
            "bad_statement" to canonical.replace("recovery-veto", "recovery-rotation"),
        )) {
            val r = veto(st)
            assertEquals(400, r.status.value, "$code: $st ${r.bodyAsText()}"); assertEquals(code, r.errorCode(), st)
        }
        assertEquals("bad_frame", c.call(post, "/api/v1/recovery/requests/$reqId/veto", """{"statement":"!!"}""", a.me.token).errorCode())
        assertEquals(200, veto(canonical).status.value)
    }

    @Test
    fun row68_requestCreate_invalidEmail_andTheSilentAddressCap() = testApplication {
        val clock = MutableClock()
        val key = TestKit.Identity().curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key), clock)
        application { andvariModule(s) }
        val c = client
        val a = assisted(c, s, clock, key)
        val body = { email: String -> """{"email":"$email","rPub":"${b32()}","pollHash":"${"a".repeat(64)}","platform":"android"}""" }
        val bad = c.call(post, "/api/v1/recovery/requests", body("not an address"))
        assertEquals(400, bad.status.value); assertEquals("invalid_email", bad.errorCode())
        // 5 a day per address, then still 202 but nothing is sent: a decoy is stored.
        repeat(5) { assertEquals(202, c.call(post, "/api/v1/recovery/requests", body(a.me.email)).status.value) }
        val mails = Flow.sink(s).size
        val real = s.db.read { it.count("SELECT COUNT(*) FROM recovery_requests WHERE userId IS NOT NULL") }
        assertEquals(202, c.call(post, "/api/v1/recovery/requests", body(a.me.email)).status.value)
        assertEquals(real, s.db.read { it.count("SELECT COUNT(*) FROM recovery_requests WHERE userId IS NOT NULL") })
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM recovery_requests WHERE userId IS NULL") })
        assertEquals(mails, Flow.sink(s).size)
    }

    /** Rows 6 and 68: a stalled outbox (a transport that keeps failing, ten minutes on) is `503 mail_unavailable`. */
    @Test
    fun rows6and68_aStalledOutbox_isMailUnavailable() = testApplication {
        val clock = MutableClock()
        val key = TestKit.Identity().curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key, mode = "open"), clock)
        var sent = 0
        s.mailTransport = MailTransport { sent++; SendResult.Transient("down") }
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        c.login(me) // a new_device notice: the outbox is not empty
        s.mail.drain()
        // Before ten minutes: both routes accept.
        clock.advance(Mail.STALL_MS - 1)
        suspend fun start(email: String) = c.call(post, "/api/v1/signup/start", """{"email":"$email","ageConfirmed":true}""")
        suspend fun request(email: String) = c.call(post, "/api/v1/recovery/requests", """{"email":"$email","rPub":"${b32()}","pollHash":"${"a".repeat(64)}","platform":"android"}""")
        assertEquals(202, start("new1@example.com").status.value)
        assertEquals(202, request(me.email).status.value)
        clock.advance(1)
        for (r in listOf(start("new2@example.com"), request(me.email), request("nobody@example.com"))) {
            assertEquals(503, r.status.value, r.bodyAsText()); assertEquals("mail_unavailable", r.errorCode())
        }
        assertEquals(true, sent > 0, "no real mail: the transport is the test's")
    }

    /** A row past its discardAt will never be sent, so it does not make the outbox stalled (spec 03 §14.5). */
    @Test
    fun rowsPastTheirDiscardTime_doNotCountAsStalled() = testApplication {
        val clock = MutableClock()
        val key = TestKit.Identity().curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key), clock)
        s.mailTransport = MailTransport { SendResult.Transient("down") }
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        c.login(me)
        s.mail.drain()
        clock.advance(Mail.STALL_MS)
        assertEquals(true, s.db.read { s.mail.stalled(it) })
        // A day on, every queued notice is past its discardAt, and no drain has run since.
        clock.advance(Clock.DAY_MS)
        assertEquals(true, s.db.read { it.count("SELECT COUNT(*) FROM mail_outbox") } > 0)
        assertEquals(false, s.db.read { s.mail.stalled(it) })
        val r = c.call(post, "/api/v1/recovery/requests", """{"email":"${me.email}","rPub":"${b32()}","pollHash":"${"a".repeat(64)}","platform":"android"}""")
        assertEquals(202, r.status.value, r.bodyAsText())
        // A fresh notice is a live row again: ten minutes on, with the transport still down, the outbox stalls.
        c.login(me)
        clock.advance(Mail.STALL_MS)
        assertEquals(true, s.db.read { s.mail.stalled(it) })
    }
}
