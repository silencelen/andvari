package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.EscrowUpload
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The per-recipient mail caps (spec 03 §14.5, design §11.4) and the per-address bucket of
 * `POST /recovery/requests` (design §9.3): nothing an unauthenticated caller can trigger may use up the
 * budget of the security notices.
 */
class MailCapTest {
    private fun b32() = Bytes.toB64(TestKit.crypto.randomBytes(32))
    private fun create(email: String) = """{"email":"$email","rPub":"${b32()}","pollHash":"${sha256Hex(TestKit.crypto.randomBytes(32))}","platform":"android"}"""

    @Test
    fun recoveryRequests_forAPrivateAccount_cannotExhaustItsSecurityNotices() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        Flow.sink(s)
        // Anyone, from as many addresses as they like, asks for recovery in the member's name.
        repeat(25) { assertEquals(202, c.call(HttpMethod.Post, "/api/v1/recovery/requests", create(me.email)).status.value) }
        val privates = Flow.sink(s).count { it.first == "recovery_request_private" }
        assertEquals(5, privates)
        // The security notices still go out.
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/auth/login", me.loginBody()).status.value)
        val pw = """{"currentAuthKey":"${me.authKey}","newAuthKey":"${b32()}","newKdfSalt":"${Bytes.toB64(ByteArray(16) { 5 })}","newKdfParams":{"v":1,"alg":"argon2id13","ops":1,"memBytes":8388608},"newWrappedUvk":"AAAA"}"""
        assertEquals(200, c.call(HttpMethod.Put, "/api/v1/account/password", pw, me.token).status.value)
        val after = Flow.sink(s).map { it.first }
        assertTrue(after.containsAll(listOf("new_device", "password_changed")), after.toString())
    }

    @Test
    fun recoveryRequests_perAddressBucket_skipsSilently_forAnOperatorPostureAccount() = testApplication {
        val key = TestKit.Identity().curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key))
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Me("me@example.com")
        Flow.register(c, s, me, Flow.enrolAuth(s), "operator", Flow.escrow(me, sha256Hex(key)))
        Flow.sink(s)
        val answers = (1..8).map { c.call(HttpMethod.Post, "/api/v1/recovery/requests", create(me.email)) }
        // The answer is uniform: 202 with a request id every time.
        assertTrue(answers.all { it.status.value == 202 && it.bodyAsText().contains("requestId") })
        assertEquals(5, Flow.sink(s).count { it.first == "recovery_request_code" })
        assertEquals(5L, s.db.read { it.count("SELECT COUNT(*) FROM recovery_requests WHERE userId=?", me.userId) })
        // An unknown address spends its own bucket and is answered the same way.
        repeat(7) { assertEquals(202, c.call(HttpMethod.Post, "/api/v1/recovery/requests", create("nobody@example.com")).status.value) }
    }

    @Test
    fun securityNotices_keepTheirOwnCapOfTwentyADay() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        Flow.sink(s)
        // Twenty security notices fill the day (queued directly: twenty password logins are slow on a busy host)...
        repeat(20) { s.db.tx { db -> notify(s, db, me.userId, "password_changed") } }
        // ...so a real login's new_device notice is dropped and audited, and the unsolicited cap is untouched.
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/auth/login", me.loginBody(secret = b32())).status.value)
        assertEquals(0, Flow.sink(s).count { it.first == "new_device" })
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='email_dropped' AND meta='template=new_device'") })
        assertEquals(202, c.call(HttpMethod.Post, "/api/v1/recovery/requests", create(me.email)).status.value)
        assertEquals(1, Flow.sink(s).count { it.first == "recovery_request_private" })
        // The next day the budget is back.
        clock.advance(Clock.DAY_MS)
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/auth/login", me.loginBody(secret = b32())).status.value)
        assertEquals(1, Flow.sink(s).count { it.first == "new_device" })
    }
}
