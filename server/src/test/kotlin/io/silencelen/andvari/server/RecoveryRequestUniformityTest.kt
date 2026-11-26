package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.RecoveryRequestCreated
import io.silencelen.andvari.core.model.wire.RecoveryVerifyResponse
import io.silencelen.andvari.core.model.wire.WireJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * An answer to a caller who has not proven an account tells nothing about whether the account exists (spec 03 §18.4,
 * spec 05 T11): the poll of an assisted-recovery request that has not passed its mailed code never changes with what
 * the account's owner does. Before 2026-11-17, a password change, a switch of the recovery setting or a recovery turned
 * a real request `vetoed` in its own poll while a decoy stayed `unverified` (and an account deletion made it
 * `404 request_unknown`), so whoever opened a request could later learn that the address has an account. Now the
 * cancel is told only at the code step, to someone who has shown that they read the mailbox.
 */
class RecoveryRequestUniformityTest {
    private val post = HttpMethod.Post

    private class Fix(val c: HttpClient, val s: Services, val clock: MutableClock, val real: Me, val priv: Me)

    private class Opened(val requestId: String, val poll: String)

    private fun app(block: suspend (Fix) -> Unit) = testApplication {
        val clock = MutableClock()
        val key = TestKit.Identity().curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key), clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val real = Me("real@example.com")
        Flow.register(c, s, real, Flow.enrolAuth(s), "operator", Flow.escrow(real, sha256Hex(key)))
        val priv = Flow.member(c, s, "private@example.com")
        Flow.sink(s)
        block(Fix(c, s, clock, real, priv))
    }

    private suspend fun open(f: Fix, email: String): Opened {
        val poll = TestKit.crypto.randomBytes(32)
        val body = """{"email":"$email","rPub":"${b32()}","pollHash":"${sha256Hex(poll)}","platform":"android"}"""
        val r = f.c.call(post, "/api/v1/recovery/requests", body)
        val text = r.bodyAsText()
        assertEquals(202, r.status.value, text)
        return Opened(WireJson.json.decodeFromString(RecoveryRequestCreated.serializer(), text).requestId, Bytes.toB64(poll))
    }

    private suspend fun poll(f: Fix, o: Opened): String {
        val r = f.c.call(post, "/api/v1/recovery/requests/${o.requestId}/poll", """{"pollSecret":"${o.poll}"}""")
        return "${r.status.value} ${r.headers.entries().filter { it.key != "Date" }.sortedBy { it.key }} ${r.bodyAsText()}"
    }

    private suspend fun verify(f: Fix, o: Opened, code: String): HttpResponse =
        f.c.call(post, "/api/v1/recovery/requests/${o.requestId}/verify", """{"code":"$code"}""")

    /**
     * A real request and a decoy are opened; the owner of the real account acts; each poll answers byte for byte as it
     * did before, and as the other's. Then the code step: the real request's right code is told the cancel
     * (`409 request_state`, and its poll then says `vetoed`), a wrong code is the uniform `400 bad_code`, and the
     * decoy's code is `400 bad_code` as always. Returns nothing; [toldAtCode] is false where the request's row stops
     * naming the account (the account's deletion), whose code is then refused as a decoy's is.
     */
    private fun ownerActs(toldAtCode: Boolean = true, act: suspend (Fix) -> Unit) = app { f ->
        val r = open(f, f.real.email)
        val code = Flow.codeIn(Flow.sink(f.s).last { it.first == "recovery_request_code" }.third)
        val d = open(f, "nobody@example.com")
        val r0 = poll(f, r); val d0 = poll(f, d)
        assertEquals(r0, d0)
        assertTrue(""""state":"unverified"""" in r0, r0)
        act(f)
        val r1 = poll(f, r); val d1 = poll(f, d)
        assertEquals(r0, r1, "the real request's poll after the owner acted")
        assertEquals(d0, d1, "the decoy's poll")
        val wrongCode = if (code == "000000") "111111" else "000000"
        val wrong = verify(f, r, wrongCode)
        assertEquals(400, wrong.status.value); assertEquals("bad_code", wrong.errorCode())
        assertEquals("bad_code", verify(f, d, code).errorCode())
        val told = verify(f, r, code)
        if (toldAtCode) {
            assertEquals(409, told.status.value, told.bodyAsText()); assertEquals("request_state", told.errorCode())
            assertTrue(""""state":"vetoed"""" in poll(f, r))
            // Nothing more for it: the code is spent, and the next try is the uniform refusal.
            assertEquals("bad_code", verify(f, r, code).errorCode())
        } else {
            assertEquals(400, told.status.value); assertEquals("bad_code", told.errorCode())
            assertEquals(r0, poll(f, r))
        }
        assertEquals(d0, poll(f, d))
    }

    @Test
    fun aPasswordChange_doesNotChangeAnUnverifiedRequestsPoll() = ownerActs { f ->
        val pw = """{"currentAuthKey":"${f.real.authKey}","newAuthKey":"${b32()}","newKdfSalt":"${Bytes.toB64(ByteArray(16) { 5 })}","newKdfParams":{"v":1,"alg":"argon2id13","ops":1,"memBytes":8388608},"newWrappedUvk":"AAAA"}"""
        assertEquals(200, f.c.call(HttpMethod.Put, "/api/v1/account/password", pw, f.real.token).status.value)
    }

    @Test
    fun switchingTheRecoverySettingToPrivate_doesNotChangeAnUnverifiedRequestsPoll() = ownerActs { f ->
        val body = """{"posture":"private","currentAuthKey":"${f.real.authKey}","accountState":{"sealedState":"AAAA","baseSeq":0}}"""
        val r = f.c.call(HttpMethod.Put, "/api/v1/account/recovery", body, f.real.token)
        assertEquals(200, r.status.value, r.bodyAsText())
    }

    @Test
    fun aKitRecovery_doesNotChangeAnUnverifiedRequestsPoll() = ownerActs { f ->
        val v = WireJson.json.decodeFromString(
            RecoveryVerifyResponse.serializer(),
            f.c.call(post, "/api/v1/recovery/self/verify", """{"email":"${f.real.email}","recoveryAuthKey":"${f.real.recoveryAuthKey}"}""").bodyAsText(),
        )
        val tail = """"newKdfSalt":"${Bytes.toB64(ByteArray(16) { 5 })}","newKdfParams":{"v":1,"alg":"argon2id13","ops":1,"memBytes":8388608},"newWrappedUvk":"AAAA","newMemberRecovery":{"recoveryWrappedUvk":"AAAA","recoveryAuthKey":"${b32()}"},"device":{"platform":"ios","name":"x","deviceSecret":"${b32()}"}"""
        val kc = f.c.call(post, "/api/v1/recovery/self/commit", """{"recoveryTicket":"${v.recoveryTicket}","newAuthKey":"${b32()}",$tail}""")
        assertEquals(200, kc.status.value, kc.bodyAsText())
    }

    @Test
    fun deletingTheAccount_doesNotChangeAnUnverifiedRequestsPoll_whichBecomesADecoy() = ownerActs(toldAtCode = false) { f ->
        val r = f.c.call(post, "/api/v1/account/delete", """{"confirmEmail":"${f.real.email}","currentAuthKey":"${f.real.authKey}","leaves":[]}""", f.real.token)
        assertEquals(200, r.status.value, r.bodyAsText())
        // The row no longer names the account.
        assertEquals(0L, f.s.db.read { it.count("SELECT COUNT(*) FROM recovery_requests WHERE userId=?", f.real.userId) })
    }
}
