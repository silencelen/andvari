package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.EscrowUpload
import io.silencelen.andvari.core.model.wire.RecoveryRequestCreated
import io.silencelen.andvari.core.model.wire.WireJson
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Spec 03 §18, spec 05 T11: a recovery request answers alike whether the address has an
 * operator-posture account, a private-posture one or none, and a stranger's wrong codes cannot lock the owner out.
 */
class AssistedUniformityTest {
    private val post = HttpMethod.Post

    private class Opened(val requestId: String, val pollSecret: String)

    private suspend fun open(c: HttpClient, email: String): Opened {
        val poll = Bytes.toB64(TestKit.crypto.randomBytes(32))
        val r = c.call(post, "/api/v1/recovery/requests", """{"email":"$email","rPub":"${b32()}","pollHash":"${sha256Hex(Bytes.fromB64(poll))}","platform":"android"}""")
        assertEquals(202, r.status.value, r.bodyAsText())
        return Opened(WireJson.json.decodeFromString(RecoveryRequestCreated.serializer(), r.bodyAsText()).requestId, poll)
    }

    private val reset =
        """"newAuthKey":"${b32()}","newKdfSalt":"${Bytes.toB64(ByteArray(16) { 5 })}","newKdfParams":{"v":1,"alg":"argon2id13","ops":1,"memBytes":8388608},""" +
            """"newWrappedUvk":"AAAA","newMemberRecovery":{"recoveryWrappedUvk":"AAAA","recoveryAuthKey":"${b32()}"},"device":{"platform":"ios","name":"x","deviceSecret":"${b32()}"}"""

    @Test
    fun pollVerifyAndCommit_answerAlikeForEveryPosture() = testApplication {
        val key = TestKit.Identity().curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key))
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val operatorPosture = Me("op-posture@example.com")
        Flow.register(c, s, operatorPosture, Flow.enrolAuth(s), "operator", Flow.escrow(operatorPosture, sha256Hex(key)))
        val privatePosture = Flow.member(c, s, "private@example.com")
        val answers = HashMap<String, List<String>>()
        for (email in listOf(operatorPosture.email, privatePosture.email, "nobody@example.com")) {
            val o = open(c, email)
            val seen = ArrayList<String>()
            val poll = c.call(post, "/api/v1/recovery/requests/${o.requestId}/poll", """{"pollSecret":"${o.pollSecret}"}""")
            seen += "poll ${poll.status.value} ${poll.bodyAsText()}"
            repeat(11) {
                val v = c.call(post, "/api/v1/recovery/requests/${o.requestId}/verify", """{"code":"000000"}""")
                seen += "verify ${v.status.value} ${v.errorCode()}"
            }
            val commit = c.call(post, "/api/v1/recovery/requests/${o.requestId}/commit", """{"pollSecret":"${o.pollSecret}",$reset}""")
            seen += "commit ${commit.status.value} ${commit.errorCode()}"
            answers[email] = seen
        }
        val expected = answers.getValue(operatorPosture.email)
        assertEquals("poll 200 {\"state\":\"unverified\"}", expected.first())
        assertEquals(expected, answers.getValue(privatePosture.email))
        assertEquals(expected, answers.getValue("nobody@example.com"))
    }

    @Test
    fun aStrangersWrongCodes_doNotLockTheOwnerOut() = testApplication {
        val key = TestKit.Identity().curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key))
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Me("me@example.com")
        Flow.register(c, s, me, Flow.enrolAuth(s), "operator", Flow.escrow(me, sha256Hex(key)))
        Flow.sink(s)
        // A stranger opens two requests for the address and posts ten wrong codes.
        repeat(2) {
            val o = open(c, me.email)
            repeat(5) { c.call(post, "/api/v1/recovery/requests/${o.requestId}/verify", """{"code":"999999"}""") }
        }
        // The owner's own request, with the right code, verifies.
        val mine = open(c, me.email)
        val code = Flow.codeIn(Flow.sink(s).last { it.first == "recovery_request_code" }.third)
        val r = c.call(post, "/api/v1/recovery/requests/${mine.requestId}/verify", """{"code":"$code"}""")
        assertEquals(200, r.status.value, r.bodyAsText())
    }
}
