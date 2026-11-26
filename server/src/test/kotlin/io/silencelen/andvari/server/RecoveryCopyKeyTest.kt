package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.AdminEscrowResponse
import io.silencelen.andvari.core.model.wire.AdminRecoveryRequest
import io.silencelen.andvari.core.model.wire.RecoveryRequestCreated
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The operator learns which recovery key an account's stored copy is sealed to (spec 03 §18.6): each row of
 * `GET /admin/recovery-requests` carries `escrowFingerprint` and the copy download carries `fingerprint`, the
 * fingerprint the copy was stored under, as the server has it. After a rotation, an account that has not sealed a new
 * copy still has one on the outgoing key, and a console must be able to say that the offline tool then needs both
 * sheets. Both fields are additive and reach only the operator; an account without a copy has no such key.
 */
class RecoveryCopyKeyTest {
    private val post = HttpMethod.Post
    private val get = HttpMethod.Get

    private val recovery = TestKit.Identity()
    private val fp = sha256Hex(recovery.curvePub)
    private val next = TestKit.Identity()
    private val nextFp = sha256Hex(next.curvePub)

    /** Opens and verifies a request for [me]; returns its id. */
    private suspend fun request(c: HttpClient, s: Services, me: Me): String {
        s.limiter.clear()
        val created = c.call(post, "/api/v1/recovery/requests", """{"email":"${me.email}","rPub":"${b32()}","pollHash":"${"a".repeat(64)}","platform":"android"}""")
        val reqId = WireJson.json.decodeFromString(RecoveryRequestCreated.serializer(), created.bodyAsText()).requestId
        val code = Flow.codeIn(Flow.sink(s).last { it.first == "recovery_request_code" && it.second == me.email }.third)
        assertEquals(200, c.call(post, "/api/v1/recovery/requests/$reqId/verify", """{"code":"$code"}""").status.value)
        return reqId
    }

    private fun rowsOf(text: String): Map<String, JsonObject> =
        (WireJson.json.parseToJsonElement(text) as JsonArray).associate { (it as JsonObject)["requestId"]!!.jsonPrimitive.content to it }

    @Test
    fun theRowsAndTheDownloadNameTheCopysKey_currentOrOutgoing_andAnAccountWithoutACopyHasNone() = testApplication {
        val s = TestKit.services(TestKit.config(recoveryKey = recovery.curvePub))
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        // Before the rotation: two accounts store their copies on the key of card 0.
        val old = Me("old@example.com")
        Flow.register(c, s, old, Flow.enrolAuth(s), "operator", Flow.escrow(old, fp))
        val gone = Me("gone@example.com")
        Flow.register(c, s, gone, Flow.enrolAuth(s), "operator", Flow.escrow(gone, fp))

        // The rotation: the signed statement, then the card that names the new key.
        val setup = s.db.read { s.instance.setupOn(it)!! }
        val card0 = s.db.read { db -> db.queryOne("SELECT frame FROM instance_cards WHERE seq=0") { Bytes.fromB64(it.getString(1)) }!! }
        val rotation = Bytes.toB64(recovery.frame(8, """{"v":2,"purpose":"recovery-rotation","instanceId":"${setup.instanceId}","fromFp":"$fp","toFp":"$nextFp","issuedAt":1800000000000}"""))
        s.limiter.clear()
        assertEquals(200, c.call(HttpMethod.Put, "/api/v1/instance/rotation", """{"statement":"$rotation","currentAuthKey":"${op.authKey}"}""", op.token).status.value)
        val card1 = op.identity.frame(
            4, TestKit.cardStatement(setup.instanceId, 1, sha256Hex(card0), s.config.canonicalOrigin, setup.name, s.config.instanceKind, op.userId, op.identity.edPub, nextFp, 1_800_000_000_001),
        )
        s.limiter.clear()
        val put = c.call(HttpMethod.Put, "/api/v1/instance/card", """{"card":"${Bytes.toB64(card1)}","currentAuthKey":"${op.authKey}"}""", op.token)
        assertEquals(200, put.status.value, put.bodyAsText())
        // After it: a new account stores its copy on the current key.
        val fresh = Me("fresh@example.com")
        Flow.register(c, s, fresh, Flow.enrolAuth(s), "operator", Flow.escrow(fresh, nextFp))
        // And one account's copy is gone from the store while its request is open.
        val oldReq = request(c, s, old)
        val freshReq = request(c, s, fresh)
        val goneReq = request(c, s, gone)
        s.db.tx { it.exec("DELETE FROM escrow WHERE userId=?", gone.userId) }

        s.limiter.clear()
        val listed = c.call(get, "/api/v1/admin/recovery-requests", token = op.token)
        assertEquals(200, listed.status.value, listed.bodyAsText())
        val rows = rowsOf(listed.bodyAsText())
        assertEquals(setOf(oldReq, freshReq, goneReq), rows.keys)
        assertEquals(fp, rows.getValue(oldReq)["escrowFingerprint"]!!.jsonPrimitive.content, "a copy on the outgoing key")
        assertEquals(nextFp, rows.getValue(freshReq)["escrowFingerprint"]!!.jsonPrimitive.content, "a copy on the current key")
        assertFalse("escrowFingerprint" in rows.getValue(goneReq), "no copy, no key (never a null)")
        // The field is the row's last key, after the ones it had; the rest of each row reads as before.
        assertEquals("escrowFingerprint", rows.getValue(oldReq).keys.last())
        val decoded = WireJson.json.decodeFromString(ListSerializer(AdminRecoveryRequest.serializer()), listed.bodyAsText())
        assertEquals(setOf(old.userId, fresh.userId, gone.userId), decoded.map { it.userId }.toSet())

        // The download carries the same word.
        suspend fun download(me: Me) = s.limiter.clear().let { c.call(post, "/api/v1/admin/accounts/${me.userId}/escrow", """{"currentAuthKey":"${op.authKey}"}""", op.token) }
        for ((me, key) in listOf(old to fp, fresh to nextFp)) {
            val r = download(me)
            assertEquals(200, r.status.value, r.bodyAsText())
            val tree = WireJson.json.parseToJsonElement(r.bodyAsText()) as JsonObject
            assertEquals(key, tree["fingerprint"]!!.jsonPrimitive.content, me.email)
            assertEquals(me.userId, WireJson.json.decodeFromString(AdminEscrowResponse.serializer(), r.bodyAsText()).userId)
        }
        assertNotEquals(fp, nextFp)
        val none = download(gone)
        assertEquals(404, none.status.value); assertEquals("no_escrow", none.errorCode())
        assertFalse(none.bodyAsText().contains("fingerprint"), none.bodyAsText())
    }

    @Test
    fun aMembersSessionNeverSeesTheKey() = testApplication {
        val s = TestKit.services(TestKit.config(recoveryKey = recovery.curvePub))
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Me("me@example.com")
        Flow.register(c, s, me, Flow.enrolAuth(s), "operator", Flow.escrow(me, fp))
        val reqId = request(c, s, me)
        // The operator's routes refuse the member, with nothing of the copy in the answer.
        s.limiter.clear()
        val list = c.call(get, "/api/v1/admin/recovery-requests", token = me.token)
        assertEquals(403, list.status.value, list.bodyAsText())
        s.limiter.clear()
        val dl = c.call(post, "/api/v1/admin/accounts/${me.userId}/escrow", """{"currentAuthKey":"${me.authKey}"}""", me.token)
        assertEquals(403, dl.status.value, dl.bodyAsText())
        // The member's own list of its requests names the request and never the copy's key.
        s.limiter.clear()
        val own = c.call(get, "/api/v1/account/recovery-requests", token = me.token)
        assertEquals(200, own.status.value, own.bodyAsText())
        assertTrue(own.bodyAsText().contains(reqId), own.bodyAsText())
        for (text in listOf(list.bodyAsText(), dl.bodyAsText(), own.bodyAsText())) {
            assertFalse(text.contains(fp), text); assertFalse(text.contains("ingerprint"), text)
        }
        assertNull(s.db.read { it.queryOne("SELECT 1 FROM audit WHERE type='operator_escrow_read'") { r -> r.getInt(1) } })
    }
}
