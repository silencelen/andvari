package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.plugins.websocket.DefaultClientWebSocketSession
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import io.silencelen.andvari.core.model.wire.AuditRow
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.builtins.ListSerializer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Index row 78 (spec 03 §7.1, rule of 2026-11-17): the record of an operator's removal of a device names the operator
 * (userId), the removed device (deviceId) and, in its details, the account that device belonged to and the operator's own
 * device (`target=<account>,by=<operator's device>`), so that every record of a removal says who did it and from which
 * device, as the owner's own removal (`account_device_revoke`, deviceId = the removing device) already does. What the
 * existing fields mean is unchanged, older rows without `by=` read as before, and the removed device still learns only
 * that its session ended.
 */
class OperatorRevokeRecordTest {
    private val post = HttpMethod.Post
    private val get = HttpMethod.Get

    private fun reauth(me: Me) = """{"currentAuthKey":"${me.authKey}"}"""

    private suspend fun ticket(c: HttpClient, token: String): String =
        Regex("\"ticket\":\"([^\"]+)\"").find(c.call(post, "/api/v1/events/ticket", token = token).bodyAsText())!!.groupValues[1]

    private suspend fun ApplicationTestBuilder.withSocket(token: String, whileOpen: suspend DefaultClientWebSocketSession.() -> Unit) {
        val ws = createClient { install(WebSockets) }
        ws.webSocket("/api/v1/events?ticket=${ticket(client, token)}") {
            send(Frame.Text("ping"))
            assertEquals("pong", (withTimeout(5_000) { incoming.receive() } as Frame.Text).readText())
            whileOpen()
        }
    }

    private fun rows(s: Services, type: String) = s.db.read { c ->
        c.queryAll("SELECT userId,deviceId,meta FROM audit WHERE type=? ORDER BY id", type) { Triple(it.getString(1), it.getString(2), it.getString(3)) }
    }

    @Test
    fun theRecordNamesTheOperatorItsDevice_theRemovedDeviceAndItsAccount_andTheRemovedDeviceLearnsOnlyThatItsSessionEnded() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val m = Flow.member(c, s, "m@example.com")
        val kept = c.login(m)
        withSocket(m.token) {
            assertEquals(200, c.call(post, "/api/v1/admin/devices/${m.deviceId}/revoke", reauth(op), op.token).status.value)
            // The removed device's socket is told exactly that its session ended, and is closed.
            val f = withTimeout(5_000) { incoming.receive() }
            assertEquals("""{"type":"revoked"}""", (f as Frame.Text).readText())
            val end = withTimeout(5_000) { incoming.receiveCatching() }
            assertTrue(end.isClosed || end.getOrNull() is Frame.Close, "closed after the notice")
        }
        // The record: the operator, the removed device, its account and the operator's own device.
        assertEquals(listOf(Triple(op.userId, m.deviceId, "target=${m.userId},by=${op.deviceId}")), rows(s, "operator_device_revoke"))
        assertNotEquals(op.deviceId, m.deviceId)
        // The operator's audit list serves it as stored.
        val listed = WireJson.json.decodeFromString(
            ListSerializer(AuditRow.serializer()),
            c.call(get, "/api/v1/admin/audit?type=operator_device_revoke", token = op.token).bodyAsText(),
        ).single()
        assertEquals(op.userId, listed.userId)
        assertEquals(m.deviceId, listed.deviceId)
        assertEquals(op.deviceId, operatorRevokeBy(listed.meta))
        // The removed device: its requests and its refresh are refused as any ended session's, naming no one.
        val req = c.call(get, "/api/v1/account/keys", token = m.token)
        assertEquals(401, req.status.value); assertEquals("invalid_credentials", req.errorCode())
        val ref = c.call(post, "/api/v1/auth/refresh", """{"refreshToken":"${m.session!!.refreshToken}"}""")
        assertEquals(401, ref.status.value); assertEquals("session_revoked", ref.errorCode())
        for (body in listOf(req.bodyAsText(), ref.bodyAsText())) {
            assertFalse(body.contains(op.deviceId) || body.contains(op.userId) || body.contains("operator"), body)
        }
        // The account's notice says "the operator", and never the operator's device.
        val mail = Flow.sink(s).last { it.first == "device_removed" }
        assertTrue(mail.third.contains("the operator"), mail.third)
        assertFalse(mail.third.contains(op.deviceId), mail.third)
        // The account's other device is untouched.
        assertEquals(200, c.call(get, "/api/v1/account/keys", token = kept.accessToken).status.value)
    }

    @Test
    fun anOlderRowWithoutTheOperatorsDevice_stillReads_andADeletionReKeysTheOperatorsDeviceInEveryRow() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val m = Flow.member(c, s, "m@example.com")
        // A row written before the operator's device was recorded: `target=` alone.
        s.db.tx { s.audit.on(it, "operator_device_revoke", op.userId, m.deviceId, "10.0.0.1", "target=${m.userId}") }
        assertNull(operatorRevokeBy("target=${m.userId}"))
        val second = c.login(m)
        assertEquals(200, c.call(post, "/api/v1/admin/devices/${second.deviceId}/revoke", reauth(op), op.token).status.value)
        val listed = WireJson.json.decodeFromString(
            ListSerializer(AuditRow.serializer()),
            c.call(get, "/api/v1/admin/audit?type=operator_device_revoke", token = op.token).bodyAsText(),
        )
        assertEquals(listOf("target=${m.userId},by=${op.deviceId}", "target=${m.userId}"), listed.map { it.meta }, "newest first, both read")
        assertEquals(listOf(op.deviceId, null), listed.map { operatorRevokeBy(it.meta) })

        // An account that wrote such rows (a former operator, after a handover) is deleted: its device in `by=` gets the
        // same new id as on its own rows, and the removed device and its account, another account's, are left alone.
        // The rows are written here as the former operator wrote them; deleting an operator is refused.
        val former = Flow.member(c, s, "former@example.com")
        s.db.tx {
            s.audit.on(it, "operator_device_revoke", former.userId, m.deviceId, "10.0.0.2", "target=${m.userId}")
            s.audit.on(it, "operator_device_revoke", former.userId, m.deviceId, "10.0.0.2", operatorRevokeMeta(m.userId, former.deviceId))
        }
        val gone = c.call(post, "/api/v1/account/delete", """{"confirmEmail":"${former.email}","currentAuthKey":"${former.authKey}","leaves":[]}""", former.token)
        assertEquals(200, gone.status.value, gone.bodyAsText())
        val alias = s.db.read { db -> db.queryOne("SELECT deviceId FROM audit WHERE type='register' AND userId<>? AND userId<>? ", op.userId, m.userId) { it.getString(1) } }!!
        assertNotEquals(former.deviceId, alias)
        val pseudonym = s.db.read { db -> db.queryOne("SELECT userId FROM audit WHERE type='account_delete'") { it.getString(1) } }!!
        val formerRows = rows(s, "operator_device_revoke").filter { it.first == pseudonym }
        assertEquals(listOf(Triple(pseudonym, m.deviceId, "target=${m.userId}"), Triple(pseudonym, m.deviceId, "target=${m.userId},by=$alias")), formerRows)
        assertEquals(0L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE instr(meta, ?) > 0 OR deviceId=?", former.deviceId, former.deviceId) }, "no row names the deleted account's device")
        // The operator's own rows are unchanged.
        assertEquals(2, rows(s, "operator_device_revoke").count { it.first == op.userId })
    }
}
