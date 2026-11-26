package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import kotlin.test.Test
import kotlin.test.assertEquals

/** Spec 03 §7.1: a denied operator call leaves its audit row although the route refuses. */
class DeniedAuditTest {
    @Test
    fun deniedOperatorCalls_keepTheirAuditRows() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val nobody = uuid()
        val r1 = c.call(HttpMethod.Post, "/api/v1/admin/accounts/$nobody/disable", """{"reason":"other","currentAuthKey":"${op.authKey}"}""", op.token)
        assertEquals(400, r1.status.value, r1.bodyAsText()); assertEquals("no_such_user", r1.errorCode())
        val r2 = c.call(HttpMethod.Post, "/api/v1/admin/devices/$nobody/revoke", """{"currentAuthKey":"${op.authKey}"}""", op.token)
        assertEquals(404, r2.status.value, r2.bodyAsText()); assertEquals("no_such_device", r2.errorCode())
        val types = s.db.read { db -> db.queryAll("SELECT type FROM audit WHERE type LIKE '%denied' ORDER BY id") { it.getString(1) } }
        assertEquals(listOf("operator_disable_denied", "device_revoke_denied"), types)
    }
}
