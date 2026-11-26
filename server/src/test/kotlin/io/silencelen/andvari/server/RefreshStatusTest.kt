package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import kotlin.test.Test
import kotlin.test.assertEquals

/** Spec 03 §2: refresh refuses a session of an account that is not active or of a revoked device. */
class RefreshStatusTest {
    private val post = HttpMethod.Post

    @Test
    fun refresh_refusesAnInactiveAccount_andARevokedDevice_withoutConsumingTheToken() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val refresh = me.session!!.refreshToken
        suspend fun refresh(t: String) = c.call(post, "/api/v1/auth/refresh", """{"refreshToken":"$t"}""")
        // The account disabled without its sessions revoked (the status is what the check reads).
        s.db.tx { it.exec("UPDATE users SET status='disabled', disabledAt=1 WHERE userId=?", me.userId) }
        val r1 = refresh(refresh)
        assertEquals(401, r1.status.value, r1.bodyAsText()); assertEquals("invalid_credentials", r1.errorCode())
        assertEquals(0L, s.db.read { it.count("SELECT COUNT(*) FROM sessions WHERE userId=? AND refreshConsumedAt IS NOT NULL", me.userId) }, "not consumed")
        s.db.tx { it.exec("UPDATE users SET status='active', disabledAt=NULL WHERE userId=?", me.userId) }
        // The device revoked without its sessions revoked.
        s.db.tx { it.exec("UPDATE devices SET revokedAt=1 WHERE deviceId=?", me.deviceId) }
        val r2 = refresh(refresh)
        assertEquals(401, r2.status.value, r2.bodyAsText()); assertEquals("invalid_credentials", r2.errorCode())
        s.db.tx { it.exec("UPDATE devices SET revokedAt=NULL WHERE deviceId=?", me.deviceId) }
        // The same token still works once both are live again: neither refusal consumed it.
        assertEquals(200, refresh(refresh).status.value)
    }
}
