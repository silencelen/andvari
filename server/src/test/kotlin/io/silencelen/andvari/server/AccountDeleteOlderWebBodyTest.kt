package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.trust.MemberRole
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/**
 * The web app's older account deletion route (`ApiClient.deleteAccount`) sends a body with the confirmation and the
 * password proof only, and no `leaves`. The route requires `leaves` (spec 03 §13), so the server refuses that body as a
 * bad request before any rule of the deletion is reached, for an account that is a member of a shared vault and for one
 * that is not, and nothing is deleted.
 */
class AccountDeleteOlderWebBodyTest {
    private val post = HttpMethod.Post

    private fun exists(s: Services, userId: String) =
        s.db.read { it.queryOne("SELECT userId FROM users WHERE userId=?", userId) { r -> r.getString(1) } }

    /** The JSON the older web route writes (`JSON.stringify({ confirmEmail, currentAuthKey })`), with no two-step code. */
    private fun olderWebBody(me: Me) = """{"confirmEmail":"${me.email}","currentAuthKey":"${me.authKey}"}"""

    @Test
    fun theOlderWebBodyWithoutLeaves_isRefusedAsABadRequest_andNoAccountIsDeleted() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val owner = Flow.member(c, s, "owner@example.com")
        val member = Flow.member(c, s, "member@example.com")
        val alone = Flow.member(c, s, "alone@example.com")
        SharedVault(c, s, owner).create().add(member, MemberRole.WRITER)

        for ((name, me) in listOf("a member of a shared vault" to member, "an account with no shared vault" to alone)) {
            s.limiter.clear()
            val r = c.call(post, "/api/v1/account/delete", olderWebBody(me), me.token)
            assertEquals(400, r.status.value, "$name: ${r.bodyAsText()}")
            assertEquals("bad_request", r.errorCode(), name)
            assertNotNull(exists(s, me.userId), "$name: the account is still there")
        }
    }
}
