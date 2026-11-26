package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.DeletedAtResponse
import io.silencelen.andvari.core.model.wire.WireJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The one exception to the operator's 30-day wait (spec 03 §7.1; owner policy 2026-11-15): a deletion that
 * states `reason: "under_minimum_age"` of a disabled account proceeds at once, is audited with the reason on
 * the operator's own row (which outlives the account), and sends `account_deleted_by_operator`. Every other
 * reason, a missing reason, an active account and a non-operator are refused as before.
 */
class OperatorUnderAgeDeleteTest {
    private val post = HttpMethod.Post

    @Test
    fun underMinimumAge_deletesADisabledAccountAtOnce_andIsAudited_everythingElseRefused() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val child = Flow.member(c, s, "child@example.com")
        val other = Flow.member(c, s, "other@example.com")
        fun exists() = s.db.read { it.count("SELECT COUNT(*) FROM users WHERE userId=?", child.userId) } == 1L
        suspend fun delete(body: String, token: String = op.token) =
            s.limiter.clear().let { _ -> c }.call(post, "/api/v1/admin/accounts/${child.userId}/delete", body, token)
        fun body(reason: String?, key: String = op.authKey) =
            if (reason == null) """{"currentAuthKey":"$key"}""" else """{"currentAuthKey":"$key","reason":"$reason"}"""

        // An active account: the reason lifts the wait, not the disable.
        val active = delete(body("under_minimum_age"))
        assertEquals(409, active.status.value); assertEquals("not_disabled_long_enough", active.errorCode())
        assertTrue(exists())

        assertEquals(200, c.call(post, "/api/v1/admin/accounts/${child.userId}/disable", """{"reason":"other","currentAuthKey":"${op.authKey}"}""", op.token).status.value)
        clock.advance(Clock.MINUTE_MS)

        // No reason, and an explicit null: the 30-day rule, exactly as before.
        for (b in listOf(body(null), """{"currentAuthKey":"${op.authKey}","reason":null}""")) {
            val r = delete(b)
            assertEquals(409, r.status.value); assertEquals("not_disabled_long_enough", r.errorCode())
            assertTrue(r.bodyAsText().contains("\"disabledAt\""))
        }
        // The reason is a closed value: any other value, free text naming the same thing included, unlocks nothing.
        for (reason in listOf("abuse", "request", "other", "Under the minimum age", "UNDER_MINIMUM_AGE", "under_minimum_age ", "")) {
            val r = delete(body(reason))
            assertEquals(400, r.status.value, reason); assertEquals("bad_reason", r.errorCode(), reason)
        }
        assertEquals("bad_request", delete("""{"currentAuthKey":"${op.authKey}","reason":13}""").errorCode())
        // A non-operator, and the operator without its password proof, are refused as before.
        assertEquals("not_operator", delete(body("under_minimum_age", other.authKey), other.token).errorCode())
        val wrong = delete(body("under_minimum_age", Bytes.toB64(TestKit.crypto.randomBytes(32))))
        assertEquals(403, wrong.status.value); assertEquals("reauth_failed", wrong.errorCode())
        assertTrue(exists())
        assertEquals(0L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='operator_delete'") })

        // The exception: a minute after the disable, the account is deleted.
        val ok = delete(body("under_minimum_age"))
        assertEquals(200, ok.status.value)
        assertEquals(clock.now(), WireJson.json.decodeFromString(DeletedAtResponse.serializer(), ok.bodyAsText()).deletedAt)
        assertTrue(!exists())

        // The audit: the operator's own row names the act and the reason, under the operator's id, with the
        // target's pseudonym; it survives the deletion (it was read after it), and no row carries an email.
        val rows = s.db.read { it.queryAll("SELECT userId,meta FROM audit WHERE type='operator_delete'") { r -> r.getString(1) to r.getString(2) } }
        assertEquals(1, rows.size)
        assertEquals(op.userId, rows.single().first)
        val meta = rows.single().second
        val pseudonym = Regex("^target=([0-9a-f-]{36}),reason=under_minimum_age$").find(meta)?.groupValues?.get(1)
        assertNotNull(pseudonym, meta)
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='account_delete' AND userId=?", pseudonym) })
        assertEquals(0L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE userId=? OR instr(COALESCE(meta,''), ?) > 0", child.userId, child.userId) })
        assertEquals(0L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE instr(COALESCE(meta,''), '@') > 0") })
        val api = c.call(HttpMethod.Get, "/api/v1/admin/audit?type=operator_delete", token = op.token).bodyAsText()
        assertTrue(api.contains("reason=under_minimum_age") && !api.contains("@example.com"), api)

        // The deletion notice the design defines, to the captured address.
        val mail = Flow.sink(s).last()
        assertEquals("account_deleted_by_operator", mail.first)
        assertEquals(child.email, mail.second)
        assertTrue(mail.third.contains("It had been disabled since"), mail.third)
    }

    @Test
    fun withoutTheReason_anAccountDisabledThirtyDays_isDeletedAndAuditedAsBefore() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val m = Flow.member(c, s, "m@example.com")
        assertEquals(200, c.call(post, "/api/v1/admin/accounts/${m.userId}/disable", """{"reason":"request","currentAuthKey":"${op.authKey}"}""", op.token).status.value)
        clock.advance(30 * Clock.DAY_MS - Clock.MINUTE_MS)
        val op2 = c.call(post, "/api/v1/auth/login", op.loginBody(deviceId = op.deviceId))
        val token = (WireJson.json.parseToJsonElement(op2.bodyAsText()) as kotlinx.serialization.json.JsonObject)["accessToken"]!!.toString().trim('"')
        val early = c.call(post, "/api/v1/admin/accounts/${m.userId}/delete", """{"currentAuthKey":"${op.authKey}"}""", token)
        assertEquals("not_disabled_long_enough", early.errorCode())
        clock.advance(Clock.MINUTE_MS)
        s.limiter.clear()
        assertEquals(200, c.call(post, "/api/v1/admin/accounts/${m.userId}/delete", """{"currentAuthKey":"${op.authKey}"}""", token).status.value)
        val meta = s.db.read { it.queryOne("SELECT meta FROM audit WHERE type='operator_delete'") { r -> r.getString(1) } }!!
        assertTrue(Regex("^target=[0-9a-f-]{36}$").matches(meta), meta)
        assertEquals("account_deleted_by_operator", Flow.sink(s).last().first)
    }
}
