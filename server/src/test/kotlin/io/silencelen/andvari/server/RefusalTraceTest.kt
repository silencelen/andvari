package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.trust.MemberRole
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * A refusal by a limit leaves a trace an operator can see (decided on 2026-11-17): one audit record when an address or a
 * device runs into its back-off's wait, and one when an account deletion is refused because a vault's log moved on,
 * each once per period and never once per request, so a flood of refused requests cannot fill the log. Before, such a
 * refusal wrote nothing: past the fifth wrong sign-in the operator saw only counts of 429 answers.
 */
class RefusalTraceTest {
    private val post = HttpMethod.Post
    private val put = HttpMethod.Put

    private class Row(val userId: String?, val deviceId: String?, val meta: String?)

    private fun rows(s: Services, type: String): List<Row> =
        s.db.read { c -> c.queryAll("SELECT userId,deviceId,meta FROM audit WHERE type=? ORDER BY id", type) { Row(it.getString(1), it.getString(2), it.getString(3)) } }

    private fun wrongKey() = Bytes.toB64(TestKit.crypto.randomBytes(32))

    @Test
    fun signInsRefusedByTheAddresssBackOff_leaveOneRecordPerAddressPerPeriod_keyedAsTheAddressIs() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val stranger = Me("nobody@example.com")
        suspend fun signIn(who: Me) = c.call(post, "/api/v1/auth/login", who.loginBody(secret = b32()))
        // Five wrong sign-ins arm each address's lock; fifty sign-ins with the right password are then refused.
        for (who in listOf(me, stranger)) repeat(5) { s.loginBackoff.fail(who.email) }
        repeat(50) {
            for (who in listOf(me, stranger)) assertEquals("rate_limited", signIn(who).errorCode())
        }
        val first = rows(s, "login_wait")
        assertEquals(listOf(me.userId, null), first.map { it.userId }, "one record per address; the account when it has one")
        val (mine, theirs) = first.map { it.meta!! }
        assertTrue(mine.startsWith("addr=") && mine.endsWith(" at=login"), mine)
        val addr = mine.removePrefix("addr=").substringBefore(' ')
        assertEquals(s.config.addressHash(me.email).take(8), addr)
        assertFalse(sha256Hex(me.email).startsWith(addr), "the record keeps the keyed hash, not the plain one")
        assertNotEquals(mine, theirs)
        // A new lock inside the same period adds nothing; the first refusal of the next period adds one.
        clock.advance(60_000)
        s.loginBackoff.fail(me.email)
        repeat(5) { assertEquals("rate_limited", signIn(me).errorCode()) }
        assertEquals(2, rows(s, "login_wait").size)
        clock.advance(RefusalTrace.BACKOFF_PERIOD_MS)
        s.loginBackoff.fail(me.email)
        assertEquals("rate_limited", signIn(me).errorCode())
        val all = rows(s, "login_wait")
        assertEquals(3, all.size)
        assertEquals(mine, all.last().meta, "the same address ties to the same value")
    }

    @Test
    fun proofsAndCodesRefusedByTheDevicesBackOffs_leaveOneRecordPerDevicePerPeriod() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val counter = s.deviceCounterKey(me.deviceId)
        val link = """{"enabled":false,"currentAuthKey":"${me.authKey}"}"""
        // The proofs: the lock armed, and every try the route's own budget lets through (five a minute) refused.
        repeat(5) { s.proofBackoff.fail(counter) }
        repeat(5) { assertEquals("rate_limited", c.call(put, "/api/v1/account/require-link", link, me.token).errorCode()) }
        val proofs = rows(s, "reauth_wait")
        assertEquals(1, proofs.size)
        assertEquals(me.userId, proofs[0].userId)
        assertEquals(me.deviceId, proofs[0].deviceId)
        assertTrue(proofs[0].meta!!.startsWith("route="), proofs[0].meta)
        clock.advance(2 * 60_000)
        s.proofBackoff.fail(counter)
        repeat(5) { assertEquals("rate_limited", c.call(put, "/api/v1/account/require-link", link, me.token).errorCode()) }
        assertEquals(1, rows(s, "reauth_wait").size, "inside the period")
        clock.advance(RefusalTrace.BACKOFF_PERIOD_MS)
        s.proofBackoff.fail(counter)
        assertEquals("rate_limited", c.call(put, "/api/v1/account/require-link", link, me.token).errorCode())
        assertEquals(2, rows(s, "reauth_wait").size, "the next period")
        // The codes: a two-step setup waiting for its code, the codes' lock armed, every code refused: one record.
        s.proofBackoff.success(counter)
        val setup = c.call(post, "/api/v1/account/totp/setup", """{"currentAuthKey":"${me.authKey}"}""", me.token)
        assertEquals(200, setup.status.value, setup.bodyAsText())
        repeat(5) { s.codeBackoff.fail(counter) }
        repeat(5) { assertEquals("rate_limited", c.call(post, "/api/v1/account/totp/confirm", """{"code":"000000"}""", me.token).errorCode()) }
        val codes = rows(s, "totp_verify_wait")
        assertEquals(1, codes.size)
        assertEquals(me.deviceId, codes[0].deviceId)
        assertEquals(0, rows(s, "totp_verify_fail").size, "a refused code is not looked at")
    }

    @Test
    fun deletionsRefusedForAMovedLog_leaveOneRecordPerAccountPerHour() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val owner = Flow.member(c, s, "owner@example.com")
        val me = Flow.member(c, s, "me@example.com")
        SharedVault(c, s, owner).create().add(me, MemberRole.WRITER)
        val body = """{"confirmEmail":"${me.email}","currentAuthKey":"${me.authKey}","leaves":[]}"""
        repeat(20) {
            val r = c.call(post, "/api/v1/account/delete", body, me.token)
            assertEquals("account_delete_log_stale", r.errorCode(), r.bodyAsText())
        }
        val first = rows(s, "account_delete_stale")
        assertEquals(1, first.size)
        assertEquals(me.userId, first[0].userId)
        assertEquals(me.deviceId, first[0].deviceId)
        assertEquals("vaults=1", first[0].meta)
        clock.advance(RefusalTrace.DELETE_STALE_PERIOD_MS + 1)
        me.session = c.login(me) // the hour outlived the session's access token
        assertEquals("account_delete_log_stale", c.call(post, "/api/v1/account/delete", body, me.token).errorCode())
        assertEquals(2, rows(s, "account_delete_stale").size)
    }
}
