package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.AccountDeletePreview
import io.silencelen.andvari.core.model.wire.TotpSetupResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.trust.LogEntry
import io.silencelen.andvari.core.trust.MemberRole
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * An account deletion refused because a vault's log moved on costs the person nothing (decided on 2026-11-17): the try's
 * draws on the limits per device, the deletion's own (5 an hour) and the two-step code's (5 a minute), are given back,
 * since nothing about the person was decided. Before, each such refusal spent one of each, so a person whose co-members
 * kept changing a shared vault while the browser tried again (three tries a press) met `429` at the sixth try and waited
 * up to an hour.
 */
class AccountDeleteStaleGiveBackTest {
    private val post = HttpMethod.Post
    private val get = HttpMethod.Get

    @Test
    fun refusalsForAMovedLog_spendNoDraw_andTheDeletionIsTakenWithinTheSameHour() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val owner = Flow.member(c, s, "owner@example.com")
        val me = Flow.member(c, s, "me@example.com")
        val v = SharedVault(c, s, owner).create()
        v.add(me, MemberRole.WRITER)
        val secret = WireJson.json.decodeFromString(TotpSetupResponse.serializer(), c.call(post, "/api/v1/account/totp/setup", """{"currentAuthKey":"${me.authKey}"}""", me.token).bodyAsText()).secretBase32
        assertEquals(200, c.call(post, "/api/v1/account/totp/confirm", """{"code":"${Flow.totp(secret, clock.now())}"}""", me.token).status.value)
        clock.advance(30_000)
        val code = Flow.totp(secret, clock.now())
        val head = WireJson.json.decodeFromString(AccountDeletePreview.serializer(), c.call(get, "/api/v1/account/delete/preview", token = me.token).bodyAsText())
            .memberships.single().head
        fun body(leaves: List<String>) =
            """{"confirmEmail":"${me.email}","currentAuthKey":"${me.authKey}","totp":"$code","leaves":${leaves.joinToString(",", "[", "]") { "\"$it\"" }}}"""

        // Two presses of three tries each, every one refused because the vault's log is not where the leave expects (here
        // no leave at all, which the server answers the same way): six refusals inside one minute.
        repeat(6) { i ->
            val r = c.call(post, "/api/v1/account/delete", body(emptyList()), me.token)
            assertEquals(409, r.status.value, "try ${i + 1}: ${r.bodyAsText()}")
            assertEquals("account_delete_log_stale", r.errorCode())
        }
        assertEquals(0, s.limiter.count(Bucket.deviceKey(ACCOUNT_DELETE_BUCKET, me.deviceId)))
        assertEquals(0, s.limiter.count(Bucket.deviceKey(SharedBuckets.TOTP_VERIFY, me.deviceId)))
        // The account's ceiling keeps them (it is never given back): six of its twenty.
        assertEquals(6, s.limiter.count(Bucket.accountKey(ACCOUNT_DELETE_BUCKET, me.userId)))

        // The deletion with the right leave is taken within the same minute and hour.
        val leave = v.sign(me, LogEntry.Leave(v.vaultId, head.seq + 1, head.hash, me.userId, maxOf(clock.now(), head.at)))
        val done = c.call(post, "/api/v1/account/delete", body(listOf(leave)), me.token)
        assertEquals(200, done.status.value, done.bodyAsText())
    }

    /**
     * The give-back opens no unlimited tries (decided on 2026-11-17). A member of a shared vault produces the refusal for a
     * moved log at will by leaving the leaf out, with the right password, and each try runs the password's hash. Forty
     * tries at one instant: the first twenty (the account's ceiling for deletions, never given back) are refused for the
     * moved log, each with one hash; the other twenty are `429` before any hashing. Before, all forty were refused for
     * the moved log with no draw left behind, and the server ran forty hashes.
     */
    @Test
    fun fortyTriesThatLeaveTheLeafOut_stopAtTheAccountsCeiling_beforeAnyHashing() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val owner = Flow.member(c, s, "owner@example.com")
        val me = Flow.member(c, s, "me@example.com")
        SharedVault(c, s, owner).create().add(me, MemberRole.WRITER)
        val body = """{"confirmEmail":"${me.email}","currentAuthKey":"${me.authKey}","leaves":[]}"""
        val ceiling = ACCOUNT_DELETE_BUCKET.accountCeiling!!
        val answers = LinkedHashMap<String, Int>()
        val hashesBefore = ServerCrypto.argon2Calls.get()
        repeat(40) {
            val r = c.call(post, "/api/v1/account/delete", body, me.token)
            val key = "${r.status.value} ${r.errorCode()}"
            answers[key] = (answers[key] ?: 0) + 1
        }
        val hashes = ServerCrypto.argon2Calls.get() - hashesBefore
        assertEquals(mapOf("409 account_delete_log_stale" to ceiling, "429 rate_limited" to 40 - ceiling), answers)
        assertEquals(ceiling.toLong(), hashes, "one hash per try within the ceiling, none after it")
        assertEquals(0, s.limiter.count(Bucket.deviceKey(ACCOUNT_DELETE_BUCKET, me.deviceId)))
        assertEquals(ceiling, s.limiter.count(Bucket.accountKey(ACCOUNT_DELETE_BUCKET, me.userId)))
        // The hour over, the account's ceiling has room again (the session's access token has expired by then, so the
        // limiter is asked directly).
        clock.advance(Clock.HOUR_MS)
        assertEquals(null, s.limiter.drawDevice(ACCOUNT_DELETE_BUCKET, me.userId, me.deviceId))
    }

    /** Any other refusal keeps its draws: a wrong code is still counted against the deletion's limit and the code's. */
    @Test
    fun aWrongCode_keepsItsDraws() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val secret = WireJson.json.decodeFromString(TotpSetupResponse.serializer(), c.call(post, "/api/v1/account/totp/setup", """{"currentAuthKey":"${me.authKey}"}""", me.token).bodyAsText()).secretBase32
        assertEquals(200, c.call(post, "/api/v1/account/totp/confirm", """{"code":"${Flow.totp(secret, clock.now())}"}""", me.token).status.value)
        clock.advance(30_000)
        val wrong = if (Flow.totp(secret, clock.now()) == "000000") "111111" else "000000"
        val r = c.call(post, "/api/v1/account/delete", """{"confirmEmail":"${me.email}","currentAuthKey":"${me.authKey}","totp":"$wrong","leaves":[]}""", me.token)
        assertEquals("bad_totp_code", r.errorCode())
        assertEquals(1, s.limiter.count(Bucket.deviceKey(ACCOUNT_DELETE_BUCKET, me.deviceId)))
        assertEquals(1, s.limiter.count(Bucket.deviceKey(SharedBuckets.TOTP_VERIFY, me.deviceId)))
    }
}
