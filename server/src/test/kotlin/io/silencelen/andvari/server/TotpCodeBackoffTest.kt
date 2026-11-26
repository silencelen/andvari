package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.TokenPair
import io.silencelen.andvari.core.model.wire.TotpSetupResponse
import io.silencelen.andvari.core.model.wire.WireJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A two-step code sent on a signed-in session has a back-off of its own (spec 03 §2, §8): per account, with the
 * curve of the sign-in's and the proofs' back-offs (five free, then 2^(n−5) s, capped at 900 s), counted only by
 * codes checked on that account's own sessions (TOTP setup, confirm and disable, and the account deletion's code),
 * and refusing only the checking of a code. While it is in force a code is refused before it is looked at, with
 * `429 rate_limited`, `Retry-After: 60`, exactly as a proof is; a right code clears it.
 *
 * Before it, only the per-minute buckets bounded a session: 5 a minute on setup and 5 on disable (the deletion's
 * code shares disable's), 14,400 guesses a day at the account's current code, each over three steps. With it, a
 * session gets 109 a day over all those routes together.
 */
class TotpCodeBackoffTest {
    private val post = HttpMethod.Post
    private val put = HttpMethod.Put

    private companion object {
        const val SETUP = "/api/v1/account/totp/setup"
        const val CONFIRM = "/api/v1/account/totp/confirm"
        const val DISABLE = "/api/v1/account/totp/disable"
        const val DELETE = "/api/v1/account/delete"
        const val DAY = 86_400_000L
    }

    /** The lock that failure [n] (n ≥ 5) arms: the sign-in back-off's curve. */
    private fun lock(n: Int) = (1000L shl (n - 5)).coerceAtMost(900_000)

    private fun code(secret: String, clock: Clock) = Flow.totp(secret, clock.now())

    /** A six-digit code that matches none of the three steps the server accepts at [clock]'s time. */
    private fun wrong(secret: String, clock: Clock): String {
        val near = (-1..1).map { Flow.totp(secret, clock.now() + it * 30_000L) }.toSet()
        return (0..9).map { "$it".repeat(6) }.first { it !in near }
    }

    // The bodies of the routes that take a code, each with the code as its only variable (the proof is always right).
    private fun rotate(me: Me, code: String) = """{"code":"$code","currentAuthKey":"${me.authKey}"}"""
    private fun disable(me: Me, code: String) = """{"code":"$code","currentAuthKey":"${me.authKey}"}"""
    private fun confirm(code: String) = """{"code":"$code"}"""
    private fun delete(me: Me, code: String) = """{"confirmEmail":"${me.email}","totp":"$code","currentAuthKey":"${me.authKey}","leaves":[]}"""

    /** Two-step sign-in on for [me], from the session registration gave (with the proof); returns the secret, a step later. */
    private suspend fun enrol(c: HttpClient, clock: MutableClock, me: Me): String {
        val setup = c.call(post, SETUP, """{"currentAuthKey":"${me.authKey}"}""", me.token)
        assertEquals(200, setup.status.value, setup.bodyAsText())
        val secret = WireJson.json.decodeFromString(TotpSetupResponse.serializer(), setup.bodyAsText()).secretBase32
        assertEquals(200, c.call(post, CONFIRM, confirm(code(secret, clock)), me.token).status.value)
        clock.advance(30_000)
        return secret
    }

    private fun failRows(s: Services, userId: String) =
        s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='totp_verify_fail' AND userId=?", userId) }

    private fun totpRow(s: Services, userId: String) = s.db.read {
        it.queryOne("SELECT totpSecret,totpPendingSecret,totpLastStep FROM users WHERE userId=?", userId) { r -> Triple(r.getString(1), r.getString(2), r.getLong(3)) }!!
    }

    /** Fifteen failures, each sent as the previous lock lapses (buckets emptied first), which take a back-off to its cap. */
    private suspend fun walkToCap(s: Services, clock: MutableClock, expect: String, send: suspend (Int) -> String?) {
        for (n in 1..15) {
            s.limiter.clear()
            assertEquals(expect, send(n), "failure $n")
            if (n in 5..14) clock.advance(lock(n))
        }
    }

    @Test
    fun wrongCodesOverTheThreeRoutes_armTheBackoff_andARightCodeIsThenRefusedUnread() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val a = enrol(c, clock, me)
        // A rotation with the right code leaves a pending secret, so the confirm route has a code to check.
        val rot = c.call(post, SETUP, rotate(me, code(a, clock)), me.token)
        assertEquals(200, rot.status.value, rot.bodyAsText())
        val b = WireJson.json.decodeFromString(TotpSetupResponse.serializer(), rot.bodyAsText()).secretBase32
        clock.advance(30_000) // a step the rotation did not use, so the right codes below are right
        // Five wrong codes over the three routes, inside one minute (no route's own bucket is reached).
        val answers = ArrayList<String>()
        suspend fun send(path: String, body: String) {
            val r = c.call(post, path, body, me.token)
            answers += "$path:${r.status.value}:${r.errorCode()}"
        }
        repeat(2) { send(SETUP, rotate(me, wrong(a, clock))) }
        repeat(2) { send(CONFIRM, confirm(wrong(b, clock))) }
        send(DISABLE, disable(me, wrong(a, clock)))
        assertEquals(5, answers.count { it.endsWith(":400:bad_totp_code") }, answers.joinToString("\n"))
        assertEquals(5L, failRows(s, me.userId))
        val before = totpRow(s, me.userId)
        // The fifth armed the lock: a RIGHT code is refused on every route that takes one, before it is looked at.
        for ((path, body) in listOf(DISABLE to disable(me, code(a, clock)), SETUP to rotate(me, code(a, clock)), CONFIRM to confirm(code(b, clock)), DELETE to delete(me, code(a, clock)))) {
            val r = c.call(post, path, body, me.token)
            assertEquals(429, r.status.value, "$path: ${r.bodyAsText()}"); assertEquals("rate_limited", r.errorCode(), path)
            // The codes' lock names its real wait: one second after the fifth wrong code, the clock standing still.
            assertEquals("1", r.headers["Retry-After"], path)
        }
        // Nothing was looked at: no row, no step consumed, the factor and the pending secret as they were, the account there.
        assertEquals(5L, failRows(s, me.userId))
        assertEquals(before, totpRow(s, me.userId))
        assertEquals(a, before.first); assertEquals(b, before.second)
        // The curve is the sign-in's: one millisecond before each lock lapses a code is still refused, then the next
        // wrong one is looked at and refused as wrong. The refusals in between are not counted and extend nothing.
        val routes = listOf(SETUP, CONFIRM, DISABLE)
        for (n in 6..15) {
            clock.advance(lock(n - 1) - 1)
            s.limiter.clear()
            assertEquals("rate_limited", c.call(post, DISABLE, disable(me, wrong(a, clock)), me.token).errorCode(), "just before failure $n")
            clock.advance(1)
            s.limiter.clear()
            val path = routes[n % 3]
            val body = when (path) { SETUP -> rotate(me, wrong(a, clock)); CONFIRM -> confirm(wrong(b, clock)); else -> disable(me, wrong(a, clock)) }
            assertEquals("bad_totp_code", c.call(post, path, body, me.token).errorCode(), "failure $n on $path")
        }
        assertEquals(15L, failRows(s, me.userId))
        // The sixteenth, at once, is refused; so is the right code fourteen minutes on: the lock holds 900 s.
        s.limiter.clear()
        assertEquals("rate_limited", c.call(post, DISABLE, disable(me, wrong(a, clock)), me.token).errorCode())
        clock.advance(14 * 60_000L)
        s.limiter.clear()
        assertEquals(429, c.call(post, DISABLE, disable(me, code(a, clock)), me.token).status.value)
        assertEquals(a, totpRow(s, me.userId).first)
        // When it lapses, the right code is served.
        clock.advance(60_000)
        s.limiter.clear()
        val off = c.call(post, DISABLE, disable(me, code(a, clock)), me.token)
        assertEquals(200, off.status.value, off.bodyAsText())
        assertEquals(null, totpRow(s, me.userId).first)
        assertEquals(15L, failRows(s, me.userId))
    }

    @Test
    fun aRightCodeAfterASlip_isServed_andClearsTheCount() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val a = enrol(c, clock, me)
        // One slip, then the right code: served.
        assertEquals("bad_totp_code", c.call(post, DISABLE, disable(me, wrong(a, clock)), me.token).errorCode())
        val rot = c.call(post, SETUP, rotate(me, code(a, clock)), me.token)
        assertEquals(200, rot.status.value, rot.bodyAsText())
        val b = WireJson.json.decodeFromString(TotpSetupResponse.serializer(), rot.bodyAsText()).secretBase32
        clock.advance(30_000)
        // Four slips over four routes (the deletion's code among them), then the right code: served, and it clears the
        // four, so one more slip is an ordinary slip and not the fifth: the right code after it is served too.
        s.limiter.clear()
        assertEquals("bad_totp_code", c.call(post, SETUP, rotate(me, wrong(a, clock)), me.token).errorCode())
        assertEquals("bad_totp_code", c.call(post, CONFIRM, confirm(wrong(b, clock)), me.token).errorCode())
        assertEquals("bad_totp_code", c.call(post, DELETE, delete(me, wrong(a, clock)), me.token).errorCode())
        assertEquals("bad_totp_code", c.call(post, DISABLE, disable(me, wrong(a, clock)), me.token).errorCode())
        assertEquals(200, c.call(post, CONFIRM, confirm(code(b, clock)), me.token).status.value)
        assertEquals(0L, s.codeLock(me))
        assertEquals("bad_totp_code", c.call(post, DISABLE, disable(me, wrong(b, clock)), me.token).errorCode())
        clock.advance(30_000)
        s.limiter.clear()
        val off = c.call(post, DISABLE, disable(me, code(b, clock)), me.token)
        assertEquals(200, off.status.value, off.bodyAsText())
        assertEquals(6L, failRows(s, me.userId))
    }

    @Test
    fun aSessionTriesAtMost109CodesADay_andThePerMinuteBucketStays() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val a = enrol(c, clock, me)
        // A session in the wrong hands sends a wrong code the moment each lock lapses, for a day, alternating the
        // two routes that check the current code. The routes' own buckets are left as they are: they never bind.
        var tokens = TokenPair(me.session!!.accessToken, me.session!!.refreshToken)
        var refreshedAt = clock.now()
        val start = clock.now()
        var tried = 0
        while (true) {
            val until = s.codeLock(me)
            if (until > clock.now()) {
                if (tried % 10 == 0) {
                    val early = c.call(post, DISABLE, disable(me, wrong(a, clock)), tokens.accessToken)
                    assertEquals("rate_limited", early.errorCode(), "while locked, after $tried")
                }
                clock.advance(until - clock.now())
            }
            if (clock.now() - start > DAY || tried > 1_000) break
            if (clock.now() - refreshedAt > 30 * 60_000L) {
                val r = c.call(post, "/api/v1/auth/refresh", """{"refreshToken":"${tokens.refreshToken}"}""")
                assertEquals(200, r.status.value, r.bodyAsText())
                tokens = WireJson.json.decodeFromString(TokenPair.serializer(), r.bodyAsText())
                refreshedAt = clock.now()
            }
            val path = if (tried % 2 == 0) DISABLE else SETUP
            val body = if (path == DISABLE) disable(me, wrong(a, clock)) else rotate(me, wrong(a, clock))
            val r = c.call(post, path, body, tokens.accessToken)
            assertEquals("bad_totp_code", r.errorCode(), "attempt ${tried + 1} at +${(clock.now() - start) / 1000} s on $path")
            tried++
        }
        // 5 at once, 10 more as the locks of 1 s to 512 s lapse (the 15th at 1023 s), then one every 900 s: 15 + 94.
        assertEquals(109, tried)
        assertEquals(109L, failRows(s, me.userId))
        assertEquals(a, totpRow(s, me.userId).first)
        // The per-minute bucket stays: on an account without two-step sign-in, whose codes are never looked at, the
        // sixth call in a minute is still refused.
        val other = Flow.member(c, s, "other@example.com")
        repeat(5) { assertEquals("totp_not_enrolled", c.call(post, DISABLE, disable(other, "123456"), other.token).errorCode()) }
        val sixth = c.call(post, DISABLE, disable(other, "123456"), other.token)
        assertEquals(429, sixth.status.value); assertEquals("rate_limited", sixth.errorCode())
        assertEquals(0L, s.codeLock(other))
    }

    @Test
    fun wrongCodesNeverArmTheSignInsOrTheProofsBackoff_andTheyNeverArmThisOne() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val link = { key: String -> """{"enabled":false,"currentAuthKey":"$key"}""" }

        // One way: fifteen wrong codes on the session take the codes' lock to its cap ...
        val me = Flow.member(c, s, "me@example.com")
        val a = enrol(c, clock, me)
        walkToCap(s, clock, "bad_totp_code") { n ->
            if (n % 2 == 0) c.call(post, DISABLE, disable(me, wrong(a, clock)), me.token).errorCode()
            else c.call(post, SETUP, rotate(me, wrong(a, clock)), me.token).errorCode()
        }
        assertTrue(s.codeLock(me) > clock.now() + 14 * 60_000L)
        // ... and neither other back-off moved: a right proof is served, and so is a sign-in with the password and code.
        assertEquals(0L, s.proofLock(me)); assertEquals(0L, s.loginBackoff.lockedUntil(me.email))
        s.limiter.clear()
        assertEquals(200, c.call(put, "/api/v1/account/require-link", link(me.authKey), me.token).status.value)
        s.limiter.clear()
        val signIn = c.call(post, "/api/v1/auth/login", me.loginBody(totp = code(a, clock)))
        assertEquals(200, signIn.status.value, signIn.bodyAsText())
        // A wrong code at sign-in is the sign-in's own, answered as one; and none of that lifted the session's lock.
        s.limiter.clear()
        assertEquals("invalid_credentials", c.call(post, "/api/v1/auth/login", me.loginBody(totp = wrong(a, clock))).errorCode())
        clock.advance(30_000)
        s.limiter.clear()
        assertEquals(429, c.call(post, DISABLE, disable(me, code(a, clock)), me.token).status.value)

        // The other way: fifteen sign-ins with the right password and a wrong code, and fifteen wrong proofs, take both
        // of those back-offs to their caps ...
        val you = Flow.member(c, s, "you@example.com")
        val y = enrol(c, clock, you)
        // (A rotation first, so that a code can be checked by the confirm route, which needs no proof.)
        val pending = c.call(post, SETUP, rotate(you, code(y, clock)), you.token)
        assertEquals(200, pending.status.value, pending.bodyAsText())
        val z = WireJson.json.decodeFromString(TotpSetupResponse.serializer(), pending.bodyAsText()).secretBase32
        clock.advance(30_000)
        for (n in 1..15) {
            s.limiter.clear()
            assertEquals("invalid_credentials", c.call(post, "/api/v1/auth/login", you.loginBody(totp = wrong(y, clock))).errorCode(), "sign-in $n")
            assertEquals("reauth_failed", c.call(put, "/api/v1/account/require-link", link(b32()), you.token).errorCode(), "proof $n")
            if (n in 5..14) clock.advance(lock(n))
        }
        assertTrue(s.loginBackoff.lockedUntil(you.email) > clock.now()); assertTrue(s.proofLock(you) > clock.now())
        // ... and never touched the codes' back-off: one slip is a plain slip, and the right code is served.
        assertEquals(0L, s.codeLock(you))
        s.limiter.clear()
        assertEquals("bad_totp_code", c.call(post, CONFIRM, confirm(wrong(z, clock)), you.token).errorCode())
        assertEquals(200, c.call(post, CONFIRM, confirm(code(z, clock)), you.token).status.value)
        assertEquals(z, totpRow(s, you.userId).first)
        // The right code lifted neither of theirs (and the disable and delete routes, which check the proof before the
        // code, stop at the proof; the delete's code is never looked at, so the codes' back-off is still untouched).
        s.limiter.clear()
        assertEquals(429, c.call(post, DISABLE, disable(you, code(z, clock)), you.token).status.value)
        s.limiter.clear()
        assertEquals(429, c.call(post, DELETE, delete(you, wrong(z, clock)), you.token).status.value)
        assertEquals(0L, s.codeLock(you))
        assertEquals(1L, failRows(s, you.userId))
        assertEquals(z, totpRow(s, you.userId).first)
        s.limiter.clear()
        assertEquals(429, c.call(put, "/api/v1/account/require-link", link(you.authKey), you.token).status.value)
        s.limiter.clear()
        assertEquals(429, c.call(post, "/api/v1/auth/login", you.loginBody(totp = code(y, clock))).status.value)
    }
}
