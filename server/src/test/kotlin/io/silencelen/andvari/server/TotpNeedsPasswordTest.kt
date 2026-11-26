package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.TotpSetupResponse
import io.silencelen.andvari.core.model.wire.WireJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

/**
 * Turning two-step sign-in off, and replacing its secret on an account that already has one, need the password
 * (spec 03 §2): the request carries the password proof (`currentAuthKey`) beside the code, and the proof is checked
 * first, on the proofs' own back-off, before the code is looked at. Before, both took a signed-in session and the
 * current code alone, so a session in the wrong hands could remove the second factor by guessing the code. A wrong
 * or missing proof never tells whether the code was right: the answer is the same for a right code and a wrong one,
 * nothing is consumed and the code is not counted. Setting two-step sign-in up on an account that has none needs the
 * proof too, on every session (since 2026-11-17; before, a session a password login minted under ten minutes earlier
 * needed none).
 */
class TotpNeedsPasswordTest {
    private val post = HttpMethod.Post

    private companion object {
        const val SETUP = "/api/v1/account/totp/setup"
        const val CONFIRM = "/api/v1/account/totp/confirm"
        const val DISABLE = "/api/v1/account/totp/disable"
    }

    private fun code(secret: String, clock: Clock) = Flow.totp(secret, clock.now())

    private fun wrong(secret: String, clock: Clock): String {
        val near = (-1..1).map { Flow.totp(secret, clock.now() + it * 30_000L) }.toSet()
        return (0..9).map { "$it".repeat(6) }.first { it !in near }
    }

    private fun body(code: String?, key: String?) =
        listOfNotNull(code?.let { "\"code\":\"$it\"" }, key?.let { "\"currentAuthKey\":\"$it\"" }).joinToString(",", "{", "}")

    private suspend fun enrol(c: HttpClient, clock: MutableClock, me: Me): String {
        val setup = c.call(post, SETUP, body(null, me.authKey), me.token)
        assertEquals(200, setup.status.value, setup.bodyAsText())
        val secret = WireJson.json.decodeFromString(TotpSetupResponse.serializer(), setup.bodyAsText()).secretBase32
        assertEquals(200, c.call(post, CONFIRM, """{"code":"${code(secret, clock)}"}""", me.token).status.value)
        clock.advance(30_000)
        return secret
    }

    private fun totpRow(s: Services, userId: String) = s.db.read {
        it.queryOne("SELECT totpSecret,totpPendingSecret,totpLastStep FROM users WHERE userId=?", userId) { r -> Triple(r.getString(1), r.getString(2), r.getLong(3)) }!!
    }

    private fun rows(s: Services, type: String, userId: String) =
        s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type=? AND userId=?", type, userId) }

    /** Each route's answers without the right proof, a right code and a wrong one side by side; then with it. */
    private fun checkTheProofComesFirst(path: String, failKind: String) = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val a = enrol(c, clock, me)
        val before = totpRow(s, me.userId)
        // No proof, on the fresh session registration gave: the code is not looked at, whether right or wrong.
        for (k in listOf(null, b32())) {
            val right = c.call(post, path, body(code(a, clock), k), me.token)
            s.limiter.clear()
            val wrongOne = c.call(post, path, body(wrong(a, clock), k), me.token)
            s.limiter.clear()
            val expect = if (k == null) "reauth_required" else "reauth_failed"
            assertEquals(403, right.status.value, "$path, proof $k: ${right.bodyAsText()}"); assertEquals(expect, right.errorCode())
            assertEquals(right.status.value, wrongOne.status.value); assertEquals(right.bodyAsText(), wrongOne.bodyAsText(), "$path: the answer tells nothing of the code")
        }
        // Nothing happened: no step consumed, the secret and the pending slot as they were, no code counted or recorded,
        // and the two wrong proofs recorded under the route's proof kind.
        assertEquals(before, totpRow(s, me.userId))
        assertEquals(0L, rows(s, "totp_verify_fail", me.userId))
        assertEquals(0L, s.codeLock(me))
        assertEquals(2L, rows(s, failKind, me.userId))
        // With the right proof, a wrong code is refused as a wrong code (and a missing one: disable's body requires it),
        // and the right one is served.
        assertEquals("bad_totp_code", c.call(post, path, body(wrong(a, clock), me.authKey), me.token).errorCode())
        assertEquals(if (path == DISABLE) "bad_request" else "bad_totp_code", c.call(post, path, body(null, me.authKey), me.token).errorCode())
        assertEquals(if (path == DISABLE) 1L else 2L, rows(s, "totp_verify_fail", me.userId))
        s.limiter.clear()
        val ok = c.call(post, path, body(code(a, clock), me.authKey), me.token)
        assertEquals(200, ok.status.value, ok.bodyAsText())
        val after = totpRow(s, me.userId)
        if (path == DISABLE) {
            assertEquals(null, after.first)
            assertEquals("two_step_off", Flow.sink(s).last().first)
        } else {
            assertEquals(a, after.first)
            assertNotEquals(null, after.second)
            assertEquals(WireJson.json.decodeFromString(TotpSetupResponse.serializer(), ok.bodyAsText()).secretBase32, after.second)
        }
    }

    @Test
    fun turningTwoStepOff_needsThePassword_checkedBeforeTheCode() = checkTheProofComesFirst(DISABLE, "reauth_fail")

    @Test
    fun replacingAnEnrolledSecret_needsThePassword_checkedBeforeTheCode() = checkTheProofComesFirst(SETUP, "totp_setup_reauth_fail")

    @Test
    fun wrongProofsRunIntoTheProofsBackoff_andTheCodeIsNeverLookedAt() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val a = enrol(c, clock, me)
        val before = totpRow(s, me.userId)
        // Five wrong proofs, each with the RIGHT code, over the two routes: five reauth_failed and the proofs' lock.
        val answers = ArrayList<String>()
        for (n in 1..5) {
            s.limiter.clear()
            val r = c.call(post, if (n % 2 == 0) SETUP else DISABLE, body(code(a, clock), b32()), me.token)
            answers += "${r.status.value}:${r.errorCode()}"
        }
        assertEquals(List(5) { "403:reauth_failed" }, answers)
        // Now even the right proof with the right code is refused by the proofs' back-off, before either is looked at.
        s.limiter.clear()
        val locked = c.call(post, DISABLE, body(code(a, clock), me.authKey), me.token)
        // The lock's real wait: one second after the fifth wrong proof (spec 03 §8, since 2026-11-17).
        assertEquals(429, locked.status.value, locked.bodyAsText()); assertEquals("1", locked.headers["Retry-After"])
        assertEquals(before, totpRow(s, me.userId))
        assertEquals(0L, rows(s, "totp_verify_fail", me.userId))
        assertEquals(0L, s.codeLock(me))
        // When it lapses, the right proof and the right code turn two-step sign-in off.
        clock.advance(1_000)
        s.limiter.clear()
        assertEquals(200, c.call(post, DISABLE, body(code(a, clock), me.authKey), me.token).status.value)
        assertEquals(null, totpRow(s, me.userId).first)
    }

    @Test
    fun aFirstSetup_alwaysNeedsThePassword_evenOnASessionAMinuteOld_andTheProofComesFirst() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        // Turning off what is not on answers so before any proof is asked for.
        assertEquals("totp_not_enrolled", c.call(post, DISABLE, """{"code":"123456"}""", me.token).errorCode())
        // The registration's session is a minute old, and a sign-in on another device is a minute old too: neither
        // sets up a first factor without the password (until 2026-11-17 both could, for ten minutes).
        clock.advance(60_000)
        val signIn = c.call(post, "/api/v1/auth/login", me.loginBody(secret = b32()))
        assertEquals(200, signIn.status.value, signIn.bodyAsText())
        val other = WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.SessionResponse.serializer(), signIn.bodyAsText()).accessToken
        clock.advance(60_000)
        // Whatever else the request carries, no proof is reauth_required, and nothing is looked at or stored.
        val missing = listOf("{}", "", "not json", """{"code":"123456"}""", """{"currentAuthKey":null}""")
        for (tok in listOf(me.token, other)) for (b in missing) {
            s.limiter.clear()
            val r = c.call(post, SETUP, b, tok)
            assertEquals(403, r.status.value, "$b: ${r.bodyAsText()}"); assertEquals("reauth_required", r.errorCode(), b)
        }
        assertEquals(null, totpRow(s, me.userId).second)
        // A wrong proof is reauth_failed, audited, on the proofs' back-off of the session's device; a code beside it
        // changes nothing.
        for (b in listOf(body(null, b32()), body("123456", b32()))) {
            s.limiter.clear()
            assertEquals("reauth_failed", c.call(post, SETUP, b, me.token).errorCode(), b)
        }
        assertEquals(2L, rows(s, "totp_setup_reauth_fail", me.userId))
        assertEquals(null, totpRow(s, me.userId).second)
        repeat(3) { s.limiter.clear(); assertEquals("reauth_failed", c.call(post, SETUP, body(null, b32()), me.token).errorCode()) }
        s.limiter.clear()
        val locked = c.call(post, SETUP, body(null, me.authKey), me.token)
        assertEquals(429, locked.status.value, locked.bodyAsText()); assertEquals("1", locked.headers["Retry-After"])
        assertEquals(null, totpRow(s, me.userId).second)
        // Once the lock lapses the right proof sets it up; confirming the first secret takes the code alone.
        clock.advance(1_000)
        s.limiter.clear()
        val setup = c.call(post, SETUP, body(null, me.authKey), me.token)
        assertEquals(200, setup.status.value, setup.bodyAsText())
        val secret = WireJson.json.decodeFromString(TotpSetupResponse.serializer(), setup.bodyAsText()).secretBase32
        assertEquals(200, c.call(post, CONFIRM, """{"code":"${code(secret, clock)}"}""", me.token).status.value)
        assertEquals(secret, totpRow(s, me.userId).first)
    }
}
