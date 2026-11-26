package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.TotpSetupResponse
import io.silencelen.andvari.core.model.wire.WireJson
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The wait a refusal by a back-off names (spec 03 §8; decided on 2026-11-17). The back-offs of password proofs and of
 * two-step codes on routes that need a session are kept per device, so the session that is refused learns only how long
 * its own device must wait, which it could count itself: their `Retry-After` is the real remaining wait. Before, it was
 * always 60 seconds while the real wait could be fifteen minutes, so a person was told "try again in a minute" up to
 * fifteen times. The sign-in's back-off and the device-link pickup's answer a caller who has proven nothing about an
 * address anyone can type, and keep their fixed 60 seconds: the real wait would tell that caller how many wrong tries
 * were made for that address lately.
 */
class BackoffWaitsTest {
    private val post = HttpMethod.Post
    private val put = HttpMethod.Put

    private companion object {
        const val SETUP = "/api/v1/account/totp/setup"
        const val CONFIRM = "/api/v1/account/totp/confirm"
        const val DISABLE = "/api/v1/account/totp/disable"
        const val LINK = "/api/v1/account/require-link"
    }

    /** The lock that failure [n] (n ≥ 5) arms: the sign-in back-off's curve. */
    private fun lock(n: Int) = (1000L shl (n - 5)).coerceAtMost(900_000)

    private fun wrongKey() = Bytes.toB64(TestKit.crypto.randomBytes(32))

    private fun code(secret: String, clock: Clock) = Flow.totp(secret, clock.now())

    private fun wrong(secret: String, clock: Clock): String {
        val near = (-1..1).map { Flow.totp(secret, clock.now() + it * 30_000L) }.toSet()
        return (0..9).map { "$it".repeat(6) }.first { it !in near }
    }

    private fun link(key: String) = """{"enabled":false,"currentAuthKey":"$key"}"""
    private fun withCode(key: String, code: String) = """{"code":"$code","currentAuthKey":"$key"}"""

    private suspend fun enrol(c: HttpClient, clock: MutableClock, me: Me): String {
        val setup = c.call(post, SETUP, """{"currentAuthKey":"${me.authKey}"}""", me.token)
        assertEquals(200, setup.status.value, setup.bodyAsText())
        val secret = WireJson.json.decodeFromString(TotpSetupResponse.serializer(), setup.bodyAsText()).secretBase32
        assertEquals(200, c.call(post, CONFIRM, """{"code":"${code(secret, clock)}"}""", me.token).status.value)
        clock.advance(30_000)
        return secret
    }

    private suspend fun refused(r: HttpResponse, seconds: Long, what: String) {
        assertEquals(429, r.status.value, "$what: ${r.bodyAsText()}")
        assertEquals("rate_limited", r.errorCode(), what)
        assertEquals("$seconds", r.headers["Retry-After"], what)
    }

    @Test
    fun aSessionIsToldTheRealWaitOfItsDevicesProofBackOff_alongTheWholeCurve_andAsItCountsDown() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        // Fifteen wrong proofs, each sent as the previous lock lapses; after each one from the fifth on, the right proof
        // sent at once is refused, and told the lock that failure armed: 1, 2, 4 ... 512 seconds, then the cap of 900.
        for (n in 1..15) {
            s.limiter.clear()
            assertEquals("reauth_failed", c.call(put, LINK, link(wrongKey()), me.token).errorCode(), "failure $n")
            if (n >= 5) {
                s.limiter.clear()
                refused(c.call(put, LINK, link(me.authKey), me.token), lock(n) / 1000, "after failure $n")
                if (n < 15) clock.advance(lock(n))
            }
        }
        // The wait counts down with the clock, in whole seconds rounded up.
        clock.advance(14 * 60_000L)
        s.limiter.clear()
        refused(c.call(put, LINK, link(me.authKey), me.token), 60, "14 minutes on")
        clock.advance(59_500)
        s.limiter.clear()
        refused(c.call(put, LINK, link(me.authKey), me.token), 1, "half a second before it lapses")
        clock.advance(500)
        s.limiter.clear()
        assertEquals(200, c.call(put, LINK, link(me.authKey), me.token).status.value)
    }

    @Test
    fun aSessionIsToldTheRealWaitOfItsDevicesCodeBackOff() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val secret = enrol(c, clock, me)
        // Seven wrong codes beside the right proof, each sent as the previous lock lapses; from the fifth on, the right
        // code sent at once is refused and told the real lock (1, 2, 4 seconds).
        for (n in 1..7) {
            s.limiter.clear()
            assertEquals("bad_totp_code", c.call(post, DISABLE, withCode(me.authKey, wrong(secret, clock)), me.token).errorCode(), "failure $n")
            if (n >= 5) {
                s.limiter.clear()
                refused(c.call(post, DISABLE, withCode(me.authKey, code(secret, clock)), me.token), lock(n) / 1000, "after failure $n")
                if (n < 7) clock.advance(lock(n))
            }
        }
        clock.advance(3_250)
        s.limiter.clear()
        refused(c.call(post, DISABLE, withCode(me.authKey, code(secret, clock)), me.token), 1, "three and a quarter seconds on")
        clock.advance(750)
        s.limiter.clear()
        val served = c.call(post, DISABLE, withCode(me.authKey, code(secret, clock)), me.token)
        assertEquals(200, served.status.value, served.bodyAsText())
    }

    /** A device-link pickup waiting for its pickup: created by [e], claimed, revealed and approved. Returns (linkId, proof). */
    private suspend fun approvedLink(c: HttpClient, clock: MutableClock, e: Me): Pair<String, String> {
        val linkId = Bytes.toB64(TestKit.crypto.randomBytes(16))
        assertEquals(201, c.call(post, "/api/v1/device-links", """{"linkId":"$linkId","expiresAt":${clock.now() + 3_600_000}}""", e.token).status.value)
        val proof = b32()
        val name = Grammar.nameOf("Pixel 9")!!
        val claim = """{"nPub":"${b32()}","name":"$name","platform":"android","commitN":"${"c".repeat(64)}","mac":"${b32()}"}"""
        assertEquals(200, c.call(post, "/api/v1/device-links/$linkId/claim", claim).status.value)
        assertEquals(200, c.call(post, "/api/v1/device-links/$linkId/nonce", """{"nonceE":"${b32()}","proofHash":"${sha256Hex(proof)}"}""", e.token).status.value)
        assertEquals(200, c.call(post, "/api/v1/device-links/$linkId/reveal", """{"nonceN":"${b32()}","proof":"$proof"}""").status.value)
        assertEquals(200, c.call(post, "/api/v1/device-links/$linkId/approve", """{"outer":"QUFBQUFB","inner":"SU5ORVJJ","approveMac":"${b32()}"}""", e.token).status.value)
        return linkId to proof
    }

    @Test
    fun theSignInAndTheDeviceLinkPickup_keepTheirFixedSixtySeconds_whateverTheRealLock() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val e = Flow.member(c, s, "e@example.com")
        val (linkId, proof) = approvedLink(c, clock, e)
        val pickup = """{"proof":"$proof","authKey":"${e.authKey}","device":{"deviceSecret":"${b32()}"}}"""
        // Five wrong sign-ins arm a lock of one second; the answers still say 60.
        repeat(5) {
            s.limiter.clear()
            assertEquals("invalid_credentials", c.call(post, "/api/v1/auth/login", e.loginBody(authKey = wrongKey())).errorCode())
        }
        assertEquals(clock.now() + 1_000, s.loginBackoff.lockedUntil(e.email))
        s.limiter.clear()
        refused(c.call(post, "/api/v1/auth/login", e.loginBody()), 60, "sign-in, the lock 1 s")
        s.limiter.clear()
        refused(c.call(post, "/api/v1/device-links/$linkId/pickup", pickup), 60, "pickup, the lock 1 s")
        // Taken to the cap of fifteen minutes, they still say 60.
        repeat(10) { s.loginBackoff.fail(e.email) }
        assertEquals(clock.now() + 900_000, s.loginBackoff.lockedUntil(e.email))
        s.limiter.clear()
        refused(c.call(post, "/api/v1/auth/login", e.loginBody()), 60, "sign-in, the lock 15 min")
        s.limiter.clear()
        refused(c.call(post, "/api/v1/device-links/$linkId/pickup", pickup), 60, "pickup, the lock 15 min")
    }
}
