package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.TokenPair
import io.silencelen.andvari.core.model.wire.TotpSetupResponse
import io.silencelen.andvari.core.model.wire.WireJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The back-offs of password proofs and of two-step codes sent on a session are kept per device (spec 03 §8): the key
 * is the session's device row, `devices.deviceId`, which every session of that device carries and a refresh keeps.
 * Per account, a session without the password could hold the account's counter at its cap with about a hundred
 * requests a day, and the owner was then refused every action that asks for the password again, on every device and
 * after any fresh sign-in. Per device, the held session still gets its own day's worth of guesses (109 proofs and 109
 * codes) and takes nothing from the account's other devices. A device cannot be made without the password (and the
 * code, where two-step sign-in is on), and a removed device takes its counters with it.
 */
class DeviceCountersTest {
    private val post = HttpMethod.Post
    private val put = HttpMethod.Put

    private companion object {
        const val SETUP = "/api/v1/account/totp/setup"
        const val CONFIRM = "/api/v1/account/totp/confirm"
        const val DISABLE = "/api/v1/account/totp/disable"
        const val DELETE = "/api/v1/account/delete"
        const val LINK = "/api/v1/account/require-link"
        const val PASSWORD = "/api/v1/account/password"
        const val DAY = 86_400_000L
    }

    /** One session of an account: its device and its current tokens. */
    private class Held(val deviceId: String, var tokens: TokenPair) {
        val token: String get() = tokens.accessToken
    }

    private fun held(me: Me) = Held(me.deviceId, TokenPair(me.session!!.accessToken, me.session!!.refreshToken))

    /** The lock that failure [n] (n ≥ 5) arms: the sign-in back-off's curve. */
    private fun lock(n: Int) = (1000L shl (n - 5)).coerceAtMost(900_000)

    private fun proofLock(s: Services, h: Held) = s.proofBackoff.lockedUntil(s.deviceCounterKey(h.deviceId))
    private fun codeLock(s: Services, h: Held) = s.codeBackoff.lockedUntil(s.deviceCounterKey(h.deviceId))

    private fun wrongKey() = Bytes.toB64(TestKit.crypto.randomBytes(32))

    private fun code(secret: String, clock: Clock) = Flow.totp(secret, clock.now())

    /** A six-digit code that matches none of the three steps the server accepts at [clock]'s time. */
    private fun wrong(secret: String, clock: Clock): String {
        val near = (-1..1).map { Flow.totp(secret, clock.now() + it * 30_000L) }.toSet()
        return (0..9).map { "$it".repeat(6) }.first { it !in near }
    }

    private fun link(key: String) = """{"enabled":false,"currentAuthKey":"$key"}"""
    private fun withCode(key: String, code: String) = """{"code":"$code","currentAuthKey":"$key"}"""
    private fun delete(me: Me, key: String, code: String?) =
        """{"confirmEmail":"${me.email}"${code?.let { ",\"totp\":\"$it\"" } ?: ""},"currentAuthKey":"$key","leaves":[]}"""
    private fun passwordChange(current: String, newKey: String) =
        """{"currentAuthKey":"$current","newAuthKey":"$newKey","newKdfSalt":"${Bytes.toB64(ByteArray(16) { 5 })}",""" +
            """"newKdfParams":{"v":1,"alg":"argon2id13","ops":1,"memBytes":8388608},"newWrappedUvk":"AAAA"}"""

    /** Two-step sign-in on for [me] from its registration's session (always with the proof); returns the secret. */
    private suspend fun enrol(c: HttpClient, clock: MutableClock, me: Me): String {
        val setup = c.call(post, SETUP, """{"currentAuthKey":"${me.authKey}"}""", me.token)
        assertEquals(200, setup.status.value, setup.bodyAsText())
        val secret = WireJson.json.decodeFromString(TotpSetupResponse.serializer(), setup.bodyAsText()).secretBase32
        assertEquals(200, c.call(post, CONFIRM, """{"code":"${code(secret, clock)}"}""", me.token).status.value)
        clock.advance(30_000)
        return secret
    }

    /** The owner signs in on a new device with the password (and [totp]): a second session of the same account. */
    private suspend fun signInNewDevice(c: HttpClient, me: Me, totp: String?): Held {
        val r = c.call(post, "/api/v1/auth/login", me.loginBody(secret = wrongKey(), totp = totp))
        assertEquals(200, r.status.value, r.bodyAsText())
        val sr = WireJson.json.decodeFromString(SessionResponse.serializer(), r.bodyAsText())
        return Held(sr.deviceId, TokenPair(sr.accessToken, sr.refreshToken))
    }

    private suspend fun refresh(c: HttpClient, h: Held) {
        val r = c.call(post, "/api/v1/auth/refresh", """{"refreshToken":"${h.tokens.refreshToken}"}""")
        assertEquals(200, r.status.value, r.bodyAsText())
        h.tokens = WireJson.json.decodeFromString(TokenPair.serializer(), r.bodyAsText())
    }

    /** Fifteen failures, each sent as the previous lock lapses (buckets emptied first), which take a back-off to its cap. */
    private suspend fun walkToCap(s: Services, clock: MutableClock, expect: String, send: suspend (Int) -> String?) {
        for (n in 1..15) {
            s.limiter.clear()
            assertEquals(expect, send(n), "failure $n")
            if (n in 5..14) clock.advance(lock(n))
        }
    }

    private fun proofRows(s: Services, userId: String) = s.db.read {
        it.count("SELECT COUNT(*) FROM audit WHERE type IN ('reauth_fail','password_change_fail','account_delete_reauth_fail','totp_setup_reauth_fail') AND userId=?", userId)
    }

    @Test
    fun oneSessionAtItsProofCap_neverRefusesAnotherDevicesRightProof_onAnyRouteThatAsksForIt() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val secret = enrol(c, clock, me)
        // The registration's session is the one in the wrong hands: it has no password, and walks its proofs to the cap.
        val thief = held(me)
        walkToCap(s, clock, "reauth_failed") { c.call(put, LINK, link(wrongKey()), thief.token).errorCode() }
        assertTrue(proofLock(s, thief) > clock.now() + 14 * 60_000L)
        // A refreshed token is the same device: still capped, and the right proof is refused before it is looked at.
        refresh(c, thief)
        s.limiter.clear()
        val capped = c.call(put, LINK, link(me.authKey), thief.token)
        // The wait named is the device's real one: the cap of fifteen minutes (spec 03 §8, since 2026-11-17).
        assertEquals(429, capped.status.value, capped.bodyAsText()); assertEquals("900", capped.headers["Retry-After"])
        // The other two back-offs did not move.
        assertEquals(0L, codeLock(s, thief)); assertEquals(0L, s.loginBackoff.lockedUntil(me.email))

        // The owner signs in on another device, with the password and the code: that device's counter is clean ...
        val owner = signInNewDevice(c, me, code(secret, clock))
        assertTrue(owner.deviceId != thief.deviceId)
        assertEquals(0L, proofLock(s, owner))
        // ... and every route the owner needs is served its right proof at once, while the thief stays capped.
        clock.advance(30_000)
        s.limiter.clear()
        val off = c.call(post, DISABLE, withCode(me.authKey, code(secret, clock)), owner.token)
        assertEquals(200, off.status.value, "turning two-step sign-in off: ${off.bodyAsText()}")
        s.limiter.clear()
        assertEquals(429, c.call(put, LINK, link(me.authKey), thief.token).status.value)
        val newKey = wrongKey()
        s.limiter.clear()
        val pw = c.call(put, PASSWORD, passwordChange(me.authKey, newKey), owner.token)
        assertEquals(200, pw.status.value, "changing the password: ${pw.bodyAsText()}")
        // The change revoked the thief's sessions; its device's counter is still there until the device is removed.
        assertTrue(proofLock(s, thief) > clock.now())
        s.limiter.clear()
        val revoke = c.call(post, "/api/v1/account/devices/${thief.deviceId}/revoke", """{"currentAuthKey":"$newKey"}""", owner.token)
        assertEquals(200, revoke.status.value, "removing the first device: ${revoke.bodyAsText()}")
        assertEquals(0L, proofLock(s, thief))
        s.limiter.clear()
        val gone = c.call(post, DELETE, delete(me, newKey, null), owner.token)
        assertEquals(200, gone.status.value, "deleting the account: ${gone.bodyAsText()}")
    }

    @Test
    fun oneSessionAtItsCodeCap_neverRefusesAnotherDevicesRightCode_onAnyRouteThatTakesOne() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val a = enrol(c, clock, me)
        // A session that has the password but not the code (the safer case to test: a thief without the password is
        // stopped at the proof and never reaches a code) walks its codes to the cap over the rotation and the disable.
        val thief = held(me)
        walkToCap(s, clock, "bad_totp_code") { n ->
            c.call(post, if (n % 2 == 0) DISABLE else SETUP, withCode(me.authKey, wrong(a, clock)), thief.token).errorCode()
        }
        assertTrue(codeLock(s, thief) > clock.now() + 14 * 60_000L)
        assertEquals(0L, proofLock(s, thief)); assertEquals(0L, s.loginBackoff.lockedUntil(me.email))
        refresh(c, thief)
        s.limiter.clear()
        assertEquals(429, c.call(post, DISABLE, withCode(me.authKey, code(a, clock)), thief.token).status.value)

        val owner = signInNewDevice(c, me, code(a, clock))
        assertEquals(0L, codeLock(s, owner))
        // Rotation, confirm, disable, a fresh setup's confirm, and the deletion's code: each served at once.
        clock.advance(30_000); s.limiter.clear()
        val rot = c.call(post, SETUP, withCode(me.authKey, code(a, clock)), owner.token)
        assertEquals(200, rot.status.value, "rotation: ${rot.bodyAsText()}")
        val b = WireJson.json.decodeFromString(TotpSetupResponse.serializer(), rot.bodyAsText()).secretBase32
        clock.advance(30_000); s.limiter.clear()
        assertEquals(200, c.call(post, CONFIRM, """{"code":"${code(b, clock)}"}""", owner.token).status.value, "confirm")
        // The thief is still capped (its refresh kept its device), whatever code it sends.
        clock.advance(30_000); s.limiter.clear()
        assertEquals(429, c.call(post, DISABLE, withCode(me.authKey, code(b, clock)), thief.token).status.value)
        s.limiter.clear()
        assertEquals(200, c.call(post, DISABLE, withCode(me.authKey, code(b, clock)), owner.token).status.value, "disable")
        s.limiter.clear()
        val again = c.call(post, SETUP, """{"currentAuthKey":"${me.authKey}"}""", owner.token)
        assertEquals(200, again.status.value, again.bodyAsText())
        val d = WireJson.json.decodeFromString(TotpSetupResponse.serializer(), again.bodyAsText()).secretBase32
        clock.advance(30_000); s.limiter.clear()
        assertEquals(200, c.call(post, CONFIRM, """{"code":"${code(d, clock)}"}""", owner.token).status.value, "confirm after setup")
        clock.advance(30_000); s.limiter.clear()
        assertEquals(429, c.call(post, DELETE, delete(me, me.authKey, code(d, clock)), thief.token).status.value)
        s.limiter.clear()
        val gone = c.call(post, DELETE, delete(me, me.authKey, code(d, clock)), owner.token)
        assertEquals(200, gone.status.value, "deleting the account: ${gone.bodyAsText()}")
        assertTrue(codeLock(s, thief) == 0L, "the deletion removed every device, and their counters with them")
    }

    @Test
    fun oneSessionStillTries109ProofsADay_acrossItsRefreshes() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val thief = held(me)
        var refreshedAt = clock.now()
        val start = clock.now()
        var tried = 0
        while (true) {
            val until = proofLock(s, thief)
            if (until > clock.now()) {
                if (tried % 10 == 0) {
                    s.limiter.clear()
                    assertEquals("rate_limited", c.call(put, LINK, link(wrongKey()), thief.token).errorCode(), "while locked, after $tried")
                }
                clock.advance(until - clock.now())
            }
            if (clock.now() - start > DAY || tried > 1_000) break
            if (clock.now() - refreshedAt > 30 * 60_000L) { refresh(c, thief); refreshedAt = clock.now() }
            s.limiter.clear()
            assertEquals("reauth_failed", c.call(put, LINK, link(wrongKey()), thief.token).errorCode(), "attempt ${tried + 1}")
            tried++
        }
        // 5 at once, 10 more as the locks of 1 s to 512 s lapse (the 15th at 1023 s), then one every 900 s: 15 + 94,
        // the same as the codes' (TotpCodeBackoffTest) and as before the counter moved from the account to the device.
        assertEquals(109, tried)
        assertEquals(109L, proofRows(s, me.userId))
    }

    @Test
    fun aRemovedDeviceTakesItsCountersWithIt_andANewDeviceStartsClean() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val a = enrol(c, clock, me)
        val first = held(me)
        // The first device at the cap of both counters (the codes first, while its proofs are still right).
        walkToCap(s, clock, "bad_totp_code") { c.call(post, DISABLE, withCode(me.authKey, wrong(a, clock)), first.token).errorCode() }
        walkToCap(s, clock, "reauth_failed") { c.call(put, LINK, link(wrongKey()), first.token).errorCode() }
        // (The codes' lock has lapsed during the proofs' walk; its count is still held, so the next code would lock again.)
        assertTrue(codeLock(s, first) > 0L); assertTrue(proofLock(s, first) > clock.now())
        // A second device at both caps too.
        val second = signInNewDevice(c, me, code(a, clock))
        clock.advance(30_000)
        walkToCap(s, clock, "bad_totp_code") { c.call(post, DISABLE, withCode(me.authKey, wrong(a, clock)), second.token).errorCode() }
        walkToCap(s, clock, "reauth_failed") { c.call(put, LINK, link(wrongKey()), second.token).errorCode() }
        assertTrue(codeLock(s, second) > 0L); assertTrue(proofLock(s, second) > clock.now())

        // A third device, signed in with the password and the code, starts clean: a slip is a plain slip.
        clock.advance(30_000)
        val third = signInNewDevice(c, me, code(a, clock))
        assertEquals(0L, proofLock(s, third)); assertEquals(0L, codeLock(s, third))
        s.limiter.clear()
        assertEquals("reauth_failed", c.call(put, LINK, link(wrongKey()), third.token).errorCode())
        s.limiter.clear()
        assertEquals(200, c.call(put, LINK, link(me.authKey), third.token).status.value)

        // The owner removes the first device, the operator the second: each one's counters go with it.
        s.limiter.clear()
        assertEquals(200, c.call(post, "/api/v1/account/devices/${first.deviceId}/revoke", """{"currentAuthKey":"${me.authKey}"}""", third.token).status.value)
        assertEquals(0L, proofLock(s, first)); assertEquals(0L, codeLock(s, first))
        assertTrue(proofLock(s, second) > clock.now())
        val operator = held(op).also { refresh(c, it) } // its access token aged out during the walks
        s.limiter.clear()
        val byOp = c.call(post, "/api/v1/admin/devices/${second.deviceId}/revoke", """{"currentAuthKey":"${op.authKey}"}""", operator.token)
        assertEquals(200, byOp.status.value, byOp.bodyAsText())
        assertEquals(0L, proofLock(s, second)); assertEquals(0L, codeLock(s, second))
    }
}
