package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.PreloginResponse
import io.silencelen.andvari.core.model.wire.TokenPair
import io.silencelen.andvari.core.model.wire.TotpSetupResponse
import io.silencelen.andvari.core.model.wire.WireJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** Index rows 9, 11–16 (spec 03 §2): prelogin, refresh, logout and the TOTP management routes. */
class RoutesSessionsTest {
    private val post = HttpMethod.Post
    private val get = HttpMethod.Get

    @Test
    fun row9_prelogin_realParamsForAnAccount_aStableFakeForAStranger() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val known = WireJson.json.decodeFromString(PreloginResponse.serializer(), c.call(post, "/api/v1/auth/prelogin", """{"email":"  ME@example.com "}""").bodyAsText())
        assertEquals(io.silencelen.andvari.core.crypto.Bytes.toB64(ByteArray(16) { 3 }), known.kdfSalt)
        assertEquals(TestKit.FAST_KDF, known.kdfParams)
        val f1 = c.call(post, "/api/v1/auth/prelogin", """{"email":"nobody@example.com"}""")
        assertEquals(200, f1.status.value)
        val fake = WireJson.json.decodeFromString(PreloginResponse.serializer(), f1.bodyAsText())
        assertEquals(fake, WireJson.json.decodeFromString(PreloginResponse.serializer(), c.call(post, "/api/v1/auth/prelogin", """{"email":"nobody@example.com"}""").bodyAsText()))
        assertEquals(s.policy.get().kdfParams, fake.kdfParams, "the CURRENT default params")
        assertNotEquals(fake.kdfSalt, WireJson.json.decodeFromString(PreloginResponse.serializer(), c.call(post, "/api/v1/auth/prelogin", """{"email":"other@example.com"}""").bodyAsText()).kdfSalt)
        // §0.3: an address with no emailNorm.
        assertEquals("invalid_email", c.call(post, "/api/v1/auth/prelogin", """{"email":"no at sign"}""").errorCode())
        assertTrue(me.session != null)
    }

    @Test
    fun row11_refresh_rotates_andEachRefusal() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        suspend fun refresh(tok: String) = c.call(post, "/api/v1/auth/refresh", """{"refreshToken":"$tok"}""")
        // Success: a new pair; the new access token works.
        val r1 = refresh(me.session!!.refreshToken)
        assertEquals(200, r1.status.value, r1.bodyAsText())
        val pair = WireJson.json.decodeFromString(TokenPair.serializer(), r1.bodyAsText())
        assertEquals(200, c.call(get, "/api/v1/account/keys", token = pair.accessToken).status.value)
        // invalid_refresh: unknown, empty, overlong.
        assertEquals("invalid_refresh", refresh(b32()).errorCode())
        assertEquals("invalid_refresh", refresh("").errorCode())
        assertEquals("invalid_refresh", refresh("x".repeat(129)).errorCode())
        // session_revoked: the device signed out.
        val other = c.login(me)
        assertEquals(200, c.call(post, "/api/v1/auth/logout", token = other.accessToken).status.value)
        val revoked = refresh(other.refreshToken)
        assertEquals(401, revoked.status.value); assertEquals("session_revoked", revoked.errorCode())
        // refresh_expired: past the 30-day refresh lifetime.
        val third = c.login(me)
        clock.advance(31 * Clock.DAY_MS)
        val expired = refresh(third.refreshToken)
        assertEquals(401, expired.status.value); assertEquals("refresh_expired", expired.errorCode())
        // refresh_reuse (also EventsSocketTest): the consumed token revokes the device.
        val reuse = refresh(me.session!!.refreshToken)
        assertEquals(401, reuse.status.value); assertEquals("refresh_reuse", reuse.errorCode())
        assertEquals("session_revoked", refresh(pair.refreshToken).errorCode())
    }

    /** A refresh token is refused AT `refreshExpiresAt` (expiry is exclusive), and the refused token is not consumed. */
    @Test
    fun refresh_refusedAtExactlyExpiresAt_withoutConsumingIt() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val tok = c.login(me).refreshToken
        val hash = ServerCrypto.hashToken(tok)
        val expiresAt = s.db.read { db -> db.queryOne("SELECT refreshExpiresAt FROM sessions WHERE refreshHash=?", hash) { it.getLong(1) }!! }
        clock.advance(expiresAt - clock.now())
        assertEquals(expiresAt, clock.now())
        val r = c.call(post, "/api/v1/auth/refresh", """{"refreshToken":"$tok"}""")
        assertEquals(401, r.status.value, r.bodyAsText()); assertEquals("refresh_expired", r.errorCode())
        assertEquals(0L, s.db.read { it.count("SELECT COUNT(*) FROM sessions WHERE refreshHash=? AND refreshConsumedAt IS NOT NULL", hash) })
        // Refused again the same way: an expired token is never mistaken for a reused one.
        assertEquals("refresh_expired", c.call(post, "/api/v1/auth/refresh", """{"refreshToken":"$tok"}""").errorCode())
    }

    @Test
    fun row12_logout_endsThisDeviceOnly() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val other = c.login(me)
        val r = c.call(post, "/api/v1/auth/logout", token = me.token)
        assertEquals(200, r.status.value); assertEquals("ok", r.bodyAsText())
        assertEquals("invalid_credentials", c.call(get, "/api/v1/account/keys", token = me.token).errorCode())
        assertEquals(200, c.call(get, "/api/v1/account/keys", token = other.accessToken).status.value)
        // The signed-out device stays known (§16.8): it logs back in under requireLink.
        s.db.tx { it.exec("UPDATE users SET requireLink=1 WHERE userId=?", me.userId) }
        assertEquals(200, c.call(post, "/api/v1/auth/login", me.loginBody(deviceId = me.deviceId)).status.value)
    }

    /**
     * Spec 03 §2 (decided 2026-11-16): a logout's reach is the device row. A second sign-in on the same row (two web tabs)
     * and the access token a refresh rotated away from (still valid until it expires) both end with it.
     */
    @Test
    fun row12_logout_endsEverySessionOfTheDeviceRow() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com", platform = "web")
        val sibling = WireJson.json.decodeFromString(
            io.silencelen.andvari.core.model.wire.SessionResponse.serializer(),
            // A web tab's sign-in: the browser's tabs each hold a pair on its one device row (a sign-in on any other kind
            // of row ends the row's earlier sessions).
            c.call(post, "/api/v1/auth/login", me.loginBody(deviceId = me.deviceId), client = "web/1.0.0").bodyAsText(),
        )
        assertEquals(me.deviceId, sibling.deviceId)
        val rotated =WireJson.json.decodeFromString(
            TokenPair.serializer(), c.call(post, "/api/v1/auth/refresh", """{"refreshToken":"${sibling.refreshToken}"}""").bodyAsText(),
        )
        assertEquals(200, c.call(get, "/api/v1/account/keys", token = sibling.accessToken).status.value, "a rotated-away access token lives until it expires")
        assertEquals(200, c.call(post, "/api/v1/auth/logout", token = rotated.accessToken).status.value)
        for (t in listOf(me.token, sibling.accessToken, rotated.accessToken)) {
            assertEquals("invalid_credentials", c.call(get, "/api/v1/account/keys", token = t).errorCode())
        }
    }

    /**
     * Index row 93 (spec 03 §2): `POST /auth/end-session` ends exactly the session its refresh token belongs to (a
     * per-tab lock), with no bearer. Its refresh token and the access token minted with it stop at once; a sibling
     * session on the same device row and another device are untouched; every answer is `200 ok`, whatever the token.
     * A consumed token is the reuse signal, as at refresh: the whole device row ends.
     */
    @Test
    fun row93_endSession_endsExactlyThatSession_andAConsumedTokenEndsTheDeviceRow() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com", platform = "web")
        val sibling = WireJson.json.decodeFromString(
            io.silencelen.andvari.core.model.wire.SessionResponse.serializer(),
            // A web tab's sign-in: the browser's tabs each hold a pair on its one device row (a sign-in on any other kind
            // of row ends the row's earlier sessions).
            c.call(post, "/api/v1/auth/login", me.loginBody(deviceId = me.deviceId), client = "web/1.0.0").bodyAsText(),
        )
        assertEquals(me.deviceId, sibling.deviceId)
        val otherDevice = c.login(me)
        assertNotEquals(me.deviceId, otherDevice.deviceId)
        suspend fun end(body: String) = c.call(post, "/api/v1/auth/end-session", body)
        suspend fun refresh(tok: String) = c.call(post, "/api/v1/auth/refresh", """{"refreshToken":"$tok"}""")
        suspend fun keys(t: String) = c.call(get, "/api/v1/account/keys", token = t)

        // The tab's own session: its refresh and its access token end, with no bearer sent.
        val r = end("""{"refreshToken":"${me.session!!.refreshToken}"}""")
        assertEquals(200, r.status.value, r.bodyAsText()); assertEquals("ok", r.bodyAsText())
        assertEquals("invalid_credentials", keys(me.token).errorCode())
        assertEquals("session_revoked", refresh(me.session!!.refreshToken).errorCode())
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='session_end'") })
        // Its sibling on the same device row and the other device are untouched; the device row is not signed out.
        assertEquals(200, keys(sibling.accessToken).status.value)
        assertEquals(200, keys(otherDevice.accessToken).status.value)
        assertEquals(null, s.db.read { db -> db.queryOne("SELECT signedOutAt FROM devices WHERE deviceId=?", me.deviceId) { it.longOrNull("signedOutAt") } })

        // The same answer for an already ended token, an unknown one, an empty one and an overlong one; nothing else ends.
        for (tok in listOf(me.session!!.refreshToken, b32(), "", "x".repeat(500))) {
            val again = end("""{"refreshToken":"$tok"}""")
            assertEquals(200, again.status.value); assertEquals("ok", again.bodyAsText())
        }
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='session_end'") })
        assertEquals(200, keys(sibling.accessToken).status.value)
        // Only a body that is not `{refreshToken}` is refused.
        assertEquals("bad_request", end("{}").errorCode())

        // A consumed token: the device row's every session ends (the reuse signal), the other device's does not.
        val rotated = WireJson.json.decodeFromString(TokenPair.serializer(), refresh(sibling.refreshToken).bodyAsText())
        assertEquals(200, keys(rotated.accessToken).status.value)
        val consumed = end("""{"refreshToken":"${sibling.refreshToken}"}""")
        assertEquals(200, consumed.status.value); assertEquals("ok", consumed.bodyAsText())
        for (t in listOf(sibling.accessToken, rotated.accessToken)) assertEquals("invalid_credentials", keys(t).errorCode())
        assertEquals("session_revoked", refresh(rotated.refreshToken).errorCode())
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='refresh_reuse'") })
        assertEquals(200, keys(otherDevice.accessToken).status.value)
    }

    /** Row 93's bucket: `end_session` 30/min per IP, drawn for a call whose token names no live session. */
    @Test
    fun row93_endSession_bucket30PerMinutePerIp() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        repeat(30) { assertEquals(400, client.call(post, "/api/v1/auth/end-session", "{}", ip = "10.9.9.9").status.value) }
        val r = client.call(post, "/api/v1/auth/end-session", """{"refreshToken":"x"}""", ip = "10.9.9.9")
        assertEquals(429, r.status.value); assertEquals("rate_limited", r.errorCode())
        assertEquals(200, client.call(post, "/api/v1/auth/end-session", """{"refreshToken":"x"}""", ip = "10.9.9.10").status.value)
    }

    /**
     * A neighbour cannot starve a lock. Thirty junk calls from one address spend its bucket, and
     * the lock's call from that same address is still served and ends its session; so is a consumed token's (the
     * reuse signal fires). Junk stays limited, and a token once ended is junk again.
     */
    @Test
    fun row93_endSession_aLiveTokenIsServed_afterJunkFromTheSameAddress() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val tab = c.login(me)
        val stolen = c.login(me)
        val ip = "10.7.7.7"
        suspend fun end(body: String) = c.call(post, "/api/v1/auth/end-session", body, ip = ip)
        repeat(15) { assertEquals(200, end("""{"refreshToken":"${b32()}"}""").status.value) }
        repeat(15) { assertEquals(400, end("""{"refresh":1}""").status.value) }
        assertEquals(429, end("""{"refreshToken":"${b32()}"}""").status.value)
        assertEquals(429, end("not json").status.value)
        // The lock's own call, from the same address: served, and the session is gone.
        val lock = end("""{"refreshToken":"${tab.refreshToken}"}""")
        assertEquals(200, lock.status.value, lock.bodyAsText()); assertEquals("ok", lock.bodyAsText())
        assertEquals("invalid_credentials", c.call(get, "/api/v1/account/keys", token = tab.accessToken).errorCode())
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='session_end'") })
        // Ended, the same token names no live session: it is junk now, and limited.
        assertEquals(429, end("""{"refreshToken":"${tab.refreshToken}"}""").status.value)
        // A token a thief's refresh consumed is still served: the device row ends and the reuse is audited.
        val rotated = WireJson.json.decodeFromString(TokenPair.serializer(), c.call(post, "/api/v1/auth/refresh", """{"refreshToken":"${stolen.refreshToken}"}""").bodyAsText())
        assertEquals(200, end("""{"refreshToken":"${stolen.refreshToken}"}""").status.value)
        assertEquals("invalid_credentials", c.call(get, "/api/v1/account/keys", token = rotated.accessToken).errorCode())
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='refresh_reuse'") })
    }

    @Test
    fun rows13to16_totpStatus_setupRotation_confirm_disable() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val t = me.token
        fun wrong(code: String) = if (code == "000000") "111111" else "000000"
        // Row 13.
        assertEquals("""{"enrolled":false,"pendingSetup":false}""", c.call(get, "/api/v1/account/totp", token = t).bodyAsText())
        // Row 15 and 16 before any setup.
        val noPending = c.call(post, "/api/v1/account/totp/confirm", """{"code":"123456"}""", t)
        assertEquals(400, noPending.status.value); assertEquals("no_pending_totp", noPending.errorCode())
        val notEnrolled = c.call(post, "/api/v1/account/totp/disable", """{"code":"123456"}""", t)
        assertEquals(400, notEnrolled.status.value); assertEquals("totp_not_enrolled", notEnrolled.errorCode())
        // Row 14: always the password proof, even on a fresh password session (since 2026-11-17).
        assertEquals("reauth_required", c.call(post, "/api/v1/account/totp/setup", "", t).errorCode())
        val setup = c.call(post, "/api/v1/account/totp/setup", """{"currentAuthKey":"${me.authKey}"}""", t)
        assertEquals(200, setup.status.value, setup.bodyAsText())
        val first = WireJson.json.decodeFromString(TotpSetupResponse.serializer(), setup.bodyAsText())
        assertTrue(first.otpauthUri.startsWith("otpauth://totp/") && first.otpauthUri.contains("secret=${first.secretBase32}"))
        assertEquals("""{"enrolled":false,"pendingSetup":true}""", c.call(get, "/api/v1/account/totp", token = t).bodyAsText())
        // Row 15: a wrong code, then the right one.
        val bad = c.call(post, "/api/v1/account/totp/confirm", """{"code":"${wrong(Flow.totp(first.secretBase32, clock.now()))}"}""", t)
        assertEquals(400, bad.status.value); assertEquals("bad_totp_code", bad.errorCode())
        assertEquals("bad_totp_code", c.call(post, "/api/v1/account/totp/confirm", """{"code":"12345"}""", t).errorCode())
        assertEquals(200, c.call(post, "/api/v1/account/totp/confirm", """{"code":"${Flow.totp(first.secretBase32, clock.now())}"}""", t).status.value)
        assertEquals("""{"enrolled":true,"pendingSetup":false}""", c.call(get, "/api/v1/account/totp", token = t).bodyAsText())
        // Row 14, enrolled: a rotation needs the password proof and the current code. Without the proof, even on this
        // fresh password session, it is reauth_required; the password does not stand in for the code, so no code and
        // a wrong one are refused.
        clock.advance(30_000)
        s.limiter.clear() // the setup bucket (5 a minute) is not what this part is about
        val key = me.authKey
        assertEquals("reauth_required", c.call(post, "/api/v1/account/totp/setup", "{}", t).errorCode())
        assertEquals("reauth_required", c.call(post, "/api/v1/account/totp/setup", """{"code":"${Flow.totp(first.secretBase32, clock.now())}"}""", t).errorCode())
        assertEquals("bad_totp_code", c.call(post, "/api/v1/account/totp/setup", """{"currentAuthKey":"$key"}""", t).errorCode())
        assertEquals("bad_totp_code", c.call(post, "/api/v1/account/totp/setup", """{"code":"${wrong(Flow.totp(first.secretBase32, clock.now()))}","currentAuthKey":"$key"}""", t).errorCode())
        s.limiter.clear()
        val rot = c.call(post, "/api/v1/account/totp/setup", """{"code":"${Flow.totp(first.secretBase32, clock.now())}","currentAuthKey":"$key"}""", t)
        assertEquals(200, rot.status.value, rot.bodyAsText())
        val second = WireJson.json.decodeFromString(TotpSetupResponse.serializer(), rot.bodyAsText())
        assertNotEquals(first.secretBase32, second.secretBase32)
        assertEquals("""{"enrolled":true,"pendingSetup":true}""", c.call(get, "/api/v1/account/totp", token = t).bodyAsText())
        assertEquals(200, c.call(post, "/api/v1/account/totp/confirm", """{"code":"${Flow.totp(second.secretBase32, clock.now())}"}""", t).status.value)
        // Row 16: the current code alone no longer disables (the proof is needed); with the proof, the old secret does
        // not disable and a wrong code is refused; the current one disables.
        clock.advance(30_000)
        assertEquals("reauth_required", c.call(post, "/api/v1/account/totp/disable", """{"code":"${Flow.totp(second.secretBase32, clock.now())}"}""", t).errorCode())
        assertEquals("bad_totp_code", c.call(post, "/api/v1/account/totp/disable", """{"code":"${Flow.totp(first.secretBase32, clock.now()).let { if (it == Flow.totp(second.secretBase32, clock.now())) wrong(it) else it }}","currentAuthKey":"$key"}""", t).errorCode())
        assertEquals("bad_totp_code", c.call(post, "/api/v1/account/totp/disable", """{"code":"${wrong(Flow.totp(second.secretBase32, clock.now()))}","currentAuthKey":"$key"}""", t).errorCode())
        assertEquals(200, c.call(post, "/api/v1/account/totp/disable", """{"code":"${Flow.totp(second.secretBase32, clock.now())}","currentAuthKey":"$key"}""", t).status.value)
        assertEquals("""{"enrolled":false,"pendingSetup":false}""", c.call(get, "/api/v1/account/totp", token = t).bodyAsText())
        assertEquals("two_step_off", Flow.sink(s).last().first)
    }
}
