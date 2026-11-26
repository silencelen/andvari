package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.RegisterAuth
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.SignupVerifyResponse
import io.silencelen.andvari.core.model.wire.TokenPair
import io.silencelen.andvari.core.model.wire.TotpSetupResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.trust.SignupPow
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** Sign-up (spec 03 §14.1–14.2), login with known devices and requireLink (§2, §16.8), refresh, TOTP. */
class SignupLoginTest {
    private fun start(email: String, extra: String = "") = """{"email":"$email","ageConfirmed":true$extra}"""

    @Test
    fun signup_codeTicketRegister_uniformAnswers() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(TestKit.config(mode = "open", blocklist = setOf("spam.example")), clock)
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        // An existing address and a new one get the same answer.
        val r1 = c.call(HttpMethod.Post, "/api/v1/signup/start", start("New@Example.com"))
        val r2 = c.call(HttpMethod.Post, "/api/v1/signup/start", start(op.email))
        assertEquals(202, r1.status.value)
        assertEquals(r1.bodyAsText(), r2.bodyAsText())
        assertEquals("""{"status":"sent"}""", r1.bodyAsText())
        val mails = Flow.sink(s)
        assertEquals(listOf("signup_code", "signup_existing"), mails.map { it.first })
        val code = Flow.codeIn(mails[0].third)
        assertFalse(mails[0].third.contains("andvaripass.com"), "a code message carries no link")
        assertTrue(mails[1].third.contains("https://andvaripass.com/help/lost-password/"))
        // Blocked domain, before any lookup.
        assertEquals("email_domain_blocked", c.call(HttpMethod.Post, "/api/v1/signup/start", start("a@spam.example")).errorCode())
        assertEquals("invalid_email", c.call(HttpMethod.Post, "/api/v1/signup/start", start("not-an-address")).errorCode())
        // Verify: wrong code is a uniform bad_code; the right one mints a ticket.
        assertEquals("bad_code", c.call(HttpMethod.Post, "/api/v1/signup/verify", """{"email":"new@example.com","code":"000000"}""").errorCode().let { if (code == "000000") "bad_code" else it })
        assertEquals("bad_code", c.call(HttpMethod.Post, "/api/v1/signup/verify", """{"email":"nobody@example.com","code":"$code"}""").errorCode())
        val v = c.call(HttpMethod.Post, "/api/v1/signup/verify", """{"email":"new@example.com","code":"$code"}""")
        assertEquals(200, v.status.value, v.bodyAsText())
        val ticket = WireJson.json.decodeFromString(SignupVerifyResponse.serializer(), v.bodyAsText()).signupTicket
        // The code is single-use.
        assertEquals("bad_code", c.call(HttpMethod.Post, "/api/v1/signup/verify", """{"email":"new@example.com","code":"$code"}""").errorCode())
        // A ticket is bound to its address.
        assertEquals("bad_ticket", c.call(HttpMethod.Post, "/api/v1/auth/register", Me("other@example.com").register(s, RegisterAuth.Ticket(ticket))).errorCode())
        val me = Me("new@example.com")
        Flow.register(c, s, me, RegisterAuth.Ticket(ticket))
        assertEquals("bad_ticket", c.call(HttpMethod.Post, "/api/v1/auth/register", Me("new2@example.com").register(s, RegisterAuth.Ticket(ticket))).errorCode())
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='register' AND meta='auth=signupTicket'") })
    }

    @Test
    fun signup_attemptsKillTheCode_andModeAndPowGates() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(TestKit.config(mode = "open", powBits = 8, requireAgeConfirm = true), clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        assertEquals("age_confirm_required", c.call(HttpMethod.Post, "/api/v1/signup/start", """{"email":"a@example.com","ageConfirmed":false}""").errorCode())
        assertEquals("pow_required", c.call(HttpMethod.Post, "/api/v1/signup/start", start("a@example.com")).errorCode())
        val date = Clock.utcDate(clock.now())
        val nonce = SignupPow.search(createCryptoProvider(), "a@example.com", date, 8, 0, 100_000)!!
        val bad = (0L..1000L).first { !SignupPow.accepts(createCryptoProvider(), "a@example.com", date, it, 8) }
        assertEquals("bad_pow", c.call(HttpMethod.Post, "/api/v1/signup/start", start("a@example.com", ""","pow":{"date":"$date","nonce":$bad}""")).errorCode())
        assertEquals(202, c.call(HttpMethod.Post, "/api/v1/signup/start", start("a@example.com", ""","pow":{"date":"$date","nonce":$nonce}""")).status.value)
        val code = Flow.codeIn(Flow.sink(s).last().third)
        val wrong = if (code == "123456") "654321" else "123456"
        repeat(5) { assertEquals("bad_code", c.call(HttpMethod.Post, "/api/v1/signup/verify", """{"email":"a@example.com","code":"$wrong"}""").errorCode()) }
        assertEquals("bad_code", c.call(HttpMethod.Post, "/api/v1/signup/verify", """{"email":"a@example.com","code":"$code"}""").errorCode())
        assertEquals(6L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='signup_verify_fail'") })

        val closed = TestKit.services(TestKit.config(mode = "links"))
        assertEquals("links", closed.policy.effectiveMode())
    }

    @Test
    fun login_knownDevice_newDevice_requireLink_backoffAndRefresh() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        Flow.sink(s)
        // A known device: the registered device's id and secret.
        val known = c.call(HttpMethod.Post, "/api/v1/auth/login", me.loginBody(deviceId = me.deviceId))
        assertEquals(200, known.status.value, known.bodyAsText())
        assertEquals(me.deviceId, WireJson.json.decodeFromString(SessionResponse.serializer(), known.bodyAsText()).deviceId)
        assertTrue(Flow.sink(s).none { it.first == "new_device" })
        // The right id with a wrong secret is a new device, and so is no id at all.
        val other = c.call(HttpMethod.Post, "/api/v1/auth/login", me.loginBody(deviceId = me.deviceId, secret = io.silencelen.andvari.core.crypto.Bytes.toB64(ByteArray(32))))
        val otherSession = WireJson.json.decodeFromString(SessionResponse.serializer(), other.bodyAsText())
        assertNotEquals(me.deviceId, otherSession.deviceId)
        val mails = Flow.sink(s)
        assertEquals("new_device", mails.last().first)
        assertTrue(mails.last().third.contains("Your account ID: "))
        // requireLink: a new device is refused, but only after the password verified.
        s.db.tx { it.exec("UPDATE users SET requireLink=1 WHERE userId=?", me.userId) }
        assertEquals("invalid_credentials", c.call(HttpMethod.Post, "/api/v1/auth/login", me.loginBody(authKey = io.silencelen.andvari.core.crypto.Bytes.toB64(ByteArray(32)))).errorCode())
        assertEquals("link_required", c.call(HttpMethod.Post, "/api/v1/auth/login", me.loginBody()).errorCode())
        val again = c.call(HttpMethod.Post, "/api/v1/auth/login", me.loginBody(deviceId = me.deviceId))
        assertEquals(200, again.status.value)
        val latest = WireJson.json.decodeFromString(SessionResponse.serializer(), again.bodyAsText())
        // A device has one live session: each sign-in on the known device ended the one before it.
        assertEquals("invalid_credentials", c.call(HttpMethod.Get, "/api/v1/account/keys", token = me.token).errorCode())
        // Refresh rotates; the consumed token's reuse revokes the device's sessions.
        val r1 = c.call(HttpMethod.Post, "/api/v1/auth/refresh", """{"refreshToken":"${otherSession.refreshToken}"}""")
        assertEquals(200, r1.status.value, r1.bodyAsText())
        val pair = WireJson.json.decodeFromString(TokenPair.serializer(), r1.bodyAsText())
        assertEquals(200, c.call(HttpMethod.Get, "/api/v1/account/keys", token = pair.accessToken).status.value)
        assertEquals("refresh_reuse", c.call(HttpMethod.Post, "/api/v1/auth/refresh", """{"refreshToken":"${otherSession.refreshToken}"}""").errorCode())
        assertEquals("invalid_credentials", c.call(HttpMethod.Get, "/api/v1/account/keys", token = pair.accessToken).errorCode())
        // Logout revokes this device.
        assertEquals(200, c.call(HttpMethod.Get, "/api/v1/account/keys", token = latest.accessToken).status.value)
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/auth/logout", token = latest.accessToken).status.value)
        assertEquals("invalid_credentials", c.call(HttpMethod.Get, "/api/v1/account/keys", token = latest.accessToken).errorCode())
    }

    @Test
    fun totp_enrolment_login_and_disable() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        // A first setup always needs the password proof, inside or outside ten minutes of the password (since 2026-11-17).
        assertEquals("reauth_required", c.call(HttpMethod.Post, "/api/v1/account/totp/setup", "{}", me.token).errorCode())
        clock.advance(11 * 60_000L)
        assertEquals("reauth_required", c.call(HttpMethod.Post, "/api/v1/account/totp/setup", "{}", me.token).errorCode())
        assertEquals("reauth_failed", c.call(HttpMethod.Post, "/api/v1/account/totp/setup", """{"currentAuthKey":"AAAA"}""", me.token).errorCode())
        val setup = c.call(HttpMethod.Post, "/api/v1/account/totp/setup", """{"currentAuthKey":"${me.authKey}"}""", me.token)
        assertEquals(200, setup.status.value, setup.bodyAsText())
        val secret = WireJson.json.decodeFromString(TotpSetupResponse.serializer(), setup.bodyAsText()).secretBase32
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/account/totp/confirm", """{"code":"${Flow.totp(secret, clock.now())}"}""", me.token).status.value)
        clock.advance(30_000)
        assertEquals("totp_required", c.call(HttpMethod.Post, "/api/v1/auth/login", me.loginBody(deviceId = me.deviceId)).errorCode())
        assertEquals("invalid_credentials", c.call(HttpMethod.Post, "/api/v1/auth/login", me.loginBody(deviceId = me.deviceId, totp = "000000".takeIf { it != Flow.totp(secret, clock.now()) } ?: "111111")).errorCode())
        val code = Flow.totp(secret, clock.now())
        val signedIn = c.call(HttpMethod.Post, "/api/v1/auth/login", me.loginBody(deviceId = me.deviceId, totp = code))
        assertEquals(200, signedIn.status.value)
        // The sign-in on the known device ended its earlier session (a device has one live session): the new one goes on.
        val token = WireJson.json.decodeFromString(SessionResponse.serializer(), signedIn.bodyAsText()).accessToken
        // The same step again is a replay: the uniform 401.
        assertEquals("invalid_credentials", c.call(HttpMethod.Post, "/api/v1/auth/login", me.loginBody(deviceId = me.deviceId, totp = code)).errorCode())
        clock.advance(30_000)
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/account/totp/disable", """{"code":"${Flow.totp(secret, clock.now())}","currentAuthKey":"${me.authKey}"}""", token).status.value)
        assertEquals("two_step_off", Flow.sink(s).last().first)
    }

    @Test
    fun restrictedSession_whenTotpIsRequired() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(TestKit.config(totpRequired = true), clock)
        application { andvariModule(s) }
        val c = client
        val op = Me("op@example.com")
        Flow.register(c, s, op, Flow.setupAuth(s))
        // The operator's session is restricted too: it must enrol before it can sign card 0.
        assertTrue(op.session!!.mustEnrollTotp)
        Flow.forceCard0(s, op)
        val me = Flow.member(c, s, "me@example.com")
        assertTrue(me.session!!.mustEnrollTotp)
        assertEquals("totp_enrollment_required", c.call(HttpMethod.Get, "/api/v1/account/keys", token = me.token).errorCode())
        // A restricted session gets no fresh-login exemption at setup.
        assertEquals("reauth_required", c.call(HttpMethod.Post, "/api/v1/account/totp/setup", "{}", me.token).errorCode())
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/account/totp/setup", """{"currentAuthKey":"${me.authKey}"}""", me.token).status.value)
    }
}
