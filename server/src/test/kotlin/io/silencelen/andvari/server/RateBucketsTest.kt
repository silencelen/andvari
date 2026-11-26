package io.silencelen.andvari.server

import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.RecoveryRequestCreated
import io.silencelen.andvari.core.model.wire.EscrowUpload
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.trust.LogEntry
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * One test per bucket class of spec 03 §0.1/§0.2 and §10.5: the limit is enforced, the refusal is
 * `429 rate_limited` with `Retry-After` in seconds, the bucket is keyed as the index says, and it refills.
 */
class RateBucketsTest {
    private val post = HttpMethod.Post
    private val get = HttpMethod.Get
    private val put = HttpMethod.Put

    /** The `429 rate_limited` shape, with a `Retry-After` of at most [maxSeconds]. */
    private suspend fun assertLimited(r: HttpResponse, maxSeconds: Long, what: String) {
        assertEquals(429, r.status.value, "$what: ${r.bodyAsText()}")
        assertEquals("rate_limited", r.errorCode(), what)
        val ra = r.headers["Retry-After"]?.toLongOrNull()
        assertTrue(ra != null && ra in 1..maxSeconds, "$what: Retry-After $ra")
    }

    @Test
    fun perIpPerMinute_prelogin10_keyedByIp_refills() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        repeat(10) { assertEquals(200, c.call(post, "/api/v1/auth/prelogin", """{"email":"a@example.com"}""", ip = "10.1.1.1").status.value) }
        assertLimited(c.call(post, "/api/v1/auth/prelogin", """{"email":"a@example.com"}""", ip = "10.1.1.1"), 60, "prelogin")
        assertEquals(200, c.call(post, "/api/v1/auth/prelogin", """{"email":"a@example.com"}""", ip = "10.1.1.2").status.value)
        clock.advance(60_000)
        assertEquals(200, c.call(post, "/api/v1/auth/prelogin", """{"email":"a@example.com"}""", ip = "10.1.1.1").status.value)
    }

    @Test
    fun perIpPerHour_register10_drawnBeforeTheBodyIsRead() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        repeat(10) { assertEquals(400, client.call(post, "/api/v1/auth/register", "{}", ip = "10.2.2.2").status.value) }
        assertLimited(client.call(post, "/api/v1/auth/register", "{}", ip = "10.2.2.2"), 3600, "register")
    }

    @Test
    fun perIpPerDay_signupStart_3anHourAnd10aDay() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(TestKit.config(mode = "open"), clock)
        application { andvariModule(s) }
        Flow.finishSetup(client, s)
        var n = 0
        suspend fun start() = client.call(post, "/api/v1/signup/start", """{"email":"p${n++}@example.com","ageConfirmed":true}""", ip = "10.3.3.3")
        repeat(3) { assertEquals(202, start().status.value) }
        assertLimited(start(), 3600, "signup_start hourly")
        // Hour by hour, up to ten a day.
        // The sender drains as it would in production, so the hour's jump does not leave the outbox stalled.
        repeat(2) { clock.advance(Clock.HOUR_MS); s.mail.drain(); repeat(3) { assertEquals(202, start().status.value) } }
        clock.advance(Clock.HOUR_MS); s.mail.drain()
        assertEquals(202, start().status.value)
        assertLimited(start(), 86_400, "signup_start daily")
        // Per address, 5 a day, whatever the IP.
        repeat(5) { assertEquals(202, client.call(post, "/api/v1/signup/start", """{"email":"same@example.com","ageConfirmed":true}""").status.value) }
        assertLimited(client.call(post, "/api/v1/signup/start", """{"email":"SAME@example.com","ageConfirmed":true}"""), 86_400, "signup_start per address")
    }

    @Test
    fun perAccountNamedBuckets_perMinute_perHour_perDay() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val other = Flow.member(c, s, "other@example.com")
        // totp_confirm, 5 a minute per account, whatever the IP.
        repeat(5) { assertEquals("no_pending_totp", c.call(post, "/api/v1/account/totp/confirm", """{"code":"123456"}""", me.token).errorCode()) }
        assertLimited(c.call(post, "/api/v1/account/totp/confirm", """{"code":"123456"}""", me.token), 60, "totp_confirm")
        assertEquals("no_pending_totp", c.call(post, "/api/v1/account/totp/confirm", """{"code":"123456"}""", other.token).errorCode())
        // device_link_create, 10 an hour.
        repeat(10) { assertEquals(201, c.call(post, "/api/v1/device-links", """{"linkId":"${b16()}","expiresAt":${s.clock.now() + 60_000}}""", me.token).status.value) }
        assertLimited(c.call(post, "/api/v1/device-links", """{"linkId":"${b16()}","expiresAt":${s.clock.now() + 60_000}}""", me.token), 3600, "device_link_create")
        // link_create, 30 a day (each a revoked link, so the open-links quota never bites).
        repeat(30) {
            val id = b16()
            assertEquals(201, c.call(post, "/api/v1/links", """{"linkId":"$id","kind":"connect","offer":"AAAAAAAAAAAA","expiresAt":${s.clock.now() + 60_000}}""", me.token).status.value)
            c.call(HttpMethod.Delete, "/api/v1/links/$id", token = me.token)
        }
        assertLimited(c.call(post, "/api/v1/links", """{"linkId":"${b16()}","kind":"connect","offer":"AAAAAAAAAAAA","expiresAt":${s.clock.now() + 60_000}}""", me.token), 86_400, "link_create")
    }

    @Test
    fun defaultBuckets_read60aMinute_write60anHour_perRoute_andTheReauthBucket() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        repeat(60) { assertEquals(200, c.call(get, "/api/v1/account/keys", token = me.token).status.value) }
        assertLimited(c.call(get, "/api/v1/account/keys", token = me.token), 60, "read default")
        // One bucket per route: another read is untouched.
        assertEquals(200, c.call(get, "/api/v1/account/devices", token = me.token).status.value)
        // The write default, 60 an hour (an ack of an unknown link spends it as well as a real one).
        repeat(60) { assertEquals(404, c.call(post, "/api/v1/links/${b16()}/ack", token = me.token).status.value) }
        assertLimited(c.call(post, "/api/v1/links/${b16()}/ack", token = me.token), 3600, "write default")
        assertEquals(404, c.call(HttpMethod.Delete, "/api/v1/links/${b16()}", token = me.token).status.value)
        // Every † route: 5 a minute per account, drawn before the password is verified.
        repeat(5) { assertEquals("reauth_failed", c.call(put, "/api/v1/account/require-link", """{"enabled":true,"currentAuthKey":"${b32()}"}""", me.token).errorCode()) }
        assertLimited(c.call(put, "/api/v1/account/require-link", """{"enabled":true,"currentAuthKey":"${me.authKey}"}""", me.token), 60, "reauth")
        clock.advance(60_000)
        assertEquals(200, c.call(get, "/api/v1/account/keys", token = me.token).status.value)
        assertEquals(200, c.call(put, "/api/v1/account/require-link", """{"enabled":true,"currentAuthKey":"${me.authKey}"}""", me.token).status.value)
    }

    @Test
    fun vaultLogKindBuckets_vaultCreate10anHour() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        s.db.tx { it.exec("UPDATE users SET quotaOwnedSharedVaults=100 WHERE userId=?", me.userId) }
        val made = List(10) { SharedVault(c, s, me).create() }
        val v = SharedVault(c, s, me)
        val r = v.append(me, LogEntry.Genesis(v.vaultId, me.userId, v.at, me.identity.identityPubB64, "a".repeat(64)), ""","metaBlob":"AAAA","wrappedVk":"AAAA"""")
        assertLimited(r, 3600, "vault_create")
        // Another kind's bucket is separate: a delete (vault_destructive) of one of the ten still lands.
        val one = made.first()
        one.ok(me, LogEntry.Delete(one.vaultId, one.next, one.head, me.userId, one.at, b16()))
    }

    @Test
    fun loginEmailBackoff_after5Failures_evenTheRightPasswordWaits() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        repeat(5) { assertEquals("invalid_credentials", c.call(post, "/api/v1/auth/login", me.loginBody(authKey = b32())).errorCode()) }
        assertLimited(c.call(post, "/api/v1/auth/login", me.loginBody()), 900, "login backoff")
        // The per-IP login bucket is separate (5 a minute by default).
        repeat(5) { c.call(post, "/api/v1/auth/login", """{"email":"x@example.com","authKey":"AAAA","device":{"platform":"linux","name":"x","deviceSecret":"${b32()}"}}""", ip = "10.4.4.4") }
        assertLimited(c.call(post, "/api/v1/auth/login", me.loginBody(), ip = "10.4.4.4"), 60, "login per IP")
        clock.advance(15 * 60_000L)
        assertEquals(200, c.call(post, "/api/v1/auth/login", me.loginBody()).status.value)
    }

    @Test
    fun assistedVerify_5perRequest_noAddressCap_noIpBucket() = testApplication {
        val key = TestKit.Identity().curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key))
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Me("me@example.com")
        Flow.register(c, s, me, Flow.enrolAuth(s), "operator", Flow.escrow(me, sha256Hex(key)))
        suspend fun open(): Pair<String, String> {
            val id = WireJson.json.decodeFromString(
                RecoveryRequestCreated.serializer(),
                c.call(post, "/api/v1/recovery/requests", """{"email":"${me.email}","rPub":"${b32()}","pollHash":"${"a".repeat(64)}","platform":"ios"}""").bodyAsText(),
            ).requestId
            return id to Flow.codeIn(Flow.sink(s).last { it.first == "recovery_request_code" }.third)
        }
        val (r1, code1) = open()
        val wrong = if (code1 == "000000") "111111" else "000000"
        // Five wrong codes from one IP kill the request's code; the right one is then refused too.
        repeat(5) { assertEquals("bad_code", c.call(post, "/api/v1/recovery/requests/$r1/verify", """{"code":"$wrong"}""", ip = "10.5.5.5").errorCode()) }
        assertEquals("bad_code", c.call(post, "/api/v1/recovery/requests/$r1/verify", """{"code":"$code1"}""", ip = "10.5.5.5").errorCode())
        // No per-address cap on attempts: after ten wrong codes across requests, a fresh
        // request's right code still verifies.
        val (r2, _) = open()
        repeat(5) { assertEquals("bad_code", c.call(post, "/api/v1/recovery/requests/$r2/verify", """{"code":"$wrong"}""").errorCode()) }
        val (r3, code3) = open()
        assertEquals(200, c.call(post, "/api/v1/recovery/requests/$r3/verify", """{"code":"$code3"}""").status.value)
    }
}
