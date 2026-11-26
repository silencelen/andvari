package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.TotpSetupResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The rate buckets of the routes that need a session are kept per device (spec 03 §0.2), each with a ceiling per
 * account of four times the device's limit. Kept per account, a session in the wrong hands, without the password,
 * could spend a route's budget and so keep the account's owner from that route on every device: five requests an hour
 * kept the owner from deleting the account. Per device, the held session spends only its own device's budget, a device
 * refused by its own budget spends nothing of the account's ceiling, and a removed device takes its budgets with it.
 *
 * The held session fills each bucket with bodies that are not the route's shape (`400 bad_request`): the bucket is drawn
 * before the body is read, so these spend the bucket and never reach a password proof or a code, whose own back-offs
 * would otherwise answer `429` in the bucket's place.
 */
class SessionBucketsPerDeviceTest {
    private val post = HttpMethod.Post
    private val put = HttpMethod.Put
    private val get = HttpMethod.Get

    private class Dev(val deviceId: String, val token: String)

    private fun dev(me: Me) = Dev(me.deviceId, me.token)

    private fun wrongKey() = Bytes.toB64(TestKit.crypto.randomBytes(32))

    private fun b16() = Bytes.toB64(TestKit.crypto.randomBytes(16))

    /** The owner signs in on a new device with the password ([totp] where two-step sign-in is on). */
    private suspend fun signInNewDevice(c: HttpClient, me: Me, totp: String? = null, authKey: String = me.authKey): Dev {
        val r = c.call(post, "/api/v1/auth/login", me.loginBody(secret = wrongKey(), totp = totp, authKey = authKey))
        assertEquals(200, r.status.value, r.bodyAsText())
        val sr = WireJson.json.decodeFromString(SessionResponse.serializer(), r.bodyAsText())
        return Dev(sr.deviceId, sr.accessToken)
    }

    private fun assertLimited(r: HttpResponse, retryAfter: Long, what: String) {
        assertEquals(429, r.status.value, what)
        val ra = r.headers["Retry-After"]?.toLong() ?: error("$what: no Retry-After")
        assertTrue(ra in 1..retryAfter, "$what: Retry-After $ra, expected at most $retryAfter")
    }

    /** [d] spends the whole of [b] on [path] with bodies of the wrong shape, and its next call is refused. */
    private suspend fun spend(c: HttpClient, d: Dev, method: HttpMethod, path: String, b: Bucket) {
        repeat(b.limit) { i ->
            // `400 bad_request`, or (setup, which reads a missing proof as one) `403 reauth_required`: never a proof.
            val code = c.call(method, path, "not json", d.token).errorCode()
            assertTrue(code == "bad_request" || code == "reauth_required", "${b.name} ${i + 1}: $code")
        }
        assertLimited(c.call(method, path, "not json", d.token), b.windowMs / 1000, "${b.name}: the device's own limit is what it was")
    }

    private fun deviceCount(s: Services, b: Bucket, d: Dev) = s.limiter.count(Bucket.deviceKey(b, d.deviceId))
    private fun accountCount(s: Services, b: Bucket, me: Me) = s.limiter.count(Bucket.accountKey(b, me.userId))

    private fun delete(me: Me, key: String) = """{"confirmEmail":"${me.email}","currentAuthKey":"$key","leaves":[]}"""

    private val accountDelete = Bucket.devicePerHour("account_delete", 5)

    @Test
    fun aSessionThatSpentTheDeletionsBudget_neverKeepsTheOwnerFromDeletingTheAccount() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        // The registration's session is the one in the wrong hands: it spends the deletion's five an hour ...
        val thief = dev(me)
        spend(c, thief, post, "/api/v1/account/delete", accountDelete)
        // ... and as many more as it likes, which its own budget refuses and the account's ceiling never sees.
        repeat(50) { assertEquals(429, c.call(post, "/api/v1/account/delete", "not json", thief.token).status.value) }
        assertEquals(5, deviceCount(s, accountDelete, thief))
        assertEquals(5, accountCount(s, accountDelete, me))
        // The owner, on another device, deletes the account at once.
        val owner = signInNewDevice(c, me)
        val gone = c.call(post, "/api/v1/account/delete", delete(me, me.authKey), owner.token)
        assertEquals(200, gone.status.value, "deleting the account: ${gone.bodyAsText()}")
        // Every device of the account went with it, and its budgets with it; the account's ceiling keeps its count.
        assertEquals(0, deviceCount(s, accountDelete, thief))
        assertEquals(0, deviceCount(s, accountDelete, owner))
        assertEquals(6, accountCount(s, accountDelete, me))
    }

    @Test
    fun aSessionAtItsLimitOnEachBucket_leavesAnotherDeviceServedAtOnce_andARemovedDeviceTakesItsBudgetsWithIt() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val thief = dev(me)
        val owner = signInNewDevice(c, me)

        // Setting two-step sign-in up (`totp_setup`), confirming it (`totp_confirm`) and turning it off (`totp_verify`).
        val setup = Bucket.devicePerMinute("totp_setup", 5)
        spend(c, thief, post, "/api/v1/account/totp/setup", setup)
        val st = c.call(post, "/api/v1/account/totp/setup", """{"currentAuthKey":"${me.authKey}"}""", owner.token)
        assertEquals(200, st.status.value, "setup: ${st.bodyAsText()}")
        val secret = WireJson.json.decodeFromString(TotpSetupResponse.serializer(), st.bodyAsText()).secretBase32
        val confirm = Bucket.devicePerMinute("totp_confirm", 5)
        spend(c, thief, post, "/api/v1/account/totp/confirm", confirm)
        val cf = c.call(post, "/api/v1/account/totp/confirm", """{"code":"${Flow.totp(secret, clock.now())}"}""", owner.token)
        assertEquals(200, cf.status.value, "confirm: ${cf.bodyAsText()}")
        clock.advance(30_000)
        spend(c, thief, post, "/api/v1/account/totp/disable", SharedBuckets.TOTP_VERIFY)
        val off = c.call(post, "/api/v1/account/totp/disable", """{"code":"${Flow.totp(secret, clock.now())}","currentAuthKey":"${me.authKey}"}""", owner.token)
        assertEquals(200, off.status.value, "turning two-step sign-in off: ${off.bodyAsText()}")

        // A † route's default bucket.
        val requireLink = defaultBucket(WireRoute.REQUIRE_LINK)
        spend(c, thief, put, "/api/v1/account/require-link", requireLink)
        val rl = c.call(put, "/api/v1/account/require-link", """{"enabled":false,"currentAuthKey":"${me.authKey}"}""", owner.token)
        assertEquals(200, rl.status.value, "require-link: ${rl.bodyAsText()}")

        // A read's default bucket, a write's, and a route's own (`ws_ticket`).
        val keys = defaultBucket(WireRoute.ACCOUNT_KEYS)
        repeat(keys.limit) { assertEquals(200, c.call(get, "/api/v1/account/keys", token = thief.token).status.value) }
        assertLimited(c.call(get, "/api/v1/account/keys", token = thief.token), 60, "read default")
        assertEquals(200, c.call(get, "/api/v1/account/keys", token = owner.token).status.value, "the owner's read")
        val ack = defaultBucket(WireRoute.LINK_ACK)
        repeat(ack.limit) { assertEquals(404, c.call(post, "/api/v1/links/${b16()}/ack", token = thief.token).status.value) }
        assertLimited(c.call(post, "/api/v1/links/${b16()}/ack", token = thief.token), 3600, "write default")
        assertEquals(404, c.call(post, "/api/v1/links/${b16()}/ack", token = owner.token).status.value, "the owner's write is served")
        val ticket = Bucket.devicePerMinute("ws_ticket", 60)
        repeat(ticket.limit) { assertEquals(200, c.call(post, "/api/v1/events/ticket", token = thief.token).status.value) }
        assertLimited(c.call(post, "/api/v1/events/ticket", token = thief.token), 60, "ws_ticket")
        assertEquals(200, c.call(post, "/api/v1/events/ticket", token = owner.token).status.value, "the owner's ticket")

        // The password change, which also signs the other devices out (their rows, and their budgets, stay).
        val password = Bucket.devicePerMinute("password_change", 5)
        spend(c, thief, put, "/api/v1/account/password", password)
        val newKey = wrongKey()
        val pw = c.call(put, "/api/v1/account/password", passwordChange(me.authKey, newKey), owner.token)
        assertEquals(200, pw.status.value, "changing the password: ${pw.bodyAsText()}")
        assertEquals(5, deviceCount(s, password, thief))

        // The owner removes the held device (its own `reauth_device_revoke` untouched): the device's budgets all go,
        // and the account's ceilings keep what it spent.
        val revoke = c.call(post, "/api/v1/account/devices/${thief.deviceId}/revoke", """{"currentAuthKey":"$newKey"}""", owner.token)
        assertEquals(200, revoke.status.value, "removing the held device: ${revoke.bodyAsText()}")
        for (b in listOf(setup, confirm, SharedBuckets.TOTP_VERIFY, requireLink, keys, ack, ticket, password)) {
            assertEquals(0, deviceCount(s, b, thief), "${b.name}: the removed device's budget")
        }
        assertEquals(6, accountCount(s, requireLink, me))
        assertEquals(1, deviceCount(s, requireLink, owner))
    }

    @Test
    fun theAccountKeepsACeilingOfFourDevicesBudgets_andAnOperatorsRemovalTakesTheBudgetsToo() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val requireLink = defaultBucket(WireRoute.REQUIRE_LINK)
        assertEquals(20, requireLink.accountCeiling)
        // Four devices spend their five each: twenty, the account's ceiling for this bucket in this minute.
        val devices = listOf(dev(me)) + List(3) { signInNewDevice(c, me) }
        for (d in devices) spend(c, d, put, "/api/v1/account/require-link", requireLink)
        assertEquals(20, accountCount(s, requireLink, me))
        // A fifth device has spent nothing of its own and is refused by the ceiling.
        val fifth = signInNewDevice(c, me)
        val body = """{"enabled":false,"currentAuthKey":"${me.authKey}"}"""
        assertLimited(c.call(put, "/api/v1/account/require-link", body, fifth.token), 60, "the ceiling")
        assertEquals(0, deviceCount(s, requireLink, fifth))
        // Another account's devices are untouched by this account's ceiling.
        val other = Flow.member(c, s, "other@example.com")
        assertEquals(200, c.call(put, "/api/v1/account/require-link", """{"enabled":false,"currentAuthKey":"${other.authKey}"}""", other.token).status.value)
        // The operator removes the first device: its budgets go with it, and the account's ceiling keeps its count.
        val first = devices.first()
        assertEquals(5, deviceCount(s, requireLink, first))
        val byOp = c.call(post, "/api/v1/admin/devices/${first.deviceId}/revoke", """{"currentAuthKey":"${op.authKey}"}""", op.token)
        assertEquals(200, byOp.status.value, byOp.bodyAsText())
        assertEquals(0, deviceCount(s, requireLink, first))
        assertEquals(5, deviceCount(s, requireLink, devices[1]))
        assertEquals(20, accountCount(s, requireLink, me))
        // A minute later the ceiling's window has lapsed, and the fifth device is served.
        clock.advance(60_000)
        assertEquals(200, c.call(put, "/api/v1/account/require-link", body, fifth.token).status.value)
    }

    private fun passwordChange(current: String, newKey: String) =
        """{"currentAuthKey":"$current","newAuthKey":"$newKey","newKdfSalt":"${Bytes.toB64(ByteArray(16) { 5 })}",""" +
            """"newKdfParams":{"v":1,"alg":"argon2id13","ops":1,"memBytes":8388608},"newWrappedUvk":"AAAA"}"""
}
