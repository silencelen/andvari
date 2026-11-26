package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.TokenPair
import io.silencelen.andvari.core.model.wire.WireJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Row 11's limit (spec 03 §0.2, §2, rule of 2026-11-17): a refresh whose token names a live session draws that
 * session's device (`refresh_session`, 30 a minute per device, with its ceiling per account of 120), a consumed token's
 * reuse draws nothing and is never refused by a bucket, and every other refresh draws the caller's address (`refresh`,
 * 30 a minute per IP). Drawn per address for everyone, the people behind one address shared thirty a minute, and anyone
 * behind it could keep all of them from refreshing with tokens that name nothing.
 */
class RefreshBucketTest {
    private val post = HttpMethod.Post

    private suspend fun HttpClient.refresh(token: String, ip: String = randomIp()) =
        call(post, "/api/v1/auth/refresh", """{"refreshToken":"$token"}""", ip = ip)

    private suspend fun HttpResponse.pair(): TokenPair {
        assertEquals(200, status.value, bodyAsText())
        return WireJson.json.decodeFromString(TokenPair.serializer(), bodyAsText())
    }

    private fun assertLimited(r: HttpResponse, what: String) {
        assertEquals(429, r.status.value, what)
        val ra = r.headers["Retry-After"]?.toLong() ?: error("$what: no Retry-After")
        assertTrue(ra in 1..60, "$what: Retry-After $ra")
    }

    private fun addressCount(s: Services, ip: String) = s.limiter.count("${REFRESH_ADDRESS_BUCKET.name}:${rateKeyOf(ip)}")
    private fun deviceCount(s: Services, deviceId: String) = s.limiter.count(Bucket.deviceKey(REFRESH_SESSION_BUCKET, deviceId))
    private fun ceilingCount(s: Services, userId: String) = s.limiter.count(Bucket.accountKey(REFRESH_SESSION_BUCKET, userId))

    @Test
    fun aSecondPersonBehindTheSameAddress_refreshes_whileTheFirstHasSpentTheAddressOnTokensThatNameNoSession() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val ended = c.login(me)
        assertEquals(200, c.call(post, "/api/v1/auth/end-session", """{"refreshToken":"${ended.refreshToken}"}""").status.value)
        val shared = "10.7.7.7"
        // The first person spends the address's thirty on tokens that name no session ...
        repeat(REFRESH_ADDRESS_BUCKET.limit) { i -> assertEquals("invalid_refresh", c.refresh(b32(), shared).errorCode(), "unknown token ${i + 1}") }
        assertLimited(c.refresh(b32(), shared), "an unknown token past the address's limit")
        // ... and every other call that names no live session draws the address too, and is refused.
        assertLimited(c.call(post, "/api/v1/auth/refresh", "not json", ip = shared), "a body that is not the shape")
        assertLimited(c.refresh("", shared), "an empty token")
        assertLimited(c.refresh(ended.refreshToken, shared), "a revoked session's token")
        assertEquals(REFRESH_ADDRESS_BUCKET.limit, addressCount(s, shared))
        // The second person, behind the same address, refreshes a live session: served, on its device's budget.
        val pair = c.refresh(me.session!!.refreshToken, shared).pair()
        assertEquals(1, deviceCount(s, me.deviceId))
        assertEquals(1, ceilingCount(s, me.userId))
        assertEquals(REFRESH_ADDRESS_BUCKET.limit, addressCount(s, shared), "a live session's refresh spends nothing of the address")
        // An expired session's token names no live session: it draws the address, not the device, and is refused as before.
        clock.advance(s.sessions.refreshTtlMs)
        assertEquals("refresh_expired", c.refresh(pair.refreshToken, shared).errorCode())
        assertEquals(1, addressCount(s, shared))
        assertEquals(0, deviceCount(s, me.deviceId))
    }

    @Test
    fun aDeviceAtItsOwnLimitIsRefused_whileTheAccountsOtherDeviceRefreshes_andTheCeilingBoundsTheAccount() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com", platform = "web")
        val other = c.login(me)
        // A second sign-in on the first device's row (two web tabs on a browser's row; a sign-in on any other kind of row
        // ends the row's earlier sessions): its sessions share the device's budget.
        val sibling = c.call(post, "/api/v1/auth/login", me.loginBody(deviceId = me.deviceId), client = "web/1.0.0").let {
            assertEquals(200, it.status.value, it.bodyAsText())
            WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.SessionResponse.serializer(), it.bodyAsText())
        }
        assertEquals(me.deviceId, sibling.deviceId)
        // The first device refreshes thirty times, each from a new address: its own budget, not any address's.
        var token = me.session!!.refreshToken
        repeat(REFRESH_SESSION_BUCKET.limit) { token = c.refresh(token).pair().refreshToken }
        assertLimited(c.refresh(token), "the device's own limit")
        assertEquals(REFRESH_SESSION_BUCKET.limit, deviceCount(s, me.deviceId))
        assertLimited(c.refresh(sibling.refreshToken), "another session of the same device")
        // The account's other device is served at once.
        c.refresh(other.refreshToken).pair()
        assertEquals(1, deviceCount(s, other.deviceId))
        assertEquals(REFRESH_SESSION_BUCKET.limit + 1, ceilingCount(s, me.userId), "each refresh the devices' budgets admitted, once")
        // A refused refresh consumed nothing: the same token refreshes once the device's window lapses.
        clock.advance(61_000)
        c.refresh(token).pair()

        // The ceiling: four devices' budgets fill the account's 120, and a fifth device's refresh is refused and
        // spends nothing of its own budget. Another account is unaffected.
        clock.advance(61_000)
        val devices = List(5) { c.login(me) }
        assertEquals(REFRESH_SESSION_BUCKET.limit * 4, REFRESH_SESSION_BUCKET.accountCeiling)
        for (d in devices.take(4)) {
            var t = d.refreshToken
            repeat(REFRESH_SESSION_BUCKET.limit) { t = c.refresh(t).pair().refreshToken }
        }
        assertEquals(120, ceilingCount(s, me.userId))
        assertLimited(c.refresh(devices[4].refreshToken), "the account's ceiling")
        assertEquals(0, deviceCount(s, devices[4].deviceId), "a call the ceiling refused is given back to the device")
        val you = Flow.member(c, s, "you@example.com")
        c.refresh(you.session!!.refreshToken).pair()
    }

    @Test
    fun aReusedToken_stillRevokesTheDevice_drawsNothing_andIsNeverRefusedByABucket() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val other = c.login(me)
        val ip = "10.8.8.8"
        // The rotated chain spends the device's whole budget, from one address, so both budgets the reuse could have
        // drawn are spent: the device's (by the chain) and, under the old rule, the address's.
        val consumed = me.session!!.refreshToken
        var token = consumed
        repeat(REFRESH_SESSION_BUCKET.limit) { token = c.refresh(token, ip).pair().refreshToken }
        assertLimited(c.refresh(token, ip), "the chain past the device's limit")
        // The consumed token comes back: theft is assumed and every session of the device ends, as before.
        val reuse = c.refresh(consumed, ip)
        assertEquals(401, reuse.status.value, reuse.bodyAsText())
        assertEquals("refresh_reuse", reuse.errorCode())
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='refresh_reuse'") })
        assertEquals(0L, s.db.read { it.count("SELECT COUNT(*) FROM sessions WHERE deviceId=? AND revokedAt IS NULL", me.deviceId) })
        // It drew nothing: neither the device's budget nor the address's.
        assertEquals(REFRESH_SESSION_BUCKET.limit, deviceCount(s, me.deviceId))
        assertEquals(0, addressCount(s, ip))
        // The chain's live end is now a revoked session's token: it draws the address, and says so.
        assertEquals("session_revoked", c.refresh(token, ip).errorCode())
        assertEquals("session_revoked", c.refresh(consumed, ip).errorCode())
        assertEquals(2, addressCount(s, ip))
        // The account's other device was not touched.
        c.refresh(other.refreshToken).pair()
    }
}
