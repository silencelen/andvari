package io.silencelen.andvari.server

import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import kotlin.test.Test
import kotlin.test.assertEquals

/** Spec 03 §8: per-IP buckets key an IPv6 client on its /64; audit keeps the full address. */
class Ipv6RateKeyTest {
    @Test
    fun theRateKey() {
        assertEquals("2001:db8:1:2::/64", rateKeyOf("2001:db8:1:2:aaaa:bbbb:cccc:dddd"))
        assertEquals("2001:db8:1:2::/64", rateKeyOf("2001:0db8:0001:0002::1"))
        assertEquals("2001:db8:1:3::/64", rateKeyOf("2001:db8:1:3::1"))
        assertEquals("203.0.113.9", rateKeyOf("203.0.113.9"))
        assertEquals("203.0.113.9", rateKeyOf("::ffff:203.0.113.9"))
    }

    @Test
    fun oneSlash64_isOneBucket_andAuditKeepsTheAddress() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        suspend fun prelogin(ip: String) = c.call(HttpMethod.Post, "/api/v1/auth/prelogin", """{"email":"x@example.com"}""", ip = ip).status.value
        val statuses = (1..11).map { prelogin("2001:db8:7:7::${it.toString(16)}") }
        assertEquals(List(10) { 200 } + 429, statuses)
        assertEquals(429, prelogin("2001:db8:7:7:ffff:ffff:ffff:ffff"))
        assertEquals(200, prelogin("2001:db8:7:8::1"), "the next /64 is another bucket")
        // Audit rows keep the full address.
        val me = Flow.member(c, s, "me@example.com")
        c.call(HttpMethod.Post, "/api/v1/auth/login", me.loginBody(secret = b32(), authKey = b32()), ip = "2001:db8:9:9::abcd")
        assertEquals("2001:db8:9:9::abcd", s.db.read { db -> db.queryOne("SELECT ip FROM audit WHERE type='login_fail'") { it.getString(1) } })
    }
}
