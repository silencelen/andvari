package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Per-IP rate buckets key an IPv6 client on its /64. One subscriber is routinely handed a whole /64,
 * so keying on the full address made every per-IP limit (prelogin, login, register, refresh, and the
 * self-recovery verify with its 64 MiB Argon2id) no limit at all for one subscriber. Audit rows keep
 * the full address.
 */
class RateKeyIpv6Test : P4TestSupport() {

    @Test
    fun rateKey_isThe64OfAnIpv6Address_andAnythingElseAsIs() {
        assertEquals("2001:db8:1:2::/64", rateKeyOf("2001:db8:1:2:aaaa:bbbb:cccc:dddd"))
        assertEquals("2001:db8:1:2::/64", rateKeyOf("2001:DB8:1:2::99"))
        assertEquals("2001:db8:1:3::/64", rateKeyOf("2001:db8:1:3::1"))
        assertEquals("0:0:0:0::/64", rateKeyOf("::1"))
        assertEquals("203.0.113.7", rateKeyOf("203.0.113.7"))
        assertEquals("203.0.113.7", rateKeyOf("::ffff:203.0.113.7"), "an IPv4-mapped address is its IPv4 address")
        assertEquals("localhost", rateKeyOf("localhost"), "a non-literal passes through")
    }

    /** Over a real socket (the test engine reports the peer as "localhost", which is never a trusted proxy). */
    @Test
    fun prelogin_bucketIsShared_acrossOne64() {
        val services = buildServices(config(), Notifier())
        val server = embeddedServer(Netty, port = 0, host = "127.0.0.1") { andvariModule(services) }
        server.start(wait = false)
        try {
            val port = runBlocking { server.engine.resolvedConnectors().first().port }
            val client = HttpClient(Java)
            fun prelogin(from: String): HttpStatusCode = runBlocking {
                client.post("http://127.0.0.1:$port/api/v1/auth/prelogin") {
                    contentType(ContentType.Application.Json)
                    header("X-Andvari-Client", "test/1.0.0")
                    header("X-Forwarded-For", from)
                    setBody("""{"email":"v6@example.com"}""")
                }.status
            }
            // The prelogin bucket is 10 a minute: ten addresses of one /64 spend it.
            for (i in 1..10) assertEquals(HttpStatusCode.OK, prelogin("2001:db8:1:2::$i"), "address $i of the /64")
            assertEquals(HttpStatusCode.TooManyRequests, prelogin("2001:db8:1:2::ffff"), "another address of the same /64 shares the bucket")
            assertEquals(HttpStatusCode.OK, prelogin("2001:db8:1:3::1"), "the next /64 has its own")
            assertEquals(HttpStatusCode.OK, prelogin("203.0.113.9"), "IPv4 is keyed as before")

            // The audit row keeps the full address: a failed login from one address of the /64.
            runBlocking {
                client.post("http://127.0.0.1:$port/api/v1/auth/login") {
                    contentType(ContentType.Application.Json)
                    header("X-Andvari-Client", "test/1.0.0")
                    header("X-Forwarded-For", "2001:db8:9:9::42")
                    setBody("""{"email":"nobody@example.com","authKey":"AAAA","device":{"platform":"test","name":"t"}}""")
                }
            }
            assertEquals("2001:db8:9:9::42", services.repo.auditQuery(0, "login_fail", null, 10).single().ip)
            client.close()
        } finally {
            server.stop(500, 2_000)
        }
    }
}
