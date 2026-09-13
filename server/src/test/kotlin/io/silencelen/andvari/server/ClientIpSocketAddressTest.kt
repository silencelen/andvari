package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * H82 (audit 2026-09-13): clientIp()'s no-forwarded-header fallback was Ktor's `remoteHost` —
 * on the Netty engine InetSocketAddress.getHostName, a blocking reverse-DNS lookup, name first
 * and the literal only as a fallback — not the socket address spec 03 §8 names. Probed live:
 * every loopback request without XFF wrote `localhost` into the audit ip column, and on a LAN
 * with PTR records the login bucket was keyed on DHCP-lease-dependent hostnames. The fallback is
 * now the same `remoteAddress` literal peerIsLoopback() already read.
 *
 * Deliberately a REAL Netty listener, not testApplication: the test engine reports "localhost"
 * for BOTH remoteHost and remoteAddress, so only a genuine socket can tell the two accessors
 * apart — which is exactly why this slipped past every existing clientIp pin.
 */
class ClientIpSocketAddressTest : P4TestSupport() {

    @Test
    fun unforwardedLoopbackPeer_isRecordedAsTheSocketLiteral_neverAHostname() {
        val services = buildServices(config(), Notifier())
        val server = embeddedServer(Netty, port = 0, host = "127.0.0.1") { andvariModule(services) }
        server.start(wait = false)
        try {
            val port = runBlocking { server.engine.resolvedConnectors().first().port }
            val client = HttpClient(Java) { install(ContentNegotiation) { json(json) } }
            val vc = VirtualClient("ip@x.com", "socket literal password one", fast = true)
            runBlocking {
                // No X-Forwarded-For: the fallback path — the direct-LAN self-host and every local
                // audit read; the reference front-ends always forward and never reach it.
                val resp = client.post("http://127.0.0.1:$port/api/v1/auth/register") {
                    contentType(ContentType.Application.Json)
                    header("X-Andvari-Client", "test/1.0.0")
                    setBody(vc.buildRegister(bootstrapToken, recovery.publicKey, fingerprint))
                }
                assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
            }
            client.close()
            val row = services.repo.auditQuery(0, "register", null, 10).single()
            assertEquals("127.0.0.1", row.ip, "the socket address literal — never a resolver's name for it")
        } finally {
            server.stop(500, 2_000)
        }
    }
}
