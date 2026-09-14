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
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * H14 (audit 2026-09-13): WHICH direct peers may speak for a client.
 *
 * Forwarded-IP headers used to be honoured only when the peer was loopback. That is wrong for the
 * self-host topology docs/self-hosting.md prescribes — a host-side proxy pointed at the container's
 * published `127.0.0.1:8080` reaches the JVM through the Docker bridge, so the peer is the bridge
 * GATEWAY, never 127.0.0.1. Every client then collapsed into ONE rate-limit key (one stranger's
 * failed logins 429 the household) and ONE audit ip, and `ANDVARI_TRUSTED_IP_HEADERS` could not
 * fix it because the header was never read at all.
 *
 * The peer set is now operator-declared: `ANDVARI_TRUSTED_PROXY_CIDRS`, loopback by default (so
 * every existing deployment is unchanged). These tests pin the three cases that matter: the
 * default loopback proxy, a peer inside a declared CIDR, and an UNTRUSTED peer whose forged header
 * must be ignored.
 */
class TrustedProxyCidrTest : P4TestSupport() {

    private fun cfg(trustedProxyCidrs: List<String> = Config.DEFAULT_TRUSTED_PROXY_CIDRS) = Config(
        host = "127.0.0.1", port = 0,
        dbPath = File(tmpDir, "tp-${System.nanoTime()}.db").absolutePath,
        blobDir = File(tmpDir, "tp-blobs-${System.nanoTime()}").absolutePath, webDir = null,
        recoveryPublicKey = recovery.publicKey, recoveryFingerprint = fingerprint,
        enumSecret = ByteArray(32) { 7 }, publicHostname = null, bootstrapToken = bootstrapToken,
        trustedProxyCidrs = trustedProxyCidrs,
    )

    // ---- the pure trust decision (no socket needed) ----

    @Test
    fun defaultCidrs_trustOnlyLoopback() {
        val nets = Config.DEFAULT_TRUSTED_PROXY_CIDRS.mapNotNull { CidrBlock.parse(it) }
        assertEquals(2, nets.size, "both default entries must parse")
        assertTrue(isTrustedProxyPeer("127.0.0.1", nets))
        assertTrue(isTrustedProxyPeer("127.0.0.53", nets), "the whole 127/8 block, not just .1")
        assertTrue(isTrustedProxyPeer("::1", nets))
        // The exact defect H14 names: the compose bridge gateway is NOT loopback.
        assertFalse(isTrustedProxyPeer("172.18.0.1", nets), "the Docker bridge gateway is not trusted by default")
        assertFalse(isTrustedProxyPeer("192.168.1.40", nets), "a LAN client can never speak for someone else")
        assertFalse(isTrustedProxyPeer("2001:db8::1", nets))
    }

    @Test
    fun declaredCidr_trustsThatPeer_andNothingAdjacent() {
        val nets = listOf("172.18.0.0/16").mapNotNull { CidrBlock.parse(it) }
        assertTrue(isTrustedProxyPeer("172.18.0.1", nets), "the declared bridge gateway")
        assertTrue(isTrustedProxyPeer("172.18.255.254", nets))
        assertFalse(isTrustedProxyPeer("172.19.0.1", nets), "the neighbouring bridge is a different network")
        // Declaring a bridge does NOT silently keep loopback: the operator's list is the whole list.
        assertFalse(isTrustedProxyPeer("127.0.0.1", nets))
        // Prefix matching is on BYTES, never on the printed string — the classic /8 bug.
        val eight = listOf("10.0.0.0/8").mapNotNull { CidrBlock.parse(it) }
        assertTrue(isTrustedProxyPeer("10.255.3.4", eight))
        assertFalse(isTrustedProxyPeer("100.1.2.3", eight), "'10' is a string prefix of '100' but not a network prefix")
        // Sub-byte prefixes.
        val half = listOf("192.168.128.0/17").mapNotNull { CidrBlock.parse(it) }
        assertTrue(isTrustedProxyPeer("192.168.200.9", half))
        assertFalse(isTrustedProxyPeer("192.168.127.9", half))
    }

    @Test
    fun cidrParse_failsClosedOnAnythingMalformed() {
        // A hostname would make the trusted set depend on a resolver; a bad prefix or junk is a typo.
        for (bad in listOf("proxy.internal", "proxy.internal/32", "127.0.0.1/33", "::1/129", "127.0.0.1/-1", "127.0.0.1/x", "", "  ", "999.1.1.1", "/8")) {
            assertNull(CidrBlock.parse(bad), "'$bad' must not parse into a trusted network")
        }
        // A bare literal is a single host.
        val host = CidrBlock.parse("172.18.0.1")!!
        assertTrue(host.contains(java.net.InetAddress.getByName("172.18.0.1")))
        assertFalse(host.contains(java.net.InetAddress.getByName("172.18.0.2")))
        // Families never cross-match, in either direction.
        assertFalse(CidrBlock.parse("0.0.0.0/0")!!.contains(java.net.InetAddress.getByName("::1")))
        assertFalse(CidrBlock.parse("::/0")!!.contains(java.net.InetAddress.getByName("127.0.0.1")))
        // …but /0 does admit its own family wholesale, which is why declaring one is an operator act.
        assertTrue(CidrBlock.parse("0.0.0.0/0")!!.contains(java.net.InetAddress.getByName("8.8.8.8")))
        // An unparseable PEER is not trusted either (fail closed).
        assertFalse(isTrustedProxyPeer("not-an-address-!", listOf(CidrBlock.parse("0.0.0.0/0")!!)))
    }

    @Test
    fun env_parsesAndLints() {
        val base = mapOf(
            "ANDVARI_ENUM_SECRET" to io.silencelen.andvari.core.crypto.Bytes.toB64(ByteArray(32) { 3 }),
        )
        // Unset ⇒ the loopback default (today's behaviour verbatim).
        assertEquals(Config.DEFAULT_TRUSTED_PROXY_CIDRS, Config.fromEnv { base[it] }.trustedProxyCidrs)
        val env = base + mapOf("ANDVARI_TRUSTED_PROXY_CIDRS" to "127.0.0.0/8, 172.18.0.1")
        val cfg = Config.fromEnv { env[it] }
        assertEquals(listOf("127.0.0.0/8", "172.18.0.1"), cfg.trustedProxyCidrs)
        assertTrue(isTrustedProxyPeer("172.18.0.1", cfg.trustedProxyNets))
        assertTrue(Config.envLint(env).problems.isEmpty(), "a well-formed list must lint clean: ${Config.envLint(env).problems}")
        // A typo'd entry is dropped by the parser (fail closed) and NAMED by the lint — otherwise
        // the operator would face an instance that still shares one rate-limit key, silently.
        val bad = mapOf("ANDVARI_TRUSTED_PROXY_CIDRS" to "127.0.0.0/8,172.18.0.1/48")
        val problems = Config.envLint(bad).problems
        assertEquals(1, problems.size, "exactly the bad entry: $problems")
        assertTrue(problems.single().contains("172.18.0.1/48"), problems.single())
        // Set-but-empty is a declaration of NO trusted proxy, not "unset".
        val emptyEnv = base + mapOf("ANDVARI_TRUSTED_PROXY_CIDRS" to "")
        assertTrue(Config.fromEnv { emptyEnv[it] }.trustedProxyNets.isEmpty())
        assertTrue(Config.envLint(emptyEnv).notes.any { it.contains("ANDVARI_TRUSTED_PROXY_CIDRS") })
    }

    // ---- over a REAL socket: what actually lands in the audit ip column ----

    /**
     * Deliberately a real Netty listener (the ClientIpSocketAddressTest lesson): the test engine
     * reports "localhost" for the peer, so only a genuine socket proves what the peer literal is.
     */
    private fun registeredAuditIp(config: Config, email: String, forwardedFor: String?): String {
        val services = buildServices(config, Notifier())
        val server = embeddedServer(Netty, port = 0, host = "127.0.0.1") { andvariModule(services) }
        server.start(wait = false)
        try {
            val port = runBlocking { server.engine.resolvedConnectors().first().port }
            val client = HttpClient(Java) { install(ContentNegotiation) { json(json) } }
            val vc = VirtualClient(email, "trusted proxy cidr password", fast = true)
            runBlocking {
                val resp = client.post("http://127.0.0.1:$port/api/v1/auth/register") {
                    contentType(ContentType.Application.Json)
                    header("X-Andvari-Client", "test/1.0.0")
                    forwardedFor?.let { header("X-Forwarded-For", it) }
                    setBody(vc.buildRegister(bootstrapToken, recovery.publicKey, fingerprint))
                }
                assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
            }
            client.close()
            return services.repo.auditQuery(0, "register", null, 10).single().ip ?: ""
        } finally {
            server.stop(500, 2_000)
        }
    }

    /** Case 1 — the reference topology: a loopback proxy, default config. Header honoured. */
    @Test
    fun loopbackPeer_defaultCidrs_forwardedHeaderIsHonoured() {
        assertEquals(
            "203.0.113.7",
            registeredAuditIp(cfg(), "loopback@tp.test", "203.0.113.7"),
            "the default loopback proxy must still speak for its client — no behaviour change for existing deployments",
        )
    }

    /** Case 2 — the peer is inside a DECLARED CIDR (here loopback named explicitly, since a test
     *  cannot conjure a Docker bridge). Trust follows the declaration, not the loopback special case. */
    @Test
    fun declaredCidrPeer_forwardedHeaderIsHonoured() {
        assertEquals(
            "198.51.100.22",
            registeredAuditIp(cfg(listOf("127.0.0.1/32")), "declared@tp.test", "198.51.100.22"),
            "a peer inside the operator's declared CIDR speaks for its client",
        )
    }

    /**
     * Case 3 — the peer is OUTSIDE every declared CIDR and forges a header. It must be ignored:
     * the audit row and the rate key stay on the peer's own address. This is the property that
     * keeps widening the CIDR set a bounded decision rather than an open door.
     */
    @Test
    fun untrustedPeer_forgedForwardedHeaderIsIgnored() {
        assertEquals(
            "127.0.0.1",
            registeredAuditIp(cfg(listOf("10.0.0.0/8")), "forged@tp.test", "8.8.8.8"),
            "a peer outside the trusted set must never be able to name its own client IP",
        )
    }
}
