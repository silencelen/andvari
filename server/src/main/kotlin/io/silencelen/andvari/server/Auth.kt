package io.silencelen.andvari.server

import io.ktor.server.application.ApplicationCall
import io.ktor.server.plugins.origin
import io.ktor.server.request.header
import io.silencelen.andvari.core.model.ClientPolicy

/**
 * The authenticated caller, resolved from a Bearer access token. [mustEnrollTotp] marks a
 * RESTRICTED session (design 2026-07-15 §2.6: instance `totpRequired` + user not TOTP-enrolled):
 * requirePrincipal answers 403 totp_enrollment_required on every route except TOTP setup/confirm +
 * logout until enrollment completes. Computed from live DB state at authenticate() time, so
 * confirming TOTP lifts the restriction on the SAME session, tokens unchanged.
 */
data class Principal(
    val userId: String,
    val deviceId: String,
    val sessionId: String,
    val isAdmin: Boolean,
    val mustEnrollTotp: Boolean = false,
)

class UpgradeRequired(val platform: String, val minVersion: String) : Exception()
class Unauthorized(val reason: String = "invalid_credentials") : Exception()
class Forbidden(val reason: String = "forbidden") : Exception()
class BadRequest(val reason: String) : Exception()
class NotFound(val reason: String) : Exception()
class RateLimited : Exception()
class ResyncRequired : Exception()

// Vault lifecycle (spec 03 §11): operation-identity conflicts (vault_state_changed,
// stale_meta, transfer_not_pending, vault_deleted) → 409; past-grace restore → 410.
class Conflict(val reason: String) : Exception()
class Gone(val reason: String) : Exception()

// Upstream (HIBP relay) failure → 502: distinct from a client-input 400 so "HIBP is down"
// never reads as "your prefix was malformed" (polish audit 2026-07-27 bug-server--2).
class BadGateway(val reason: String) : Exception()

// This instance is not CONFIGURED for the thing asked of it → 503: nothing the caller sent is
// wrong and no retry helps until the operator acts (polish audit 2026-07-27 bug-server--9).
// Exists so such a route can still answer inside the ApiError taxonomy every client decodes —
// a bare-string 503 body degrades to the generic "http_503" in AndvariApi.errorFrom, losing the
// one thing the caller needed: the named cause.
class ServiceUnavailable(val reason: String) : Exception()

/** X-Andvari-Client: <platform>/<semver>; used for version pins + audit. */
data class ClientId(val platform: String, val version: String)

fun ApplicationCall.clientId(): ClientId {
    val raw = request.header("X-Andvari-Client") ?: return ClientId("unknown", "0.0.0")
    val slash = raw.indexOf('/')
    return if (slash < 0) ClientId(raw, "0.0.0") else ClientId(raw.take(slash), raw.substring(slash + 1))
}

/**
 * A plausible build string: the semver alphabet (digits, letters, dot, plus, hyphen — enough for
 * `0.21.0`, `1.2.3-rc.4+build.9`) and at most 32 chars. Anchored, so one stray character rejects
 * the whole value rather than letting a prefix through.
 */
private val CLIENT_VERSION_RE = Regex("^[A-Za-z0-9.+-]{1,32}$")

/**
 * The build to stamp on the device row (F23 — `devices.clientVersion`, the Admin device list's
 * "Client" column): the version half of X-Andvari-Client, or null when the caller declared none —
 * or declared something that is not plausibly a build string.
 *
 * Deliberately NOT [ClientId.version]'s "0.0.0" fallback — that sentinel exists so
 * [enforceMinVersion] treats an undeclared build as older than any pin, and persisting it would
 * tell an admin "this device runs 0.0.0" when the truth is "this device never said". Null renders
 * as "—", which is honest.
 *
 * VALIDATED against [CLIENT_VERSION_RE] because this is attacker-chosen text on an UNAUTHENTICATED
 * route (register/login both stamp it) that is now PERSISTED and rendered in the Admin console
 * (server review 2026-08-13). Unbounded, one caller could park a kilobyte of newlines or markup in
 * the row an operator reads to decide a minVersion pin. Rejection returns null — "never said" —
 * rather than a truncated value, so the column never shows a build no device is running; on refresh
 * the COALESCE in issueSession's sibling UPDATE leaves the last GOOD version standing. The console
 * escaping is unchanged and still the XSS boundary; this bounds what reaches the DB at all.
 */
fun ApplicationCall.declaredClientVersion(): String? {
    if (request.header("X-Andvari-Client")?.contains('/') != true) return null
    return clientId().version.takeIf { CLIENT_VERSION_RE.matches(it) }
}

/**
 * Client IP for rate keys + audit rows (spec 03 §8). Both reference front-ends (tailscale serve,
 * cloudflared) terminate TLS on loopback, so the raw peer address would collapse every
 * remote caller to one address. Forwarded-IP headers are trusted ONLY when the direct
 * peer is a TRUSTED PROXY — the operator-declared `ANDVARI_TRUSTED_PROXY_CIDRS`, loopback-only
 * by default; a peer outside that set (a LAN client) can never spoof via XFF.
 * The /metrics gate deliberately does NOT use this (raw loopback peer only).
 */
/**
 * True when the DIRECT TCP peer is a loopback address. RAW loopback, never the operator's
 * trusted-proxy set: the /metrics gate is the one caller, and widening it to a declared CIDR
 * would hand the whole scrape (every metric name and value on the instance) to anything that can
 * reach the port from inside that CIDR. Kept distinct from [peerIsTrustedProxy] for exactly that
 * reason — H14 split the two so the forwarded-header trust decision can be widened by the
 * operator while metrics access cannot.
 */
fun ApplicationCall.peerIsLoopback(): Boolean =
    runCatching { java.net.InetAddress.getByName(peerAddress()).isLoopbackAddress }.getOrDefault(false)

/**
 * One CIDR block from [Config.trustedProxyCidrs], parsed once at boot. Prefix-bit comparison on
 * the raw address bytes: no string prefixes (which would make `10.0.0.0/8` match `100.1.2.3`),
 * and the address FAMILY must match, so an IPv4 block never admits an IPv6 peer or vice versa.
 */
internal class CidrBlock(private val base: ByteArray, private val prefixBits: Int) {
    fun contains(addr: java.net.InetAddress): Boolean {
        val bytes = addr.address
        if (bytes.size != base.size) return false // different family — never a match
        var bits = prefixBits
        var i = 0
        while (bits >= 8) {
            if (bytes[i] != base[i]) return false
            i++; bits -= 8
        }
        if (bits == 0) return true
        val mask = (0xFF shl (8 - bits)) and 0xFF
        return (bytes[i].toInt() and mask) == (base[i].toInt() and mask)
    }

    companion object {
        /**
         * `a.b.c.d/len`, `[v6]/len`, or a bare literal (treated as a single host: /32 or /128).
         * Returns null for anything malformed — a hostname, a bad prefix length, junk — so a
         * typo'd env entry can only ever make the trusted set SMALLER, never wider.
         * [Config.envLint] is the loud channel that names the dropped entry.
         */
        fun parse(raw: String): CidrBlock? {
            val s = raw.trim()
            if (s.isEmpty()) return null
            val slash = s.lastIndexOf('/')
            val host = if (slash < 0) s else s.substring(0, slash)
            // IP LITERAL only — getByName would happily DNS-resolve a hostname, which would make
            // the trusted-proxy set depend on a resolver an attacker may influence.
            if (!isIpLiteral(host)) return null
            val addr = runCatching { java.net.InetAddress.getByName(host) }.getOrNull() ?: return null
            val bytes = addr.address
            val maxBits = bytes.size * 8
            val prefix = if (slash < 0) maxBits else (s.substring(slash + 1).toIntOrNull() ?: return null)
            if (prefix !in 0..maxBits) return null
            return CidrBlock(bytes, prefix)
        }
    }
}

/**
 * True when [peer] (a socket-address literal) falls inside one of [nets]. Pure, so the trust
 * decision this whole header story rests on is unit-testable without a socket (H14).
 * An unparseable peer is NOT trusted — fail closed.
 */
internal fun isTrustedProxyPeer(peer: String, nets: List<CidrBlock>): Boolean {
    val addr = runCatching { java.net.InetAddress.getByName(peer) }.getOrNull() ?: return false
    return nets.any { it.contains(addr) }
}

/**
 * True when the DIRECT TCP peer is an operator-declared trusted reverse proxy — the gate on
 * honouring forwarded-IP headers (H14, audit 2026-09-13).
 *
 * This used to be [peerIsLoopback] alone, on the premise that a front-end always terminates on
 * 127.0.0.1. That premise is false for the topology docs/self-hosting.md actually prescribes: a
 * host-side proxy (nginx, cloudflared, `tailscale serve`) pointed at the container's PUBLISHED
 * `127.0.0.1:8080` reaches the JVM through docker-proxy or the bridge DNAT, so the peer the
 * server sees is the compose bridge GATEWAY (172.x.0.1) — never loopback. Every request then
 * shared one rate-limit key (one stranger's failed logins 429'd the whole household) and one
 * audit `ip`, and setting ANDVARI_TRUSTED_IP_HEADERS could not help, because the header was
 * never consulted at all.
 *
 * The operator now DECLARES which peers are their proxy. Default is loopback only, so every
 * existing deployment keeps byte-identical behaviour; a bridge self-host adds its gateway (or
 * the bridge subnet) and gets real per-client keys. Declaring a wide CIDR is a real decision —
 * anything inside it can name its own client IP — which is why it is an explicit operator act
 * and not something the server infers from the peer it happens to see.
 */
fun ApplicationCall.peerIsTrustedProxy(config: Config): Boolean =
    isTrustedProxyPeer(peerAddress(), config.trustedProxyNets)

/**
 * The direct TCP peer's SOCKET ADDRESS as a literal — the one accessor both [peerIsLoopback] and
 * [clientIp]'s fallback read, so the two halves of spec 03 §8's "client IP" paragraph can never
 * disagree about what a peer IS (H82, audit 2026-09-13). Deliberately `remoteAddress`, never
 * Ktor's `remoteHost`: on the Netty engine remoteHost is InetSocketAddress.getHostName — a
 * blocking reverse-DNS (PTR) lookup, name first and the literal only as a fallback — so the
 * old fallback (a) wrote `localhost` into audit rows for every loopback peer and, on a LAN with
 * PTR records, DHCP-lease-dependent hostnames into a column labelled "ip", (b) keyed the login
 * bucket on whatever the resolver said (two hosts sharing a stale PTR shared one 5/min budget),
 * and (c) parked every un-forwarded new peer's first request on a PTR timeout while the LAN
 * resolver was down. The reference front-ends always carry XFF and never hit the fallback; the
 * direct-LAN self-host (ANDVARI_BIND=0.0.0.0) and every local audit read did. Reverse names,
 * if ever wanted for the admin view, belong in the UI — never in the request path.
 */
internal fun ApplicationCall.peerAddress(): String = request.origin.remoteAddress

/**
 * Reverse-proxy forwarding headers that a genuine LOCAL scrape/caller never carries but that
 * BOTH front-ends (tailscale-serve, cloudflared) stamp on every request they forward. Used ONLY
 * by the /metrics gate: peerIsLoopback() is true for every PROXIED request too (both front-ends
 * terminate TLS on 127.0.0.1), so it alone cannot tell a real local Alloy scrape from a request
 * that merely arrived via a front-end — a request bearing ANY of these did. Deliberately a broad
 * superset of trustedIpHeaders (presence-only; never consulted for clientIp trust).
 */
val FORWARDED_HEADER_NAMES = listOf(
    "X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP", "True-Client-IP",
    "Forwarded", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port",
)

/**
 * True when the request carries any reverse-proxy forwarding header (see [FORWARDED_HEADER_NAMES])
 * OR any operator-configured trusted IP header ([extraTrusted], normally `config.trustedIpHeaders`).
 * A genuine loopback Alloy /metrics scrape has none; anything via tailscale-serve or cloudflared has
 * at least one. Including [extraTrusted] makes the "superset of trustedIpHeaders" contract real, so a
 * custom front-end stamping only a non-default trusted header can't slip past the /metrics gate
 * (server review 2026-07-15). Header-PRESENCE check only — it does not affect clientIp() trust.
 */
fun ApplicationCall.hasForwardedHeader(extraTrusted: List<String> = emptyList()): Boolean =
    (FORWARDED_HEADER_NAMES + extraTrusted).any { request.header(it) != null }

fun ApplicationCall.clientIp(config: Config): String =
    pickClientIp(peerIsTrustedProxy(config), { request.header(it) }, config.trustedIpHeaders, peerAddress())

/**
 * Pure header selection: the first trusted header bearing a non-loopback IP LITERAL wins.
 * X-Forwarded-For contributes only its RIGHTMOST entry (the one appended by the trusted
 * proxy — deeper entries are client-forgeable). Literal-only because
 * InetAddress.getByName would DNS-resolve hostnames.
 */
internal fun pickClientIp(
    peerIsTrustedProxy: Boolean,
    header: (String) -> String?,
    trustedHeaders: List<String>,
    fallback: String,
): String {
    if (!peerIsTrustedProxy) return fallback
    for (name in trustedHeaders) {
        val raw = header(name) ?: continue
        val candidate = (if (name.equals("X-Forwarded-For", ignoreCase = true)) raw.substringAfterLast(',') else raw).trim()
        if (candidate.isEmpty() || !isIpLiteral(candidate)) continue
        val addr = runCatching { java.net.InetAddress.getByName(candidate) }.getOrNull() ?: continue
        // Reject loopback (127.0.0.1/::1) and wildcard/unspecified (0.0.0.0/"::") literals —
        // they name no client and would just poison rate keys + audit rows.
        if (!addr.isLoopbackAddress && !addr.isAnyLocalAddress) return candidate
    }
    return fallback
}

private val IPV4_RE = Regex("""^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$""")

internal fun isIpLiteral(s: String): Boolean {
    if (IPV4_RE.matchEntire(s) != null) return s.split('.').all { o -> o.toInt() in 0..255 }
    return s.contains(':') && s.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }
}

/**
 * True when the request arrived via the configured public (break-glass) hostname. EXACT host
 * equality after stripping any `:port` suffix (design 2026-07-15 §7.2 hygiene): the old substring
 * `contains` let a crafted Host header (`evil-<public>`, `<public>.evil.com`) select — or dodge —
 * the public régime at will. Unset env ⇒ never public: single-origin instances get today's private
 * régime verbatim, and the whole break-glass bundle stays in the code, inert.
 */
fun ApplicationCall.isPublicOrigin(config: Config): Boolean {
    val public = config.publicHostname?.takeIf { it.isNotBlank() } ?: return false
    // `host[:port]` → host. A bracketed IPv6 literal degrades to a never-matching token ("["…),
    // which is correct here by construction: publicHostname is a DNS name, never an IP literal.
    // Strip :port AND a trailing FQDN root dot ("pubhost." == "pubhost") — else a proxied request with a
    // trailing-dot Host would exact-mismatch and be served the PRIVATE régime over the public tunnel
    // (review 2026-07-16 F1 — the old host.contains() matched the trailing-dot form).
    val host = (request.header("Host") ?: request.origin.serverHost).trim().substringBefore(':').removeSuffix(".")
    return host.equals(public, ignoreCase = true)
}

/** semver compare a<b → -1; only numeric major.minor.patch (pre-release ignored). */
fun compareVersions(a: String, b: String): Int {
    fun parts(v: String) = v.substringBefore('-').split('.').map { it.toIntOrNull() ?: 0 }
    val pa = parts(a); val pb = parts(b)
    for (i in 0 until maxOf(pa.size, pb.size)) {
        val x = pa.getOrElse(i) { 0 }; val y = pb.getOrElse(i) { 0 }
        if (x != y) return x.compareTo(y)
    }
    return 0
}

fun enforceMinVersion(policy: ClientPolicy, client: ClientId) {
    val min = policy.minVersion[client.platform] ?: return
    if (compareVersions(client.version, min) < 0) throw UpgradeRequired(client.platform, min)
}
