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

/** X-Andvari-Client: <platform>/<semver>; used for version pins + audit. */
data class ClientId(val platform: String, val version: String)

fun ApplicationCall.clientId(): ClientId {
    val raw = request.header("X-Andvari-Client") ?: return ClientId("unknown", "0.0.0")
    val slash = raw.indexOf('/')
    return if (slash < 0) ClientId(raw, "0.0.0") else ClientId(raw.take(slash), raw.substring(slash + 1))
}

/**
 * Client IP for rate keys + audit rows (spec 03 §8). Both front-ends (tailscale serve,
 * cloudflared) terminate TLS on loopback, so the raw peer address would collapse every
 * remote caller to 127.0.0.1. Forwarded-IP headers are trusted ONLY when the direct
 * peer is loopback; a non-loopback peer (LAN client) can never spoof via XFF.
 * The /metrics loopback gate deliberately does NOT use this (raw peer only).
 */
/**
 * True when the DIRECT TCP peer is a loopback address (both front-ends terminate on
 * 127.0.0.1). The single authority for "is this a local proxy?" — shared by clientIp()'s
 * forwarded-header trust gate and the /metrics access gate so the two can never drift.
 */
fun ApplicationCall.peerIsLoopback(): Boolean =
    runCatching { java.net.InetAddress.getByName(request.origin.remoteAddress).isLoopbackAddress }.getOrDefault(false)

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
    pickClientIp(peerIsLoopback(), { request.header(it) }, config.trustedIpHeaders, request.origin.remoteHost)

/**
 * Pure header selection: the first trusted header bearing a non-loopback IP LITERAL wins.
 * X-Forwarded-For contributes only its RIGHTMOST entry (the one appended by the trusted
 * loopback proxy — deeper entries are client-forgeable). Literal-only because
 * InetAddress.getByName would DNS-resolve hostnames.
 */
internal fun pickClientIp(
    peerIsLoopback: Boolean,
    header: (String) -> String?,
    trustedHeaders: List<String>,
    fallback: String,
): String {
    if (!peerIsLoopback) return fallback
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
