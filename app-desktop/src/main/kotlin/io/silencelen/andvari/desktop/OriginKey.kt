package io.silencelen.andvari.desktop

import java.security.MessageDigest

/**
 * (origin, userId) namespacing key — design 2026-07-15-multi-tenant-endpoints §4.2 (B2-3/B2-7).
 *
 *     originKey = hex(sha256(canonical origin)).take(16)
 *     canonical  = lowercase `scheme://host[:non-default port]`
 *
 * BYTE-PARITY CONTRACT (binding): Android (`app-android/.../OriginNamespace.kt` — the verified
 * twin: same trim/lowercase/default-port rules, same fallback, same sha256-hex-16 rendering) and
 * the extension compute the SAME key from the SAME hash input, so a household member's originKey
 * is identical across their phone, desktop, and browser. The canonical form is pinned by the
 * shared vectors below (asserted in OriginNamespaceTest — Android's lane pins the same literals):
 *
 *     https://andvari.monahanhosting.com  -> e1fd6516bf573c7f
 *     https://andvari.taila2dff2.ts.net   -> edfce5729b02fa19
 *     http://192.168.2.122:8080           -> 63572e635897bbf3
 *     https://example.org                 -> 50d7a905e3046b88
 *     https://example.org:8443            -> 3e1098e31ab128b1
 *
 * Canonicalization rules (must not drift — any change re-keys every namespace on disk):
 *  - scheme + host lowercased; the DEFAULT port is stripped (https:443 / http:80), any other
 *    port is kept as `:port`. No path / trailing slash / userinfo / query (a stored baseUrl
 *    never carries them; anything past the authority is dropped by the URI parse).
 *  - IPv6 literals keep their brackets (java.net.URI's host form), hex lowercased.
 *  - An unparseable input falls back to hashing the lowercased trimmed string itself — still
 *    deterministic, and such a baseUrl can't reach a server anyway (EnrollLink's ORIGIN regex
 *    and the ServerField only ever produce parseable http(s) origins).
 *
 * The 16-hex-char (64-bit) truncation is stable and path-safe; it names a LOCAL directory /
 * prefs bucket, not a security boundary — collisions would only co-locate two origins' encrypted
 * caches, never leak plaintext.
 */
internal fun originKey(baseUrl: String): String = sha256Hex16(canonicalOrigin(baseUrl))

private fun sha256Hex16(s: String): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(s.encodeToByteArray())
    val sb = StringBuilder(16)
    for (i in 0 until 8) {
        val b = digest[i].toInt() and 0xff
        sb.append(HEX[b ushr 4]).append(HEX[b and 0xf])
    }
    return sb.toString()
}

/**
 * A path-safe rendering of a SERVER-SUPPLIED identifier for use as a path segment or filename
 * fragment (the Android `OriginNamespace.pathSafe` twin — identical regex + digest). Under the
 * endpoint-agnostic model the server is untrusted, and `userId` is server-minted: a hostile
 * server that names a user `../<victim>` must not alias its namespace into another origin's
 * (§4.1 rule 2 holds against hostile INPUTS, not just hostile timing). Benign ids
 * (UUID/ULID-shaped) pass through UNCHANGED — which keeps the §4.2 adoption one-shot's moved
 * legacy filenames (`vault-<userId>.db`, minted from real ids) addressable by the scoped
 * readers. Anything else (separators, dots, over-long, empty) maps to a stable digest — never
 * a traversal.
 */
internal fun pathSafe(raw: String): String =
    if (SAFE_SEGMENT.matches(raw)) raw else sha256Hex16(raw)

private val SAFE_SEGMENT = Regex("[A-Za-z0-9_-]{1,64}")

/** The pinned canonical origin form (see [originKey] header). Exposed for tests. */
internal fun canonicalOrigin(url: String): String {
    val trimmed = url.trim().trimEnd('/')
    val uri = runCatching { java.net.URI(trimmed) }.getOrNull()
    val scheme = uri?.scheme?.lowercase()
    val host = uri?.host?.lowercase()
    if (uri == null || scheme == null || host.isNullOrEmpty()) return trimmed.lowercase()
    val defaultPort = when (scheme) {
        "https" -> 443
        "http" -> 80
        else -> -1
    }
    val port = uri.port
    return if (port == -1 || port == defaultPort) "$scheme://$host" else "$scheme://$host:$port"
}

private const val HEX = "0123456789abcdef"
