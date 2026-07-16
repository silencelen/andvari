package io.silencelen.andvari.app

import java.io.File
import java.security.MessageDigest

/**
 * (origin, userId) namespacing for everything durable this app keeps per server — the vault
 * cache DB, the quick-unlock blob, and the `ns.<originKey>.` SharedPreferences prefix
 * (design 2026-07-15-multi-tenant-endpoints §4.2, breakers B2-3/B2-7).
 *
 * Invariant the whole scheme exists to enforce: **a probe of / switch to server B never reads,
 * mints, or wipes server A's namespace** (§4.1 rule 2). Before this, a mere policy probe of an
 * `offlineCacheAllowed=false` server ran an origin-blind GLOBAL purge that destroyed the home
 * server's offline data and account keys.
 *
 * The key is stable and path-safe: `hex(sha256(canonical origin)).take(16)` over the canonical
 * lowercase `scheme://host[:non-default port]` form — so the SAME instance reached through the
 * SAME URL always lands in the same namespace, and two fronts of one instance (tailnet vs
 * public) are DIFFERENT namespaces by design (§6.2's migration moves data between them).
 */
object OriginNamespace {

    /**
     * Canonical origin per §4.2: lowercase `scheme://host[:port]` with the scheme-default port
     * stripped (`:443` for https, `:80` for http) and any path/trailing slash dropped. An
     * unparseable input falls back to its lowercased trimmed self — still deterministic, so a
     * malformed persisted URL keeps mapping to one stable (garbage) namespace instead of
     * throwing on every store read.
     */
    fun canonicalOrigin(url: String): String {
        val trimmed = url.trim().trimEnd('/')
        val uri = runCatching { java.net.URI(trimmed) }.getOrNull()
        val scheme = uri?.scheme?.lowercase()
        val host = uri?.host?.lowercase() // URI keeps IPv6 brackets ("[::1]") — fine, deterministic
        if (scheme == null || host.isNullOrEmpty()) return trimmed.lowercase()
        val port = uri.port // -1 when absent
        val isDefault = (scheme == "https" && port == 443) || (scheme == "http" && port == 80)
        return if (port == -1 || isDefault) "$scheme://$host" else "$scheme://$host:$port"
    }

    /** `hex(sha256(canonical origin)).take(16)` — stable, path-safe, collision-negligible. */
    fun originKey(url: String): String = sha256Hex16(canonicalOrigin(url))

    /**
     * The on-disk namespace directory: `<base>/ns/<originKey>/<userId>/`. Callers that WRITE
     * under it run `mkdirs()` at the use site; this function has no side effects.
     *
     * [userId] is SERVER-SUPPLIED (login/register responses mint it), and under the
     * endpoint-agnostic model the server is untrusted — so the segment is laundered through
     * [pathSafe] before it becomes a path component. A hostile server that names a user
     * `../<victim>` must not alias its namespace into another origin's (§4.1 rule 2 holds
     * against hostile INPUTS, not just hostile timing).
     */
    fun dir(base: File, originKey: String, userId: String): File =
        File(File(File(base, "ns"), pathSafe(originKey)), pathSafe(userId))

    /**
     * A path-safe rendering of a server-supplied identifier for use as a path segment or
     * filename fragment. Benign ids (UUID/ULID-shaped) pass through UNCHANGED — which keeps the
     * adoption one-shot's moved legacy filenames (`vault-<userId>.db`, minted from real ids)
     * addressable by the scoped readers. Anything else (separators, dots, over-long, empty)
     * maps to a stable digest — never a traversal.
     */
    fun pathSafe(raw: String): String =
        if (SAFE_SEGMENT.matches(raw)) raw else sha256Hex16(raw)

    private val SAFE_SEGMENT = Regex("[A-Za-z0-9_-]{1,64}")

    private fun sha256Hex16(s: String): String =
        MessageDigest.getInstance("SHA-256").digest(s.encodeToByteArray())
            .joinToString("") { "%02x".format(it) }
            .take(16)
}
