package io.silencelen.andvari.core.client

import java.security.MessageDigest

/**
 * (origin, userId) namespacing primitives — design 2026-07-15-multi-tenant-endpoints §4.2
 * (breakers B2-3/B2-7), and the strict address validation of §4.4.
 *
 *     originKey = hex(sha256(canonical origin)).take(16)
 *     canonical = lowercase `scheme://host[:non-default port]`
 *
 * WHY THIS FILE EXISTS (audit F37). Android and desktop each carried their own copy of these
 * five functions, and the coupling between them was declared as a comment — "BYTE-PARITY
 * CONTRACT (binding)" — enforced only by two test files repeating the same literals in two
 * modules. That is a hand-maintained invariant guarding an on-disk key: a one-sided edit
 * silently splits a household member's originKey between their phone and their laptop, pointing
 * each at a DIFFERENT namespace (different vault cache DB, different quick-unlock blob) for the
 * same server, with no error anywhere. The copies had already drifted in shape (two different
 * hex renderings, one extra helper on android) though not yet in output. `src/jvmShared` compiles
 * into both `jvmMain` and `androidMain`, so the same bytes now reach both apps by construction
 * and the contract is the compiler's, not a comment's. The app-side files stay as thin,
 * module-local aliases so call sites and their tests read unchanged.
 *
 * The pinned canonical forms (asserted here by OriginCanonTest, and still by each app's own
 * OriginNamespaceTest and by the extension — they now agree BECAUSE there is one implementation):
 *
 *     https://vault.example.net -> 45858d4d141c5edd
 *     http://192.168.1.9:8080   -> 4e629db6dc46b0f6
 *     https://example.org       -> 50d7a905e3046b88
 *     https://example.org:8443  -> 3e1098e31ab128b1
 *
 * Canonicalization rules (must not drift — any change re-keys every namespace on disk):
 *  - scheme + host lowercased; the DEFAULT port is stripped (https:443 / http:80), any other
 *    port is kept as `:port`. No path / trailing slash / userinfo / query (a stored baseUrl
 *    never carries them; anything past the authority is dropped by the URI parse).
 *  - IPv6 literals keep their brackets (java.net.URI's host form), hex lowercased.
 *  - An unparseable input falls back to hashing the lowercased trimmed string itself — still
 *    deterministic, so a malformed persisted URL keeps mapping to one stable (garbage)
 *    namespace instead of throwing on every store read.
 *
 * The 16-hex-char (64-bit) truncation is stable and path-safe; it names a LOCAL directory /
 * prefs bucket, not a security boundary — a collision would only co-locate two origins'
 * encrypted caches, never leak plaintext.
 */
object OriginCanon {

    /** The pinned canonical origin form (see the header). Total: never throws. */
    fun canonicalOrigin(url: String): String {
        val trimmed = url.trim().trimEnd('/')
        val uri = runCatching { java.net.URI(trimmed) }.getOrNull()
        val scheme = uri?.scheme?.lowercase()
        val host = uri?.host?.lowercase() // URI keeps IPv6 brackets ("[::1]") — fine, deterministic
        if (scheme == null || host.isNullOrEmpty()) return trimmed.lowercase()
        return "$scheme://$host" + portSuffix(scheme, uri.port)
    }

    /**
     * Strict validate + canonicalize a USER-TYPED server address for the manual switch (design
     * §4.4; review 2026-07-16). A userinfo/path-bearing input is a bearer-credential PHISHING
     * vector — `https://real.host@evil.example` would let the Trust Gate show a reassuring host
     * while the HTTP stack dials `evil.example`, and a manual switch commits immediately, so the
     * next sign-in leaks an offline-crackable authKey of the real master password (the B2-6
     * threat). REJECT anything that is not a bare http(s) origin — any userinfo, any path beyond
     * "/", any query/fragment — returning null so the caller refuses it. On success returns the
     * canonical `scheme://host[:port]` the gate shows AND dials. Mirrors the extension's
     * `canonicalizeServerUrl`.
     */
    fun canonicalServerOrigin(input: String): String? {
        val trimmed = input.trim().trimEnd('/')
        val uri = runCatching { java.net.URI(trimmed) }.getOrNull() ?: return null
        val scheme = uri.scheme?.lowercase() ?: return null
        if (scheme != "https" && scheme != "http") return null
        if (uri.userInfo != null) return null // `user[:pass]@` — the phishing vector; refuse outright
        val host = uri.host?.lowercase()
        if (host.isNullOrEmpty()) return null
        if (!uri.rawPath.isNullOrEmpty() && uri.rawPath != "/") return null // no path
        if (uri.rawQuery != null || uri.rawFragment != null) return null // no query/fragment
        return "$scheme://$host" + portSuffix(scheme, uri.port)
    }

    /** `hex(sha256(canonical origin)).take(16)` — stable, path-safe, collision-negligible. */
    fun originKey(url: String): String = sha256Hex16(canonicalOrigin(url))

    /**
     * A path-safe rendering of a SERVER-SUPPLIED identifier for use as a path segment or
     * filename fragment. Under the endpoint-agnostic model the server is untrusted, and `userId`
     * is server-minted: a hostile server that names a user `../<victim>` must not alias its
     * namespace into another origin's (§4.1 rule 2 holds against hostile INPUTS, not just
     * hostile timing). Benign ids (UUID/ULID-shaped) pass through UNCHANGED — which keeps the
     * §4.2 adoption one-shot's moved legacy filenames (`vault-<userId>.db`, minted from real
     * ids) addressable by the scoped readers. Anything else (separators, dots, over-long, empty)
     * maps to a stable digest — never a traversal.
     */
    fun pathSafe(raw: String): String =
        if (SAFE_SEGMENT.matches(raw)) raw else sha256Hex16(raw)

    /** "" for the scheme's default port (and for an absent one), ":$port" otherwise. */
    private fun portSuffix(scheme: String, port: Int): String {
        val default = when (scheme) {
            "https" -> 443
            "http" -> 80
            else -> -1
        }
        return if (port == -1 || port == default) "" else ":$port"
    }

    private val SAFE_SEGMENT = Regex("[A-Za-z0-9_-]{1,64}")

    private fun sha256Hex16(s: String): String =
        MessageDigest.getInstance("SHA-256").digest(s.encodeToByteArray())
            .joinToString("") { "%02x".format(it) }
            .take(16)
}
