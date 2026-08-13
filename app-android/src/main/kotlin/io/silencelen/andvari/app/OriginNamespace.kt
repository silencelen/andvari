package io.silencelen.andvari.app

import io.silencelen.andvari.core.client.OriginCanon
import java.io.File

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
 *
 * The canonicalization itself lives in core's [OriginCanon] (audit F37) — it used to be
 * hand-copied here and in the desktop app under a comment declaring a "BYTE-PARITY CONTRACT",
 * which is not a thing a comment can enforce over a key that names on-disk state. This object is
 * now the android-local NAME for that one implementation, plus [dir], which is android's alone.
 */
object OriginNamespace {

    /**
     * Canonical origin per §4.2: lowercase `scheme://host[:port]` with the scheme-default port
     * stripped (`:443` for https, `:80` for http) and any path/trailing slash dropped. An
     * unparseable input falls back to its lowercased trimmed self — still deterministic, so a
     * malformed persisted URL keeps mapping to one stable (garbage) namespace instead of
     * throwing on every store read.
     */
    fun canonicalOrigin(url: String): String = OriginCanon.canonicalOrigin(url)

    /**
     * Strict validate + canonicalize a USER-TYPED server address for the manual switch (design §4.4;
     * review 2026-07-16). A userinfo/path-bearing input is a bearer-credential PHISHING vector —
     * `https://real.host@evil.example` would let the Trust Gate show a reassuring host while the HTTP
     * stack dials `evil.example`, and a manual switch commits immediately, so the next sign-in leaks an
     * offline-crackable authKey of the real master password (the B2-6 threat). REJECT anything that is
     * not a bare http(s) origin — any userinfo, any path beyond "/", any query/fragment — returning null
     * so the caller refuses it. On success returns the canonical `scheme://host[:port]` the gate shows
     * AND dials.
     */
    fun canonicalServerOrigin(input: String): String? = OriginCanon.canonicalServerOrigin(input)

    /** `hex(sha256(canonical origin)).take(16)` — stable, path-safe, collision-negligible. */
    fun originKey(url: String): String = OriginCanon.originKey(url)

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
    fun pathSafe(raw: String): String = OriginCanon.pathSafe(raw)
}
