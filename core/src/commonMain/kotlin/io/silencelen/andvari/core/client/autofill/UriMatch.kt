package io.silencelen.andvari.core.client.autofill

/**
 * URI normalization + matching for autofill (spec 02 §3.1) — pure, no Android deps, so
 * the security-critical rule is vector-tested in :core:jvmTest and mirrored in the web +
 * extension clients. Since the 2026-07-10 eTLD+1 amendment, cross-registrable-domain fill
 * is refused whenever both sides positively resolve against the vendored PSL ([Psl]): the
 * new registrable-equality rule both GRANTS same-site matches the old suffix rule missed
 * (saved `login.example.co.uk` now fills `example.co.uk`) and KILLS the boundary crossings
 * it allowed (a saved wildcard-derived suffix like `us-east-1.compute.amazonaws.com` no
 * longer fills every tenant under it). Hosts the snapshot cannot positively resolve —
 * `.lan`/`.local`/unknown TLDs — keep the pre-amendment rules bit-for-bit (fail-safe).
 */
sealed interface SavedUri {
    data class Web(val host: String) : SavedUri
    data class AndroidApp(val pkg: String) : SavedUri
}

/**
 * The fill request target. [webHost] is set by the caller ONLY when the requesting
 * package is a trusted browser (else null → package matching only); it is the domain of
 * the specific field/frame being filled (per-field, so a cross-origin iframe cannot
 * borrow another frame's domain).
 */
data class FillTarget(val webHost: String?, val packageName: String)

object UriMatch {
    const val ANDROID_APP_SCHEME = "androidapp://"

    /** Normalize a saved URI string → SavedUri, or null if unparseable (null never matches). */
    fun parseSavedUri(raw: String): SavedUri? {
        val s = raw.trim()
        if (s.isEmpty()) return null
        if (s.startsWith(ANDROID_APP_SCHEME)) {
            val pkg = s.substring(ANDROID_APP_SCHEME.length).trim()
            return if (pkg.isNotEmpty()) SavedUri.AndroidApp(pkg) else null
        }
        val host = normalizeHost(s) ?: return null
        return SavedUri.Web(host)
    }

    /** Extract + normalize the host of a web URI (mirrors CsvImport.nameFallback host logic). */
    fun normalizeHost(raw: String): String? {
        var s = raw.trim()
        if (s.isEmpty()) return null
        s = Regex("^[A-Za-z][A-Za-z0-9+.\\-]*://").replace(s, "")
        val cut = s.indexOfFirst { it == '/' || it == '?' || it == '#' }
        if (cut >= 0) s = s.substring(0, cut)
        val at = s.lastIndexOf('@')
        if (at >= 0) s = s.substring(at + 1)
        s = if (s.startsWith("[")) {
            val close = s.indexOf(']')
            if (close >= 0) s.substring(1, close) else s.drop(1) // IPv6
        } else {
            // Strip a numeric port ONLY when there is exactly one colon: a bare (unbracketed)
            // IPv6 literal carries ≥2 colons and must survive re-normalization intact — the
            // old lastIndexOf rule turned "2001:db8::1" into "2001:db8:" on a second pass.
            // (Idempotence matters: callers may normalize before matches() normalizes again.)
            val colon = s.lastIndexOf(':')
            val oneColon = colon >= 0 && s.indexOf(':') == colon
            if (oneColon && colon < s.length - 1 && s.substring(colon + 1).all { it in '0'..'9' }) s.substring(0, colon) else s
        }
        s = s.trim().trimEnd('.').lowercase()
        // Strip EVERY leading "www." label (not just one) — normalizeHost must be idempotent,
        // and a single-strip made normalize(normalize("www.www.x")) ≠ normalize("www.www.x"),
        // which had the extension (which pre-normalizes) disagreeing with core/Android.
        while (s.startsWith("www.")) s = s.substring(4)
        if (s.isEmpty()) return null
        // A5: an empty label (".example.com", "a..example.com") is garbage that must not
        // match ANYTHING — the eTLD+1 resolver would otherwise resolve it to its rightmost
        // real family and quietly grant it the new equality rule. (IPv6 hosts contain no
        // dots between hex groups, so this cannot reject them.)
        if (s.split('.').any { it.isEmpty() }) return null
        return s
    }

    private fun isIpLiteral(host: String): Boolean {
        if (host.contains(':')) return true // IPv6 (brackets already stripped)
        val parts = host.split('.')
        // ASCII digits ONLY: Char.isDigit()/toIntOrNull() accept any Unicode Nd digit
        // ("١٢٣" parses as 123), which classified "١.٢.٣.٤" an IP here while the TS
        // mirrors' /^\d+$/ did not — a cross-impl divergence. Vector-pinned.
        return parts.size == 4 && parts.all { p -> p.isNotEmpty() && p.all { it in '0'..'9' } && (p.toIntOrNull() ?: 999) in 0..255 }
    }

    fun matches(saved: SavedUri, target: FillTarget): Boolean = when (saved) {
        is SavedUri.AndroidApp -> saved.pkg == target.packageName
        is SavedUri.Web -> {
            // Normalize the page host symmetrically with saved.host (case / www. / port / trailing
            // dot) — the browser reports it raw, so "GitHub.com" would otherwise miss "github.com".
            val page = target.webHost?.let { normalizeHost(it) }
            when {
                page == null -> false // no trusted web domain → web items don't match by package
                saved.host == page -> true
                isIpLiteral(saved.host) || isIpLiteral(page) -> false // IPs: exact only
                else -> {
                    // eTLD+1 rules (spec 02 §3.1 amendment, design A3):
                    val sr = Psl.resolve(saved.host)
                    val pr = Psl.resolve(page)
                    when {
                        // R-SUFFIX-BARE: a bare public suffix is exact-only in BOTH roles — saved
                        // `github.io` fills no tenant; a page AT `b.kawasaki.jp` gets no
                        // `kawasaki.jp` item. Wildcard-derived suffixes included (A1).
                        sr is PslResult.PublicSuffix || pr is PslResult.PublicSuffix -> false
                        // R-EQ: both positively resolved → EQUALITY decides. Grants the reverse/
                        // sibling matches the old suffix rule missed, and refuses every
                        // known-registrable-boundary crossing the old rule allowed.
                        sr is PslResult.Registrable && pr is PslResult.Registrable -> sr.domain == pr.domain
                        // R-OLD: ≥1 side Unknown (intranet TLDs, snapshot staleness) → the
                        // pre-amendment subdomain rule, bit-for-bit.
                        else -> saved.host.contains('.') && page.endsWith("." + saved.host)
                    }
                }
            }
        }
    }

    /** True if any of an item's login URIs matches the target. */
    fun matchLogins(uris: List<String>, target: FillTarget): Boolean =
        uris.any { parseSavedUri(it)?.let { s -> matches(s, target) } == true }
}
