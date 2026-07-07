package io.silencelen.andvari.core.client.autofill

/**
 * URI normalization + matching for autofill (spec 02 §3.1) — pure, no Android deps, so
 * the security-critical rule is vector-tested in :core:jvmTest and mirrored in the web
 * client (future browser extension). Cross-registrable-domain fill is impossible by
 * construction: the label-boundary suffix rule only applies to saved hosts with ≥2
 * labels; single-label / TLD hosts match exact-only.
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
            val colon = s.lastIndexOf(':')
            if (colon >= 0 && colon < s.length - 1 && s.substring(colon + 1).all { it.isDigit() }) s.substring(0, colon) else s
        }
        s = s.trim().trimEnd('.').lowercase()
        if (s.startsWith("www.")) s = s.substring(4)
        return s.ifEmpty { null }
    }

    private fun isIpLiteral(host: String): Boolean {
        if (host.contains(':')) return true // IPv6 (brackets already stripped)
        val parts = host.split('.')
        return parts.size == 4 && parts.all { it.isNotEmpty() && it.all { c -> c.isDigit() } && (it.toIntOrNull() ?: 999) in 0..255 }
    }

    fun matches(saved: SavedUri, target: FillTarget): Boolean = when (saved) {
        is SavedUri.AndroidApp -> saved.pkg == target.packageName
        is SavedUri.Web -> {
            val page = target.webHost
            when {
                page == null -> false // no trusted web domain → web items don't match by package
                saved.host == page -> true
                isIpLiteral(saved.host) || isIpLiteral(page) -> false // IPs: exact only
                saved.host.contains('.') && page.endsWith("." + saved.host) -> true // ≥2-label suffix
                else -> false
            }
        }
    }

    /** True if any of an item's login URIs matches the target. */
    fun matchLogins(uris: List<String>, target: FillTarget): Boolean =
        uris.any { parseSavedUri(it)?.let { s -> matches(s, target) } == true }
}
