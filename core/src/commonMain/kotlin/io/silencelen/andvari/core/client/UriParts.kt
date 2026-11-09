package io.silencelen.andvari.core.client

/** The components [OriginCanon] reads from a URI. `port` is -1 when absent. */
internal class UriParts(
    val scheme: String?,
    val userInfo: String?,
    val host: String?,
    val port: Int,
    val rawPath: String?,
    val rawQuery: String?,
    val rawFragment: String?,
)

/**
 * Parses a URI, or returns null if it is malformed. The JVM and Android keep java.net.URI, so
 * origin keys on installed clients cannot change. iOS uses [parseUriRfc2396].
 */
internal expect fun parseUriParts(input: String): UriParts?

/**
 * RFC 2396 URI parsing with the same results as java.net.URI for the fields in [UriParts]:
 * RFC 2732 IPv6 literals, an authority that falls back to registry-based (host null) when it is
 * not a valid server, and visible non-ASCII characters allowed where escapes are.
 * OriginUriDifferentialTest compares the two across a large generated corpus.
 */
internal fun parseUriRfc2396(input: String): UriParts? = try {
    Rfc2396Parser(input).parse()
} catch (_: MalformedUri) {
    null
}

private class MalformedUri : Exception()

private class Rfc2396Parser(private val s: String) {
    private var scheme: String? = null
    private var userInfo: String? = null
    private var host: String? = null
    private var port = -1
    private var path: String? = null
    private var query: String? = null
    private var fragment: String? = null

    private fun bad(): Nothing = throw MalformedUri()

    private fun at(i: Int, c: Char, end: Int = s.length) = i < end && s[i] == c

    /** The first index in [from, end) holding a char of [stops], else [end]. */
    private fun firstOf(from: Int, end: Int, stops: String): Int {
        var i = from
        while (i < end && s[i] !in stops) i++
        return i
    }

    /** Advances past chars in [set]. With [escapes], also past %HH and visible non-ASCII; a broken %HH is malformed. */
    private fun skip(from: Int, end: Int, set: Set<Char>, escapes: Boolean): Int {
        var i = from
        while (i < end) {
            val c = s[i]
            when {
                c in set -> i++
                escapes && c == '%' -> {
                    if (i + 3 > end || s[i + 1] !in HEX || s[i + 2] !in HEX) bad()
                    i += 3
                }
                escapes && c.code > 128 && !c.isSpaceChar() && !c.isISOControl() -> i++
                else -> return i
            }
        }
        return i
    }

    private fun require(from: Int, end: Int, set: Set<Char>) {
        if (skip(from, end, set, escapes = true) != end) bad()
    }

    fun parse(): UriParts {
        val n = s.length
        val colon = firstOf(0, n, ":/?#")
        var p: Int
        if (colon < n && s[colon] == ':') {
            if (colon == 0 || s[0] !in ALPHA) bad()
            if ((1 until colon).any { s[it] !in SCHEME }) bad()
            scheme = s.substring(0, colon)
            p = colon + 1
            if (at(p, '/')) {
                p = hierarchical(p)
            } else {
                val q = firstOf(p, n, "#")
                if (q <= p) bad()
                require(p, q, URIC)
                p = q
            }
        } else {
            p = hierarchical(0)
        }
        if (at(p, '#')) {
            require(p + 1, n, URIC)
            fragment = s.substring(p + 1)
            p = n
        }
        if (p < n) bad()
        return UriParts(scheme, userInfo, host, port, path, query, fragment)
    }

    private fun hierarchical(start: Int): Int {
        val n = s.length
        var p = start
        if (at(p, '/') && at(p + 1, '/')) {
            p += 2
            val q = firstOf(p, n, "/?#")
            if (q > p) authority(p, q) else if (q >= n) bad()
            p = q
        }
        var q = firstOf(p, n, "?#")
        require(p, q, PATH)
        path = s.substring(p, q)
        p = q
        if (at(p, '?')) {
            p++
            q = firstOf(p, n, "#")
            require(p, q, URIC)
            query = s.substring(p, q)
            p = q
        }
        return p
    }

    private fun authority(start: Int, end: Int) {
        val server = if (firstOf(start, end, "]") > start) SERVER_PERCENT else SERVER
        val serverChars = skip(start, end, server, escapes = true) == end
        val registryChars = skip(start, end, REGISTRY, escapes = true) == end
        if (serverChars) {
            try {
                server(start, end)
                return
            } catch (e: MalformedUri) {
                userInfo = null
                host = null
                port = -1
                if (!registryChars) throw e
                return
            }
        }
        if (!registryChars) bad()
    }

    private fun server(start: Int, end: Int) {
        var p = start
        val at = firstOf(p, end, "@")
        if (at < end) {
            require(p, at, USER_INFO)
            userInfo = s.substring(p, at)
            p = at + 1
        }
        if (at(p, '[', end)) {
            p = ipv6Literal(p, end)
        } else {
            val v4 = ipv4(p, end)
            p = if (v4 > p) v4 else hostname(p, end)
        }
        if (at(p, ':', end)) {
            p++
            val digits = firstOf(p, end, "/")
            if (digits > p) {
                if ((p until digits).any { s[it] !in DIGIT }) bad()
                port = s.substring(p, digits).toIntOrNull() ?: bad()
                p = digits
            }
        }
        if (p < end) bad()
    }

    private fun ipv6Literal(start: Int, end: Int): Int {
        val open = start + 1
        val close = firstOf(open, end, "]")
        if (close <= open || close >= end) bad()
        val percent = firstOf(open, close, "%")
        if (percent < close) {
            if (percent + 1 == close) bad()
            if ((percent + 1 until close).any { s[it] !in SCOPE_ID }) bad()
        }
        if (!isIpv6(s.substring(open, percent))) bad()
        host = s.substring(start, close + 1)
        return close + 1
    }

    /** The end of a dotted-quad at [start] that is alone or followed by ':', else -1. */
    private fun ipv4(start: Int, end: Int): Int {
        val stop = skip(start, end, DIGIT_DOT, escapes = false)
        if (stop <= start || !isIpv4(s.substring(start, stop))) return -1
        if (stop < end && s[stop] != ':') return -1
        host = s.substring(start, stop)
        return stop
    }

    private fun hostname(start: Int, end: Int): Int {
        var p = start
        var lastLabel = -1
        while (true) {
            val first = skip(p, end, ALNUM, escapes = false)
            if (first <= p) break
            lastLabel = p
            p = first
            val rest = skip(p, end, ALNUM_DASH, escapes = false)
            if (rest > p) {
                if (s[rest - 1] == '-') bad()
                p = rest
            }
            if (!at(p, '.', end)) break
            p++
            if (p >= end) break
        }
        if (p < end && s[p] != ':') bad()
        if (lastLabel < 0) bad()
        if (lastLabel > start && s[lastLabel] !in ALPHA) bad()
        host = s.substring(start, p)
        return p
    }

    private companion object {
        val ALPHA = (('a'..'z') + ('A'..'Z')).toSet()
        val DIGIT = ('0'..'9').toSet()
        val HEX = DIGIT + ('a'..'f') + ('A'..'F')
        val ALNUM = ALPHA + DIGIT
        val ALNUM_DASH = ALNUM + '-'
        val DIGIT_DOT = DIGIT + '.'
        val SCHEME = ALNUM + "+-.".toSet()
        val UNRESERVED = ALNUM + "_-!.~'()*".toSet()
        val URIC = UNRESERVED + ";/?:@&=+$,[]".toSet()
        val PATH = UNRESERVED + ":@&=+$,;/".toSet()
        val USER_INFO = UNRESERVED + ";:&=+$,".toSet()
        val REGISTRY = UNRESERVED + "$,;:@&=+".toSet()
        val SERVER = USER_INFO + ALNUM + "-.:@[]".toSet()
        val SERVER_PERCENT = SERVER + '%'
        val SCOPE_ID = ALNUM + "_.".toSet()

        fun Char.isSpaceChar() = category == CharCategory.SPACE_SEPARATOR ||
            category == CharCategory.LINE_SEPARATOR || category == CharCategory.PARAGRAPH_SEPARATOR

        fun isIpv4(t: String): Boolean {
            val parts = t.split('.')
            return parts.size == 4 && parts.all { part -> part.all { it in DIGIT } && (part.toIntOrNull() ?: 256) <= 255 }
        }

        /** Hex groups of 1 to 4 digits, optionally one "::", optionally ending in a dotted quad; 16 bytes in total. */
        fun isIpv6(t: String): Boolean {
            val gap = t.indexOf("::")
            if (gap >= 0 && t.indexOf("::", gap + 1) >= 0) return false
            fun bytes(part: String, last: Boolean): Int? {
                if (part.isEmpty()) return 0
                val groups = part.split(':')
                var total = 0
                groups.forEachIndexed { i, g ->
                    total += when {
                        g.length in 1..4 && g.all { it in HEX } -> 2
                        last && i == groups.lastIndex && isIpv4(g) -> 4
                        else -> return null
                    }
                }
                return total
            }
            if (gap < 0) return bytes(t, last = true) == 16
            val left = bytes(t.substring(0, gap), last = false) ?: return false
            val right = bytes(t.substring(gap + 2), last = true) ?: return false
            return left + right < 16
        }
    }
}
