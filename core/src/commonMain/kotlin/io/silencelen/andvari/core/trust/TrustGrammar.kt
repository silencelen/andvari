package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Bytes

/**
 * The value types of the canonical statement grammar (design 2026-11-15 §2.2) and the encoding rules
 * every domain string shares (§2.3, R3). One implementation for every statement, link, bundle and kit,
 * so that a value is judged the same wherever it appears.
 *
 * Every function is total and table-free: no regular-expression engine, locale or Unicode table decides
 * an outcome, so the JVM, Android, iOS and the web twin (`web/src/crypto/trust/grammar.ts`) cannot
 * disagree. `spec/test-vectors/encodings.json` and the grammar rows of `statement-v2.json` grade it.
 *
 * Text form. A statement carries every value as text, and the types below are the predicates over
 * that text. The typed statement classes of this package hold the SAME canonical text for ids, keys and
 * hashes (a `b64_32` key is its 43 characters), so two keys are equal exactly when their strings are:
 * the strict decode (re-encode and compare) makes text and bytes a bijection.
 */
object TrustGrammar {
    /** 2^53: every `int` and `ms` is below it, so a JavaScript engine reads it exactly. */
    const val INT_CEILING = 9007199254740992L

    /** 64 `0` characters: `prev` of a log's genesis (§3.2) and of card 0 (§4.2). */
    const val ZERO_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    /** The literal a `hex64n` or `email_b64n` field carries when it has no value (§2.2). */
    const val NONE = "none"

    /** §2.3: the closed list of `platform` values. */
    val PLATFORMS: Set<String> = setOf("android", "ios", "windows", "macos", "linux", "web", "cli", "extension")

    // ---- inherited types (spec 01 §5.1) ------------------------------------------------------------

    /** `uuid`: lowercase `8-4-4-4-12` hex. No version or variant is checked. */
    fun isUuid(s: String): Boolean {
        if (s.length != 36) return false
        for (i in s.indices) {
            val c = s[i]
            if (i == 8 || i == 13 || i == 18 || i == 23) {
                if (c != '-') return false
            } else if (!isLowerHex(c)) {
                return false
            }
        }
        return true
    }

    /** `hex64`: exactly 64 lowercase hex characters. */
    fun isHex64(s: String): Boolean = s.length == 64 && s.all(::isLowerHex)

    /** `b64_16`: 22 characters of unpadded base64url that decode to 16 bytes and re-encode identically. */
    fun isB64_16(s: String): Boolean = s.length == 22 && Bytes.fromB64Exact(s, 16) != null

    /** `b64_32`: 43 characters of unpadded base64url that decode to 32 bytes and re-encode identically. */
    fun isB64_32(s: String): Boolean = s.length == 43 && Bytes.fromB64Exact(s, 32) != null

    /** `ms`: `1 <= x < 2^53`. (The text form has no sign and no leading zero; see [parseMs].) */
    fun isMs(x: Long): Boolean = x in 1 until INT_CEILING

    // ---- new types (§2.2) --------------------------------------------------------------------------

    /** `int`: `0 <= x < 2^53`. (Text form: `0`, or `[1-9][0-9]*`; see [parseInt].) */
    fun isInt(x: Long): Boolean = x in 0 until INT_CEILING

    /** The value of an `int` token, or null when [token] is not `0` or `[1-9][0-9]*` below 2^53. */
    fun parseInt(token: String): Long? {
        if (token.isEmpty() || token.length > 16) return null
        if (token.any { it !in '0'..'9' }) return null
        if (token.length > 1 && token[0] == '0') return null
        return token.toLong().takeIf(::isInt)
    }

    /** The value of an `ms` token, or null when [token] is not `[1-9][0-9]*` with `1 <= x < 2^53`. */
    fun parseMs(token: String): Long? = parseInt(token)?.takeIf(::isMs)

    /** `hex64n`: a `hex64`, or the literal `none`. */
    fun isHex64n(s: String): Boolean = s == NONE || isHex64(s)

    /** `role`: `writer` or `reader`. `owner` is never a statement value: only `genesis` and `accept` make one. */
    fun isRole(s: String): Boolean = s == "writer" || s == "reader"

    /** §2.3: one of [PLATFORMS]. */
    fun isPlatform(s: String): Boolean = s in PLATFORMS

    /**
     * `origin` (§2.2, R4, VR-5): **the single source** for every origin a client stores, dials or shows.
     * `OriginCanon`, the Trust Gate and `andvari setup` refuse whatever this refuses.
     *
     * - `https://` + host + optional `:port`, all lowercase.
     * - Host: a DNS name of at least two labels, each `[a-z0-9]([a-z0-9-]*[a-z0-9])?` and 1..63
     *   characters, joined by `.`, with no trailing dot; the whole host is at most 253 characters.
     * - An `xn--` label is an ordinary label: compared byte for byte, never decoded or checked as
     *   punycode, so no engine's IDNA tables decide anything.
     * - **IP literals are refused.** A bracketed IPv6 literal fails the label grammar. A host whose LAST
     *   label is all digits, or is `0x` followed only by hex digits, is refused, because URL parsers read
     *   such a host as an IPv4 address whatever the count or range of its labels (`1.2.3`, `999.1.1.1`,
     *   `example.123`).
     * - Port: `1..65535` without leading zeros, and never the scheme's default (`443` for https, `80`
     *   for http).
     * - The only plain-http forms are `http://localhost[:port]` and `http://127.0.0.1[:port]`
     *   (development only).
     * - No path (not even a trailing `/`), query, fragment or userinfo.
     */
    fun isOrigin(s: String): Boolean {
        val rest: String
        val plainHttp: Boolean
        when {
            s.startsWith("https://") -> {
                rest = s.substring(8)
                plainHttp = false
            }
            s.startsWith("http://") -> {
                rest = s.substring(7)
                plainHttp = true
            }
            else -> return false
        }
        val colon = rest.indexOf(':')
        val host = if (colon < 0) rest else rest.substring(0, colon)
        if (colon >= 0 && !isPort(rest.substring(colon + 1), defaultPort = if (plainHttp) 80 else 443)) return false
        return if (plainHttp) host == "localhost" || host == "127.0.0.1" else isDnsName(host)
    }

    private fun isPort(p: String, defaultPort: Int): Boolean {
        if (p.isEmpty() || p.length > 5) return false
        if (p.any { it !in '0'..'9' } || p[0] == '0') return false
        val n = p.toInt()
        return n in 1..65535 && n != defaultPort
    }

    private fun isDnsName(host: String): Boolean {
        if (host.length > 253) return false
        val labels = host.split('.')
        if (labels.size < 2) return false
        for (label in labels) {
            if (label.isEmpty() || label.length > 63) return false // empty: a leading, trailing or doubled dot
            if (label.first() == '-' || label.last() == '-') return false
            if (label.any { !(it in 'a'..'z' || it in '0'..'9' || it == '-') }) return false
        }
        return !isNumberLabel(labels.last())
    }

    /** The "ends in a number" test of URL host parsing: all digits, or `0x` and then only hex digits. */
    private fun isNumberLabel(label: String): Boolean {
        if (label.all { it in '0'..'9' }) return true
        return label.startsWith("0x") && label.substring(2).all(::isLowerHex)
    }

    /**
     * `name` (§2.2, R3), decoded: the text of a display name, or null when [b64] is not one.
     *
     * - Unpadded base64url that re-encodes identically, decoding to 1..64 bytes.
     * - The bytes are valid UTF-8, decoded here (overlong forms, surrogates, code points above U+10FFFF
     *   and truncated sequences are all refused), so no platform decoder decides.
     * - None of these code points: U+0000–U+001F, U+007F–U+009F, U+00AD, U+061C, U+180E, U+200B–U+200F,
     *   U+2028–U+202E, U+2060–U+2064, U+2066–U+206F, U+FEFF, U+FFF9–U+FFFB. The list is explicit so that
     *   no engine's Unicode tables decide the outcome.
     * - No leading or trailing U+0020.
     *
     * No normalisation is applied. Clients render the result only as plain text.
     */
    fun decodeName(b64: String): String? {
        val bytes = Bytes.fromB64Canonical(b64) ?: return null
        if (bytes.size !in 1..64) return null
        val codePoints = decodeUtf8Strict(bytes) ?: return null
        if (codePoints.any(::isRefusedNameCodePoint)) return null
        if (codePoints.first() == 0x20 || codePoints.last() == 0x20) return null
        return bytes.decodeToString() // lossless: the bytes were just proven to be well-formed UTF-8
    }

    /** `name`: see [decodeName]. */
    fun isName(b64: String): Boolean = decodeName(b64) != null

    /**
     * The `name` form of [text] (unpadded base64url of its UTF-8 bytes), or null when [text] cannot be a
     * name: empty, longer than 64 UTF-8 bytes, ill-formed UTF-16, a refused code point, or a leading or
     * trailing space. A caller that takes a name from a person checks it with this before it signs.
     */
    fun encodeName(text: String): String? {
        val bytes = try {
            text.encodeToByteArray(throwOnInvalidSequence = true)
        } catch (e: Exception) {
            return null // a lone surrogate
        }
        val b64 = Bytes.toB64(bytes)
        return if (decodeName(b64) != null) b64 else null
    }

    /**
     * `emailNorm` (§2.3, VR-6): the one normal form of an email address, or null when the address is
     * refused (the verdict `invalid_email`; on the wire `400 invalid_email`).
     *
     * 1. Strip ASCII white space (space, tab, CR, LF) from both ends.
     * 2. Refuse an address that, AFTER the strip, is shorter than 3 or longer than 254 octets, holds any
     *    byte outside `0x21..0x7E` (so an interior space, a tab, any control character, DEL and any
     *    non-ASCII character), or does not have exactly one `@` with non-empty parts.
     * 3. Lowercase ASCII `A–Z` only: no Unicode case folding, no locale.
     * 4. The lowercased address must be `local@domain` (spec 01 §5.5): `local` a dot-atom
     *    of 1..[EMAIL_LOCAL_MAX] characters of `a–z`, `0–9` and ``!#$%&'*+/=?^_`{|}~-`` with single dots
     *    between non-empty parts (so no quote, comment, angle bracket, space, leading, trailing or
     *    doubled dot), and `domain` two or more labels under the host grammar of [isOrigin]'s https form
     *    (the same function; the plain-http `localhost` and `127.0.0.1` forms are the origin type's, not
     *    the host grammar's, so no address domain takes them).
     *
     * This is the ONE address rule: every statement field, link offer, device-link `outer` and bundle,
     * kit and sign-up input in core goes through it, and the server's `Grammar.emailNorm` builds on it.
     */
    fun emailNorm(raw: String): String? {
        var start = 0
        var end = raw.length
        while (start < end && isAsciiSpace(raw[start])) start++
        while (end > start && isAsciiSpace(raw[end - 1])) end--
        val t = raw.substring(start, end)
        // Every accepted character is one octet, so the character count is the octet count.
        if (t.length < 3 || t.length > 254) return null
        for (c in t) if (c.code < 0x21 || c.code > 0x7E) return null
        val at = t.indexOf('@')
        if (at <= 0 || at == t.length - 1 || at != t.lastIndexOf('@')) return null
        val out = StringBuilder(t.length)
        for (c in t) out.append(if (c in 'A'..'Z') (c.code + 0x20).toChar() else c)
        val norm = out.toString()
        if (!isDotAtom(norm.substring(0, at))) return null
        if (!isDnsName(norm.substring(at + 1))) return null
        return norm
    }

    /** The longest local part an `emailNorm` takes (spec 01 §5.5). */
    const val EMAIL_LOCAL_MAX = 64

    /**
     * The local part of an `emailNorm` (spec 01 §5.5), already lowercased: 1..[EMAIL_LOCAL_MAX]
     * characters, each a lowercase letter, a digit, one of ``!#$%&'*+/=?^_`{|}~-`` or a dot, where a dot
     * only ever stands between two non-empty runs of the others.
     */
    private fun isDotAtom(local: String): Boolean {
        if (local.isEmpty() || local.length > EMAIL_LOCAL_MAX) return false
        if (local.first() == '.' || local.last() == '.') return false
        for (i in local.indices) {
            val c = local[i]
            if (c == '.') {
                if (local[i - 1] == '.') return false
            } else if (!(c in 'a'..'z' || c in '0'..'9' || c in ATEXT_PUNCTUATION)) {
                return false
            }
        }
        return true
    }

    /** The punctuation of a dot-atom (spec 01 §5.5): ``!#$%&'*+/=?^_`{|}~-``. */
    private const val ATEXT_PUNCTUATION = "!#$%&'*+/=?^_`{|}~-"

    /**
     * `email_b64n` (§2.2, N3, VR-7), decoded. Returns [Email.None] for the literal `none`, [Email.Of] for
     * the unpadded base64url of the ASCII bytes of an `emailNorm` (decoded 3..254 bytes, re-encoding
     * identically), and null for anything else. The decoded bytes must ALREADY be normal: `emailNorm` of
     * them equals them exactly, so an uppercase letter or a surrounding space inside is refused.
     */
    fun decodeEmail(field: String): Email? {
        if (field == NONE) return Email.None
        val bytes = Bytes.fromB64Canonical(field) ?: return null
        if (bytes.size !in 3..254) return null
        if (bytes.any { it < 0x21 || it > 0x7E }) return null
        val text = bytes.decodeToString()
        return if (emailNorm(text) == text) Email.Of(text) else null
    }

    /** `email_b64n`: see [decodeEmail]. */
    fun isEmailB64n(field: String): Boolean = decodeEmail(field) != null

    /**
     * The `email_b64n` form of [emailNorm] (null: the literal `none`), or null when [emailNorm] is not
     * already an `emailNorm`. A caller normalises with [emailNorm] first; nothing is normalised here.
     */
    fun encodeEmail(emailNorm: String?): String? {
        if (emailNorm == null) return NONE
        if (emailNorm(emailNorm) != emailNorm) return null
        return Bytes.toB64(emailNorm.encodeToByteArray())
    }

    /** The decoded value of an `email_b64n` field. */
    sealed class Email {
        /** The literal `none`. */
        object None : Email()

        /** An address in its `emailNorm` form. */
        class Of(val emailNorm: String) : Email()

        /** The address, or null for `none`. */
        val orNull: String? get() = (this as? Of)?.emailNorm
    }

    // ---- shared helpers ----------------------------------------------------------------------------

    /** The ASCII white space of §2.3 and §6.1: space, tab, CR, LF. */
    fun isAsciiSpace(c: Char): Boolean = c == ' ' || c == '\t' || c == '\r' || c == '\n'

    /** [text] without any ASCII white space (§6.1: "chat apps wrap lines"). */
    fun stripAsciiSpace(text: String): String = if (text.none(::isAsciiSpace)) text else text.filterNot(::isAsciiSpace)

    private fun isLowerHex(c: Char): Boolean = c in '0'..'9' || c in 'a'..'f'

    /**
     * True when the code point [cp] may not stand in a name: THE one list of characters a name refuses, for a server's
     * name (`name`, [decodeName]) and for the server's `text` (display and device names, [isText]) alike. The server
     * keeps its own copy (`Grammar.isRefusedInText`) and a test that compares the two over every code point; every
     * client checks a name it is about to send with [isText] or [encodeName], so the person hears "not allowed" before
     * the server says `400`.
     *
     * The list: U+0000–U+001F, U+007F–U+009F, U+00AD, U+061C, U+180E, U+200B–U+200F, U+2028–U+202E, U+2060–U+2064,
     * U+2066–U+206F, U+FEFF, U+FFF9–U+FFFB (controls, the soft hyphen, the direction marks, embeddings, overrides and
     * isolates, the zero-width characters, the line and paragraph separators, the invisible operators, the byte-order
     * mark and the interlinear annotation characters). It is explicit, so that no engine's Unicode tables decide. A
     * surrogate (U+D800–U+DFFF) is not a code point of well-formed text: both callers refuse it before they ask.
     */
    fun isRefusedNameCodePoint(cp: Int): Boolean =
        cp <= 0x1F || cp in 0x7F..0x9F || cp == 0xAD || cp == 0x61C || cp == 0x180E ||
            cp in 0x200B..0x200F || cp in 0x2028..0x202E || cp in 0x2060..0x2064 || cp in 0x2066..0x206F ||
            cp == 0xFEFF || cp in 0xFFF9..0xFFFB

    /** The longest `text` the server takes (spec 03 §0.1), in UTF-16 characters. */
    const val TEXT_MAX_CHARS = 256

    /**
     * The server's `text` type (spec 03 §0.1; a display name, a device name), exactly as the server checks it: 1 to
     * [TEXT_MAX_CHARS] UTF-16 characters, well formed (no lone surrogate), and no code point [isRefusedNameCodePoint]
     * refuses. Spaces are allowed anywhere, leading and trailing included, and nothing is normalised. A client calls
     * this on a name before it sends one, and says what is wrong itself rather than waiting for `400 bad_device` or
     * `400 bad_display_name`.
     */
    fun isText(text: String): Boolean {
        if (text.isEmpty() || text.length > TEXT_MAX_CHARS) return false
        var i = 0
        while (i < text.length) {
            val ch = text[i]
            val cp = when {
                ch.isHighSurrogate() -> {
                    if (i + 1 >= text.length || !text[i + 1].isLowSurrogate()) return false
                    i++
                    0x10000 + ((ch.code - 0xD800) shl 10) + (text[i].code - 0xDC00)
                }
                ch.isLowSurrogate() -> return false
                else -> ch.code
            }
            if (isRefusedNameCodePoint(cp)) return false
            i++
        }
        return true
    }

    /**
     * Strict UTF-8 to code points (RFC 3629): null on a continuation byte out of place, an overlong
     * form, a surrogate (U+D800–U+DFFF), a code point above U+10FFFF or a truncated sequence.
     */
    internal fun decodeUtf8Strict(bytes: ByteArray): IntArray? {
        val out = IntArray(bytes.size)
        var n = 0
        var i = 0
        fun cont(at: Int): Int {
            if (at >= bytes.size) return -1
            val b = bytes[at].toInt() and 0xFF
            return if ((b and 0xC0) == 0x80) b and 0x3F else -1
        }
        while (i < bytes.size) {
            val b0 = bytes[i].toInt() and 0xFF
            val cp: Int
            when {
                b0 < 0x80 -> {
                    cp = b0
                    i += 1
                }
                b0 in 0xC2..0xDF -> {
                    val c1 = cont(i + 1)
                    if (c1 < 0) return null
                    cp = ((b0 and 0x1F) shl 6) or c1
                    i += 2
                }
                b0 in 0xE0..0xEF -> {
                    val c1 = cont(i + 1)
                    val c2 = cont(i + 2)
                    if (c1 < 0 || c2 < 0) return null
                    cp = ((b0 and 0x0F) shl 12) or (c1 shl 6) or c2
                    if (cp < 0x800 || cp in 0xD800..0xDFFF) return null
                    i += 3
                }
                b0 in 0xF0..0xF4 -> {
                    val c1 = cont(i + 1)
                    val c2 = cont(i + 2)
                    val c3 = cont(i + 3)
                    if (c1 < 0 || c2 < 0 || c3 < 0) return null
                    cp = ((b0 and 0x07) shl 18) or (c1 shl 12) or (c2 shl 6) or c3
                    if (cp < 0x10000 || cp > 0x10FFFF) return null
                    i += 4
                }
                else -> return null // 0x80..0xC1 (a stray continuation or an overlong lead), 0xF5..0xFF
            }
            out[n++] = cp
        }
        return out.copyOf(n)
    }
}
