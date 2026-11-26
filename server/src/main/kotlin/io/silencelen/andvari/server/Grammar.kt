package io.silencelen.andvari.server

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireGrammar

/**
 * Field checks the wire needs beyond [WireGrammar] (spec 03 §0.1, spec 01 §5.1). Each `require*` throws
 * `400 bad_<field>` (or the code the route names) on failure.
 */
object Grammar {
    /** The `name` type (spec 01 §5.1): delegated to the shared grammar of `core/trust`. */
    fun isName(b64: String): Boolean = io.silencelen.andvari.core.trust.TrustGrammar.isName(b64)

    /** UTF-8 text → the `name` type, or null when the text cannot be one. */
    fun nameOf(text: String): String? = io.silencelen.andvari.core.trust.TrustGrammar.encodeName(text)

    /**
     * The `text` type (spec 03 §0.1; device names and display names): 1 to 256 UTF-16 characters, well formed (no
     * lone surrogate), and none of the code points the `name` type refuses: the controls,
     * the soft hyphen, the direction marks, embeddings, overrides and isolates, the zero-width characters, the line
     * and paragraph separators, the invisible operators, the byte-order mark and the interlinear annotation
     * characters. Such a name could reorder or hide what a console or a notice email draws around it.
     */
    fun isText(s: String): Boolean {
        if (s.isEmpty() || s.length > 256) return false
        var i = 0
        while (i < s.length) {
            val ch = s[i]
            val cp = when {
                ch.isHighSurrogate() -> {
                    if (i + 1 >= s.length || !s[i + 1].isLowSurrogate()) return false
                    Character.toCodePoint(ch, s[i + 1]).also { i++ }
                }
                ch.isLowSurrogate() -> return false
                else -> ch.code
            }
            if (isRefusedInText(cp)) return false
            i++
        }
        return true
    }

    /**
     * The code points refused in `text`: exactly the list of the `name` type (spec 01 §5.1, core's
     * `TrustGrammar.isRefusedInName`, which is private there; GrammarTextTest proves the two agree on every code
     * point). The list is explicit so that no engine's Unicode tables decide.
     */
    fun isRefusedInText(cp: Int): Boolean =
        cp <= 0x1F || cp in 0x7F..0x9F || cp == 0xAD || cp == 0x61C || cp == 0x180E ||
            cp in 0x200B..0x200F || cp in 0x2028..0x202E || cp in 0x2060..0x2064 || cp in 0x2066..0x206F ||
            cp == 0xFEFF || cp in 0xFFF9..0xFFFB

    /** Unpadded canonical base64url decoding to [minBytes]..[maxBytes] bytes; at most [maxChars] characters checked first. */
    fun b64Bytes(s: String, minBytes: Int, maxBytes: Int): ByteArray? {
        if (s.isEmpty() || s.length > (maxBytes * 4 + 2) / 3) return null
        val b = runCatching { Bytes.fromB64(s) }.getOrNull() ?: return null
        if (b.size < minBytes || b.size > maxBytes || Bytes.toB64(b) != s) return null
        return b
    }

    fun requireUuid(s: String?, field: String): String =
        s?.takeIf { WireGrammar.isUuid(it) } ?: badRequest(WireErrors.badField(field))

    fun requireB64_16(s: String?, field: String): String =
        s?.takeIf { WireGrammar.isB64_16(it) } ?: badRequest(WireErrors.badField(field))

    fun requireB64_32(s: String?, field: String): String =
        s?.takeIf { WireGrammar.isB64_32(it) } ?: badRequest(WireErrors.badField(field))

    fun requireHex64(s: String?, field: String): String =
        s?.takeIf { WireGrammar.isHex64(it) } ?: badRequest(WireErrors.badField(field))

    /** A `b64` field capped at [maxChars] characters of the encoded string, non-empty and canonical. */
    fun requireB64(s: String?, field: String, maxChars: Int): String {
        if (s == null || s.isEmpty() || s.length > maxChars) badRequest(WireErrors.badField(field))
        val b = runCatching { Bytes.fromB64(s) }.getOrNull()
        if (b == null || b.isEmpty() || Bytes.toB64(b) != s) badRequest(WireErrors.badField(field))
        return s
    }

    fun requireText(s: String?, field: String): String = s?.takeIf { isText(it) } ?: badRequest(WireErrors.badField(field))

    fun requirePlatform(s: String?): String =
        s?.takeIf { it in io.silencelen.andvari.core.model.wire.WirePlatform.ALL } ?: badRequest(WireErrors.BAD_PLATFORM)

    /** `emailNorm` of a typed address (spec 03 §0.3), or `400 invalid_email`. */
    fun requireEmail(typed: String?): String = typed?.let { emailNorm(it) } ?: badRequest(WireErrors.INVALID_EMAIL)

    fun emailOrNull(typed: String): String? = emailNorm(typed)

    /**
     * `emailNorm` (spec 01 §5.5): the shared steps, then the address must be `local@domain` with
     * exactly one `@`, `local` a dot-atom of 1 to 64 characters, `domain` two or more labels under the host
     * grammar of the `origin` type. Anything else (a display name, angle brackets, a comment, a quoted local
     * part, an address literal, a one-label domain) has no `emailNorm`, so the server's string and the mail
     * library's mailbox are always the same address.
     */
    fun emailNorm(typed: String): String? = WireGrammar.emailNorm(typed)?.takeIf { isMailbox(it) }

    private const val ATEXT_SPECIALS = "!#$%&'*+/=?^_`{|}~-"

    private fun isAtext(ch: Char): Boolean = ch in 'a'..'z' || ch in 'A'..'Z' || ch in '0'..'9' || ch in ATEXT_SPECIALS

    /** `local@domain` as [emailNorm] requires it. */
    fun isMailbox(address: String): Boolean {
        val at = address.indexOf('@')
        if (at < 0 || at != address.lastIndexOf('@')) return false
        val local = address.substring(0, at)
        val domain = address.substring(at + 1)
        if (local.length !in 1..64) return false
        if (local.split('.').any { part -> part.isEmpty() || !part.all(::isAtext) }) return false
        // The host grammar of the `origin` type: only lowercase letters, digits, `-` and `.` reach it, so no
        // port, path or bracket can be read into the domain.
        if (!domain.all { it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '.' }) return false
        return WireGrammar.isOrigin("https://$domain")
    }

    /**
     * hex SHA-256 of `emailNorm`: the plain hash. It is never written into a record (rows, audit, journal keep
     * [Config.addressHash] since 2026-11-18): it keys the in-memory allowances only, and is looked for beside the keyed
     * hash in the two kinds of row that can outlive an upgrade by days (a mailbox value, an enrol link bound to an
     * address), so that a row written before still works until it expires.
     */
    fun emailHash(emailNorm: String): String = sha256Hex(emailNorm)
}
