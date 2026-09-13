package io.silencelen.andvari.core.client.autofill

/**
 * Host A-label (punycode) canonicalization for URI matching — spec 02 §3.1 "Normalization"
 * (amended 2026-09-13, audit H22). Mirrored byte-for-byte in web/src/vault/urimatch.ts and
 * extension/src/urimatch.ts; all three run spec/test-vectors/urimatch-idna.json.
 *
 * WHY THIS EXISTS. Every browser reports a page host in ASCII: Chrome's `location.hostname`,
 * the extension's `sender.origin`, and Android's `ViewNode.getWebDomain()` all carry
 * `xn--bcher-kva.de`, never `bücher.de`. The household, on the other hand, TYPES the Unicode
 * form — that is what the omnibox shows, what a copied link often pastes as, and what other
 * managers' CSV exports contain. [UriMatch.normalizeHost] used to compare the two byte-wise, so
 * a login saved as `https://bücher.de` never filled on any client, with no error anywhere; and
 * because [Psl.resolve] treats non-ASCII as UNKNOWN, not even the suffix fallback could bridge
 * it. Converting BOTH sides to the A-label makes the comparison — and the PSL walk — see one
 * spelling.
 *
 * WHY A HAND-ROLLED ENCODER AND NOT THE PLATFORM IDNA. The four implementations must agree
 * byte-for-byte, and the platforms do not: `java.net.IDN` is IDNA2003 (maps `ß` → `ss`, the
 * TRANSITIONAL form browsers abandoned in 2023 — Chrome/Firefox report `xn--strae-oqa.de` for
 * straße.de), while `new URL()` is UTS46 non-transitional. One algorithm, ported verbatim, is
 * the only way the vectors can pin all three. The algorithm is deliberately MINIMAL and
 * matches what a modern browser reports for every real-world host we have seen: the host is
 * already lowercased by normalizeHost; each label is NFC-normalized, and a label with any
 * non-ASCII code point becomes `xn--` + RFC 3492 punycode. No UTS46 mapping table is applied
 * (full-width forms, `ẞ` → `ss`, ligature decomposition) — a saved host using those spellings
 * still canonicalizes deterministically on every client, it just does not match the browser's
 * spelling. That is the fail-CLOSED corner: an under-match, never a cross-origin fill. Bidi and
 * joiner validity checks are likewise not applied: an invalid label is punycoded all the same
 * and matches only itself.
 *
 * FAIL CLOSED. The only runtime failure the encoder can have is arithmetic overflow on an
 * absurd label; it returns null and normalizeHost returns null, which never matches anything.
 */
internal object Idna {
    /**
     * Convert an already-normalized (lowercased, trailing-dot-free, non-empty-label) host to
     * its A-label form. ASCII input returns unchanged — the step is idempotent by construction,
     * which normalizeHost's callers rely on (they may normalize before matches() normalizes again).
     */
    fun toAscii(host: String): String? {
        if (isAscii(host)) return host
        val out = StringBuilder(host.length + 8)
        val labels = host.split('.')
        for ((i, label) in labels.withIndex()) {
            if (i > 0) out.append('.')
            if (isAscii(label)) {
                out.append(label)
            } else {
                val encoded = Punycode.encode(nfc(label)) ?: return null
                out.append("xn--").append(encoded)
            }
        }
        return out.toString()
    }

    private fun isAscii(s: String): Boolean = s.all { it.code < 128 }
}

/**
 * Unicode NFC — the composition step IDNA requires before punycoding, so `u` + COMBINING
 * DIAERESIS and precomposed `ü` (both legitimate keyboard outputs) reach the same A-label.
 * Platform-provided (java.text.Normalizer on both JVM-family targets; `String.normalize("NFC")`
 * in the TS twins).
 */
internal expect fun nfc(s: String): String

/**
 * RFC 3492 punycode ENCODER (§6.3, the reference algorithm, with the §6.4 overflow guard).
 * Decoding is never needed: a stored A-label is compared as-is. Kept in common Kotlin (no
 * `String.codePointAt`) so :core carries it for every target; surrogate pairs are combined by
 * hand. Verbatim twin of `punycodeEncode` in the TS urimatch.ts files.
 */
internal object Punycode {
    private const val BASE = 36
    private const val T_MIN = 1
    private const val T_MAX = 26
    private const val SKEW = 38
    private const val DAMP = 700
    private const val INITIAL_BIAS = 72
    private const val INITIAL_N = 128
    private const val MAX_INT = Int.MAX_VALUE.toLong()

    /** The encoded label WITHOUT the `xn--` prefix, or null on overflow. */
    fun encode(label: String): String? {
        val input = codePoints(label)
        val out = StringBuilder()
        // Basic (ASCII) code points pass through first, in order.
        for (cp in input) if (cp < INITIAL_N) out.append(cp.toChar())
        val basicCount = out.length
        var handled = basicCount
        if (basicCount > 0) out.append('-')
        var n = INITIAL_N.toLong()
        var delta = 0L
        var bias = INITIAL_BIAS
        while (handled < input.size) {
            // Next code point to insert: the smallest one >= n still unhandled.
            var m = MAX_INT
            for (cp in input) if (cp >= n && cp < m) m = cp.toLong()
            // Overflow guard (§6.4) — with Long arithmetic and a 32-bit ceiling this can only
            // trip on an absurd label; fail closed rather than emit a wrong A-label.
            if (m - n > (MAX_INT - delta) / (handled + 1)) return null
            delta += (m - n) * (handled + 1)
            n = m
            for (cp in input) {
                if (cp < n) {
                    delta++
                    if (delta > MAX_INT) return null
                }
                if (cp.toLong() == n) {
                    var q = delta
                    var k = BASE
                    while (true) {
                        val t = if (k <= bias) T_MIN else if (k >= bias + T_MAX) T_MAX else k - bias
                        if (q < t) break
                        out.append(digit((t + (q - t) % (BASE - t)).toInt()))
                        q = (q - t) / (BASE - t)
                        k += BASE
                    }
                    out.append(digit(q.toInt()))
                    bias = adapt(delta, handled + 1, handled == basicCount)
                    delta = 0
                    handled++
                }
            }
            delta++
            n++
        }
        return out.toString()
    }

    private fun adapt(deltaIn: Long, numPoints: Int, firstTime: Boolean): Int {
        var delta = if (firstTime) deltaIn / DAMP else deltaIn / 2
        delta += delta / numPoints
        var k = 0
        while (delta > ((BASE - T_MIN) * T_MAX) / 2) {
            delta /= (BASE - T_MIN)
            k += BASE
        }
        return (k + (BASE - T_MIN + 1) * delta / (delta + SKEW)).toInt()
    }

    private fun digit(d: Int): Char = if (d < 26) ('a' + d) else ('0' + (d - 26))

    /** UTF-16 → code points, pairing surrogates; a lone surrogate is kept as its own value. */
    private fun codePoints(s: String): IntArray {
        val out = ArrayList<Int>(s.length)
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c.isHighSurrogate() && i + 1 < s.length && s[i + 1].isLowSurrogate()) {
                out.add(0x10000 + ((c.code - 0xD800) shl 10) + (s[i + 1].code - 0xDC00))
                i += 2
            } else {
                out.add(c.code)
                i++
            }
        }
        return out.toIntArray()
    }
}
