package io.silencelen.andvari.core.client.autofill

/**
 * Pure card-value normalization — vector-tested (spec/test-vectors/card.json), mirrored by the
 * web + extension TS ports. Storage canonical form (spec 02 CardData): digits-only number,
 * expMonth "01".."12", expYear 4-digit. Brand is display-only and recomputed at every save from
 * the IIN, so it can never go stale against an edited number.
 *
 * "Digit" throughout means ASCII '0'..'9' ONLY (never Char.isDigit(), which is Unicode-wide):
 * Eastern-Arabic/Devanagari/full-width digits are stripped by digitsOnly and REJECTED by
 * luhnValid/padMonth/yearTo4/yearTo2 — the Luhn loop does ASCII `c - '0'` arithmetic, so a
 * Unicode digit slipping through would compute garbage that could spuriously validate.
 */
object CardNormalize {
    private fun isAsciiDigit(c: Char): Boolean = c in '0'..'9'

    /** Cross-port determinism: the adapters trim ONLY this pinned ASCII whitespace set.
     *  Platform trims disagree at the Unicode margins (JS strips U+FEFF, JVM strips
     *  U+001C..U+001F) and the same string must parse identically on every client —
     *  vector-pinned in card.json. */
    private val TRIMMABLE = charArrayOf(' ', '\t', '\n', '\r', '\u000B', '\u000C')
    private fun trimAscii(raw: String): String = raw.trim { it in TRIMMABLE }
    /** Canonical expiry: [expMonth] "01".."12" zero-padded, [expYear] 4-digit. */
    data class Expiry(val expMonth: String, val expYear: String)

    /** Storage canonicalization: strip everything but ASCII digits ("4111 1111-1111.1111" → PAN). */
    fun digitsOnly(raw: String): String = raw.filter { isAsciiDigit(it) }

    /**
     * Luhn gate for save/update flows. Accepts digit groups separated by spaces/dashes/dots;
     * any other character fails, as does a digit count outside 12..19 (ISO/IEC 7812) — so a
     * lone "0" or a phone number can never look like a savable card.
     */
    fun luhnValid(raw: String): Boolean {
        if (raw.any { !isAsciiDigit(it) && it != ' ' && it != '-' && it != '.' }) return false
        val d = digitsOnly(raw)
        if (d.length !in 12..19) return false
        var sum = 0
        for ((i, c) in d.reversed().withIndex()) {
            var v = c - '0'
            if (i % 2 == 1) { v *= 2; if (v > 9) v -= 9 }
            sum += v
        }
        return sum % 10 == 0
    }

    /**
     * IIN → brand: visa | mastercard | amex | discover, null when unknown OR while the typed
     * prefix is still ambiguous (e.g. "62" could be inside or outside the Discover range) —
     * decisive-prefix semantics so a live editor badge can appear as early as the first digit.
     */
    fun brand(raw: String): String? {
        val d = digitsOnly(raw)
        return when {
            d.startsWith("4") -> "visa"
            d.length >= 2 && d.take(2) in AMEX_IIN -> "amex"
            d.length >= 2 && d.take(2).toInt() in 51..55 -> "mastercard"
            d.length >= 4 && d.take(4).toInt() in 2221..2720 -> "mastercard"
            d.startsWith("6011") || d.startsWith("65") -> "discover"
            d.length >= 3 && d.take(3).toInt() in 644..649 -> "discover"
            d.length >= 6 && d.take(6).toInt() in 622126..622925 -> "discover"
            else -> null
        }
    }

    /**
     * Expiry text → canonical, or null. Accepts M[M]<sep>YY|YYYY (sep = any non-digit run, so
     * "12/27", "12-2027", "12 . 27" all parse) and the separator-free runs MYY/MMYY/MYYYY/MMYYYY;
     * 2-digit years pivot into 2000–2099 (fixed window — card expiries cannot reach 2100).
     */
    fun parseExpiry(raw: String): Expiry? {
        val groups = Regex("[0-9]+").findAll(raw).map { it.value }.toList() // [0-9] = ASCII-only, deliberately not \d
        val (m, y) = when (groups.size) {
            2 -> {
                if (groups[0].length !in 1..2 || groups[1].length !in setOf(2, 4)) return null
                groups[0] to groups[1]
            }
            1 -> when (groups[0].length) {
                3 -> groups[0].take(1) to groups[0].drop(1)
                4 -> groups[0].take(2) to groups[0].drop(2)
                5 -> groups[0].take(1) to groups[0].drop(1)
                6 -> groups[0].take(2) to groups[0].drop(2)
                else -> return null
            }
            else -> return null
        }
        return Expiry(padMonth(m) ?: return null, yearTo4(y) ?: return null)
    }

    /** Month adapter: "1"/"01".."12" → zero-padded canonical; null otherwise. */
    fun padMonth(raw: String): String? {
        val t = trimAscii(raw)
        if (t.isEmpty() || t.length > 2 || t.any { !isAsciiDigit(it) }) return null
        val m = t.toInt()
        return if (m in 1..12) m.toString().padStart(2, '0') else null
    }

    /** Year adapter for 4-digit targets: "27" pivots to "2027", 4-digit passes through; null otherwise. */
    fun yearTo4(raw: String): String? {
        val t = trimAscii(raw)
        if (t.any { !isAsciiDigit(it) }) return null
        return when (t.length) { 2 -> "20$t"; 4 -> t; else -> null }
    }

    /** Year adapter for 2-digit targets: "2027" → "27", 2-digit passes through; null otherwise. */
    fun yearTo2(raw: String): String? {
        val t = trimAscii(raw)
        if (t.any { !isAsciiDigit(it) }) return null
        return when (t.length) { 2 -> t; 4 -> t.substring(2); else -> null }
    }

    /** Fill adapter for combined expiry targets: canonical month + year → "MM/YY". */
    fun composeShortExpiry(expMonth: String, expYear: String): String? {
        val m = padMonth(expMonth) ?: return null
        val y = yearTo2(expYear) ?: return null
        return "$m/$y"
    }

    private val AMEX_IIN = setOf("34", "37")
}
