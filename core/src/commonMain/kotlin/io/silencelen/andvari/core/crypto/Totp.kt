package io.silencelen.andvari.core.crypto

/** RFC 4648 base32 (case-insensitive, padding and ASCII whitespace ignored) — TOTP secrets. */
object Base32 {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    /** Cross-port determinism (2026-07-09 review; the CardNormalize.TRIMMABLE precedent):
     *  the decoder ignores ONLY '=' padding plus this pinned ASCII whitespace set — never
     *  Char.isWhitespace()/JS `\s`, which disagree at the Unicode margins (JS `\s` strips
     *  U+FEFF where JVM keeps it; JVM isWhitespace strips U+001C..U+001F and Unicode
     *  spaces where JS differs). Any other character (U+FEFF, NBSP, …) fails decode on
     *  EVERY client, so a secret one twin could never parse back is never stored (A5
     *  reject-don't-corrupt). The web twin pins the same set in base32Decode. */
    private const val IGNORED = "= \t\n\u000B\u000C\r"

    fun decode(text: String): ByteArray {
        val clean = text.uppercase().filter { it !in IGNORED }
        val out = ArrayList<Byte>(clean.length * 5 / 8)
        var buffer = 0
        var bits = 0
        for (c in clean) {
            val v = ALPHABET.indexOf(c)
            if (v < 0) throw CryptoException("invalid base32 character '$c'")
            buffer = (buffer shl 5) or v
            bits += 5
            if (bits >= 8) {
                bits -= 8
                out.add(((buffer shr bits) and 0xFF).toByte())
            }
        }
        return out.toByteArray()
    }

    fun encode(bytes: ByteArray): String {
        val sb = StringBuilder()
        var buffer = 0
        var bits = 0
        for (b in bytes) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) {
                bits -= 5
                sb.append(ALPHABET[(buffer shr bits) and 0x1F])
            }
        }
        if (bits > 0) sb.append(ALPHABET[(buffer shl (5 - bits)) and 0x1F])
        return sb.toString()
    }
}

enum class TotpAlgorithm { SHA1, SHA256, SHA512 }

data class TotpConfig(
    val secret: ByteArray,
    val algorithm: TotpAlgorithm = TotpAlgorithm.SHA1,
    val digits: Int = 6,
    val periodSeconds: Int = 30,
    val label: String = "",
    val issuer: String = "",
)

/** RFC 6238 (over RFC 4226 truncation); spec 02 §3. */
object Totp {

    fun code(crypto: CryptoProvider, config: TotpConfig, unixSeconds: Long): String {
        require(config.digits in 6..10) { "TOTP digits out of range" }
        require(config.periodSeconds > 0) { "TOTP period must be positive" }
        val counter = unixSeconds / config.periodSeconds
        val msg = ByteArray(8)
        for (i in 0..7) msg[i] = ((counter ushr ((7 - i) * 8)) and 0xFF).toByte()
        val mac = when (config.algorithm) {
            TotpAlgorithm.SHA1 -> crypto.hmacSha1(config.secret, msg)
            TotpAlgorithm.SHA256 -> crypto.hmacSha256(config.secret, msg)
            TotpAlgorithm.SHA512 -> crypto.hmacSha512(config.secret, msg)
        }
        val offset = mac[mac.size - 1].toInt() and 0x0F
        val binary = ((mac[offset].toInt() and 0x7F) shl 24) or
            ((mac[offset + 1].toInt() and 0xFF) shl 16) or
            ((mac[offset + 2].toInt() and 0xFF) shl 8) or
            (mac[offset + 3].toInt() and 0xFF)
        var mod = 1L
        repeat(config.digits) { mod *= 10 }
        return (binary % mod).toString().padStart(config.digits, '0')
    }

    fun secondsRemaining(config: TotpConfig, unixSeconds: Long): Int =
        (config.periodSeconds - (unixSeconds % config.periodSeconds)).toInt()

    /**
     * The ONE shared TOTP normalize (spec 06 §9.2, design 2026-07-09 A5; the web twin is
     * `normalizeTotp` in web/src/totp.ts) — byte-exact and delegated to by every editor
     * and import adapter (private copies are deleted):
     * strip ALL ASCII whitespace (TAB LF FF CR SPACE); empty → unchanged; an `otpauth://`
     * prefix (case-insensitive) → returned as-is; else if the string base32-decodes when
     * uppercased (padding-tolerant, the [Base32] decoder) it wraps to
     * `otpauth://totp/andvari?secret=<s>` with the ORIGINAL case preserved (matching the
     * historical web editor behavior); anything else is returned unchanged. Validity is a
     * SEPARATE question: a value is usable iff [parseUri] accepts the normalized string.
     */
    fun normalize(raw: String): String {
        val s = buildString(raw.length) {
            for (c in raw) if (c != ' ' && c != '\t' && c != '\n' && c != '\u000C' && c != '\r') append(c)
        }
        if (s.isEmpty()) return s
        if (s.lowercase().startsWith("otpauth://")) return s
        return try {
            Base32.decode(s)
            "otpauth://totp/andvari?secret=$s"
        } catch (e: CryptoException) {
            s
        }
    }

    /** Parse an otpauth://totp/… URI (the storage format inside item plaintext, spec 02 §3). */
    fun parseUri(uri: String): TotpConfig {
        val prefix = "otpauth://totp/"
        if (!uri.startsWith(prefix, ignoreCase = true)) throw CryptoException("not an otpauth totp URI")
        val rest = uri.substring(prefix.length)
        val qIndex = rest.indexOf('?')
        val label = percentDecode(if (qIndex >= 0) rest.take(qIndex) else rest)
        val params = if (qIndex >= 0) {
            rest.substring(qIndex + 1).split('&').filter { it.isNotEmpty() }.associate {
                val eq = it.indexOf('=')
                if (eq < 0) it to "" else it.take(eq).lowercase() to percentDecode(it.substring(eq + 1))
            }
        } else emptyMap()
        // A5 reject-don't-corrupt (2026-07-09 review): this parse is the ONE validity gate
        // for editors and import adapters, so it must reject what [code] cannot evaluate —
        // an empty/blank secret (empty HMAC key crashes SecretKeySpec at render time) and
        // digits/period outside code()'s own require()s — instead of storing a config whose
        // 2FA display throws later. Byte-exact with web parseOtpauthUri.
        val secret = params["secret"]?.takeIf { it.isNotEmpty() } ?: throw CryptoException("otpauth URI missing secret")
        val algorithm = when (params["algorithm"]?.uppercase() ?: "SHA1") {
            "SHA1" -> TotpAlgorithm.SHA1
            "SHA256" -> TotpAlgorithm.SHA256
            "SHA512" -> TotpAlgorithm.SHA512
            else -> throw CryptoException("unsupported otpauth algorithm")
        }
        val secretBytes = Base32.decode(secret)
        if (secretBytes.isEmpty()) throw CryptoException("otpauth secret decodes to empty key")
        // toIntOrNull semantics are pinned (full-string match, 32-bit range; junk → the
        // default) — the TS twin mirrors them with an explicit toIntOrNull port, never
        // Number.parseInt's partial parse ("8x" → 8, "0" || 6 → 6).
        val digits = params["digits"]?.toIntOrNull() ?: 6
        if (digits !in 6..10) throw CryptoException("otpauth digits out of range")
        val period = params["period"]?.toIntOrNull() ?: 30
        if (period <= 0) throw CryptoException("otpauth period out of range")
        return TotpConfig(
            secret = secretBytes,
            algorithm = algorithm,
            digits = digits,
            periodSeconds = period,
            label = label,
            issuer = params["issuer"] ?: label.substringBefore(':', ""),
        )
    }

    // Byte-accurate so multi-byte UTF-8 escapes (%C3%A9) decode correctly; '+' stays literal.
    private fun percentDecode(s: String): String {
        val out = ArrayList<Byte>(s.length)
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '%') {
                if (i + 3 > s.length) throw CryptoException("bad percent-encoding")
                val v = s.substring(i + 1, i + 3).toIntOrNull(16)
                    ?: throw CryptoException("bad percent-encoding")
                out.add(v.toByte())
                i += 3
            } else {
                for (b in c.toString().encodeToByteArray()) out.add(b)
                i++
            }
        }
        return out.toByteArray().decodeToString()
    }
}
