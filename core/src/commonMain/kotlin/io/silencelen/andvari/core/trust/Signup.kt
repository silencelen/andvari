package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.CryptoProvider

/**
 * The optional sign-up proof of work (design 2026-11-15 §2.3, §7.5). When the instance sets
 * `powBits > 0`, `signup/start` requires a `nonce` whose digest has that many leading zero bits. The
 * client searches for one; the server recomputes one hash and is stateless about it.
 *
 * Twin: `web/src/crypto/trust/signup.ts`. Vectors: the `powInput` and `powLeadingZeroBits` rows of
 * `spec/test-vectors/encodings.json`.
 */
object SignupPow {
    /**
     * The hashed string: `"andvari/v2|signup-pow|" + emailNorm + "|" + utcDate + "|" + nonce` (§2.3).
     * [utcDate] is `YYYY-MM-DD` (UTC); [nonce] is written in decimal with no leading zeros, and is an
     * `int` (`0 <= n < 2^53`). Refuses (`IllegalArgumentException`) inputs outside those forms.
     */
    fun input(emailNorm: String, utcDate: String, nonce: Long): String {
        require(TrustGrammar.emailNorm(emailNorm) == emailNorm) { "not an emailNorm" }
        require(isUtcDate(utcDate)) { "utcDate is not YYYY-MM-DD" }
        require(TrustGrammar.isInt(nonce)) { "nonce out of range" }
        return "andvari/v2|signup-pow|$emailNorm|$utcDate|$nonce"
    }

    /** `SHA-256` of [input]'s UTF-8 bytes: the 32-byte proof-of-work digest. */
    fun digest(crypto: CryptoProvider, emailNorm: String, utcDate: String, nonce: Long): ByteArray =
        crypto.sha256(input(emailNorm, utcDate, nonce).encodeToByteArray())

    /**
     * The number of leading zero bits of [digest], counted from the most significant bit of byte 0,
     * then byte 1, and so on (§2.3). An all-zero digest counts every bit.
     */
    fun leadingZeroBits(digest: ByteArray): Int {
        var bits = 0
        for (b in digest) {
            val v = b.toInt() and 0xFF
            if (v == 0) {
                bits += 8
                continue
            }
            var mask = 0x80
            while (v and mask == 0) {
                bits++
                mask = mask shr 1
            }
            return bits
        }
        return bits
    }

    /** True when [nonce] solves the proof of work for [powBits] leading zero bits. `powBits <= 0` accepts every nonce. */
    fun accepts(crypto: CryptoProvider, emailNorm: String, utcDate: String, nonce: Long, powBits: Int): Boolean =
        powBits <= 0 || leadingZeroBits(digest(crypto, emailNorm, utcDate, nonce)) >= powBits

    /**
     * Try [tries] nonces starting at [from] and return the first that solves the proof of work, or
     * null when none of them does. A client calls it in slices from a background thread and shows
     * progress between slices (§7.5: 20 bits is about a second on a phone).
     */
    fun search(crypto: CryptoProvider, emailNorm: String, utcDate: String, powBits: Int, from: Long, tries: Int): Long? {
        var nonce = from
        repeat(tries) {
            if (!TrustGrammar.isInt(nonce)) return null
            if (accepts(crypto, emailNorm, utcDate, nonce, powBits)) return nonce
            nonce++
        }
        return null
    }

    /** `YYYY-MM-DD`: four digits, a dash, two digits, a dash, two digits. The shape only; whose day it is, is the server's check. */
    fun isUtcDate(s: String): Boolean {
        if (s.length != 10) return false
        for (i in s.indices) {
            val c = s[i]
            if (i == 4 || i == 7) {
                if (c != '-') return false
            } else if (c !in '0'..'9') {
                return false
            }
        }
        return true
    }
}

/**
 * The sign-up code check (design §2.3, §7.2): what the SERVER stores instead of the 6-digit code it
 * emailed. `HMAC-SHA-256(signupSecret, "andvari/v2|signup-code|" + emailNorm + "|" + code)`, where
 * `signupSecret` is the 32-byte `ANDVARI_SIGNUP_SECRET`. It lives here so that every `andvari/v2|`
 * label has one home; only the server calls it.
 */
object SignupCode {
    fun mac(crypto: CryptoProvider, signupSecret: ByteArray, emailNorm: String, code: String): ByteArray {
        require(signupSecret.size == 32) { "signup secret must be 32 bytes" }
        require(TrustGrammar.emailNorm(emailNorm) == emailNorm) { "not an emailNorm" }
        require(code.length == 6 && code.all { it in '0'..'9' }) { "code must be six digits" }
        return crypto.hmacSha256(signupSecret, "andvari/v2|signup-code|$emailNorm|$code".encodeToByteArray())
    }
}
