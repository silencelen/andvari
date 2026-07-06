package io.silencelen.andvari.core.crypto

/**
 * HIBP k-anonymity range check (spec 03 §8): SHA-1 computed locally, 5-char prefix
 * queried via the server relay, suffixes compared locally. Full hashes never leave
 * the device.
 */
object Hibp {
    fun sha1UpperHex(crypto: CryptoProvider, password: String): String =
        Bytes.toHexUpper(crypto.sha1(password.encodeToByteArray()))

    fun prefix(sha1UpperHex: String): String = sha1UpperHex.take(5)

    fun suffix(sha1UpperHex: String): String = sha1UpperHex.substring(5)

    /**
     * Parse an upstream-format range response ("SUFFIX:COUNT" lines, CRLF or LF)
     * and return the breach count for this hash, 0 when absent.
     */
    fun countInRange(rangeResponse: String, sha1UpperHex: String): Long {
        val want = suffix(sha1UpperHex).uppercase()
        for (line in rangeResponse.lineSequence()) {
            val trimmed = line.trim()
            if (trimmed.isEmpty()) continue
            val colon = trimmed.indexOf(':')
            if (colon <= 0) continue
            if (trimmed.take(colon).uppercase() == want) {
                return trimmed.substring(colon + 1).trim().toLongOrNull() ?: 0L
            }
        }
        return 0L
    }
}
