package io.silencelen.andvari.core.crypto

/**
 * RFC 5869 HKDF-SHA-256 (spec 01 §2). Empty salt ⇒ HashLen zero bytes.
 *
 * The pseudorandom key, every block `T(n)` and every HMAC input built from one are zeroed before
 * [sha256] returns: each is as good as the input key for whoever reads it. What this code cannot reach
 * is the platform HMAC's own working copy of the key, inside the provider.
 */
object Hkdf {
    private const val HASH_LEN = 32

    fun sha256(crypto: CryptoProvider, ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..255 * HASH_LEN) { "HKDF length out of range" }
        // Nothing is derived from a wiped key: KeysGoneException. An all-zero salt is RFC 5869's own default.
        KeyFloor.requireKey(ikm)
        val prk = crypto.hmacSha256(if (salt.isEmpty()) ByteArray(HASH_LEN) else salt, ikm)
        val out = ByteArray(length)
        var t = ByteArray(0)
        var done = false
        try {
            var generated = 0
            var counter = 1
            while (generated < length) {
                // T(n) = HMAC(PRK, T(n-1) || info || n)
                val input = ByteArray(t.size + info.size + 1)
                t.copyInto(input)
                info.copyInto(input, t.size)
                input[input.size - 1] = counter.toByte()
                val next = try {
                    crypto.hmacSha256(prk, input)
                } finally {
                    input.fill(0)
                }
                t.fill(0)
                t = next
                val n = minOf(HASH_LEN, length - generated)
                t.copyInto(out, generated, 0, n)
                generated += n
                counter++
            }
            done = true
            return out
        } finally {
            prk.fill(0)
            t.fill(0)
            if (!done) out.fill(0)
        }
    }
}
