package io.silencelen.andvari.core.crypto

/** RFC 5869 HKDF-SHA-256 (spec 01 §2). Empty salt ⇒ HashLen zero bytes. */
object Hkdf {
    private const val HASH_LEN = 32

    fun sha256(crypto: CryptoProvider, ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..255 * HASH_LEN) { "HKDF length out of range" }
        val prk = crypto.hmacSha256(if (salt.isEmpty()) ByteArray(HASH_LEN) else salt, ikm)
        val out = ByteArray(length)
        var t = ByteArray(0)
        var generated = 0
        var counter = 1
        while (generated < length) {
            t = crypto.hmacSha256(prk, t + info + byteArrayOf(counter.toByte()))
            val n = minOf(HASH_LEN, length - generated)
            t.copyInto(out, generated, 0, n)
            generated += n
            counter++
        }
        return out
    }
}
