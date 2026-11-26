package io.silencelen.andvari.core.crypto

/** What common code asks about an X25519 public key that came from somewhere else, before it uses it. */
object X25519 {
    /**
     * Curve25519's points of low order (1, 2, 4 and 8, on the curve and on its twist), in every form 31
     * bytes and 7 bits can give them: the seven strings of libsodium's `has_small_order`. The top bit
     * of the last byte is left out, as X25519 leaves it out (RFC 7748 §5).
     */
    private val LOW_ORDER: List<ByteArray> = listOf(
        "0000000000000000000000000000000000000000000000000000000000000000", // 0
        "0100000000000000000000000000000000000000000000000000000000000000", // 1
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", // a point of order 8
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157", // the other point of order 8
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p - 1
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p, which reads as 0
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p + 1, which reads as 1
    ).map { requireNotNull(Bytes.fromHexLower(it)) }

    /**
     * True when [publicKey] is a key that something may be sealed to, or agreed with: 32 bytes, and not
     * one of Curve25519's low-order points. False for anything else, a wrong length included.
     *
     * A Diffie-Hellman with a low-order point has an output that does not depend on the other side's
     * secret key, so a box sealed to one is sealed to nobody: anyone can open it. libsodium refuses to
     * seal to such a key (`crypto_box_seal` fails, and [CryptoProvider.sealTo] throws), but that is a
     * throw in the middle of a flow, and it is one provider's behaviour. A verifier that is handed a
     * key by another party asks here FIRST, so that the refusal is a verdict.
     */
    fun isUsablePublicKey(publicKey: ByteArray): Boolean {
        if (publicKey.size != 32) return false
        for (point in LOW_ORDER) {
            var difference = 0
            for (i in 0 until 31) difference = difference or (publicKey[i].toInt() xor point[i].toInt())
            difference = difference or ((publicKey[31].toInt() and 0x7f) xor point[31].toInt())
            if (difference == 0) return false
        }
        return true
    }
}
