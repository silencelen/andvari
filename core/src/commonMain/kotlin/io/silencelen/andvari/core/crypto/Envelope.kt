package io.silencelen.andvari.core.crypto

/**
 * spec 02 §2 — the AEAD envelope: version ‖ alg ‖ nonce(24) ‖ ct+tag(≥16),
 * transported as unpadded base64url.
 */
object Envelope {
    const val VERSION: Byte = 0x01
    const val ALG_XCHACHA20POLY1305_IETF: Byte = 0x01
    const val NONCE_BYTES = 24
    const val TAG_BYTES = 16
    private const val HEADER_BYTES = 2 + NONCE_BYTES
    const val MIN_BYTES = HEADER_BYTES + TAG_BYTES

    /** Encrypt with an explicit nonce — used by vector generation; production callers use [seal]. */
    fun sealWithNonce(
        crypto: CryptoProvider,
        key: ByteArray,
        nonce: ByteArray,
        plaintext: ByteArray,
        ad: ByteArray,
    ): ByteArray {
        require(nonce.size == NONCE_BYTES) { "nonce must be $NONCE_BYTES bytes" }
        val ct = crypto.aeadEncrypt(key, nonce, plaintext, ad)
        return byteArrayOf(VERSION, ALG_XCHACHA20POLY1305_IETF) + nonce + ct
    }

    fun seal(crypto: CryptoProvider, key: ByteArray, plaintext: ByteArray, ad: ByteArray): ByteArray =
        sealWithNonce(crypto, key, crypto.randomBytes(NONCE_BYTES), plaintext, ad)

    fun open(crypto: CryptoProvider, key: ByteArray, envelope: ByteArray, ad: ByteArray): ByteArray {
        if (envelope.size < MIN_BYTES) throw CryptoException("envelope too short")
        if (envelope[0] != VERSION) throw CryptoException("unknown envelope version ${envelope[0]}")
        if (envelope[1] != ALG_XCHACHA20POLY1305_IETF) throw CryptoException("unknown envelope alg ${envelope[1]}")
        val nonce = envelope.copyOfRange(2, HEADER_BYTES)
        val ct = envelope.copyOfRange(HEADER_BYTES, envelope.size)
        return crypto.aeadDecrypt(key, nonce, ct, ad)
    }

    fun sealB64(crypto: CryptoProvider, key: ByteArray, plaintext: ByteArray, ad: ByteArray): String =
        Bytes.toB64(seal(crypto, key, plaintext, ad))

    fun openB64(crypto: CryptoProvider, key: ByteArray, envelopeB64: String, ad: ByteArray): ByteArray =
        open(crypto, key, Bytes.fromB64(envelopeB64), ad)
}
