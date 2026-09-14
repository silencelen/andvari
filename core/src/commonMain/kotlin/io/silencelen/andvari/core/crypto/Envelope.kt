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

    /**
     * The three STRUCTURAL refusals [open] makes before any key is used — length, version, alg —
     * as a reason string (null = the header is well-formed), single-sourced here so a caller that
     * must tell "this blob is damaged/foreign" apart from "this key is wrong" never re-implements
     * (and drifts from) the checks below.
     *
     * WHY the distinction is security-relevant (audit H67): only the AEAD tag failure at the end of
     * [open] is genuinely ambiguous — it is what a wrong password looks like. These three depend
     * solely on the blob's PUBLIC header and are decided before the key matters, so folding them
     * into a "wrong password" verdict tells a member with a corrupt or newer-version account row to
     * go and reset a password that was never wrong. Callers holding an ACCOUNT-KEY blob
     * (Account.unlock's wrappedUvk) consult this first; every other caller keeps the plain
     * [CryptoException] fail-closed behaviour, because for an item blob "damaged" and "not for this
     * key" are equally unactionable to the user.
     */
    fun structuralRefusal(envelope: ByteArray): String? = when {
        envelope.size < MIN_BYTES -> "envelope too short"
        envelope[0] != VERSION -> "unknown envelope version ${envelope[0]}"
        envelope[1] != ALG_XCHACHA20POLY1305_IETF -> "unknown envelope alg ${envelope[1]}"
        else -> null
    }

    fun open(crypto: CryptoProvider, key: ByteArray, envelope: ByteArray, ad: ByteArray): ByteArray {
        structuralRefusal(envelope)?.let { throw CryptoException(it) }
        val nonce = envelope.copyOfRange(2, HEADER_BYTES)
        val ct = envelope.copyOfRange(HEADER_BYTES, envelope.size)
        return crypto.aeadDecrypt(key, nonce, ct, ad)
    }

    fun sealB64(crypto: CryptoProvider, key: ByteArray, plaintext: ByteArray, ad: ByteArray): String =
        Bytes.toB64(seal(crypto, key, plaintext, ad))

    fun openB64(crypto: CryptoProvider, key: ByteArray, envelopeB64: String, ad: ByteArray): ByteArray =
        open(crypto, key, Bytes.fromB64(envelopeB64), ad)
}
