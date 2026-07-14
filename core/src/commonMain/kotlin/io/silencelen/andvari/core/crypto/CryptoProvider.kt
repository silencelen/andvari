package io.silencelen.andvari.core.crypto

/** Raised whenever a primitive fails — bad MAC, malformed input, unavailable backend. */
class CryptoException(message: String, cause: Throwable? = null) : Exception(message, cause)

class KeyPairBytes(val publicKey: ByteArray, val privateKey: ByteArray)

class SecretStreamResult(val header: ByteArray, val chunks: List<ByteArray>)

/**
 * Platform gateway to libsodium plus the two platform hash primitives the spec
 * needs that libsodium does not ship (HMAC-SHA-1 for TOTP, SHA-1 for HIBP).
 *
 * Implementations: lazysodium-java (jvm), lazysodium-android (android),
 * libsodium-wrappers-sumo + WebCrypto (the independent TS implementation in web/).
 * All higher-level constructions (KDF chains, envelopes, wrapping, escrow) live in
 * common code against this interface and are pinned by spec/test-vectors.
 */
interface CryptoProvider {
    fun randomBytes(n: Int): ByteArray

    /** Argon2id v1.3 via libsodium crypto_pwhash. */
    fun argon2id(
        password: ByteArray,
        salt: ByteArray,
        outLen: Int,
        opsLimit: Long,
        memLimitBytes: Long,
    ): ByteArray

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray
    fun hmacSha1(key: ByteArray, data: ByteArray): ByteArray
    fun hmacSha512(key: ByteArray, data: ByteArray): ByteArray
    fun sha256(data: ByteArray): ByteArray
    fun sha1(data: ByteArray): ByteArray

    /** XChaCha20-Poly1305-IETF; returns ciphertext||tag. */
    fun aeadEncrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, ad: ByteArray): ByteArray

    /** Throws [CryptoException] on MAC failure. */
    fun aeadDecrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, ad: ByteArray): ByteArray

    /** X25519 keypair derived deterministically from a 32-byte seed (crypto_box_seed_keypair). */
    fun boxKeypairFromSeed(seed: ByteArray): KeyPairBytes

    /** crypto_box_seal — anonymous sealed box to a recipient public key. */
    fun sealTo(recipientPublicKey: ByteArray, plaintext: ByteArray): ByteArray

    /** crypto_box_seal_open. Throws [CryptoException] if the box does not open. */
    fun sealOpen(publicKey: ByteArray, privateKey: ByteArray, sealed: ByteArray): ByteArray

    /** crypto_secretstream_xchacha20poly1305 push over pre-chunked plaintext (attachments). */
    fun secretstreamEncrypt(key: ByteArray, chunks: List<ByteArray>): SecretStreamResult

    /** Pull counterpart; throws [CryptoException] on any corrupt/truncated chunk. */
    fun secretstreamDecrypt(key: ByteArray, header: ByteArray, chunks: List<ByteArray>): List<ByteArray>

    /**
     * Ed25519 detached-signature VERIFY (crypto_sign_verify_detached) — the signed-update channel
     * (H2). True iff [signature] (64 bytes) is a valid signature of [message] by [publicKey] (32
     * bytes). Verify-only on purpose: clients never sign; the release-signing private key lives on
     * the owner's workstation (design 2026-07-13-signed-updates §A/§F). Never throws — bad sizes or
     * a bad signature return false (fail-closed).
     */
    fun signVerifyDetached(publicKey: ByteArray, signature: ByteArray, message: ByteArray): Boolean
}

/** Platform factory; each target wires its libsodium binding here. */
expect fun createCryptoProvider(): CryptoProvider
