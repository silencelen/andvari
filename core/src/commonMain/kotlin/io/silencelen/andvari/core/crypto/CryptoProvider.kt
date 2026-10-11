package io.silencelen.andvari.core.crypto

/** Raised whenever a primitive fails — bad MAC, malformed input, unavailable backend. */
class CryptoException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * The platform's native libsodium binding could not be LOADED at all (audit H15/H89): the
 * JVM/Android [createCryptoProvider] actuals wrap whatever the loader threw — an
 * `UnsatisfiedLinkError`, lazysodium's `LibraryLoadingException`, a `NoClassDefFoundError`
 * — in this ONE common type so household copy can name the condition without knowing a
 * platform class.
 *
 * Deliberately NOT a [CryptoException]: the unlock and save ladders read a bare
 * [CryptoException] as "wrong master password" (the AEAD-open contract), and a library that
 * never loaded is neither the password's fault nor retryable. It is permanent and local for
 * the life of the process — every later `createCryptoProvider()` re-throws it — so clients
 * treat it as a blocking state, not a per-action error.
 */
class CryptoUnavailableException(cause: Throwable) :
    RuntimeException("native crypto library did not load: ${cause::class.simpleName}: ${cause.message}", cause)

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
     * Ed25519 detached-signature VERIFY (crypto_sign_verify_detached). True iff [signature] (64
     * bytes) is a valid signature of [message] by [publicKey] (32 bytes). Never throws — bad sizes
     * or a bad signature return false (fail-closed). Two callers: the signed-update channel (H2,
     * whose release-signing key lives on the owner's workstation, design 2026-07-13-signed-updates)
     * and [SignedStatement.verify] (security review 2026-10, root cause A).
     */
    fun signVerifyDetached(publicKey: ByteArray, signature: ByteArray, message: ByteArray): Boolean

    /**
     * Ed25519 keypair from a 32-byte seed (crypto_sign_seed_keypair): public 32 bytes, secret 64
     * bytes (seed ‖ public, libsodium's layout). Clients DO sign, with exactly one key: the JOINT
     * key over the existing identity seed (security review 2026-10, root cause A §1.1; owner
     * decision: joint key). Both this and [boxKeypairFromSeed] take the clamped low half of SHA-512(seed) as
     * the scalar, so `ed25519PkToCurve25519(sign.publicKey) == box.publicKey` for every account and
     * no identity fingerprint changes. The secret is as sensitive as the seed itself (it CONTAINS
     * the seed): derive it at unlock, never persist it, and give its input the seed's zeroization.
     */
    fun signKeypairFromSeed(seed: ByteArray): KeyPairBytes

    /** Ed25519 detached signature (crypto_sign_detached) with a 64-byte [secretKey]; deterministic. */
    fun signDetached(secretKey: ByteArray, message: ByteArray): ByteArray

    /**
     * crypto_sign_ed25519_pk_to_curve25519: the Montgomery (X25519) image of an Ed25519 public key.
     * The input is attacker-supplied in every use (a signerPub shipped inside an envelope), so a
     * wrong length, a non-point or a small-order point throws [CryptoException] and never returns.
     * NOTE: `A` and `−A` map to the SAME output; the mapping check alone is not authentication,
     * the signature check that follows it is ([SignedStatement.verify] does both, in order).
     */
    fun ed25519PkToCurve25519(ed25519PublicKey: ByteArray): ByteArray
}

/** Platform factory; each target wires its libsodium binding here. */
expect fun createCryptoProvider(): CryptoProvider
