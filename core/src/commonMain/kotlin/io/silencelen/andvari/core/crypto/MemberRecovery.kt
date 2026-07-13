package io.silencelen.andvari.core.crypto

/**
 * spec 04 §per-member / design 2026-07-12 §F.6 — the per-member SELF-SERVICE recovery piece.
 *
 * The symmetric counterpart to org [Escrow]. The member holds ONE high-entropy secret at both
 * seal-time (enroll) and open-time (recovery), so there is no org public key a hostile server
 * could substitute — spec 05 T10 does not apply and the enrollment fingerprint ceremony has
 * nothing to defend on this path. The worst a hostile server can do is serve a wrong/tampered
 * blob → the AEAD tag fails → recovery FAILS CLOSED (pure availability denial, accepted under T1).
 *
 *  - `recoverySecret` = 32 CSPRNG bytes ([CryptoProvider.randomBytes]) — 256-bit, matching the org
 *    seed. It is GENERATED, shown ONCE, then dropped; it is NEVER `Math.random` and NEVER derived
 *    from user input (the invariant the whole T8 posture rests on — §F.6).
 *  - HKDF-SHA-256 (empty-salt, the same construction as [Keys.authKey]/[Keys.wrapKey]) SPLITS the
 *    secret into a wrap key and an auth key. The split severs them: the value the server verifies
 *    (`recoveryAuthKey`) can never open the wrapped UVK, exactly like `authKey` vs `wrapKey`.
 *  - The UVK is sealed under the wrap key in an AEAD [Envelope] bound to [Ad.recovery] (userId).
 *  - base64url of a CSPRNG is unbiased, so the printed/QR sheet needs NO rejection sampling and NO
 *    Argon2id on this path (128-bit generated entropy is already computationally unreachable).
 */
object MemberRecovery {
    const val SECRET_BYTES = 32
    const val KEY_BYTES = 32
    private val INFO_WRAP = "andvari/v1/recovery-wrap".encodeToByteArray()
    private val INFO_AUTH = "andvari/v1/recovery-auth".encodeToByteArray()

    /** Strip ASCII whitespace the way the printed sheet may hard-wrap it. base64url's alphabet
     *  includes `-` and `_`, so only whitespace is a safe separator to drop (mirrors [EnrollLink]). */
    private const val WHITESPACE = " \t\n\r"

    /** HKDF-SHA-256(recoverySecret, "andvari/v1/recovery-wrap", 32) — the KEK that wraps the UVK. */
    fun wrapKey(crypto: CryptoProvider, recoverySecret: ByteArray): ByteArray =
        Hkdf.sha256(crypto, recoverySecret, ByteArray(0), INFO_WRAP, KEY_BYTES)

    /** HKDF-SHA-256(recoverySecret, "andvari/v1/recovery-auth", 32) — the server-verified proof.
     *  The server stores `crypto_pwhash_str(recoveryAuthKey)`; severed from [wrapKey], it opens nothing. */
    fun authKey(crypto: CryptoProvider, recoverySecret: ByteArray): ByteArray =
        Hkdf.sha256(crypto, recoverySecret, ByteArray(0), INFO_AUTH, KEY_BYTES)

    /**
     * The generated piece: the raw [recoverySecret] to display ONCE, plus the two wire fields
     * ([recoveryWrappedUvk] + [recoveryAuthKey], both base64url) that go into the register /
     * self-setup request. Mirrors org escrow's split of "secret stays with the holder, ciphertext +
     * one-way verifier go to the server."
     */
    class Piece(
        val recoverySecret: ByteArray,
        val recoveryWrappedUvk: String,
        val recoveryAuthKey: String,
    )

    /**
     * Generate a fresh recovery piece over [uvk]. The 256-bit [Piece.recoverySecret] is CSPRNG and
     * NEVER user input (§F.6); the caller shows it once (via [displayForm]) and drops it.
     */
    fun generate(crypto: CryptoProvider, userId: String, uvk: ByteArray): Piece {
        val recoverySecret = crypto.randomBytes(SECRET_BYTES)
        val recoveryWrappedUvk = Envelope.sealB64(crypto, wrapKey(crypto, recoverySecret), uvk, Ad.recovery(userId))
        val recoveryAuthKey = Bytes.toB64(authKey(crypto, recoverySecret))
        return Piece(recoverySecret, recoveryWrappedUvk, recoveryAuthKey)
    }

    /** Recompute the base64url `recoveryAuthKey` the server verifies for a given secret (recovery path). */
    fun deriveAuthKey(crypto: CryptoProvider, recoverySecret: ByteArray): String =
        Bytes.toB64(authKey(crypto, recoverySecret))

    /**
     * Open the UVK from a `recoveryWrappedUvk` (recovery path). A wrong secret or a wrong/tampered
     * blob fails the AEAD tag → [CryptoException] (fail-closed; availability denial only, T1).
     * Returns the SAME UVK that was sealed at enroll — never a regenerated one (the UVK is invariant,
     * so both the org-escrow and member-recovery blobs stay valid across a password reset).
     */
    fun openUvk(crypto: CryptoProvider, recoverySecret: ByteArray, recoveryWrappedUvk: String, userId: String): ByteArray =
        Envelope.openB64(crypto, wrapKey(crypto, recoverySecret), recoveryWrappedUvk, Ad.recovery(userId))

    /**
     * The printed/display encoding of [recoverySecret]: base64url of the raw random bytes — the exact
     * form the org recovery sheet renders (`tools/recovery-cli/.../Main.kt:80`, `Bytes.toB64(seed)`),
     * so the two sheets read identically. UI layers may visually group it with SPACES for readability
     * (base64url's `-`/`_` rule out any other separator); [confirmMatches] and the recovery-entry
     * decode tolerate that whitespace.
     */
    fun displayForm(recoverySecret: ByteArray): String = Bytes.toB64(recoverySecret)

    /**
     * Decode a typed/scanned-back recovery phrase to its raw secret bytes, or null if malformed.
     * TOTAL (never throws) — it runs in UI layers. Strips hard-wrap whitespace, then base64url-decodes.
     */
    fun parseSecret(typed: String): ByteArray? = try {
        Bytes.fromB64(typed.filterNot { it in WHITESPACE })
    } catch (_: CryptoException) {
        null
    }

    /**
     * CONFIRMATION ONLY (§F.6): does what the user typed back re-decode to the SAME secret we
     * generated? Constant-time compare over the raw bytes ([Bytes.ctEquals]). This gates the
     * un-skippable "I saved my phrase" step; it is NEVER a KDF source — a mistype must fail the
     * confirm, never silently mis-key the wrap/auth derivation.
     */
    fun confirmMatches(recoverySecret: ByteArray, typedBackEncoded: String): Boolean {
        val typed = parseSecret(typedBackEncoded) ?: return false
        return Bytes.ctEquals(recoverySecret, typed)
    }
}
