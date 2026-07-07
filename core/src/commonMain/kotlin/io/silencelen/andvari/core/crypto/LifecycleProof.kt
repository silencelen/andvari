package io.silencelen.andvari.core.crypto

/**
 * Lifecycle proofs (spec 03 §11) — the trust layer for destructive shared-vault ops.
 *
 * Each delete/restore/transfer/remove op carries an HMAC-SHA-256 under a key derived from
 * the vault key VK, which the server never holds. A member's 0.5.0 client recomputes the
 * proof under its held VK and constant-time-compares before treating a server's destructive
 * claim as a genuine owner action; a mismatch degrades to retain-and-warn, never a purge.
 *
 * These are MACs, not signatures: any current VK holder could mint a valid proof, so this
 * removes only the SERVER from the forgery set (server-side owner-principal authz remains
 * the real gate). Full sender-signed grants (Ed25519 identity) are deferred to P6.
 *
 * Wire encoding (pinned by spec/test-vectors/lifecycleproof.json — web + JVM must not
 * drift): domain strings are `|`-joined UTF-8 (spec 00); integers are decimal; the
 * accept proof embeds the LOWERCASE-HEX SHA-256 of the posted wrappedVk STRING's UTF-8
 * bytes (binds the exact blob the server stored). Proof values are base64url, unpadded.
 */
object LifecycleProof {
    private const val LIFECYCLE_INFO = "andvari/v1|lifecycle"

    /** `lifecycleKey = HKDF-SHA-256(ikm = VK, salt = "", info = "andvari/v1|lifecycle", 32)`. */
    fun lifecycleKey(crypto: CryptoProvider, vk: ByteArray): ByteArray =
        Hkdf.sha256(crypto, ikm = vk, salt = ByteArray(0), info = LIFECYCLE_INFO.encodeToByteArray(), length = 32)

    private fun mac(crypto: CryptoProvider, key: ByteArray, domain: String): String =
        Bytes.toB64(crypto.hmacSha256(key, domain.encodeToByteArray()))

    fun delete(crypto: CryptoProvider, key: ByteArray, vaultId: String, deleteId: String): String =
        mac(crypto, key, "andvari/v1|lifecycle|delete|$vaultId|$deleteId")

    fun restore(crypto: CryptoProvider, key: ByteArray, vaultId: String, deleteId: String): String =
        mac(crypto, key, "andvari/v1|lifecycle|restore|$vaultId|$deleteId")

    fun offer(
        crypto: CryptoProvider, key: ByteArray,
        vaultId: String, offerId: String, toUserId: String, expiresAt: Long, seq: Long,
    ): String = mac(crypto, key, "andvari/v1|lifecycle|transfer|$vaultId|$offerId|$toUserId|$expiresAt|$seq")

    fun accept(
        crypto: CryptoProvider, key: ByteArray,
        vaultId: String, offerId: String, newOwnerUserId: String, seq: Long, wrappedVk: String,
    ): String {
        val wrapHash = Bytes.toHexLower(crypto.sha256(wrappedVk.encodeToByteArray()))
        return mac(crypto, key, "andvari/v1|lifecycle|transfer-accept|$vaultId|$offerId|$newOwnerUserId|$seq|$wrapHash")
    }

    fun remove(crypto: CryptoProvider, key: ByteArray, vaultId: String, targetUserId: String, nonce: String): String =
        mac(crypto, key, "andvari/v1|lifecycle|remove|$vaultId|$targetUserId|$nonce")

    /** Constant-time compare of a [presented] base64url proof against the [expected] value
     *  (recompute expected with the mint helper above). Any decode failure ⇒ false. */
    fun verify(expected: String, presented: String): Boolean {
        val e = runCatching { Bytes.fromB64(expected) }.getOrNull() ?: return false
        val p = runCatching { Bytes.fromB64(presented) }.getOrNull() ?: return false
        return Bytes.ctEquals(e, p)
    }
}
