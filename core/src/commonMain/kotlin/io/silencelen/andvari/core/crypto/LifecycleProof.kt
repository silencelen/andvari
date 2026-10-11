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

    /** [Ad.join] parity (F33: a check, not a comment): several of these components arrive on
     *  server rows, and a `|` inside one would shift the tuple boundaries so two different
     *  tuples MAC identically. Conforming values (UUIDs, hex, base64url) can never contain
     *  `|`, so honest input — and the lifecycleproof.json vectors — never trips this. On the
     *  verify side every recompute site is runCatching-wrapped, so a throw degrades to
     *  "unverified" → retain-and-warn, exactly like a bad proof. */
    private fun requireDomainSafe(vararg parts: String) {
        for (p in parts) require('|' !in p) { "lifecycle proof component must not contain '|'" }
    }

    fun delete(crypto: CryptoProvider, key: ByteArray, vaultId: String, deleteId: String): String {
        requireDomainSafe(vaultId, deleteId)
        return mac(crypto, key, "andvari/v1|lifecycle|delete|$vaultId|$deleteId")
    }

    fun restore(crypto: CryptoProvider, key: ByteArray, vaultId: String, deleteId: String): String {
        requireDomainSafe(vaultId, deleteId)
        return mac(crypto, key, "andvari/v1|lifecycle|restore|$vaultId|$deleteId")
    }

    fun offer(
        crypto: CryptoProvider, key: ByteArray,
        vaultId: String, offerId: String, toUserId: String, expiresAt: Long, seq: Long,
    ): String {
        requireDomainSafe(vaultId, offerId, toUserId)
        return mac(crypto, key, "andvari/v1|lifecycle|transfer|$vaultId|$offerId|$toUserId|$expiresAt|$seq")
    }

    fun accept(
        crypto: CryptoProvider, key: ByteArray,
        vaultId: String, offerId: String, newOwnerUserId: String, seq: Long, wrappedVk: String,
    ): String {
        val wrapHash = Bytes.toHexLower(crypto.sha256(wrappedVk.encodeToByteArray()))
        return acceptFromHash(crypto, key, vaultId, offerId, newOwnerUserId, seq, wrapHash)
    }

    /**
     * Accept proof from the wrap HASH directly (mirror of web `acceptProofFromHash`): other
     * members receive only `lastTransfer.wrapHash` (= hexLower(sha256(utf8(wrappedVk)))),
     * never the new owner's wrappedVk blob, yet must re-verify the seq-chained acceptProof
     * to trust the ownership flip. Byte-identical domain to [accept] — the accepter passes
     * its own wrappedVk there.
     */
    fun acceptFromHash(
        crypto: CryptoProvider, key: ByteArray,
        vaultId: String, offerId: String, newOwnerUserId: String, seq: Long, wrapHash: String,
    ): String {
        requireDomainSafe(vaultId, offerId, newOwnerUserId, wrapHash)
        return mac(crypto, key, "andvari/v1|lifecycle|transfer-accept|$vaultId|$offerId|$newOwnerUserId|$seq|$wrapHash")
    }

    fun remove(crypto: CryptoProvider, key: ByteArray, vaultId: String, targetUserId: String, nonce: String): String {
        requireDomainSafe(vaultId, targetUserId, nonce)
        return mac(crypto, key, "andvari/v1|lifecycle|remove|$vaultId|$targetUserId|$nonce")
    }

    // ---- removal proofs v2 (security review 2026-10, root cause A §6.1; branch A7) ----
    //
    // Freshness-bound and single-use: a 16-byte CSPRNG nonce (base64url, unpadded) and the actor's wall clock
    // `issuedAt` (ms, decimal) ride every remove and every leave. Still MACs under [lifecycleKey] (owner decision
    // Q11: delete / restore / transfer stay MACs too): the server never holds VK, so it cannot mint one. The
    // verifier's order and the single-use rule live in [RemovalProof.decide].

    /** `andvari/v1|lifecycle|remove-v2|{vaultId}|{targetUserId}|{nonce}|{issuedAt}`. */
    fun removeV2(crypto: CryptoProvider, key: ByteArray, vaultId: String, targetUserId: String, nonce: String, issuedAt: Long): String {
        requireDomainSafe(vaultId, targetUserId, nonce)
        return mac(crypto, key, "andvari/v1|lifecycle|remove-v2|$vaultId|$targetUserId|$nonce|$issuedAt")
    }

    /** `andvari/v1|lifecycle|leave|{vaultId}|{userId}|{nonce}|{issuedAt}`: minted by the LEAVING member's client. */
    fun leave(crypto: CryptoProvider, key: ByteArray, vaultId: String, userId: String, nonce: String, issuedAt: Long): String {
        requireDomainSafe(vaultId, userId, nonce)
        return mac(crypto, key, "andvari/v1|lifecycle|leave|$vaultId|$userId|$nonce|$issuedAt")
    }

    /** A fresh v2 nonce: 16 CSPRNG bytes, base64url unpadded (22 chars). */
    fun newNonce(crypto: CryptoProvider): String = Bytes.toB64(crypto.randomBytes(16))

    /** True for a well-formed v2 nonce: base64url that decodes to exactly 16 bytes and re-encodes to itself. */
    fun isV2Nonce(nonce: String): Boolean {
        val raw = runCatching { Bytes.fromB64(nonce) }.getOrNull() ?: return false
        return raw.size == 16 && Bytes.toB64(raw) == nonce
    }

    /** Constant-time compare of a [presented] base64url proof against the [expected] value
     *  (recompute expected with the mint helper above). Any decode failure ⇒ false. */
    fun verify(expected: String, presented: String): Boolean {
        val e = runCatching { Bytes.fromB64(expected) }.getOrNull() ?: return false
        val p = runCatching { Bytes.fromB64(presented) }.getOrNull() ?: return false
        return Bytes.ctEquals(e, p)
    }
}
