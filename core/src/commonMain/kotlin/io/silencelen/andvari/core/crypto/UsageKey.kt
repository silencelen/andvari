package io.silencelen.andvari.core.crypto

/**
 * The usage-ledger key (spec 02 §8.2) — the Kotlin twin of web/src/crypto/usagekey.ts.
 *
 * Derived from the PERSONAL VAULT KEY rather than the UVK, for a client reason rather than a
 * cryptographic one: the browser extension's UVK is memory-only and never persisted (spec 01
 * breaker B1), and an evicted MV3 service worker restores a session holding `vaultKeys` but no
 * UVK — so a UVK-bound ledger would be unwritable from the client that does most of the
 * filling. Every unlocked client holds the personal VK in every session.
 *
 * Domain-separated from the VK's own AEAD use exactly as [LifecycleProof.lifecycleKey] is:
 * same construction, different info string. The AEAD associated data stays
 * `andvari/v1|usage|{userId}` ([Ad.usage]), so the blob remains bound to the user's slot.
 */
object UsageKey {
    private const val USAGE_INFO = "andvari/v1|usage"

    /** `usageKey = HKDF-SHA-256(ikm = VK(personalVault), salt = "", info = "andvari/v1|usage", 32)`. */
    fun usageKey(crypto: CryptoProvider, vk: ByteArray): ByteArray =
        Hkdf.sha256(crypto, ikm = vk, salt = ByteArray(0), info = USAGE_INFO.encodeToByteArray(), length = 32)
}
