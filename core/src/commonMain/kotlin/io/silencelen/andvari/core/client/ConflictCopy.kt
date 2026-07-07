package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider

/**
 * Deterministic conflict-copy id (spec 03 §5): UUIDv4-shaped, derived from
 * sha256("conflict|itemId|rev"). Concurrent materializers across members/devices converge
 * on ONE copy id, absorbed by the server's idempotent existing-item path — a divergence
 * here between implementations silently doubles conflict copies, which is why the
 * derivation is vector-pinned (spec/test-vectors/conflictcopy.json) and shared: SyncEngine
 * calls this, vector-gen generates from it, and web/src/vault/store.ts mirrors it
 * byte-for-byte.
 */
object ConflictCopy {
    fun id(crypto: CryptoProvider, itemId: String, rev: Long): String {
        val h = crypto.sha256("conflict|$itemId|$rev".encodeToByteArray()).copyOf(16)
        h[6] = ((h[6].toInt() and 0x0F) or 0x40).toByte() // version nibble 4
        h[8] = ((h[8].toInt() and 0x3F) or 0x80).toByte() // variant 10
        val hex = Bytes.toHexLower(h)
        return "${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}"
    }
}
