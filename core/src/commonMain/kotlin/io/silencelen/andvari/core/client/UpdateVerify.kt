package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider

/**
 * H2 signed-update channel — client-side verification of the `/downloads` manifest (design
 * 2026-07-13-signed-updates §D/§M). Before offering any update, a client verifies a detached Ed25519
 * signature over the EXACT fetched manifest bytes against a PINNED public-key SET. Verify-only: the
 * release-signing private key lives on the owner's workstation (Option B, §A), never on any server.
 *
 * SECONDARY control by design (§M-D1): the load-bearing H2 fix is OS/store installer signing
 * (Authenticode MSI / GPG deb / store-signed extension). This layer kills a FABRICATED "update
 * available" nag and validly-signed downgrade-steering; it does NOT by itself stop a user who
 * downloads a trojan out-of-band from a compromised server.
 */
object UpdateVerify {
    /**
     * The pinned Ed25519 update-signing PUBLIC keys (base64url, 32 bytes each). A key SET (§M-D7) so
     * a rotation can overlap without bricking already-fielded clients. Ships with ONLY the
     * [TEST_PUBKEY] sentinel until the owner mints the real workstation key (§F) and its pubkey is
     * pinned here — at which point remove the sentinel.
     */
    const val TEST_PUBKEY = "TEST_KEY_placeholder__pin_the_real_workstation_pubkey_here"
    val PINNED: List<String> = listOf(TEST_PUBKEY)

    /**
     * §M-D3 — the update path is HARD-DISABLED while only the placeholder is pinned. A build that
     * cannot verify a genuine release must offer NO updates at all (fail-closed), never fall through
     * to a test-key-signed manifest (which would be forgeable by anyone holding the test seed).
     */
    fun updatesEnabled(pinned: List<String> = PINNED): Boolean = pinned.any { it != TEST_PUBKEY }

    /**
     * True iff [signature] is a valid detached Ed25519 signature over the EXACT [rawManifest] bytes
     * by any pinned key. Fail-closed: false if updates are disabled, on any base64 decode failure,
     * or on a bad signature. The caller MUST pass the RAW fetched bytes (never a re-serialized
     * object — §M-D6) and parse only AFTER this returns true.
     */
    fun verify(crypto: CryptoProvider, rawManifest: ByteArray, signature: ByteArray, pinned: List<String> = PINNED): Boolean {
        if (!updatesEnabled(pinned)) return false
        return pinned.any { pk ->
            runCatching { crypto.signVerifyDetached(Bytes.fromB64(pk), signature, rawManifest) }.getOrDefault(false)
        }
    }
}
