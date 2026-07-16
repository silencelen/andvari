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

    /**
     * The real workstation update-signing public key(s) (ceremony 2026-07-14 —
     * `docs/runbooks/release-signing-keys.md`). A SET (§M-D7) so a future rotation can add the next
     * key and overlap without bricking fielded clients. The private key lives only on the owner's
     * workstation; each release's `/downloads/manifest.json` is signed there with `tools/update-signer`.
     */
    val PINNED: List<String> = listOf("e_2TpyoQG4ygtbdVO9RUWbUW4MTHGPO8eXL7Jqc_tHI")

    /**
     * §M-D4(a) — compile-time anti-rollback FLOOR: the lowest signed-manifest `seq` a FRESH desktop
     * install (or one whose persisted desktop `lastAcceptedSeq` was wiped) will accept. Desktop
     * `Platform.checkForUpdate` floors the caller's stored seq at this
     * (`maxOf(storedSeq, MIN_SEQ)`), shrinking the fresh-install window a T1 server could use to
     * steer a client to a validly-signed-but-older (known-vuln) manifest below the floor.
     *
     * 0 for now: NO signed manifest is published to `/downloads` yet (H2 signing is owner-pending),
     * so 0 admits the first real release (`seq` 1) while flooring any wiped state at ≥ 0. Bump to the
     * first published manifest's `seq` at the first signed release. Mirrors the extension's
     * `updateverify.ts MIN_SEQ = 0` (a DIFFERENT lane owns the extension) — keep the two in lockstep.
     */
    const val MIN_SEQ: Long = 0

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
