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
     * The placeholder sentinel. Pinning ONLY this value hard-disables the update path (§M-D3
     * fail-closed) — which is the SHIPPED state again since the 2026-07-15 multi-tenant pivot
     * deliberately un-armed the channel (design §9; see [PINNED]).
     */
    const val TEST_PUBKEY = "TEST_KEY_placeholder__pin_the_real_workstation_pubkey_here"

    /**
     * UN-ARMED for the endpoint-agnostic pivot (design 2026-07-15-multi-tenant-endpoints §9): under
     * self-hosting, a single owner-pinned key makes every self-host `/downloads`
     * unverifiable-by-construction while keeping a live verification path aimed at untrusted
     * servers — so the shipped default re-pins the [TEST_PUBKEY] sentinel, which hard-disables the
     * whole update path fail-closed-quiet (§M-D3: [updatesEnabled] → false, no manifest fetch, no
     * nag). `/downloads` keeps serving as plain pull distribution. Per-instance signed updates
     * (key discovery/pinning/rotation) are separate later work; the signer + real key (ceremony
     * 2026-07-14, `docs/runbooks/release-signing-keys.md`) stay on the owner workstation. Still a
     * SET (§M-D7) so any future re-arm can rotate with overlap. Byte-locked to the extension's
     * `updateverify.ts PINNED_UPDATE_KEYS` by `updateverify.test.ts` — change together.
     */
    val PINNED: List<String> = listOf(TEST_PUBKEY)

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
