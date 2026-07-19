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
     * ARMED 2026-07-18 with the ceremony key (minted 2026-07-14 on the owner workstation, public
     * record `docs/runbooks/release-signing-keys.md`; the PRIVATE key never leaves that machine —
     * Option B). The 2026-07-15 multi-tenant pivot had UN-armed this (design §9): a single
     * owner-pinned key makes every self-host `/downloads` unverifiable-by-construction. That
     * objection is answered by SCOPE, not by staying dark: the CALLERS (desktop
     * `Platform.checkForUpdate`, extension `background.checkForUpdate`) gate the whole channel on
     * the configured server being the shipped REFERENCE origin — a self-host/custom origin never
     * fetches the manifest at all, landing in the same fail-closed-quiet "disabled" state the
     * un-armed build had. Per-instance signed updates (key discovery/pinning/rotation) remain
     * separate later work. Still a SET (§M-D7) so a rotation can overlap without bricking fielded
     * clients. Byte-locked to the extension's `updateverify.ts PINNED_UPDATE_KEYS` by
     * `updateverify.test.ts` — change together.
     */
    val PINNED: List<String> = listOf("e_2TpyoQG4ygtbdVO9RUWbUW4MTHGPO8eXL7Jqc_tHI")

    /**
     * §M-D4(a) — compile-time anti-rollback FLOOR: the lowest signed-manifest `seq` a FRESH desktop
     * install (or one whose persisted desktop `lastAcceptedSeq` was wiped) will accept. Desktop
     * `Platform.checkForUpdate` floors the caller's stored seq at this
     * (`maxOf(storedSeq, MIN_SEQ)`), shrinking the fresh-install window a T1 server could use to
     * steer a client to a validly-signed-but-older (known-vuln) manifest below the floor.
     *
     * 1 since the first signed manifest published (seq 1, 2026-07-18 — the arming release); track
     * the published floor upward on later releases when raising it is worth the recompile. NOTE the
     * deliberate NUMERIC asymmetry with the extension's `MIN_SEQ = 0`: desktop refuses
     * `seq < floor` (equal passes — steady-state re-fetch of the accepted manifest), the extension
     * refuses `seq <= lastAccepted` (its floor doubles as "already recorded"), so the SAME semantic
     * floor — "the earliest acceptable published seq is 1" — is 1 here and 0 there. Keep the two in
     * SEMANTIC lockstep (both must admit the current first-published seq and refuse anything older).
     */
    const val MIN_SEQ: Long = 1

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
