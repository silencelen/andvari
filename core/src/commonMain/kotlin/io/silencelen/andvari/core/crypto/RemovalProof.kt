package io.silencelen.andvari.core.crypto

/**
 * The removal-proof verifier (security review 2026-10, root cause A §6.3, §8.6; branch A7): what the TARGET's
 * device concludes about a `removed` or `left` entry of `removedGrantsInfo`, for a vault whose key it held before
 * the pull. Pure, so `spec/test-vectors/lifecycleproof.json` → `verdicts` grades exactly the function
 * [io.silencelen.andvari.core.client.SyncEngine] calls. Web twin: `decideRemoval` in `web/src/crypto/lifecycleproof.ts`.
 *
 * The caller handles reason `deleted` (its deleteId-consumption logic is unchanged) and a self-initiated drop
 * (`suppressDrop`) BEFORE this runs. Then the steps run in order and the FIRST failure is the verdict:
 *
 *  3. `proofV == 2` with `proof`, `nonce` (16 bytes, base64url) and `issuedAt` present. Otherwise, while the
 *     compatibility window is open (release N, §8.6): a v1 `remove` proof is "valid (legacy)" iff its MAC verifies
 *     for this target and its nonce is unconsumed (then it is consumed); a `left` with no proof at all is
 *     [Verdict.LEFT_UNPROVEN] ("You left" plus "Didn't do this? Tell your admin"); anything else is an anomaly.
 *     (After the window, branch A8 makes both of those anomalies; not built here.)
 *  4. the MAC for the reason's domain (`remove-v2` for removed, `leave` for left) with target = MY userId,
 *     constant-time compared;
 *  5. the nonce is not in THIS DEVICE's consumed set — else [Verdict.REPLAY_DENIED];
 *  6. `liveSince − 10 min <= issuedAt <= now + 10 min`, where `liveSince` is the DEVICE-LOCAL time this device last
 *     saw the vault go from not-live to live (never a server value). A missing `liveSince` fails closed.
 *  6′. (A7 review MEDIUM-2, a refinement of design §6.3 step 5) a nonce found only in the ACCOUNT-STATE set, inside
 *     this device's window, was consumed by another of this user's devices for the same genuine removal:
 *     [Verdict.ALREADY_RECORDED], calm, and consumed here too. The window is checked first, so a proof replayed
 *     after a re-add this device saw is still an anomaly.
 *  7. valid: the caller consumes `(vaultId, nonce, issuedAt)` in the same transaction that moves the vault to the
 *     holding area.
 *
 * A verdict changes only the banner's wording and attribution: the data handling (holding area, 30 days) is the
 * same either way.
 */
object RemovalProof {
    /** ±10 minutes of clock skew around `liveSince` and `now` (§6.3 step 6). */
    const val SKEW_MS = 10L * 60 * 1000

    enum class Verdict(val code: String) {
        /** A v2 proof that passed every step: the attributed notice. */
        VALID("valid"),

        /** In-window only (§8.6): a v1 `remove` proof whose MAC verifies and whose nonce was unconsumed. */
        VALID_LEGACY("valid_legacy"),

        /** In-window only (§8.6): `left` with no proof at all. "You left" plus "Didn't do this? Tell your admin". */
        LEFT_UNPROVEN("left_unproven"),

        /** Any failed step except a consumed nonce: the "server may be misbehaving" warning. */
        ANOMALY("anomaly"),

        /** The nonce was already consumed on THIS device (§6.3 step 5). Anomaly tone. */
        REPLAY_DENIED("replay_denied"),

        /** The nonce is only in account state: another of this user's devices consumed it. Calm (A7 review MEDIUM-2). */
        ALREADY_RECORDED("already_recorded"),
    }

    /** The verdict, and for a valid one the record to consume. [step] names the §6.3 step that decided it. */
    class Decision(val verdict: Verdict, val step: String, val consumeNonce: String? = null, val consumeIssuedAt: Long? = null)

    fun decide(
        crypto: CryptoProvider,
        lifecycleKey: ByteArray,
        vaultId: String,
        myUserId: String,
        reason: String,
        proofV: Int?,
        proof: String?,
        nonce: String?,
        issuedAt: Long?,
        consumed: Set<String>,
        consumedAccount: Set<String>,
        liveSince: Long?,
        now: Long,
    ): Decision {
        if (reason != "removed" && reason != "left") return Decision(Verdict.ANOMALY, "reason")
        // Step 3: a complete v2 proof, else the in-window legacy rows.
        if (proofV != 2) return legacy(crypto, lifecycleKey, vaultId, myUserId, reason, proofV, proof, nonce, consumed, consumedAccount, now)
        if (proof.isNullOrEmpty() || nonce == null || issuedAt == null || !LifecycleProof.isV2Nonce(nonce)) {
            return Decision(Verdict.ANOMALY, "fields")
        }
        // Step 4: the MAC for this reason's domain, addressed to ME.
        val expected = runCatching {
            if (reason == "removed") LifecycleProof.removeV2(crypto, lifecycleKey, vaultId, myUserId, nonce, issuedAt)
            else LifecycleProof.leave(crypto, lifecycleKey, vaultId, myUserId, nonce, issuedAt)
        }.getOrNull() ?: return Decision(Verdict.ANOMALY, "mac")
        if (!LifecycleProof.verify(expected, proof)) return Decision(Verdict.ANOMALY, "mac")
        // Step 5: single use on THIS device.
        if (nonce in consumed) return Decision(Verdict.REPLAY_DENIED, "nonce")
        // Step 6: inside THIS device's own window.
        if (liveSince == null || issuedAt < liveSince - SKEW_MS || issuedAt > now + SKEW_MS) return Decision(Verdict.ANOMALY, "window")
        // Step 6': consumed by another of my devices (account state only).
        if (nonce in consumedAccount) return Decision(Verdict.ALREADY_RECORDED, "recorded", nonce, issuedAt)
        return Decision(Verdict.VALID, "valid", nonce, issuedAt)
    }

    /** §8.6 in-window rows. A v1 proof has no issuedAt: it is consumed with the local time of consumption. */
    private fun legacy(
        crypto: CryptoProvider,
        lifecycleKey: ByteArray,
        vaultId: String,
        myUserId: String,
        reason: String,
        proofV: Int?,
        proof: String?,
        nonce: String?,
        consumed: Set<String>,
        consumedAccount: Set<String>,
        now: Long,
    ): Decision {
        if (proofV != null && proofV != 1) return Decision(Verdict.ANOMALY, "fields") // an unknown proof version
        if (reason == "left") {
            // No leave proof existed before v2: a bare `left` is the in-window row, anything half-present is not.
            return if (proof == null && nonce == null) Decision(Verdict.LEFT_UNPROVEN, "legacy") else Decision(Verdict.ANOMALY, "fields")
        }
        if (proof.isNullOrEmpty() || nonce.isNullOrEmpty()) return Decision(Verdict.ANOMALY, "fields")
        val expected = runCatching { LifecycleProof.remove(crypto, lifecycleKey, vaultId, myUserId, nonce) }.getOrNull()
            ?: return Decision(Verdict.ANOMALY, "mac")
        if (!LifecycleProof.verify(expected, proof)) return Decision(Verdict.ANOMALY, "mac")
        if (nonce in consumed) return Decision(Verdict.REPLAY_DENIED, "nonce")
        if (nonce in consumedAccount) return Decision(Verdict.ALREADY_RECORDED, "recorded", nonce, now)
        return Decision(Verdict.VALID_LEGACY, "legacy", nonce, now)
    }
}
