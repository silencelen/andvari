package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.KdfParams

/**
 * F61 KDF-upgrade decision (spec 01 §7, design 2026-07-10 §4) — a PURE partial-order test with
 * no crypto and no IO. [shouldUpgrade] is the SOLE gate on the silent re-key: it must be
 * impossible for a hostile/compromised `/client-policy` response to talk a client into either
 * WEAKENING its own KDF or turning every unlock into a memory-exhaustion DoS (spec 05 T1).
 * Never sideways, never down, never absurd — and never throw (nonsense returns false).
 */
object KdfUpgrade {
    // Client-side sanity fence (spec 01 §7 "client-side sanity bounds"), enforced on the POLICY
    // regardless of how it compares to the account. Below the floor = a weakening disguised as
    // an upgrade (spec 01 §9 never-below-64-MiB); above the ceiling = a cost-inflation DoS a
    // compromised server could switch on at every unlock.
    const val MIN_MEM_BYTES = 67_108_864L      // 64 MiB — the spec 01 §9 memory floor.
    const val MIN_OPS = 3L                     // never re-key below t=3.
    const val MAX_MEM_BYTES = 1_073_741_824L   // 1 GiB — refuse absurd cost inflation.
    const val MAX_OPS = 10L

    /**
     * True iff [policy] is a legitimate UPGRADE of [account]: it dominates on BOTH cost axes
     * (`memBytes >= AND ops >=`), is STRICTLY greater on at least one (equal params are a no-op,
     * not an upgrade), has `policy.v >= account.v`, and sits inside the sanity fence above.
     *
     * PARTIAL-ORDER GAP (breaker-named, accepted): "dominates on both axes" is a partial order,
     * so an account that STRADDLES the policy — higher on one axis, lower on the other — never
     * converges to it: a mixed policy is intentionally NOT an upgrade, because reaching it would
     * require ALSO lowering an axis, which spec 01 §7 forbids. Convergence is therefore
     * guaranteed only for accounts already `<=` policy on both axes; that is the accepted cost of
     * refusing sideways moves. Downgrade-safety beats universal convergence.
     */
    fun shouldUpgrade(account: KdfParams, policy: KdfParams): Boolean {
        // Fail closed on a version regression rather than reason about an unknown scheme. (The
        // KdfParams invariant pins v==1 today, so this is future-proofing, not a live branch.)
        if (policy.v < account.v) return false
        // Sanity fence FIRST: a policy outside [floor, ceiling] is never an upgrade, no matter
        // how it compares to the account — a compromised server must be able to neither weaken
        // nor DoS the KDF.
        if (policy.memBytes < MIN_MEM_BYTES || policy.ops < MIN_OPS) return false
        if (policy.memBytes > MAX_MEM_BYTES || policy.ops > MAX_OPS) return false
        // Upgrade-only: the policy must dominate the account on BOTH axes...
        if (policy.memBytes < account.memBytes || policy.ops < account.ops) return false
        // ...and be strictly greater on at least one (else it is an equal-params no-op).
        return policy.memBytes > account.memBytes || policy.ops > account.ops
    }

    /**
     * H1 compliance fence (spec 05 T1 / spec 01 §9) — reject SERVER-SUPPLIED [KdfParams] that fall
     * outside the client-side sanity bounds BEFORE they are ever fed to argon2id on a login / enroll
     * / recovery path. A compromised or misconfigured server must be unable to (a) WEAKEN the
     * master-password KDF below the 64 MiB floor (the derived authKey would become offline-crackable
     * once the server captures it — the exact T1 break), or (b) inflate it past the ceiling to turn
     * every unlock into a memory-exhaustion DoS. Enforced at the server-response ingestion boundary
     * (AndvariApi), NEVER inside Keys.masterKey: the cross-impl test vectors and the deliberately
     * separate backup-KDF window (spec 07 §2.3) legitimately derive below this floor. Inclusive
     * bounds — at-floor DEFAULT (64 MiB / t=3) passes (mirrors [shouldUpgrade]'s strict `<`/`>`).
     * The fence numbers are pinned by KdfBoundsTest against the web + extension copies (spec 01 §9).
     */
    fun requireServerKdfParams(p: KdfParams) {
        if (p.memBytes < MIN_MEM_BYTES || p.ops < MIN_OPS) throw KdfPolicyViolationException("kdf_below_floor", p)
        if (p.memBytes > MAX_MEM_BYTES || p.ops > MAX_OPS) throw KdfPolicyViolationException("kdf_above_ceiling", p)
    }
}

/**
 * Raised when a server-supplied [KdfParams] fails [KdfUpgrade.requireServerKdfParams] — a hostile or
 * misconfigured server tried to weaken (or DoS) the master-password KDF (spec 05 T1). Deliberately
 * NOT an ApiException, so generic API error handling cannot relabel it as a transport / auth failure:
 * clients surface it as a distinct "the server sent weakened security settings" warning, never as a
 * wrong-password error. [reason] is `kdf_below_floor` or `kdf_above_ceiling`.
 */
class KdfPolicyViolationException(val reason: String, val params: KdfParams) :
    Exception("server KDF params rejected ($reason): ops=${params.ops} memBytes=${params.memBytes}")
