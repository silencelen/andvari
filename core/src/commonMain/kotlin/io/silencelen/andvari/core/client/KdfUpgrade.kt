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
}
