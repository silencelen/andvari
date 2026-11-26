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
     * not an upgrade), has `policy.v >= account.v`, sits inside the sanity fence above, and asks for
     * a memory cost that is a whole number of KiB.
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
        if (!withinFence(policy)) return false
        // Upgrade-only: the policy must dominate the account on BOTH axes...
        if (policy.memBytes < account.memBytes || policy.ops < account.ops) return false
        // ...and be strictly greater on at least one (else it is an equal-params no-op).
        return policy.memBytes > account.memBytes || policy.ops > account.ops
    }

    /**
     * Whether the quiet raising of the account's cost is due on the new engine (decided on 2026-11-17): the served cost
     * [served] is inside this client's fence ([withinFence]) and [account] is below it on ANY figure (memory or passes),
     * with `served.v >= account.v`. The wrap is then made at [wrapCost] (figure by figure the higher of the two, inside
     * this client's limits), so no figure is ever lowered and none is raised beyond what the server serves or this device
     * accepts. Unlike [shouldUpgrade], an account that stands above the served cost on one figure and below it on the
     * other is raised (only on the figure it lacks): the server refuses a new wrap below its served cost on any figure.
     * Nonsense answers false, never a throw.
     */
    fun belowServed(account: KdfParams, served: KdfParams): Boolean {
        if (served.v < account.v) return false
        if (!withinFence(served)) return false
        return account.memBytes < served.memBytes || account.ops < served.ops
    }

    /**
     * The fence a re-key target must pass, on its own (spec 01 §7): never below the floor, never above the ceiling, and a
     * memory cost that is a whole number of KiB. The last one because the server refuses any other cost as
     * `kdf_mem_not_kib_multiple` (spec 03), and the Argon2id engines round such a cost differently, so a wrap made at one
     * could open on one client and read as a wrong password on another. A wrap the server serves that is neither this
     * device's own nor its pending one is tried only at a cost inside it, so a server can make a device derive neither a
     * cheap hash of the password nor an absurdly costly one.
     */
    fun withinFence(p: KdfParams): Boolean {
        if (p.memBytes < MIN_MEM_BYTES || p.ops < MIN_OPS) return false
        if (p.memBytes > MAX_MEM_BYTES || p.ops > MAX_OPS) return false
        return p.memBytes % 1024L == 0L
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
     * The fence numbers are pinned against the web + extension copies by
     * AndvariApiFenceTest.fenceConstantsPinnedToWebAndExtension (spec 01 §9).
     */
    fun requireServerKdfParams(p: KdfParams) {
        if (p.memBytes < MIN_MEM_BYTES || p.ops < MIN_OPS) throw KdfPolicyViolationException("kdf_below_floor", p)
        if (p.memBytes > MAX_MEM_BYTES || p.ops > MAX_OPS) throw KdfPolicyViolationException("kdf_above_ceiling", p)
        // The whole fence on every served cost, not only on a re-key's target or a served wrap's try: the Argon2id engines
        // round a memory cost that is not a whole number of KiB differently, so deriving at one could read as a wrong
        // password on one client and open on another. A server that serves one is at fault, never the password.
        if (p.memBytes % 1024L != 0L) throw KdfPolicyViolationException(NOT_KIB, p)
    }

    /** [KdfPolicyViolationException.reason] for a served memory cost that is not a whole number of KiB. */
    const val NOT_KIB = "kdf_mem_not_kib_multiple"

    /**
     * The cost a NEW wrap of the master password is made at (spec 01 §7; decided on 2026-11-17): figure by figure, the
     * higher of what the account already has ([own], each wrap this device knows of it, none when there is no account yet
     * or the device does not know its cost) and what the server serves ([served]), kept inside this client's own limits.
     * A server floor raised above an account's cost, or an account that stands above the served cost on one figure and
     * below it on the other, so both meet a cost the server takes. Before, a registration was made at the fixed default and
     * a password change or a recovery at the account's own cost raised only where [shouldUpgrade] held: on a server whose
     * floor was raised, every registration was refused, and an account that straddled the served cost could neither change
     * its password nor recover on a device that keeps it.
     *
     * A [served] cost outside the fence ([withinFence]) is not taken, as before: nothing is derived at it, and the cost is
     * the one without it. Null [served] (the policy could not be read): the account's own, or the default. The default is
     * the floor of the result, and every figure is kept inside [MIN_OPS]..[MAX_OPS] and [MIN_MEM_BYTES]..[MAX_MEM_BYTES],
     * the memory a whole number of KiB. This is the cost of a wrap made; WHEN the quiet raising is due is [shouldUpgrade]'s
     * alone, unchanged.
     */
    fun wrapCost(served: KdfParams?, vararg own: KdfParams?): KdfParams {
        var ops = KdfParams.DEFAULT.ops
        var mem = KdfParams.DEFAULT.memBytes
        val taken = served?.takeIf { withinFence(it) }
        for (p in listOfNotNull(taken, *own)) {
            ops = maxOf(ops, p.ops)
            mem = maxOf(mem, p.memBytes)
        }
        ops = ops.coerceIn(MIN_OPS, MAX_OPS)
        mem = ((mem + 1023L) / 1024L * 1024L).coerceIn(MIN_MEM_BYTES, MAX_MEM_BYTES)
        return KdfParams(ops = ops, memBytes = mem)
    }
}

/**
 * Raised when a server-supplied [KdfParams] fails [KdfUpgrade.requireServerKdfParams] — a hostile or
 * misconfigured server tried to weaken (or DoS) the master-password KDF (spec 05 T1). Deliberately
 * NOT an ApiException, so generic API error handling cannot relabel it as a transport / auth failure:
 * clients surface it as a distinct "the server sent weakened security settings" warning, never as a
 * wrong-password error. [reason] is `kdf_below_floor`, `kdf_above_ceiling` or [KdfUpgrade.NOT_KIB].
 */
class KdfPolicyViolationException(val reason: String, val params: KdfParams) :
    Exception("server KDF params rejected ($reason): ops=${params.ops} memBytes=${params.memBytes}")
