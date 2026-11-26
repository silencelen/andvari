import { KDF_MAX_MEM_BYTES, KDF_MAX_OPS, KDF_MIN_MEM_BYTES, KDF_MIN_OPS, type KdfParams } from "../crypto/keys";

/**
 * F61's upgrade decision (spec 01 §7, "KDF upgrade"). The quiet re-key after a full-password unlock that reached the
 * server is vault/rekey.ts ({@link quietReKey}), which re-keys through the web's one password change; a password change
 * the person makes takes the policy's cost by the same decision (settingsflow.newPasswordCost).
 */

/**
 * The fence a re-key target must pass (spec 01 §7), also asked of a served wrap that is neither this browser's own nor a
 * pending one before the password is tried against it: the one scheme this client knows, never below the floor, never
 * above the ceiling, whole numbers only, and a memory cost that is a whole number of KiB.
 */
export function passesReKeyFence(p: KdfParams): boolean {
  if (p.v !== 1 || p.alg !== "argon2id13") return false;
  if (!Number.isInteger(p.ops) || !Number.isInteger(p.memBytes)) return false;
  if (p.memBytes < KDF_MIN_MEM_BYTES || p.ops < KDF_MIN_OPS) return false;
  if (p.memBytes > KDF_MAX_MEM_BYTES || p.ops > KDF_MAX_OPS) return false;
  return p.memBytes % 1024 === 0;
}

/**
 * PURE upgrade-decision — a verbatim TS replica of core `KdfUpgrade.shouldUpgrade`
 * (core/src/commonMain/.../client/KdfUpgrade.kt), which is Kotlin-only (commonMain) and so cannot be
 * called from the web bundle. The sanity-fence constants are the SAME KDF_MIN_/MAX_* already pinned in
 * crypto/keys.ts (⇔ core `KdfUpgrade.MIN_MEM_BYTES`=64 MiB / `MIN_OPS`=3 / `MAX_MEM_BYTES`=1 GiB /
 * `MAX_OPS`=10, drift-guarded across web/ext/core by client.fence.test.ts), so this can never diverge
 * from the Kotlin thresholds.
 *
 * True iff `policy` is a legitimate UPGRADE of `account`: it dominates on BOTH cost axes
 * (`memBytes >=` AND `ops >=`), is STRICTLY greater on at least one (equal params are a no-op, not an
 * upgrade), has `policy.v >= account.v`, and sits inside the sanity fence. Never sideways, never down,
 * never absurd — so a hostile `/client-policy` can neither talk a client into WEAKENING its own KDF
 * (spec 05 T1) nor into a per-unlock memory-exhaustion DoS. Both params reach here already
 * fence-validated at the API boundary (assertServerKdfParams in client.accountKeys() /
 * client.clientPolicy()), so — exactly like the Kotlin original over typed Longs — a plain numeric
 * comparison suffices and this never throws (a JS compare against a stray NaN is simply false).
 */
export function shouldUpgrade(account: KdfParams, policy: KdfParams): boolean {
  // Fail closed on a version regression rather than reason about an unknown scheme (v==1 today).
  if (policy.v < account.v) return false;
  // Sanity fence FIRST: a policy outside [floor, ceiling] is never an upgrade — below the floor is a
  // weakening disguised as an upgrade (never-below-64-MiB), above the ceiling is cost-inflation DoS.
  if (policy.memBytes < KDF_MIN_MEM_BYTES || policy.ops < KDF_MIN_OPS) return false;
  if (policy.memBytes > KDF_MAX_MEM_BYTES || policy.ops > KDF_MAX_OPS) return false;
  // Spec 01 §7: a memory cost that is not a whole number of KiB is never a target (argon2id counts memory in KiB; the
  // shared code's re-key refuses it too).
  if (policy.memBytes % 1024 !== 0) return false;
  // Upgrade-only: the policy must dominate the account on BOTH axes...
  if (policy.memBytes < account.memBytes || policy.ops < account.ops) return false;
  // ...and be strictly greater on at least one (else it is an equal-params no-op).
  return policy.memBytes > account.memBytes || policy.ops > account.ops;
}
