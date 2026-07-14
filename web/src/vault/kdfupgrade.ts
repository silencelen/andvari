import type { PasswordChangeRequest } from "../api/types";
import { KDF_MAX_MEM_BYTES, KDF_MAX_OPS, KDF_MIN_MEM_BYTES, KDF_MIN_OPS, type KdfParams } from "../crypto/keys";
import { Account } from "./account";

/**
 * F61 silent KDF upgrade (spec 01 §7, design 2026-07-10 §4) — the web + desktop mirror of the Android
 * post-unlock re-key (app-android KdfReKey + AndvariViewModel.runKdfUpgrade). After EVERY successful
 * full-master-password unlock WITH server connectivity, if the org policy raised the Argon2id cost,
 * transparently re-key with the SAME password (same UVK, new KDF params) — off the unlock path,
 * best-effort, NEVER blocking or failing the unlock. Only Android implemented it before this; web's
 * Settings changePassword was user-initiated only. NEVER on a quick-unlock/biometric or offline unlock
 * (web has neither), and never under a pending recovery-capture gate (enforced by the callers).
 */

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
  // Upgrade-only: the policy must dominate the account on BOTH axes...
  if (policy.memBytes < account.memBytes || policy.ops < account.ops) return false;
  // ...and be strictly greater on at least one (else it is an equal-params no-op).
  return policy.memBytes > account.memBytes || policy.ops > account.ops;
}

/** The two collaborators {@link maybeKdfUpgrade} needs — narrowed (the recovery-capture.ts house
 *  pattern) so a test can drive the orchestration with plain mocks, not a full ApiClient/Account. */
interface KdfUpgradeClient {
  changePassword(req: PasswordChangeRequest): Promise<unknown>;
}
interface KdfUpgradeAccount {
  buildPasswordChange(
    newPassword: string,
    params: KdfParams,
  ): Promise<{ newKdfSalt: string; newKdfParams: KdfParams; newAuthKey: string; newWrappedUvk: string }>;
}

export interface KdfUpgradeInputs {
  client: KdfUpgradeClient;
  account: KdfUpgradeAccount;
  /** The master password the caller just verified this unlock — re-derived under the new params. */
  password: string;
  /** The account's CURRENT server salt/params (the same accountKeys/prelogin values this unlock used). */
  currentKdfSalt: string;
  currentKdfParams: KdfParams;
  /** The LIVE-fetched org policy's target params — never a stale/persisted value (App.loadPolicy). */
  policyKdfParams: KdfParams;
  /** A5: an admin recovery left a temporary password live — never silently re-key it (Android parity). */
  mustChangePassword: boolean;
}

/**
 * Best-effort silent re-key (design §4). Gate on {@link shouldUpgrade}; if it fires, re-derive the
 * SAME password under the policy's params and PUT /account/password with the fresh derivation (new
 * salt / authKey / re-wrapped UVK — the UVK itself is INVARIANT across a KDF upgrade, so the vault
 * keys, identity seed and escrow all stay valid). ZK-preserving: only the derived authKey and the
 * re-wrapped UVK cross the wire, via the EXISTING changePassword. ANY failure is swallowed — the
 * unlock already succeeded and the check re-runs at the next online full-password unlock. The gate
 * runs BEFORE any argon2id, so a no-op unlock (the common case) pays nothing. Callers run this
 * DETACHED (never awaited on the unlock path) and only when the unlock reached the server and did NOT
 * route to the recovery-capture gate (a verifier rotation would strand that gate's reauth proof).
 */
export async function maybeKdfUpgrade(inputs: KdfUpgradeInputs): Promise<void> {
  if (inputs.mustChangePassword) return;
  if (!shouldUpgrade(inputs.currentKdfParams, inputs.policyKdfParams)) return;
  try {
    // currentAuthKey proves the caller knows the present password (the server re-verifies it, exactly
    // like a user-initiated change) — derived from the CURRENT salt/params the login already used.
    const currentAuthKey = await Account.deriveAuthKey(inputs.password, inputs.currentKdfSalt, inputs.currentKdfParams);
    const change = await inputs.account.buildPasswordChange(inputs.password, inputs.policyKdfParams);
    await inputs.client.changePassword({ currentAuthKey, ...change });
  } catch {
    // Best-effort by design: a transient failure (offline, 5xx, a concurrent change) just leaves the
    // account on the old params; the next online full-password unlock re-attempts.
  }
}
