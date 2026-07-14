import { utf8 } from "./bytes";
import { hkdfSha256 } from "./hkdf";
import { argon2id } from "./provider";
import { CryptoError } from "./sodium";

/** spec 01 §1 — per-user KDF parameters. */
export interface KdfParams {
  v: number;
  alg: string;
  ops: number;
  memBytes: number;
}

export const DEFAULT_KDF_PARAMS: KdfParams = { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 };
export const KDF_SALT_BYTES = 16;
export const KEY_BYTES = 32;

// H1 client-side sanity fence (spec 05 T1 / spec 01 §9). Mirrors core KdfUpgrade.MIN_/MAX_* and
// extension crypto.ts verbatim (drift-pinned by client.fence.test.ts). A hostile/misconfigured
// server must not be able to WEAKEN the master-password KDF below 64 MiB (the derived authKey would
// become offline-crackable once captured) or inflate it past 1 GiB (per-unlock DoS).
export const KDF_MIN_MEM_BYTES = 67_108_864; // 64 MiB
export const KDF_MIN_OPS = 3;
export const KDF_MAX_MEM_BYTES = 1_073_741_824; // 1 GiB
export const KDF_MAX_OPS = 10;

/** Raised when a server-supplied KdfParams falls outside the client fence — a distinct security
 *  state, never a wrong-password/transport error (spec 05 T1). */
export class KdfPolicyError extends Error {
  constructor(
    readonly code: "kdf_below_floor" | "kdf_above_ceiling",
    readonly params: KdfParams,
  ) {
    super(`server KDF params rejected (${code}): ops=${params.ops} memBytes=${params.memBytes}`);
    this.name = "KdfPolicyError";
  }
}

/** H1 fence — reject SERVER-SUPPLIED KDF params before any argon2id derives under them. Inclusive
 *  bounds (at-floor DEFAULT passes). Applied at the API-response boundary, NEVER in masterKey (the
 *  cross-impl vectors + the separate backup-KDF window legitimately derive below this floor). */
export function assertServerKdfParams(p: KdfParams): void {
  // Non-numeric / omitted fields (undefined, NaN, a string) slip past a bare `<`/`>` in JS — every
  // relational compare with them is false — so reject them explicitly. The KdfParams TS type is a
  // compile-time fiction over an unvalidated JSON.parse; a server that OMITS ops/memBytes must still
  // hit the distinct KdfPolicyError here, not derive under garbage and throw a generic crypto error.
  if (typeof p.ops !== "number" || !Number.isFinite(p.ops) || typeof p.memBytes !== "number" || !Number.isFinite(p.memBytes))
    throw new KdfPolicyError("kdf_below_floor", p);
  if (p.memBytes < KDF_MIN_MEM_BYTES || p.ops < KDF_MIN_OPS) throw new KdfPolicyError("kdf_below_floor", p);
  if (p.memBytes > KDF_MAX_MEM_BYTES || p.ops > KDF_MAX_OPS) throw new KdfPolicyError("kdf_above_ceiling", p);
}

/** Shared user-facing copy for a KdfPolicyError — a distinct security block, never a wrong-password. */
export const WEAK_KDF_MESSAGE =
  "This server sent weakened security settings for your master password. The action was blocked to protect you — contact your administrator.";

const INFO_AUTH = utf8("andvari/v1/auth");
const INFO_WRAP = utf8("andvari/v1/wrap");

export function masterKey(password: string, kdfSalt: Uint8Array, params: KdfParams): Uint8Array {
  if (params.v !== 1 || params.alg !== "argon2id13") throw new CryptoError("unsupported kdfParams");
  if (kdfSalt.length !== KDF_SALT_BYTES) throw new CryptoError("kdfSalt must be 16 bytes");
  return argon2id(utf8(password), kdfSalt, KEY_BYTES, params.ops, params.memBytes);
}

export const authKey = (mk: Uint8Array) => hkdfSha256(mk, new Uint8Array(0), INFO_AUTH, KEY_BYTES);
export const wrapKey = (mk: Uint8Array) => hkdfSha256(mk, new Uint8Array(0), INFO_WRAP, KEY_BYTES);
