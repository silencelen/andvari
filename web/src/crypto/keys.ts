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

const INFO_AUTH = utf8("andvari/v1/auth");
const INFO_WRAP = utf8("andvari/v1/wrap");

export function masterKey(password: string, kdfSalt: Uint8Array, params: KdfParams): Uint8Array {
  if (params.v !== 1 || params.alg !== "argon2id13") throw new CryptoError("unsupported kdfParams");
  if (kdfSalt.length !== KDF_SALT_BYTES) throw new CryptoError("kdfSalt must be 16 bytes");
  return argon2id(utf8(password), kdfSalt, KEY_BYTES, params.ops, params.memBytes);
}

export const authKey = (mk: Uint8Array) => hkdfSha256(mk, new Uint8Array(0), INFO_AUTH, KEY_BYTES);
export const wrapKey = (mk: Uint8Array) => hkdfSha256(mk, new Uint8Array(0), INFO_WRAP, KEY_BYTES);
