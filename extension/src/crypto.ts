import { argon2id } from "@noble/hashes/argon2.js";
import { blake2b } from "@noble/hashes/blake2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import nacl from "tweetnacl";

/**
 * andvari crypto for the extension — pure-JS @noble, no WASM, no eval → runs under the MV3
 * service-worker CSP. Byte-identical to the fleet's libsodium and to spec/test-vectors/kdf.json
 * (proven: web/src/crypto/noble-extension-poc.test.ts). Constructions mirror core Envelope.kt /
 * web envelope.ts exactly, so anything sealed here interoperates with every other client.
 */

export const KEY_BYTES = 32;
const NONCE_BYTES = 24;
const ENVELOPE_VERSION = 0x01;
const ENVELOPE_ALG_XCHACHA20POLY1305_IETF = 0x01;

export interface KdfParams {
  v: number;
  alg: string;
  ops: number;
  memBytes: number;
}
export const DEFAULT_KDF_PARAMS: KdfParams = { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 };

// H1 client-side sanity fence (spec 05 T1 / spec 01 §9). Mirrors core KdfUpgrade.MIN_/MAX_* and web
// keys.ts verbatim (drift-pinned by crypto.test). A hostile/misconfigured server must not WEAKEN the
// master-password KDF below 64 MiB (its authKey would become offline-crackable once captured) nor
// inflate it past 1 GiB — a 4 GiB memBytes would OOM the MV3 service worker.
export const KDF_MIN_MEM_BYTES = 67_108_864; // 64 MiB
export const KDF_MIN_OPS = 3;
export const KDF_MAX_MEM_BYTES = 1_073_741_824; // 1 GiB
export const KDF_MAX_OPS = 10;

/** Distinct security signal — a server tried to weaken/DoS the master-password KDF (spec 05 T1). */
export class KdfPolicyError extends Error {
  // Explicit field (not a constructor parameter property): the extension test runner is Node
  // --experimental-strip-types (strip-only), which rejects TS parameter-property shorthand.
  readonly reason: "kdf_below_floor" | "kdf_above_ceiling";
  constructor(reason: "kdf_below_floor" | "kdf_above_ceiling") {
    super(`server KDF params rejected (${reason})`);
    this.name = "KdfPolicyError";
    this.reason = reason;
  }
}

/** H1 fence — reject SERVER-SUPPLIED KDF params before any argon2id derives under them. Inclusive
 *  bounds (at-floor DEFAULT passes); applied at the unlock ingestion boundary, never in the primitive. */
export function assertServerKdfParams(p: KdfParams): void {
  // Non-numeric / omitted fields (undefined, NaN, a string) slip past a bare `<`/`>` in JS, so reject
  // them explicitly — an omitted ops/memBytes must still hit the distinct KdfPolicyError, not derive
  // under garbage (mirrors web keys.ts).
  if (typeof p.ops !== "number" || !Number.isFinite(p.ops) || typeof p.memBytes !== "number" || !Number.isFinite(p.memBytes))
    throw new KdfPolicyError("kdf_below_floor");
  if (p.memBytes < KDF_MIN_MEM_BYTES || p.ops < KDF_MIN_OPS) throw new KdfPolicyError("kdf_below_floor");
  if (p.memBytes > KDF_MAX_MEM_BYTES || p.ops > KDF_MAX_OPS) throw new KdfPolicyError("kdf_above_ceiling");
}

const utf8 = (s: string) => new TextEncoder().encode(s);

// Associated data (spec 02 §2, mirrors core Ad.kt / web ad.ts): "andvari/v1|<parts joined by |>".
const AD_NS = "andvari/v1";
function ad(...parts: string[]): Uint8Array {
  for (const p of parts) if (p.includes("|")) throw new Error("AD component must not contain '|'");
  return utf8(`${AD_NS}|${parts.join("|")}`);
}
export const adUvk = (userId: string): Uint8Array => ad("uvk", userId);
export const adVk = (vaultId: string, userId: string): Uint8Array => ad("vk", vaultId, userId);
export const adIdkey = (userId: string): Uint8Array => ad("idkey", userId);
/** Extension quick-unlock (Tier B, spec 01 §8.4) AAD: "andvari/v1|ext-quick-unlock|<userId>".
 *  Binds a PIN-wrapped UVK blob to its account (a blob copied to another userId cannot open, and
 *  a tampered blob fails the tag). Distinct token from Android's `quick-unlock` (§8.1) — the two
 *  platforms never share a blob. Applied to BOTH double-wrap layers (PIN + non-extractable co-key). */
export const adQuickUnlock = (userId: string): Uint8Array => ad("ext-quick-unlock", userId);
// Biometric quick-unlock blobs use a DISTINCT AAD (0.17.0, review amendment 2) so a cross-kind
// transplant (a bio blob relabelled 'pin' or vice versa) fails the AEAD tag, not merely key-space luck.
export const adQuickUnlockBio = (userId: string): Uint8Array => ad("ext-quick-unlock-bio", userId);
export const adItem = (vaultId: string, itemId: string, formatVersion: number): Uint8Array =>
  ad("item", vaultId, itemId, String(formatVersion));

/**
 * X25519 identity keypair from a 32-byte seed — == libsodium crypto_box_seed_keypair
 * (sk = SHA512(seed)[:32]; pk = X25519_base(sk)). Verified byte-parity with libsodium.
 */
export function boxKeypairFromSeed(seed: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const privateKey = sha512(seed).slice(0, 32); // unclamped (nacl.box.before clamps at use)
  const clamped = new Uint8Array(privateKey);
  clamped[0] &= 248;
  clamped[31] &= 127;
  clamped[31] |= 64; // X25519 clamp, only for the base-point multiply
  return { publicKey: nacl.scalarMult.base(clamped), privateKey };
}

/**
 * crypto_box_seal_open — open a libsodium sealed box (a member shared-vault grant's sealedVk).
 * tweetnacl for the box (crypto_box_beforenm + open) + @noble blake2b for the sealed-box nonce;
 * verified byte-parity with libsodium. Throws on a wrong key / corrupt box.
 */
export function sealOpen(recipientPub: Uint8Array, recipientPriv: Uint8Array, sealed: Uint8Array): Uint8Array {
  if (sealed.length < 32 + 16) throw new Error("sealed box too short");
  const epk = sealed.subarray(0, 32);
  const nonce = blake2b(new Uint8Array([...epk, ...recipientPub]), { dkLen: 24 });
  const key = nacl.box.before(epk, recipientPriv);
  const pt = nacl.box.open.after(sealed.subarray(32), nonce, key);
  if (!pt) throw new Error("crypto_box_seal_open failed (wrong key or corrupt box)");
  return pt;
}

/**
 * Master key from the master password (== libsodium crypto_pwhash ARGON2ID13). ~5–6 s at the
 * account's 64 MiB params in pure JS — run this in a Web Worker off the popup thread (spike doc).
 */
export function deriveMasterKey(password: string, params: KdfParams, salt: Uint8Array): Uint8Array {
  if (params.v !== 1 || params.alg !== "argon2id13") throw new Error("unsupported kdfParams");
  if (salt.length !== 16) throw new Error("kdf salt must be 16 bytes");
  return argon2id(utf8(password), salt, {
    t: params.ops,
    m: params.memBytes / 1024,
    p: 1,
    dkLen: KEY_BYTES,
    version: 0x13,
  });
}

/** RFC 5869 HKDF-SHA-256 (empty salt ⇒ HashLen zeros, per RFC/@noble). */
export function hkdfSha256(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  return hkdf(sha256, ikm, salt, info, length);
}

/** K_bio (0.17.0) — the OUTER quick-unlock wrap key for the biometric method. The 32-byte WebAuthn-PRF
 *  secret is full entropy (hardware-held, released only after OS user-verification), so it is HKDF'd —
 *  NOT run through Argon2id like the PIN — info-bound to the user + a versioned purpose so it can never
 *  collide with another derivation. Device-binding is provided by the non-extractable co-key inner
 *  wrap (breaker A1), NOT by this key, so a synced-PRF passkey on another device still can't open the blob. */
export function deriveKBio(prfSecret: Uint8Array, userId: string): Uint8Array {
  return hkdfSha256(prfSecret, new Uint8Array(0), utf8("andvari/qu-bio/v1|" + userId), 32);
}

const INFO_AUTH = utf8("andvari/v1/auth");
const INFO_WRAP = utf8("andvari/v1/wrap");
const EMPTY = new Uint8Array(0);
export const authKey = (mk: Uint8Array): Uint8Array => hkdfSha256(mk, EMPTY, INFO_AUTH, KEY_BYTES);
export const wrapKey = (mk: Uint8Array): Uint8Array => hkdfSha256(mk, EMPTY, INFO_WRAP, KEY_BYTES);

/** Seal: version‖alg‖nonce(24)‖ct+tag (mirrors core Envelope / web envelope.ts). */
export function seal(key: Uint8Array, plaintext: Uint8Array, ad: Uint8Array): Uint8Array {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  const ct = xchacha20poly1305(key, nonce, ad).encrypt(plaintext);
  const out = new Uint8Array(2 + NONCE_BYTES + ct.length);
  out[0] = ENVELOPE_VERSION;
  out[1] = ENVELOPE_ALG_XCHACHA20POLY1305_IETF;
  out.set(nonce, 2);
  out.set(ct, 2 + NONCE_BYTES);
  return out;
}

/** Open a sealed envelope; throws on tamper / wrong key (AEAD auth) or an unknown version/alg. */
export function open(key: Uint8Array, envelope: Uint8Array, ad: Uint8Array): Uint8Array {
  if (envelope.length < 2 + NONCE_BYTES + 16) throw new Error("envelope too short");
  if (envelope[0] !== ENVELOPE_VERSION) throw new Error(`unknown envelope version ${envelope[0]}`);
  if (envelope[1] !== ENVELOPE_ALG_XCHACHA20POLY1305_IETF) throw new Error(`unknown envelope alg ${envelope[1]}`);
  const nonce = envelope.subarray(2, 2 + NONCE_BYTES);
  const ct = envelope.subarray(2 + NONCE_BYTES);
  return xchacha20poly1305(key, nonce, ad).decrypt(ct);
}

// base64url (wire encoding) — no Node Buffer in the SW/content world.
export function toB64(u: Uint8Array): string {
  let s = "";
  for (const b of u) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function fromB64(s: string): Uint8Array {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  const u = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
  return u;
}
