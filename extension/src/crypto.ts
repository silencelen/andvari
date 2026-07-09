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
