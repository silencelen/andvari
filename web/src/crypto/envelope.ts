import { concat } from "./bytes";
import { aeadDecrypt, aeadEncrypt, randomBytes } from "./provider";
import { allZero, requireKey, requireNotWipedKey } from "./keyfloor";
import { CryptoError } from "./sodium";

/** spec 02 §2 — version ‖ alg ‖ nonce(24) ‖ ct+tag; mirrors core Envelope.kt. */
export const ENVELOPE_VERSION = 0x01;
export const ENVELOPE_ALG_XCHACHA20POLY1305_IETF = 0x01;
export const NONCE_BYTES = 24;
export const TAG_BYTES = 16;
const HEADER_BYTES = 2 + NONCE_BYTES;
export const MIN_BYTES = HEADER_BYTES + TAG_BYTES;

export function sealWithNonce(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, ad: Uint8Array): Uint8Array {
  if (nonce.length !== NONCE_BYTES) throw new CryptoError("nonce must be 24 bytes");
  // Spec 01 rule 4: nothing is sealed under a key of zeros, and no wiped key is wrapped (KeysGoneError).
  requireKey(key);
  requireNotWipedKey(plaintext);
  const ct = aeadEncrypt(key, nonce, plaintext, ad);
  return concat(Uint8Array.of(ENVELOPE_VERSION, ENVELOPE_ALG_XCHACHA20POLY1305_IETF), nonce, ct);
}

export function seal(key: Uint8Array, plaintext: Uint8Array, ad: Uint8Array): Uint8Array {
  return sealWithNonce(key, randomBytes(NONCE_BYTES), plaintext, ad);
}

/**
 * The three STRUCTURAL refusals {@link open} makes before any key is used — length, version, alg —
 * as a reason string (null = the header is well-formed). TWIN of core Envelope.structuralRefusal.
 *
 * Single-sourced here (open() calls it) so a caller that must tell "this blob is damaged/foreign"
 * apart from "this key is wrong" never re-implements — and drifts from — the checks below. WHY the
 * distinction is security-relevant (audit H67): only the AEAD tag failure at the end of open() is
 * genuinely ambiguous — it is exactly what a wrong password produces. These three are decided from
 * the blob's PUBLIC header, before the key matters, so folding them into a "wrong password" verdict
 * tells a member with a corrupt or newer-version account row to reset a password that was never
 * wrong. Account-key callers (Account.unlock's wrappedUvk) consult this first; every other caller
 * keeps the plain CryptoError fail-closed behaviour, because for an item blob "damaged" and "not
 * for this key" are equally unactionable to the user.
 */
export function structuralRefusal(envelope: Uint8Array): string | null {
  if (envelope.length < MIN_BYTES) return "envelope too short";
  if (envelope[0] !== ENVELOPE_VERSION) return `unknown envelope version ${envelope[0]}`;
  if (envelope[1] !== ENVELOPE_ALG_XCHACHA20POLY1305_IETF) return `unknown envelope alg ${envelope[1]}`;
  return null;
}

/**
 * A key taken out of a sealed structure is all zeros (the account key out of its wrap or a recovery copy, the identity
 * seed, a vault key out of the personal wrap, a grant or a log's wrap). The structure is damaged: what came out is
 * never a key, and it is never read as a lock (core `VaultKeyDamagedException`, and the shared code's other zero-key
 * refusals). A {@link CryptoError}, so every caller that fails closed on an unopenable structure still does.
 */
export class DamagedKeyError extends CryptoError {
  constructor(what: string) {
    super(`${what} opened to a key of zeros: damaged`);
    this.name = "DamagedKeyError";
  }
}

/**
 * {@link open} for an envelope whose plaintext is a key or a seed: a plaintext of all zeros is refused as
 * {@link DamagedKeyError} ([what] names it), so it is never used as a key and never meets the floor's KeysGoneError.
 */
export function openKey(key: Uint8Array, envelope: Uint8Array, ad: Uint8Array, what: string): Uint8Array {
  const k = open(key, envelope, ad);
  if (allZero(k)) throw new DamagedKeyError(what);
  return k;
}

export function open(key: Uint8Array, envelope: Uint8Array, ad: Uint8Array): Uint8Array {
  const refusal = structuralRefusal(envelope);
  if (refusal !== null) throw new CryptoError(refusal);
  // Rule 4: a key of zeros opens nothing, and says so as KeysGoneError, never as a wrong key (CryptoError).
  requireKey(key);
  const nonce = envelope.subarray(2, HEADER_BYTES);
  const ct = envelope.subarray(HEADER_BYTES);
  return aeadDecrypt(key, nonce, ct, ad);
}
