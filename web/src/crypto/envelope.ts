import { concat } from "./bytes";
import { aeadDecrypt, aeadEncrypt, randomBytes } from "./provider";
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

export function open(key: Uint8Array, envelope: Uint8Array, ad: Uint8Array): Uint8Array {
  const refusal = structuralRefusal(envelope);
  if (refusal !== null) throw new CryptoError(refusal);
  const nonce = envelope.subarray(2, HEADER_BYTES);
  const ct = envelope.subarray(HEADER_BYTES);
  return aeadDecrypt(key, nonce, ct, ad);
}
