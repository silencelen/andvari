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

export function open(key: Uint8Array, envelope: Uint8Array, ad: Uint8Array): Uint8Array {
  if (envelope.length < MIN_BYTES) throw new CryptoError("envelope too short");
  if (envelope[0] !== ENVELOPE_VERSION) throw new CryptoError(`unknown envelope version ${envelope[0]}`);
  if (envelope[1] !== ENVELOPE_ALG_XCHACHA20POLY1305_IETF) throw new CryptoError(`unknown envelope alg ${envelope[1]}`);
  const nonce = envelope.subarray(2, HEADER_BYTES);
  const ct = envelope.subarray(HEADER_BYTES);
  return aeadDecrypt(key, nonce, ct, ad);
}
