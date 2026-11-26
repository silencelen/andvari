import { requireKey } from "./keyfloor";
import { hmacSha256 } from "./provider";
import { CryptoError } from "./sodium";

const HASH_LEN = 32;

/**
 * RFC 5869 HKDF-SHA-256 (spec 01 §2). Empty salt ⇒ HashLen zero bytes.
 *
 * The pseudorandom key, every block `T(n)` and every HMAC input built from one are wiped before this
 * returns: each is as good as the input key for whoever reads it. What cannot be wiped from here is
 * WebCrypto's own copy: `importKey` keeps the PRK inside a `CryptoKey` until the engine frees it.
 */
export async function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  if (length < 1 || length > 255 * HASH_LEN) throw new CryptoError("HKDF length out of range");
  // Spec 01 rule 4: nothing is derived from an input key of zeros (KeysGoneError). The empty salt's zeros below are the
  // extract's HMAC key, which the rule does not touch.
  requireKey(ikm);
  const prk = await hmacSha256(salt.length === 0 ? new Uint8Array(HASH_LEN) : salt, ikm);
  const out = new Uint8Array(length);
  let t: Uint8Array = new Uint8Array(0);
  try {
    let generated = 0;
    let counter = 1;
    while (generated < length) {
      // T(n) = HMAC(PRK, T(n-1) || info || n)
      const input = new Uint8Array(t.length + info.length + 1);
      input.set(t, 0);
      input.set(info, t.length);
      input[input.length - 1] = counter;
      let next: Uint8Array;
      try {
        next = await hmacSha256(prk, input);
      } finally {
        input.fill(0);
      }
      t.fill(0);
      t = next;
      const n = Math.min(HASH_LEN, length - generated);
      out.set(t.subarray(0, n), generated);
      generated += n;
      counter++;
    }
    return out;
  } catch (e) {
    out.fill(0);
    throw e;
  } finally {
    prk.fill(0);
    t.fill(0);
  }
}
