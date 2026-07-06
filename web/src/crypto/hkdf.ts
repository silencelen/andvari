import { concat } from "./bytes";
import { hmacSha256 } from "./provider";
import { CryptoError } from "./sodium";

const HASH_LEN = 32;

/** RFC 5869 HKDF-SHA-256 (spec 01 §2). Empty salt ⇒ HashLen zero bytes. */
export async function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  if (length < 1 || length > 255 * HASH_LEN) throw new CryptoError("HKDF length out of range");
  const prk = await hmacSha256(salt.length === 0 ? new Uint8Array(HASH_LEN) : salt, ikm);
  const out = new Uint8Array(length);
  let t: Uint8Array = new Uint8Array(0);
  let generated = 0;
  let counter = 1;
  while (generated < length) {
    t = await hmacSha256(prk, concat(t, info, Uint8Array.of(counter)));
    const n = Math.min(HASH_LEN, length - generated);
    out.set(t.subarray(0, n), generated);
    generated += n;
    counter++;
  }
  return out;
}
