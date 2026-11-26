import { toHexLower } from "../bytes";
import { sha256Sync } from "../provider";
import { CryptoError } from "../sodium";
import { emailNorm, INT_CEILING } from "./grammar";

/**
 * The optional sign-up proof of work (design 2026-11-15 §2.3, §7.5). Twin of core `SignupPow`, graded
 * off the `powInput` and `powLeadingZeroBits` rows of `encodings.json`.
 */

const UTC_DATE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/;

/** The hashed string: `"andvari/v2|signup-pow|" + emailNorm + "|" + utcDate + "|" + nonce`, the nonce in decimal with no leading zeros. */
export function powInput(email: string, utcDate: string, nonce: number): string {
  if (emailNorm(email) !== email) throw new CryptoError("proof of work: not an emailNorm");
  if (!UTC_DATE.test(utcDate)) throw new CryptoError("proof of work: utcDate is not YYYY-MM-DD");
  if (!Number.isSafeInteger(nonce) || nonce < 0 || nonce >= INT_CEILING) throw new CryptoError("proof of work: nonce out of range");
  return `andvari/v2|signup-pow|${email}|${utcDate}|${nonce}`;
}

/** SHA-256 of {@link powInput}'s UTF-8 bytes. */
export function powDigest(email: string, utcDate: string, nonce: number): Uint8Array {
  return sha256Sync(new TextEncoder().encode(powInput(email, utcDate, nonce)));
}

/** Leading zero bits of a digest, from the most significant bit of byte 0, then byte 1, and so on. */
export function leadingZeroBits(digest: Uint8Array): number {
  let bits = 0;
  for (const byte of digest) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    return bits + Math.clz32(byte) - 24; // clz32 counts in 32 bits; a byte sits in the low 8
  }
  return bits;
}

/** True when `nonce` solves the proof of work for `powBits` leading zero bits. `powBits <= 0` accepts every nonce. */
export function powAccepts(email: string, utcDate: string, nonce: number, powBits: number): boolean {
  return powBits <= 0 || leadingZeroBits(powDigest(email, utcDate, nonce)) >= powBits;
}

/** Try `tries` nonces from `from`; the first that solves it, or null. Call it in slices and show progress between them. */
export function powSearch(email: string, utcDate: string, powBits: number, from: number, tries: number): number | null {
  for (let nonce = from; nonce < from + tries && nonce < INT_CEILING; nonce++) {
    if (powAccepts(email, utcDate, nonce, powBits)) return nonce;
  }
  return null;
}

/** For tests and logs: the digest in lowercase hex. */
export const powDigestHex = (email: string, utcDate: string, nonce: number): string => toHexLower(powDigest(email, utcDate, nonce));
