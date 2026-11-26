import { CryptoError, sodium } from "./sodium";

/** Spec 00 conventions: base64url unpadded everywhere; hex only for fingerprints. */

export function toB64(bytes: Uint8Array): string {
  const s = sodium();
  return s.to_base64(bytes, s.base64_variants.URLSAFE_NO_PADDING);
}

export function fromB64(text: string): Uint8Array {
  const s = sodium();
  try {
    return s.from_base64(text, s.base64_variants.URLSAFE_NO_PADDING);
  } catch (e) {
    throw new CryptoError("invalid base64url", { cause: e });
  }
}

/**
 * Unpadded base64url of `bytes` as ASCII BYTES, for a value that must never become a string: a key that
 * is written into a statement. A JavaScript string cannot be wiped; this array can, and the caller wipes
 * it. Each character is computed, not looked up, so no table is indexed by key material.
 */
export function toB64Bytes(bytes: Uint8Array): Uint8Array {
  const tail = bytes.length % 3;
  const out = new Uint8Array(Math.floor(bytes.length / 3) * 4 + (tail === 0 ? 0 : tail + 1));
  let o = 0;
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!;
    const b1 = i + 1 < bytes.length ? bytes[i + 1]! : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2]! : 0;
    out[o++] = b64Char(b0 >> 2);
    out[o++] = b64Char(((b0 & 3) << 4) | (b1 >> 4));
    if (i + 1 < bytes.length) out[o++] = b64Char(((b1 & 15) << 2) | (b2 >> 6));
    if (i + 2 < bytes.length) out[o++] = b64Char(b2 & 63);
  }
  return out;
}

/**
 * Strict unpadded base64url straight from the ASCII bytes `text[start..end)` to bytes, or null: only the
 * base64url alphabet, never a length of 1 mod 4, and the unused trailing bits zero (so the text is the one
 * canonical encoding of the result, as {@link toB64} would write it). No string is made of the text or of
 * the value, which is the point: this reads a key out of a statement. The caller wipes the result.
 */
export function fromB64Bytes(text: Uint8Array, start = 0, end = text.length): Uint8Array | null {
  const n = end - start;
  if (start < 0 || end > text.length || n < 0 || n % 4 === 1) return null;
  const tail = n % 4;
  const out = new Uint8Array(Math.floor(n / 4) * 3 + (tail === 0 ? 0 : tail - 1));
  let acc = 0;
  let bits = 0;
  let o = 0;
  let bad = 0;
  for (let i = start; i < end; i++) {
    const v = b64Value(text[i]!);
    bad |= v; // negative for a byte outside the alphabet
    acc = ((acc << 6) | (v & 63)) & 0xffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  if (bad < 0 || (acc & ((1 << bits) - 1)) !== 0) {
    out.fill(0);
    return null;
  }
  return out;
}

/** The base64url character for a 6-bit value, by arithmetic: `A–Z a–z 0–9 - _`. */
function b64Char(x: number): number {
  let c = x + 65;
  c += ((25 - x) >> 8) & 6; // above 25: 'a' is 6 past 'Z' + 1
  c -= ((51 - x) >> 8) & 75; // above 51: back to '0'
  c -= ((61 - x) >> 8) & 13; // 62: '-'
  c += ((62 - x) >> 8) & 49; // 63: '_'
  return c;
}

/** The 6-bit value of a base64url character, or -1, by arithmetic (each range test is all ones or zero). */
function b64Value(c: number): number {
  let v = -1;
  v += (((64 - c) & (c - 91)) >> 8) & (c - 64); // 'A'..'Z' -> 0..25
  v += (((96 - c) & (c - 123)) >> 8) & (c - 70); // 'a'..'z' -> 26..51
  v += (((47 - c) & (c - 58)) >> 8) & (c + 5); // '0'..'9' -> 52..61
  v += (((44 - c) & (c - 46)) >> 8) & 63; // '-' -> 62
  v += (((94 - c) & (c - 96)) >> 8) & 64; // '_' -> 63
  return v;
}

export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function fromUtf8(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

export function toHexLower(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function toHexUpper(bytes: Uint8Array): string {
  return toHexLower(bytes).toUpperCase();
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** Constant-time comparison for MAC-like values. */
export function ctEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let acc = 0;
  for (let i = 0; i < a.length; i++) acc |= (a[i]! ^ b[i]!);
  return acc === 0;
}
