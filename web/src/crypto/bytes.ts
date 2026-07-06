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
