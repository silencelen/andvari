import { hmacSha1, hmacSha256, hmacSha512 } from "./provider";
import { CryptoError } from "./sodium";

/** RFC 4648 base32 (case-insensitive, padding/ASCII whitespace ignored); mirrors core Base32. */
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// Cross-port determinism (2026-07-09 review; the card.ts TRIMMABLE precedent): the decoder
// ignores ONLY '=' padding plus this pinned ASCII whitespace set — never `\s`/isWhitespace,
// which disagree at the Unicode margins (JS `\s` strips U+FEFF where the JVM keeps it; JVM
// isWhitespace strips U+001C..U+001F and Unicode spaces where JS differs). Any other
// character (U+FEFF, NBSP, …) fails decode on EVERY client, so a secret one twin could
// never parse back is never stored (A5 reject-don't-corrupt). Mirrors core Base32.IGNORED.
const BASE32_IGNORED = /[= \t\n\v\f\r]/g;

export function base32Decode(text: string): Uint8Array {
  const clean = text.toUpperCase().replace(BASE32_IGNORED, "");
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const c of clean) {
    const v = ALPHABET.indexOf(c);
    if (v < 0) throw new CryptoError(`invalid base32 character '${c}'`);
    buffer = (buffer << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

export function base32Encode(bytes: Uint8Array): string {
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const b of bytes) {
    buffer = (buffer << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(buffer >> bits) & 0x1f];
    }
  }
  if (bits > 0) out += ALPHABET[(buffer << (5 - bits)) & 0x1f];
  return out;
}

export type TotpAlgorithm = "SHA1" | "SHA256" | "SHA512";

export interface TotpConfig {
  secret: Uint8Array;
  algorithm: TotpAlgorithm;
  digits: number;
  periodSeconds: number;
  label: string;
  issuer: string;
}

/** RFC 6238 (over RFC 4226 truncation); mirrors core Totp.kt. */
export async function totpCode(config: TotpConfig, unixSeconds: number): Promise<string> {
  if (config.digits < 6 || config.digits > 10) throw new CryptoError("TOTP digits out of range");
  if (config.periodSeconds <= 0) throw new CryptoError("TOTP period must be positive");
  const counter = Math.floor(unixSeconds / config.periodSeconds);
  const msg = new Uint8Array(8);
  // >2^53 never occurs (counter = time/period), so Number math is exact here.
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    msg[i] = c % 256;
    c = Math.floor(c / 256);
  }
  const mac = await (config.algorithm === "SHA1"
    ? hmacSha1(config.secret, msg)
    : config.algorithm === "SHA256"
      ? hmacSha256(config.secret, msg)
      : hmacSha512(config.secret, msg));
  const offset = mac[mac.length - 1]! & 0x0f;
  const binary =
    ((mac[offset]! & 0x7f) << 24) |
    ((mac[offset + 1]! & 0xff) << 16) |
    ((mac[offset + 2]! & 0xff) << 8) |
    (mac[offset + 3]! & 0xff);
  const mod = 10 ** config.digits;
  return String(binary % mod).padStart(config.digits, "0");
}

export function totpSecondsRemaining(config: TotpConfig, unixSeconds: number): number {
  return config.periodSeconds - (unixSeconds % config.periodSeconds);
}

/** Mirror of Kotlin String.toIntOrNull (radix 10): optional sign, decimal digits only
 *  (full-string — never Number.parseInt's partial parse, "8x" → null not 8), 32-bit
 *  range. Shared-parse twin determinism (2026-07-09 review); same pattern as csv.ts
 *  toLongOrNull. */
function toIntOrNull(s: string): number | null {
  if (!/^[+-]?[0-9]+$/.test(s)) return null;
  const v = Number.parseInt(s, 10);
  return v >= -2147483648 && v <= 2147483647 ? v : null;
}

/** Mirror of Kotlin "xx".toIntOrNull(16): full-string hex (optional sign, like Kotlin),
 *  never parseInt's prefix parse ("aG" → null, not 10). */
function hexOrNull(s: string): number | null {
  if (!/^[+-]?[0-9a-fA-F]+$/.test(s)) return null;
  return Number.parseInt(s, 16);
}

// Byte-accurate so multi-byte UTF-8 escapes decode correctly; '+' stays literal.
function percentDecode(s: string): string {
  const out: number[] = [];
  const encoder = new TextEncoder();
  let i = 0;
  while (i < s.length) {
    const c = s[i]!;
    if (c === "%") {
      if (i + 3 > s.length) throw new CryptoError("bad percent-encoding");
      const v = hexOrNull(s.slice(i + 1, i + 3)); // strict, mirrors core toIntOrNull(16)
      if (v === null) throw new CryptoError("bad percent-encoding");
      out.push(v);
      i += 3;
    } else {
      out.push(...encoder.encode(c));
      i++;
    }
  }
  // LENIENT decode (malformed → U+FFFD), byte-exact with core percentDecode's
  // decodeToString(): a Latin-1-encoded label (%E9) must ACCEPT on both twins, not
  // route the same CSV row to login.totp on one client and notes on the other
  // (2026-07-09 review — was fatal:true, a twin divergence).
  return new TextDecoder("utf-8").decode(Uint8Array.from(out));
}

/**
 * The ONE shared TOTP normalize (design 2026-07-09 A5, byte-exact; mirrors core
 * Totp.normalize): strip ALL ASCII whitespace; a full otpauth:// URI passes through
 * unchanged; a bare base32 secret (either case, padding-tolerant — the existing decoder)
 * wraps to an otpauth URI with the ORIGINAL case preserved (the web editor's historical
 * behavior); anything else returns unchanged. VALIDITY is a separate question — callers
 * gate on parseOtpauthUri ACCEPTING the result (the editors block the save; the CSV
 * adapters keep the raw text in notes instead of corrupting login.totp).
 */
export function normalizeTotp(raw: string): string {
  const s = raw.replace(/[ \t\n\f\r]+/g, ""); // the exact char set core Totp.normalizeTotp strips
  if (s.length === 0) return s;
  if (s.toLowerCase().startsWith("otpauth://")) return s;
  try {
    base32Decode(s); // case-insensitive + padding-tolerant (RFC 4648)
    return `otpauth://totp/andvari?secret=${s}`;
  } catch {
    return s;
  }
}

/** Parse an otpauth://totp/… URI; mirrors core Totp.parseUri. */
export function parseOtpauthUri(uri: string): TotpConfig {
  const prefix = "otpauth://totp/";
  if (!uri.toLowerCase().startsWith(prefix)) throw new CryptoError("not an otpauth totp URI");
  const rest = uri.slice(prefix.length);
  const qIndex = rest.indexOf("?");
  const label = percentDecode(qIndex >= 0 ? rest.slice(0, qIndex) : rest);
  const params = new Map<string, string>();
  if (qIndex >= 0) {
    for (const pair of rest.slice(qIndex + 1).split("&")) {
      if (!pair) continue;
      const eq = pair.indexOf("=");
      if (eq < 0) params.set(pair.toLowerCase(), "");
      else params.set(pair.slice(0, eq).toLowerCase(), percentDecode(pair.slice(eq + 1)));
    }
  }
  // A5 reject-don't-corrupt (2026-07-09 review): this parse is the ONE validity gate for
  // editors and import adapters, so it must reject what totpCode cannot evaluate — an
  // empty/blank secret (empty HMAC key) and digits/period outside totpCode's own checks —
  // instead of storing a config whose 2FA display throws later. Byte-exact with core
  // Totp.parseUri.
  const secret = params.get("secret");
  if (!secret) throw new CryptoError("otpauth URI missing secret");
  const algRaw = (params.get("algorithm") ?? "SHA1").toUpperCase();
  if (algRaw !== "SHA1" && algRaw !== "SHA256" && algRaw !== "SHA512") {
    throw new CryptoError("unsupported otpauth algorithm");
  }
  const secretBytes = base32Decode(secret);
  if (secretBytes.length === 0) throw new CryptoError("otpauth secret decodes to empty key");
  // Kotlin `toIntOrNull() ?: default` semantics, pinned: junk ("8x", "") → the default;
  // an explicit out-of-range value ("0") → parsed, then range-rejected below.
  const digits = toIntOrNull(params.get("digits") ?? "") ?? 6;
  if (digits < 6 || digits > 10) throw new CryptoError("otpauth digits out of range");
  const periodSeconds = toIntOrNull(params.get("period") ?? "") ?? 30;
  if (periodSeconds <= 0) throw new CryptoError("otpauth period out of range");
  const colon = label.indexOf(":");
  return {
    secret: secretBytes,
    algorithm: algRaw,
    digits,
    periodSeconds,
    label,
    issuer: params.get("issuer") ?? (colon >= 0 ? label.slice(0, colon) : ""),
  };
}
