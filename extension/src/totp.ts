import { hmac } from "@noble/hashes/hmac.js";
import { sha1 } from "@noble/hashes/legacy.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";

/**
 * TOTP for the extension — port of web/src/crypto/totp.ts with the web provider's WebCrypto HMAC
 * swapped for @noble/hashes (pure JS, sync, CSP-clean; SHA-1 lives in noble's "legacy" module).
 * Same RFC 6238 construction as core Totp.kt; all impls run spec/test-vectors/totp.json.
 */

class CryptoError extends Error {}

const hmacSha1 = (key: Uint8Array, data: Uint8Array): Uint8Array => hmac(sha1, key, data);
const hmacSha256 = (key: Uint8Array, data: Uint8Array): Uint8Array => hmac(sha256, key, data);
const hmacSha512 = (key: Uint8Array, data: Uint8Array): Uint8Array => hmac(sha512, key, data);

/** RFC 4648 base32 (case-insensitive, padding/whitespace ignored); mirrors core Base32. */
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Decode(text: string): Uint8Array {
  const clean = text.toUpperCase().replace(/[=\s]/g, "");
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

/** RFC 6238 (over RFC 4226 truncation); mirrors core Totp.kt. Sync here (noble HMAC). */
export function totpCode(config: TotpConfig, unixSeconds: number): string {
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
  const mac =
    config.algorithm === "SHA1"
      ? hmacSha1(config.secret, msg)
      : config.algorithm === "SHA256"
        ? hmacSha256(config.secret, msg)
        : hmacSha512(config.secret, msg);
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

// Byte-accurate so multi-byte UTF-8 escapes decode correctly; '+' stays literal.
function percentDecode(s: string): string {
  const out: number[] = [];
  const encoder = new TextEncoder();
  let i = 0;
  while (i < s.length) {
    const c = s[i]!;
    if (c === "%") {
      if (i + 3 > s.length) throw new CryptoError("bad percent-encoding");
      const v = Number.parseInt(s.slice(i + 1, i + 3), 16);
      if (Number.isNaN(v)) throw new CryptoError("bad percent-encoding");
      out.push(v);
      i += 3;
    } else {
      out.push(...encoder.encode(c));
      i++;
    }
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(out));
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
  const secret = params.get("secret");
  if (!secret) throw new CryptoError("otpauth URI missing secret");
  const algRaw = (params.get("algorithm") ?? "SHA1").toUpperCase();
  if (algRaw !== "SHA1" && algRaw !== "SHA256" && algRaw !== "SHA512") {
    throw new CryptoError("unsupported otpauth algorithm");
  }
  const colon = label.indexOf(":");
  return {
    secret: base32Decode(secret),
    algorithm: algRaw,
    digits: Number.parseInt(params.get("digits") ?? "6", 10) || 6,
    periodSeconds: Number.parseInt(params.get("period") ?? "30", 10) || 30,
    label,
    issuer: params.get("issuer") ?? (colon >= 0 ? label.slice(0, colon) : ""),
  };
}

/** The stored login.totp is a normalized otpauth:// URI (the web editor wraps raw base32 on
 *  save) — parse + compute in one call for the SW's reveal/totp handlers. Throws on junk. */
export function currentCode(otpauthUri: string, nowMs: number): { code: string; secondsLeft: number } {
  const config = parseOtpauthUri(otpauthUri);
  const unixSeconds = Math.floor(nowMs / 1000);
  return { code: totpCode(config, unixSeconds), secondsLeft: totpSecondsRemaining(config, unixSeconds) };
}
