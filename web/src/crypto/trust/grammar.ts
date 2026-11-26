import { fromB64, toB64 } from "../bytes";

/**
 * The value types of the canonical statement grammar (design 2026-11-15 §2.2) and the shared encoding
 * rules (§2.3, R3). Twin of core `TrustGrammar`, written on its own: the two share no code, only
 * `spec/test-vectors/encodings.json` and the grammar rows of `statement-v2.json`.
 *
 * Every pattern here is ASCII only, so no engine's Unicode tables decide an outcome.
 */

/** 2^53: every `int` and `ms` is below it. */
export const INT_CEILING = 2 ** 53;
/** 64 `0` characters: `prev` of a log's genesis (§3.2) and of card 0 (§4.2). */
export const ZERO_HASH = "0".repeat(64);
/** The literal a `hex64n` or `email_b64n` field carries when it has no value. */
export const NONE = "none";
/** §2.3: the closed list of `platform` values. */
export const PLATFORMS: readonly string[] = ["android", "ios", "windows", "macos", "linux", "web", "cli", "extension"];

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const B64URL = /^[A-Za-z0-9_-]*$/;
const INT = /^(?:0|[1-9][0-9]{0,15})$/;

/** `uuid`: lowercase `8-4-4-4-12` hex. */
export const isUuid = (s: string): boolean => UUID.test(s);
/** `hex64`: exactly 64 lowercase hex characters. */
export const isHex64 = (s: string): boolean => HEX64.test(s);
/** `hex64n`: a `hex64`, or the literal `none`. */
export const isHex64n = (s: string): boolean => s === NONE || HEX64.test(s);
/** `role`: `writer` or `reader`. */
export const isRole = (s: string): boolean => s === "writer" || s === "reader";
/** §2.3: one of {@link PLATFORMS}. */
export const isPlatform = (s: string): boolean => PLATFORMS.includes(s);

/**
 * Strict base64url: the unpadded alphabet only, and the text must re-encode to itself, so padding, the
 * standard alphabet, white space and non-zero trailing bits are all refused. Null instead of a throw.
 */
export function fromB64Canonical(text: string): Uint8Array | null {
  if (!B64URL.test(text)) return null;
  let bytes: Uint8Array;
  try {
    bytes = fromB64(text);
  } catch {
    return null;
  }
  return toB64(bytes) === text ? bytes : null;
}

/** {@link fromB64Canonical}, and the decoded value must be exactly `length` bytes. */
export function fromB64Exact(text: string, length: number): Uint8Array | null {
  const bytes = fromB64Canonical(text);
  return bytes !== null && bytes.length === length ? bytes : null;
}

/** `b64_16`: 22 characters decoding to 16 bytes, canonical. */
export const isB64_16 = (s: string): boolean => s.length === 22 && fromB64Exact(s, 16) !== null;
/** `b64_32`: 43 characters decoding to 32 bytes, canonical. */
export const isB64_32 = (s: string): boolean => s.length === 43 && fromB64Exact(s, 32) !== null;

/** The value of an `int` token (`0`, or `[1-9][0-9]*`, below 2^53), or null. */
export function parseInt53(token: string): number | null {
  if (!INT.test(token)) return null;
  const n = Number(token);
  return n < INT_CEILING ? n : null;
}

/** The value of an `ms` token (`1 <= x < 2^53`, no sign, no leading zero), or null. */
export function parseMs(token: string): number | null {
  const n = parseInt53(token);
  return n !== null && n >= 1 ? n : null;
}

export const isInt = (x: number): boolean => Number.isSafeInteger(x) && x >= 0;
export const isMs = (x: number): boolean => Number.isSafeInteger(x) && x >= 1;

const LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
const HTTPS_ORIGIN = new RegExp(`^https://(${LABEL}(?:\\.${LABEL})+)(?::([1-9][0-9]{0,4}))?$`);
const HTTP_ORIGIN = /^http:\/\/(?:localhost|127\.0\.0\.1)(?::([1-9][0-9]{0,4}))?$/;
const NUMBER_LABEL = /^(?:[0-9]+|0x[0-9a-f]*)$/;

/**
 * `origin` (§2.2, R4, VR-5): the single source for every origin a client stores, dials or shows.
 *
 * - `https://` + host + optional `:port`, all lowercase.
 * - Host: at least two labels, each `[a-z0-9]([a-z0-9-]*[a-z0-9])?` and 1..63 characters, joined by `.`,
 *   no trailing dot, at most 253 characters in all. An `xn--` label is an ordinary label, never decoded.
 * - IP literals are refused: a host whose last label is all digits, or `0x` followed only by hex digits,
 *   is an IPv4 address to URL parsers; bracketed IPv6 fails the label pattern.
 * - Port `1..65535` without leading zeros, and never the scheme's default (443 for https, 80 for http).
 * - Plain http only as `http://localhost[:port]` and `http://127.0.0.1[:port]`.
 * - No path, query, fragment or userinfo.
 */
export function isOrigin(s: string): boolean {
  const https = HTTPS_ORIGIN.exec(s);
  if (https !== null) return isDnsHost(https[1]!) && portOk(https[2], 443);
  const http = HTTP_ORIGIN.exec(s);
  return http !== null && portOk(http[1], 80);
}

const DNS_HOST = new RegExp(`^${LABEL}(?:\\.${LABEL})+$`);

/**
 * The host grammar of the https `origin` form: two or more labels of 1..63 characters
 * `[a-z0-9]([a-z0-9-]*[a-z0-9])?` joined by `.`, no trailing dot, at most 253 characters, and a last
 * label that is neither all digits nor `0x` plus hex. `emailNorm`'s domain uses this same function
 * (spec 01 §5.5); the plain-http `localhost` and `127.0.0.1` forms are not part of it.
 */
function isDnsHost(host: string): boolean {
  if (host.length > 253 || !DNS_HOST.test(host)) return false;
  return !NUMBER_LABEL.test(host.slice(host.lastIndexOf(".") + 1));
}

function portOk(port: string | undefined, defaultPort: number): boolean {
  if (port === undefined) return true;
  const n = Number(port);
  return n >= 1 && n <= 65535 && n !== defaultPort;
}

const NAME_REFUSED: ReadonlyArray<readonly [number, number]> = [
  [0x0000, 0x001f], [0x007f, 0x009f], [0x00ad, 0x00ad], [0x061c, 0x061c], [0x180e, 0x180e], [0x200b, 0x200f],
  [0x2028, 0x202e], [0x2060, 0x2064], [0x2066, 0x206f], [0xfeff, 0xfeff], [0xfff9, 0xfffb],
];

/**
 * `name` (§2.2, R3), decoded: the display name's text, or null when `b64` is not one. Canonical
 * unpadded base64url of 1..64 bytes of valid UTF-8, none of the listed code points, no leading or
 * trailing U+0020. No normalisation; render it only as plain text.
 */
export function decodeName(b64: string): string | null {
  const bytes = fromB64Canonical(b64);
  if (bytes === null || bytes.length < 1 || bytes.length > 64) return null;
  let text: string;
  try {
    // fatal: overlong forms, surrogates and truncated sequences throw. ignoreBOM: a leading U+FEFF is
    // KEPT in the text, so the list below sees it (the default would silently strip it).
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null;
  }
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    for (const [lo, hi] of NAME_REFUSED) if (cp >= lo && cp <= hi) return null;
  }
  if (text.startsWith(" ") || text.endsWith(" ")) return null;
  return text;
}

export const isName = (b64: string): boolean => decodeName(b64) !== null;

const refusedInName = (cp: number): boolean => NAME_REFUSED.some(([lo, hi]) => cp >= lo && cp <= hi);

/**
 * The `text` type (spec 03 §0.1: display names and device names; the server's `Grammar.isText` since 2026-11-16):
 * 1 to 256 UTF-16 characters, well formed (no lone surrogate), and none of the code points the `name` type refuses.
 * Spaces are allowed anywhere. Answers why it is not one (`empty`, `too_long`, `character`), or null when it is.
 */
export function textRefusal(s: string): "empty" | "too_long" | "character" | null {
  if (s.length === 0) return "empty";
  if (s.length > 256) return "too_long";
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(i + 1);
      if (!(d >= 0xdc00 && d <= 0xdfff)) return "character";
      i++;
      continue; // no supplementary code point is on the list
    }
    if (c >= 0xdc00 && c <= 0xdfff) return "character";
    if (refusedInName(c)) return "character";
  }
  return null;
}

/**
 * The kinds of character the `text` and `name` types refuse, so a screen can say which one it found: a control
 * character (C0, C1), a line or paragraph separator (U+2028, U+2029), a direction-changing mark (U+061C, U+200E,
 * U+200F, U+202A to U+202E, U+2066 to U+2069), any other invisible character (U+00AD, U+180E, U+200B to U+200D,
 * U+2060 to U+2064, U+206A to U+206F, U+FEFF, U+FFF9 to U+FFFB), or a broken one (a lone surrogate).
 */
export type RefusedCharacterKind = "control" | "line_break" | "direction" | "invisible" | "broken";

/** The kind of [cp], one the `name` list refuses, or null when it is not on the list. */
export function refusedKindOf(cp: number): Exclude<RefusedCharacterKind, "broken"> | null {
  if (!refusedInName(cp)) return null;
  if (cp <= 0x1f || (cp >= 0x7f && cp <= 0x9f)) return "control";
  if (cp === 0x2028 || cp === 0x2029) return "line_break";
  if (cp === 0x061c || cp === 0x200e || cp === 0x200f || (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069)) return "direction";
  return "invisible";
}

/** The first character of [s] the `text` type refuses: its kind and code point (null for a lone surrogate's), or null. */
export function firstRefusedCharacter(s: string): { readonly kind: RefusedCharacterKind; readonly cp: number } | null {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(i + 1);
      if (!(d >= 0xdc00 && d <= 0xdfff)) return { kind: "broken", cp: c };
      i++;
      continue;
    }
    if (c >= 0xdc00 && c <= 0xdfff) return { kind: "broken", cp: c };
    const k = refusedKindOf(c);
    if (k !== null) return { kind: k, cp: c };
  }
  return null;
}

/** [s] with every character the `text` type refuses dropped (lone surrogates included), for a name made up here. */
export function plainTextOf(s: string): string {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) out += s[i]! + s[i + 1]!;
      i += d >= 0xdc00 && d <= 0xdfff ? 1 : 0;
      continue;
    }
    if ((c >= 0xdc00 && c <= 0xdfff) || refusedInName(c)) continue;
    out += s[i]!;
  }
  return out;
}

/** The `name` form of `text`, or null when `text` cannot be a name (also for ill-formed UTF-16). */
export function encodeName(text: string): string | null {
  // TextEncoder writes U+FFFD for a lone surrogate, which would silently change the name.
  if (typeof (text as { isWellFormed?: () => boolean }).isWellFormed === "function") {
    if (!(text as unknown as { isWellFormed: () => boolean }).isWellFormed()) return null;
  } else if (/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(text)) {
    return null;
  }
  const b64 = toB64(new TextEncoder().encode(text));
  return decodeName(b64) === null ? null : b64;
}

/**
 * `emailNorm` (§2.3, VR-6), or null when the address is refused (`invalid_email`): strip space, tab, CR
 * and LF from both ends; refuse anything that is then shorter than 3 or longer than 254 octets, holds a
 * byte outside 0x21..0x7E, or lacks exactly one `@` between two non-empty parts; lowercase ASCII A–Z.
 * Then (spec 01 §5.5) the lowercased address must be `local@domain`: `local` a dot-atom of
 * 1..64 characters of `a–z`, `0–9` and ``!#$%&'*+/=?^_`{|}~-`` with single dots between non-empty parts
 * (no quote, comment, angle bracket or space), `domain` two or more labels under the origin host grammar.
 * The one address rule of the web twin (Kotlin: `TrustGrammar.emailNorm`).
 */
export function emailNorm(raw: string): string | null {
  const t = raw.replace(/^[ \t\r\n]+/, "").replace(/[ \t\r\n]+$/, "");
  if (!/^[\x21-\x7e]{3,254}$/.test(t)) return null;
  if (!/^[^@]+@[^@]+$/.test(t)) return null;
  const norm = t.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
  const at = norm.indexOf("@");
  const local = norm.slice(0, at);
  if (local.length > EMAIL_LOCAL_MAX || !DOT_ATOM.test(local)) return null;
  return isDnsHost(norm.slice(at + 1)) ? norm : null;
}

/** The longest local part an `emailNorm` takes (spec 01 §5.5). */
export const EMAIL_LOCAL_MAX = 64;
const DOT_ATOM = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/;

/** `email_b64n` (§2.2, VR-7), decoded: `{ email: null }` for `none`, the address, or null when it is not one. */
export function decodeEmail(field: string): { email: string | null } | null {
  if (field === NONE) return { email: null };
  const bytes = fromB64Canonical(field);
  if (bytes === null || bytes.length < 3 || bytes.length > 254) return null;
  let text = "";
  for (const b of bytes) {
    if (b < 0x21 || b > 0x7e) return null;
    text += String.fromCharCode(b);
  }
  // Already normal: an uppercase letter inside is refused, never folded.
  return emailNorm(text) === text ? { email: text } : null;
}

export const isEmailB64n = (field: string): boolean => decodeEmail(field) !== null;

/** The `email_b64n` form of an `emailNorm` (null: the literal `none`), or null when it is not already normal. */
export function encodeEmail(email: string | null): string | null {
  if (email === null) return NONE;
  if (emailNorm(email) !== email) return null;
  return toB64(new TextEncoder().encode(email));
}

/** Text without any ASCII white space (space, tab, CR, LF), as links and kits strip it (§6.1). */
export const stripAsciiSpace = (text: string): string => text.replace(/[ \t\r\n]/g, "");
