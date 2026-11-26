// Value types of the canonical statement grammar: design §2.2 (new types) and spec 01 §5.1
// (the inherited types uuid, b64_16, b64_32, hex64, ms), plus the §2.3 encoding rules that are
// grammars of their own (emailNorm, platform, proof-of-work bit order).
//
// Each checker takes the DECODED JSON value (a string, or a number for ms and int) and answers
// whether it is in the type. Where the design leaves an edge open, the comment says so and the
// vector files carry no row on that edge.

import { unb64u, utf8, utf8DecodeStrict } from './bytes.mjs';

export const TWO_53 = 2 ** 53;

export function isUuid(v) {
  return typeof v === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v);
}

function isB64OfLength(v, chars, bytes) {
  if (typeof v !== 'string' || v.length !== chars) return false;
  const decoded = unb64u(v);
  return decoded !== null && decoded.length === bytes;
}
export const isB64_16 = (v) => isB64OfLength(v, 22, 16);
export const isB64_32 = (v) => isB64OfLength(v, 43, 32);

export function isHex64(v) {
  return typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
}

/** ms: a decimal integer 1 <= x < 2^53. (Sign, leading zeros and exponent forms die in the re-encode compare.) */
export function isMs(v) {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 1;
}

/** int: a decimal integer 0 <= x < 2^53. */
export function isInt(v) {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && !Object.is(v, -0);
}

export function isRole(v) {
  return v === 'writer' || v === 'reader';
}

export function isHex64n(v) {
  return v === 'none' || isHex64(v);
}

// ---- origin (§2.2; "the single source for every origin a client stores, dials or shows") ----

const LABEL = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;

/** 1..65535 without leading zeros, and never the scheme's default port (VR-5). */
function isPort(text, defaultPort) {
  if (!/^[1-9][0-9]{0,4}$/.test(text)) return false;
  const n = Number(text);
  return n <= 65535 && n !== defaultPort;
}

/**
 * The host of an https origin (spec 01 §5.1 `origin`): a DNS name of at least two labels, each 1..63
 * characters of the label grammar, joined by `.` with no trailing dot, at most 253 characters in all,
 * whose last label is neither all digits nor `0x` plus hex digits (a bare `0x` too). Bracketed IPv6
 * fails the label grammar. An `xn--` label is an ordinary label: never decoded. The emailNorm domain
 * is checked with this same function (spec 01 §5.5: "two or more labels under the host grammar of
 * the `origin` type"); the plain-http localhost and 127.0.0.1 forms belong to the origin type's
 * http branch, not to this host grammar, so no address domain can take them.
 */
export function isDnsHost(host) {
  if (typeof host !== 'string' || host.length > 253) return false;
  const labels = host.split('.');
  if (labels.length < 2) return false;
  if (!labels.every((l) => l.length >= 1 && l.length <= 63 && LABEL.test(l))) return false;
  const last = labels[labels.length - 1];
  if (/^[0-9]+$/.test(last) || /^0x[0-9a-f]*$/.test(last)) return false;
  return true;
}

function splitHostPort(rest) {
  const colon = rest.indexOf(':');
  if (colon === -1) return { host: rest, port: null };
  return { host: rest.slice(0, colon), port: rest.slice(colon + 1) };
}

/**
 * https: a DNS name of at least two labels, each 1..63 characters of the label grammar, at most 253
 * characters in all, whose last label is neither all digits nor `0x` plus hex digits (URL parsers read
 * such a host as an IPv4 address; a bare `0x` is refused too). An `xn--` label is an ordinary label:
 * never decoded.
 * http: only localhost and 127.0.0.1.
 */
export function isOrigin(v) {
  if (typeof v !== 'string') return false;
  if (v.startsWith('https://')) {
    const { host, port } = splitHostPort(v.slice('https://'.length));
    if (port !== null && !isPort(port, 443)) return false;
    return isDnsHost(host);
  }
  if (v.startsWith('http://')) {
    const { host, port } = splitHostPort(v.slice('http://'.length));
    if (port !== null && !isPort(port, 80)) return false;
    return host === 'localhost' || host === '127.0.0.1';
  }
  return false;
}

// ---- name (§2.2) ----

const NAME_FORBIDDEN_RANGES = [
  [0x0000, 0x001f],
  [0x007f, 0x009f],
  [0x00ad, 0x00ad],
  [0x061c, 0x061c],
  [0x180e, 0x180e],
  [0x200b, 0x200f],
  [0x2028, 0x202e],
  [0x2060, 0x2064],
  [0x2066, 0x206f],
  [0xfeff, 0xfeff],
  [0xfff9, 0xfffb],
];

export function isNameForbiddenCodePoint(cp) {
  return NAME_FORBIDDEN_RANGES.some(([lo, hi]) => cp >= lo && cp <= hi);
}

/** Checks the decoded text of a name: 1..64 UTF-8 bytes, no forbidden code point, no U+0020 at either end. */
export function isNameText(bytes) {
  if (bytes.length < 1 || bytes.length > 64) return false;
  const text = utf8DecodeStrict(bytes);
  if (text === null) return false;
  const cps = [...text].map((ch) => ch.codePointAt(0));
  if (cps.some(isNameForbiddenCodePoint)) return false;
  if (cps[0] === 0x20 || cps[cps.length - 1] === 0x20) return false;
  return true;
}

/** name: unpadded base64url that re-encodes identically, of text that passes isNameText. */
export function isName(v) {
  if (typeof v !== 'string') return false;
  const bytes = unb64u(v);
  return bytes !== null && isNameText(bytes);
}

// ---- emailNorm (§2.3) ----

/**
 * Returns the normalised address, or null for the verdict `invalid_email`.
 * Strip ASCII white space (space, tab, CR, LF) from both ends; lowercase A-Z; then refuse anything
 * that, after the strip, is shorter than 3 or longer than 254 octets, holds a byte outside 0x21-0x7E
 * (an interior space, a tab, a control character, DEL, anything non-ASCII), or does not have exactly
 * one `@` between two non-empty parts (VR-6). Then (spec 01 §5.5) the address must be
 * `local@domain`: `local` a dot-atom of 1..64 characters of letters, digits and
 * !#$%&'*+/=?^_`{|}~- with single dots between non-empty parts; `domain` a host under the origin
 * type's host grammar (isDnsHost). Lowercasing comes first, so an upper-case domain is checked in
 * its lowercased form. Anything else has no emailNorm.
 */
export const EMAIL_LOCAL_MAX = 64;
const DOT_ATOM = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/;

export function emailNorm(input) {
  if (typeof input !== 'string') return null;
  let s = input.replace(/^[ \t\r\n]+/, '').replace(/[ \t\r\n]+$/, '');
  s = s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
  const bytes = utf8(s);
  if (bytes.length < 3 || bytes.length > 254) return null;
  for (const b of bytes) if (b < 0x21 || b > 0x7e) return null;
  const parts = s.split('@');
  if (parts.length !== 2 || parts[0].length === 0 || parts[1].length === 0) return null;
  const [local, domain] = parts;
  if (local.length > EMAIL_LOCAL_MAX || !DOT_ATOM.test(local)) return null;
  if (!isDnsHost(domain)) return null;
  return s;
}

/** email_b64n: "none", or canonical unpadded base64url of an emailNorm of 3..254 bytes. */
export function isEmailB64n(v) {
  if (v === 'none') return true;
  if (typeof v !== 'string') return false;
  const bytes = unb64u(v);
  if (bytes === null || bytes.length < 3 || bytes.length > 254) return false;
  const text = utf8DecodeStrict(bytes);
  if (text === null) return false;
  return emailNorm(text) === text;
}

/** email_b64 (spec 01 §5.1): the email_b64n grammar without the literal "none". */
export function isEmailB64(v) {
  return v !== 'none' && isEmailB64n(v);
}

// ---- §2.3 enums and counters ----

export const PLATFORMS = ['android', 'ios', 'windows', 'macos', 'linux', 'web', 'cli', 'extension'];
export const isPlatform = (v) => typeof v === 'string' && PLATFORMS.includes(v);

/** Leading zero bits, counted from the most significant bit of byte 0, then byte 1, and so on. */
export function leadingZeroBits(digest) {
  let bits = 0;
  for (const byte of digest) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    for (let mask = 0x80; mask !== 0 && (byte & mask) === 0; mask >>= 1) bits++;
    return bits;
  }
  return bits;
}

/** The decimal form §2.3 gives a proof-of-work nonce: an integer 0 <= n < 2^53 with no leading zeros. */
export function isPowNonceText(text) {
  return typeof text === 'string' && /^(0|[1-9][0-9]*)$/.test(text) && Number(text) < TWO_53 && String(Number(text)) === text;
}
