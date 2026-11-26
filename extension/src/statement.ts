import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import nacl from "tweetnacl";

/**
 * The signed-statement frame and the strict statement parser for the two purposes the extension reads
 * (design 2026-11-15-onboarding-trust §2.1, §2.2, §2.4, §12.2 rule 5): 0x04 `instance-card` and 0x05
 * `account-genesis`. It is the third implementation beside core and the web twin, and it shares no code
 * with either: core re-encodes after a platform parse, the web twin walks the template text; this one refuses
 * nesting on the bytes (§2.2), then runs `JSON.parse`, checks the key list and every value's type, then renders the values canonically and
 * compares the bytes. `statement-v2.json` (the rows with purposeCode 4 or 5) is the arbiter.
 *
 * Signer binding here is the Ed25519 form only (§2.1): the signer is compared byte for byte with the key
 * the caller hands in. The extension has no Montgomery map, so it never compares X25519 images.
 *
 * LEAF module: no chrome, so `node --test` grades the production code.
 */

export const MAGIC = Uint8Array.of(0x61, 0x76, 0x73, 0x02);
export const DOMAIN = "andvari/v2|signed-statement";
export const STATEMENT_OFFSET = 101;
export const MIN_STATEMENT_BYTES = 2;
export const MAX_STATEMENT_BYTES = 1024;
export const ZERO_HASH = "0".repeat(64);

/** Every purpose code of §2.1. Codes outside this table are reserved, and a frame carrying one is `bad_frame`. */
export const PURPOSE_CODES: Readonly<Record<string, number>> = {
  "vault-grant": 0x01,
  "escrow-uvk": 0x02,
  "vault-log": 0x03,
  "instance-card": 0x04,
  "account-genesis": 0x05,
  "link-offer": 0x06,
  "link-answer": 0x07,
  "recovery-rotation": 0x08,
  "assisted-recovery": 0x09,
  "recovery-veto": 0x0a,
};

/** The purposes the extension parses. */
export type ExtPurpose = "instance-card" | "account-genesis";

/** The verdicts of the frame and the strict parse (§2.4), in their order. */
export type ParseVerdict = "bad_frame" | "unknown_format" | "non_canonical" | "bad_statement";

export type Parsed<T, V extends string> = { ok: true; value: T } | { ok: false; verdict: V };

type ValueType = "v" | "purpose" | "uuid" | "int" | "ms" | "hex64" | "hex64n" | "b64_32" | "origin" | "name" | "instance_kind";

const TEMPLATES: Readonly<Record<ExtPurpose, readonly (readonly [string, ValueType])[]>> = {
  "instance-card": [
    ["v", "v"], ["purpose", "purpose"], ["instanceId", "uuid"], ["seq", "int"], ["prev", "hex64"], ["origin", "origin"],
    ["name", "name"], ["kind", "instance_kind"], ["operator", "uuid"], ["operatorSignKey", "b64_32"], ["recoveryFp", "hex64n"],
    ["issuedAt", "ms"],
  ],
  "account-genesis": [
    ["v", "v"], ["purpose", "purpose"], ["userId", "uuid"], ["identityKey", "b64_32"], ["instanceId", "uuid"],
    ["personalVaultId", "uuid"], ["createdAt", "ms"],
  ],
};

/** The values of a parsed statement, by field name: numbers as numbers, everything else as its exact text. */
export type Values = Readonly<Record<string, string | number>>;

/** A frame split into its parts, the statement parsed. Nothing in it is authenticated yet. */
export interface ParsedFrame {
  readonly purpose: ExtPurpose;
  readonly signerPub: Uint8Array;
  readonly signature: Uint8Array;
  readonly statement: Uint8Array;
  readonly values: Values;
}

// ---- the value types of §2.2 ----

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const B64URL_RE = /^[A-Za-z0-9_-]*$/;
const TWO_53 = 2 ** 53;

export const isUuid = (s: string): boolean => UUID_RE.test(s);
export const isHex64 = (s: string): boolean => HEX64_RE.test(s);

/** Strict unpadded base64url: the alphabet only, no `=`, and zero trailing bits, so the text is the one encoding of its bytes. */
export function b64Strict(text: string): Uint8Array | null {
  if (!B64URL_RE.test(text) || text.length % 4 === 1) return null;
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const out = new Uint8Array(Math.floor((text.length * 6) / 8));
  let acc = 0;
  let bits = 0;
  let n = 0;
  for (const ch of text) {
    acc = (acc << 6) | alphabet.indexOf(ch);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[n++] = (acc >> bits) & 0xff;
    }
  }
  if ((acc & ((1 << bits) - 1)) !== 0) return null; // non-zero leftover bits: not the canonical text of these bytes
  return out;
}

/** Unpadded base64url of `bytes`. */
export function b64Encode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const isB64_32 = (s: string): boolean => s.length === 43 && b64Strict(s)?.length === 32;

const LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
const HTTPS_RE = /^https:\/\/([^:]*)(?::([0-9]+))?$/;
const HTTP_RE = /^http:\/\/(?:localhost|127\.0\.0\.1)(?::([0-9]+))?$/;
const DNS_HOST_RE = new RegExp(`^${LABEL}(?:\\.${LABEL})+$`);

/**
 * The host grammar of the `origin` type's https branch (§2.2), also the domain of an `emailNorm` (§2.3): two or more
 * labels, each 1..63 of `[a-z0-9-]` with no edge hyphen, at most 253 characters, the last label neither all digits
 * nor `0x` plus hex digits (URL parsers read those as IPv4). `xn--` labels are plain labels, never decoded. The plain
 * http `localhost` and `127.0.0.1` forms belong to the origin type, not to this grammar.
 */
export function isDnsHost(host: string): boolean {
  if (host.length > 253 || !DNS_HOST_RE.test(host)) return false;
  const last = host.slice(host.lastIndexOf(".") + 1);
  return !/^[0-9]+$/.test(last) && !/^0x[0-9a-f]*$/.test(last);
}

function portAllowed(port: string | undefined, schemeDefault: number): boolean {
  if (port === undefined) return true;
  if (!/^[1-9][0-9]{0,4}$/.test(port)) return false;
  const n = Number(port);
  return n <= 65535 && n !== schemeDefault;
}

/**
 * The `origin` type (§2.2, R4, VR-5), the single source for every origin the extension stores, dials or
 * shows. https with a host of two or more labels (each 1..63 of `[a-z0-9-]`, no edge hyphen), at most 253
 * characters, whose last label is neither all digits nor `0x` plus hex digits (URL parsers read those as
 * IPv4); `xn--` labels are plain labels, never decoded. A port without leading zeros, never the scheme's
 * default. Plain http only for `localhost` and `127.0.0.1`. Nothing after the authority.
 */
export function isOrigin(s: string): boolean {
  const https = HTTPS_RE.exec(s);
  if (https) return isDnsHost(https[1]!) && portAllowed(https[2], 443);
  const http = HTTP_RE.exec(s);
  return http !== null && portAllowed(http[1], 80);
}

/** The code points a `name` may not contain (§2.2), inclusive ranges. */
const NAME_FORBIDDEN: readonly (readonly [number, number])[] = [
  [0x0000, 0x001f], [0x007f, 0x009f], [0x00ad, 0x00ad], [0x061c, 0x061c], [0x180e, 0x180e], [0x200b, 0x200f],
  [0x2028, 0x202e], [0x2060, 0x2064], [0x2066, 0x206f], [0xfeff, 0xfeff], [0xfff9, 0xfffb],
];

/**
 * The text of a `name` value (§2.2), or null when the value is not one: canonical unpadded base64url of 1..64
 * bytes of valid UTF-8, none of the listed code points, no space at either end. No normalisation. Shown only
 * as plain text.
 */
export function nameText(b64: string): string | null {
  const bytes = b64Strict(b64);
  if (bytes === null || bytes.length < 1 || bytes.length > 64) return null;
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null;
  }
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (NAME_FORBIDDEN.some(([lo, hi]) => cp >= lo && cp <= hi)) return null;
  }
  return text.startsWith(" ") || text.endsWith(" ") ? null : text;
}

function typed(type: ValueType, v: unknown): boolean {
  switch (type) {
    case "v":
    case "int":
      return typeof v === "number" && Number.isInteger(v) && v >= 0 && v < TWO_53;
    case "ms":
      return typeof v === "number" && Number.isInteger(v) && v >= 1 && v < TWO_53;
    case "purpose":
      return typeof v === "string" && Object.prototype.hasOwnProperty.call(PURPOSE_CODES, v);
    case "uuid":
      return typeof v === "string" && isUuid(v);
    case "hex64":
      return typeof v === "string" && isHex64(v);
    case "hex64n":
      return typeof v === "string" && (v === "none" || isHex64(v));
    case "b64_32":
      return typeof v === "string" && isB64_32(v);
    case "origin":
      return typeof v === "string" && isOrigin(v);
    case "name":
      return typeof v === "string" && nameText(v) !== null;
    case "instance_kind":
      return v === "public" || v === "private";
  }
}

/**
 * Spec 01 §5.1 "no nesting" (design §2.2): a statement is one flat object, so a `[` anywhere, or a second `{`, is
 * `non_canonical`. The twin of core's `isFlatStatement` (CanonicalJson.kt). Nothing canonical is lost: no value type of
 * the grammar admits `[` or `{`.
 */
export function isFlatStatement(statement: Uint8Array): boolean {
  let braces = 0;
  for (const b of statement) {
    if (b === 0x5b) return false; // [
    if (b === 0x7b && ++braces > 1) return false; // {
  }
  return true;
}

/** The canonical rendering of typed values: no white space, numbers in decimal, strings with nothing to escape. */
function render(fields: readonly (readonly [string, ValueType])[], obj: Record<string, unknown>): string {
  const parts = fields.map(([k, type]) => (type === "v" || type === "int" || type === "ms" ? `"${k}":${String(obj[k])}` : `"${k}":"${String(obj[k])}"`));
  return `{${parts.join(",")}}`;
}

/**
 * The strict parse of a statement under `purpose` (spec 01 §5.1 steps 2–6): printable ASCII, a JSON object
 * with exactly the template's keys in its order, every value in its type, and a byte-identical canonical
 * rendering (`non_canonical` otherwise); then `v` must be 2 and `purpose` must name this purpose
 * (`bad_statement`). Neither template has a further rule of its own section here: card 0's zero `prev` is
 * the chain's `bad_prev`.
 */
export function parseStatement(purpose: ExtPurpose, statement: Uint8Array): Parsed<Values, ParseVerdict> {
  if (statement.length < MIN_STATEMENT_BYTES || statement.length > MAX_STATEMENT_BYTES) return { ok: false, verdict: "bad_frame" };
  let text = "";
  for (const b of statement) {
    if (b < 0x20 || b > 0x7e) return { ok: false, verdict: "non_canonical" };
    text += String.fromCharCode(b);
  }
  // §2.2: no nesting, decided on the bytes before any general JSON parser sees the text (a parser that recurses once
  // per level can be made to overflow its stack by a statement of a thousand brackets: a crash, not a verdict).
  if (!isFlatStatement(statement)) return { ok: false, verdict: "non_canonical" };
  let obj: unknown;
  try {
    obj = JSON.parse(text);
  } catch {
    return { ok: false, verdict: "non_canonical" };
  }
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) return { ok: false, verdict: "non_canonical" };
  const fields = TEMPLATES[purpose];
  const rec = obj as Record<string, unknown>;
  const keys = Object.keys(rec);
  if (keys.length !== fields.length || fields.some(([k], i) => keys[i] !== k)) return { ok: false, verdict: "non_canonical" };
  for (const [k, type] of fields) if (!typed(type, rec[k])) return { ok: false, verdict: "non_canonical" };
  if (render(fields, rec) !== text) return { ok: false, verdict: "non_canonical" };
  if (rec.v !== 2 || rec.purpose !== purpose) return { ok: false, verdict: "bad_statement" };
  return { ok: true, value: rec as Values };
}

/**
 * The whole §2 parse of `frame` by the helper for `purpose`, in §2.4's order (VR-8): `bad_frame` under 4
 * bytes; `unknown_format` for a wrong magic (version byte included), read before the length; `bad_frame` for
 * a length outside 103..1125, a reserved code, or another purpose than `purpose`; then the statement.
 * No signature is checked here.
 */
export function parseFrame(frame: Uint8Array, purpose: ExtPurpose): Parsed<ParsedFrame, ParseVerdict> {
  if (frame.length < 4) return { ok: false, verdict: "bad_frame" };
  if (MAGIC.some((b, i) => frame[i] !== b)) return { ok: false, verdict: "unknown_format" };
  if (frame.length < STATEMENT_OFFSET + MIN_STATEMENT_BYTES || frame.length > STATEMENT_OFFSET + MAX_STATEMENT_BYTES) {
    return { ok: false, verdict: "bad_frame" };
  }
  if (frame[4] !== PURPOSE_CODES[purpose]) return { ok: false, verdict: "bad_frame" }; // reserved, or another purpose
  const statement = frame.slice(STATEMENT_OFFSET);
  const parsed = parseStatement(purpose, statement);
  if (!parsed.ok) return parsed;
  return {
    ok: true,
    value: { purpose, signerPub: frame.slice(5, 37), signature: frame.slice(37, STATEMENT_OFFSET), statement, values: parsed.value },
  };
}

/** The signed message M of §2.1. */
export function signedMessage(purposeCode: number, signerPub: Uint8Array, statement: Uint8Array): Uint8Array {
  const domain = new TextEncoder().encode(DOMAIN);
  const out = new Uint8Array(domain.length + 1 + 5 + signerPub.length + statement.length);
  let o = 0;
  out.set(domain, o);
  o += domain.length;
  out[o++] = 0;
  out.set(MAGIC, o);
  o += 4;
  out[o++] = purposeCode;
  out.set(signerPub, o);
  o += signerPub.length;
  out.set(statement, o);
  return out;
}

/** Signer binding, the Ed25519 form (§2.1): `signerPub` equals `key` byte for byte. */
export function signerIs(signerPub: Uint8Array, key: Uint8Array): boolean {
  return key.length === 32 && signerPub.length === 32 && signerPub.every((b, i) => b === key[i]);
}

// ---- strict Ed25519 (libsodium's rules, which the Kotlin and web engines get from libsodium itself) ----
// tweetnacl 1.0.3 accepts a signature whose S is not reduced (S + L verifies too, so every signature has a second
// encoding) and verifies under small-order public keys (the identity point verifies a forgery for anyone). The checks
// below refuse both before tweetnacl runs, so all three engines give the same verdict on the same bytes:
//  - S < L (the group order), little-endian;
//  - R and the public key are canonical encodings (y < p, the sign bit masked) and neither is one of the small-order
//    points (compared with the sign bit masked, as libsodium's `ge25519_has_small_order` does, which also covers the
//    non-canonical encodings of 0 and 1).

const ED_L = 2n ** 252n + 27742317777372353535851937790883648493n;
const ED_P = 2n ** 255n - 19n;

function leBig(bytes: Uint8Array, maskTop: boolean): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(i === bytes.length - 1 && maskTop ? bytes[i]! & 0x7f : bytes[i]!);
  return n;
}

/** The y coordinates (sign bit masked) of every small-order point, and the non-canonical encodings of 0 and 1:
 *  0 (order 4), 1 (order 1), the two order-8 values, p − 1 (order 2), p and p + 1. libsodium's blocklist. */
export const SMALL_ORDER_Y: readonly bigint[] = [
  0n,
  1n,
  leBig(Uint8Array.from("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05".match(/../g)!, (h) => parseInt(h, 16)), true),
  leBig(Uint8Array.from("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a".match(/../g)!, (h) => parseInt(h, 16)), true),
  ED_P - 1n,
  ED_P,
  ED_P + 1n,
];

/** S < L: the scalar half of a signature is reduced. */
export function scalarReduced(s: Uint8Array): boolean {
  return s.length === 32 && leBig(s, false) < ED_L;
}

/** A point encoding that is canonical (y < p) and not of small order. */
export function pointAcceptable(enc: Uint8Array): boolean {
  if (enc.length !== 32) return false;
  const y = leBig(enc, true);
  return y < ED_P && !SMALL_ORDER_Y.includes(y);
}

/** `crypto_sign_verify_detached` over M under the frame's own signer key, with libsodium's strictness (above). */
export function signatureValid(purposeCode: number, signerPub: Uint8Array, signature: Uint8Array, statement: Uint8Array): boolean {
  if (signerPub.length !== 32 || signature.length !== 64) return false;
  if (!scalarReduced(signature.subarray(32, 64))) return false;
  if (!pointAcceptable(signature.subarray(0, 32)) || !pointAcceptable(signerPub)) return false;
  try {
    return nacl.sign.detached.verify(signedMessage(purposeCode, signerPub, statement), signature, signerPub);
  } catch {
    return false;
  }
}

/** `H(frame)`: lowercase hex SHA-256 of the whole frame (§2.1). */
export function frameHash(frame: Uint8Array): string {
  return bytesToHex(sha256(frame));
}
