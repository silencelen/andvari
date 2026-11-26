import { concat, fromB64Bytes, toB64Bytes, utf8 } from "../bytes";
import { CryptoError } from "../sodium";
import { type Checked, ok, refused } from "./checked";
import {
  type FrameParts, type FrameVerdict, MAX_STATEMENT_BYTES, MIN_STATEMENT_BYTES, type Purpose, PURPOSES, splitFrame, wipeFrameParts,
} from "./frame";
import {
  decodeEmail, isB64_16, isB64_32, isEmailB64n, isHex64, isHex64n, isName, isOrigin, isRole, isUuid, parseInt53, parseMs, ZERO_HASH,
} from "./grammar";

/**
 * The strict canonical statement parser of design 2026-11-15 §2.2 and §2.4, for every template of
 * purposes 0x01 and 0x03–0x0A and the two host-minted offers of §6.4.
 *
 * It never parses JSON for a framed statement: it walks the template over the statement BYTES and
 * consumes one literal and one typed value at a time, so a statement is accepted exactly when it IS the
 * canonical rendering of in-grammar values. Core's `StatementCodec` was written on its own and works the
 * same way; `statement-v2.json` is the arbiter between the two.
 *
 * Working on the bytes is what keeps a key out of strings. Two statements carry one (a grant's `vk`, an
 * assisted recovery's `uvk`): that value is checked where it stands and never made into a string, which
 * could not be wiped. {@link secretOf} decodes it straight into a byte array.
 */

type FieldType =
  | "v" | "purpose" | "uuid" | "b64_16" | "b64_32" | "hex64" | "hex64n" | "ms" | "int" | "origin" | "name" | "role"
  | "email_b64n" | "log_kind" | "instance_kind" | "link_kind"
  /** `email_b64` (spec 01 §5.1): the `email_b64n` grammar without the literal `none`, so always an address. */
  | "email_b64"
  /** A `b64_32` that is a KEY: same grammar, but its text stays in the statement bytes ({@link secretOf}). */
  | "secret_b64_32";

type Field = readonly [name: string, type: FieldType];

/**
 * A statement's values, each as the exact text it had (a number's digits, a string's content). NOT
 * authenticated. A secret field (a grant's `vk`, an assisted recovery's `uvk`) is NOT among them.
 */
export type RawStatement = Readonly<Record<string, string>>;

/** Where each secret field's base64url text stands in the statement bytes: `[start, end)`. */
type SecretRanges = Readonly<Record<string, readonly [start: number, end: number]>>;

/** What a template match gives: the plain values, and where the secret ones stand. */
interface Matched {
  readonly values: Record<string, string>;
  readonly secrets: Record<string, readonly [number, number]>;
}

const HEAD: readonly Field[] = [["v", "v"], ["purpose", "purpose"]];

export const LOG_KINDS = ["genesis", "add", "role", "remove", "leave", "offer", "cancel", "accept", "delete", "restore"] as const;
export type LogKindLiteral = (typeof LOG_KINDS)[number];

const LOG_HEAD: readonly Field[] = [
  ...HEAD, ["vaultId", "uuid"], ["seq", "int"], ["prev", "hex64"], ["kind", "log_kind"], ["actor", "uuid"], ["at", "ms"],
];

/** §3.1: the fields each kind adds after the head. */
const LOG_TAIL: Readonly<Record<LogKindLiteral, readonly Field[]>> = {
  genesis: [["ownerKey", "b64_32"], ["vkCommit", "hex64"]],
  add: [["member", "uuid"], ["memberKey", "b64_32"], ["role", "role"], ["grantId", "b64_16"]],
  role: [["member", "uuid"], ["role", "role"]],
  remove: [["member", "uuid"]],
  leave: [],
  offer: [["to", "uuid"], ["toKey", "b64_32"], ["offerId", "b64_16"], ["expiresAt", "ms"]],
  cancel: [["offerId", "b64_16"]],
  accept: [["offerId", "b64_16"]],
  delete: [["deleteId", "b64_16"]],
  restore: [["deleteId", "b64_16"]],
};

/** The single-template purposes (spec 01 §6; design §4.1, §5.1, §6.3, §6.5, §4.5, §9.3). */
const TEMPLATES: Readonly<Partial<Record<Purpose, readonly Field[]>>> = {
  "vault-grant": [
    ...HEAD, ["from", "uuid"], ["to", "uuid"], ["toKey", "b64_32"], ["vaultId", "uuid"], ["grantId", "b64_16"],
    ["issuedAt", "ms"], ["vk", "secret_b64_32"],
  ],
  "instance-card": [
    ...HEAD, ["instanceId", "uuid"], ["seq", "int"], ["prev", "hex64"], ["origin", "origin"], ["name", "name"],
    ["kind", "instance_kind"], ["operator", "uuid"], ["operatorSignKey", "b64_32"], ["recoveryFp", "hex64n"], ["issuedAt", "ms"],
  ],
  "account-genesis": [
    ...HEAD, ["userId", "uuid"], ["identityKey", "b64_32"], ["instanceId", "uuid"], ["personalVaultId", "uuid"], ["createdAt", "ms"],
  ],
  "link-offer": [
    ...HEAD, ["linkId", "b64_16"], ["kind", "link_kind"], ["origin", "origin"], ["instanceId", "uuid"], ["cardHash", "hex64"],
    ["from", "uuid"], ["fromKey", "b64_32"], ["name", "name"], ["commit", "hex64"], ["expiresAt", "ms"], ["issuedAt", "ms"],
  ],
  "link-answer": [
    ...HEAD, ["linkId", "b64_16"], ["offerHash", "hex64"], ["to", "uuid"], ["toKey", "b64_32"], ["from", "uuid"],
    ["fromKey", "b64_32"], ["name", "name"], ["nonce", "b64_32"], ["issuedAt", "ms"],
  ],
  "recovery-rotation": [...HEAD, ["instanceId", "uuid"], ["fromFp", "hex64"], ["toFp", "hex64"], ["issuedAt", "ms"]],
  "assisted-recovery": [
    ...HEAD, ["instanceId", "uuid"], ["userId", "uuid"], ["requestId", "b64_16"], ["requestKey", "b64_32"], ["uvk", "secret_b64_32"],
    ["issuedAt", "ms"],
  ],
  "recovery-veto": [...HEAD, ["requestId", "b64_16"], ["userId", "uuid"], ["issuedAt", "ms"]],
};

/**
 * Spec 04 §7 step 3, version 3 (spec 01 §5.1 "Version-3 templates"): the old
 * assisted-recovery fields with the account's address after `userId` and the commit value after `requestKey`. The only
 * form a device accepts. Twin of core `StatementCodec.ASSISTED_V3`.
 */
const ASSISTED_V3: readonly Field[] = [
  ...HEAD, ["instanceId", "uuid"], ["userId", "uuid"], ["email", "email_b64"], ["requestId", "b64_16"], ["requestKey", "b64_32"],
  ["commit", "b64_32"], ["uvk", "secret_b64_32"], ["issuedAt", "ms"],
];

/** The statement versions a reader takes. Only 0x09 has a second template here (0x02's live in signedstatement.ts). */
export type StatementVersion = 2 | 3;

export type HostOfferPurpose = "setup-offer" | "enrol-offer";
const HOST_PURPOSES: readonly string[] = ["setup-offer", "enrol-offer"];

/** §6.4: the host-minted offers, canonical JSON with no frame. */
const HOST_TEMPLATES: Readonly<Record<HostOfferPurpose, readonly Field[]>> = {
  "setup-offer": [
    ...HEAD, ["linkId", "b64_16"], ["origin", "origin"], ["instanceId", "uuid"], ["name", "name"], ["kind", "instance_kind"],
    ["recoveryFp", "hex64n"], ["expiresAt", "ms"],
  ],
  "enrol-offer": [
    ...HEAD, ["linkId", "b64_16"], ["origin", "origin"], ["instanceId", "uuid"], ["cardHash", "hex64"], ["email", "email_b64n"],
    ["expiresAt", "ms"],
  ],
};

const isNumeric = (t: FieldType): boolean => t === "v" || t === "ms" || t === "int";

function inGrammar(type: FieldType, raw: string, purposes: readonly string[]): boolean {
  switch (type) {
    case "v": return parseInt53(raw) !== null; // the int type (VR-4); its value is checked after
    case "purpose": return purposes.includes(raw);
    case "uuid": return isUuid(raw);
    case "b64_16": return isB64_16(raw);
    case "b64_32": return isB64_32(raw);
    case "hex64": return isHex64(raw);
    case "hex64n": return isHex64n(raw);
    case "ms": return parseMs(raw) !== null;
    case "int": return parseInt53(raw) !== null;
    case "origin": return isOrigin(raw);
    case "name": return isName(raw);
    case "role": return isRole(raw);
    case "email_b64n": return isEmailB64n(raw);
    case "email_b64": return decodeEmail(raw)?.email != null;
    case "log_kind": return (LOG_KINDS as readonly string[]).includes(raw);
    case "instance_kind": return raw === "public" || raw === "private";
    case "link_kind": return raw === "connect" || raw === "register";
    case "secret_b64_32": return false; // never judged as text: see secretInGrammar
  }
}

/** The `b64_32` grammar for a key, judged on the bytes where they stand: 43 characters, canonical, 32 bytes. */
function secretInGrammar(bytes: Uint8Array, start: number, end: number): boolean {
  if (end - start !== 43) return false;
  const key = fromB64Bytes(bytes, start, end);
  if (key === null) return false;
  key.fill(0);
  return true;
}

/** The ASCII text of `bytes[start..end)`. Used for one plain value at a time, never for a whole statement. */
function asciiOf(bytes: Uint8Array, start: number, end: number): string {
  let text = "";
  for (let i = start; i < end; i++) text += String.fromCharCode(bytes[i]!);
  return text;
}

/** True when `bytes` hold exactly the ASCII characters of `text` at `pos`. */
function hasAt(bytes: Uint8Array, pos: number, text: string): boolean {
  if (pos + text.length > bytes.length) return false;
  for (let i = 0; i < text.length; i++) if (bytes[pos + i] !== text.charCodeAt(i)) return false;
  return true;
}

/**
 * Consume `fields` from `bytes` at `pos`: for each, the exact text `"name":` (after a comma unless it is
 * the first field of the object), then a bare run of digits for a number or a quoted run for a string.
 * No grammar here admits `"` or `\`, so a string value ends at the next quote. A plain value becomes a
 * string in `out.values`; a secret one is checked where it stands and only its range is recorded.
 * Returns the position after the last value, or -1 when the bytes are not this template.
 */
function consume(bytes: Uint8Array, pos: number, fields: readonly Field[], first: boolean, purposes: readonly string[], out: Matched): number {
  for (const [name, type] of fields) {
    const lead = `${first ? "" : ","}"${name}":`;
    if (!hasAt(bytes, pos, lead)) return -1;
    pos += lead.length;
    first = false;
    if (isNumeric(type)) {
      let end = pos;
      while (end < bytes.length && bytes[end]! >= 0x30 && bytes[end]! <= 0x39) end++;
      const raw = asciiOf(bytes, pos, end);
      if (!inGrammar(type, raw, purposes)) return -1;
      out.values[name] = raw;
      pos = end;
      continue;
    }
    if (bytes[pos] !== 0x22) return -1;
    const close = bytes.indexOf(0x22, pos + 1);
    if (close < 0) return -1;
    if (type === "secret_b64_32") {
      if (!secretInGrammar(bytes, pos + 1, close)) return -1;
      out.secrets[name] = [pos + 1, close];
    } else {
      const raw = asciiOf(bytes, pos + 1, close);
      if (!inGrammar(type, raw, purposes)) return -1;
      out.values[name] = raw;
    }
    pos = close + 1;
  }
  return pos;
}

/** `bytes` as exactly `{` + `fields` + `}`, or null. */
function matchWhole(bytes: Uint8Array, fields: readonly Field[], purposes: readonly string[]): Matched | null {
  if (bytes[0] !== 0x7b) return null;
  const out: Matched = { values: {}, secrets: {} };
  const end = consume(bytes, 1, fields, true, purposes, out);
  return end >= 0 && bytes.length === end + 1 && bytes[end] === 0x7d ? out : null;
}

/** A vault-log statement: the head, then the fields of whatever `kind` the head names. */
function matchLog(bytes: Uint8Array): Matched | null {
  if (bytes[0] !== 0x7b) return null;
  const out: Matched = { values: {}, secrets: {} };
  let pos = consume(bytes, 1, LOG_HEAD, true, PURPOSES, out);
  if (pos < 0) return null;
  pos = consume(bytes, pos, LOG_TAIL[out.values.kind as LogKindLiteral], false, PURPOSES, out);
  return pos >= 0 && bytes.length === pos + 1 && bytes[pos] === 0x7d ? out : null;
}

/** True when every byte is printable ASCII (0x20..0x7E). */
function isPrintableAscii(bytes: Uint8Array): boolean {
  for (const b of bytes) if (b < 0x20 || b > 0x7e) return false;
  return true;
}

/**
 * The TEMPLATE rules of the owning section (`bad_statement`). The design names exactly two (§2.4,
 * VR-1): a grant's `from != to`, and the vault log's "a genesis has seq 0 and a zero prev; every other
 * kind has seq >= 1". A card 0 with a non-zero `prev` is a chain verdict (`bad_prev`), not this.
 */
function templateRulesHold(purpose: Purpose, v: RawStatement): boolean {
  if (purpose === "vault-grant") return v.from !== v.to;
  if (purpose === "vault-log") {
    const genesis = v.kind === "genesis";
    if (genesis !== (v.seq === "0")) return false;
    return !genesis || v.prev === ZERO_HASH;
  }
  return true;
}

/**
 * The strict parse of a FRAMED statement under `purpose` (§2.2, §2.4; spec 01 §5.1 steps 2–6):
 * `bad_frame` for a length outside 2..1024 or a purpose with no template here; `non_canonical`;
 * `bad_statement` when `v` is not 2, the `purpose` literal is another purpose's, or a template rule fails.
 */
export function parseStatement(purpose: Purpose, statement: Uint8Array, version: StatementVersion = 2): Checked<RawStatement, FrameVerdict> {
  const matched = matchStatement(purpose, statement, version);
  return matched.ok ? ok(matched.value.values) : matched;
}

/**
 * {@link parseStatement}, keeping where the secret fields stand. [version] is the one statement version the caller
 * accepts. For 0x09, which has two templates (spec 01 §5.1 "Version-3 templates"), the reader tries both: the key set
 * picks one (one with `email` is the version-3 template, one without the version-2 template), the bytes must be that
 * template's canonical rendering (`non_canonical`), `v` must be its own version, and a version the caller does not
 * accept is `bad_statement`. So a version-2 key set marked 3, a version-3 key set marked 2, and a canonical answer of
 * the version the caller does not take are all `bad_statement`.
 */
function matchStatement(purpose: Purpose, statement: Uint8Array, version: StatementVersion = 2): Checked<Matched, FrameVerdict> {
  if (version === 3 && purpose !== "assisted-recovery") throw new CryptoError(`statement: no version-3 template for ${purpose}`);
  if (statement.length < MIN_STATEMENT_BYTES || statement.length > MAX_STATEMENT_BYTES) return refused("bad_frame");
  const template = TEMPLATES[purpose];
  if (purpose !== "vault-log" && template === undefined) return refused("bad_frame"); // escrow-uvk: escrow.ts verifies those
  if (!isPrintableAscii(statement)) return refused("non_canonical");
  if (purpose === "assisted-recovery") {
    const v3 = matchWhole(statement, ASSISTED_V3, PURPOSES);
    const picked = v3 ?? matchWhole(statement, template!, PURPOSES);
    if (picked === null) return refused("non_canonical");
    const own: StatementVersion = v3 !== null ? 3 : 2;
    if (picked.values.v !== String(own) || own !== version || picked.values.purpose !== purpose) return refused("bad_statement");
    return ok(picked);
  }
  const matched = purpose === "vault-log" ? matchLog(statement) : matchWhole(statement, template!, PURPOSES);
  if (matched === null) return refused("non_canonical");
  const values = matched.values;
  if (values.v !== "2" || values.purpose !== purpose || !templateRulesHold(purpose, values)) return refused("bad_statement");
  return ok(matched);
}

/** A frame that passed the whole §2 parse for one purpose. NOT authenticated. */
export interface ParsedFrame {
  readonly parts: FrameParts;
  /** Every plain field. A secret field is read with {@link secretOf}. */
  readonly raw: RawStatement;
  /** Where each secret field stands in `parts.statement`. */
  readonly secrets: SecretRanges;
}

/**
 * The whole §2 parse of `frame` by the helper for `purpose`, in §2.4's order. No signature is checked.
 * The parts are this function's own copies of the frame's bytes; when it refuses, it wipes them, so a
 * refused frame leaves nothing behind (what it held may still have been a key).
 */
export function parseFrame(frame: Uint8Array, purpose: Purpose, version: StatementVersion = 2): Checked<ParsedFrame, FrameVerdict> {
  const split = splitFrame(frame);
  if (!split.ok) return split;
  const matched: Checked<Matched, FrameVerdict> = split.value.purpose !== purpose ? refused("bad_frame") : matchStatement(purpose, split.value.statement, version);
  if (!matched.ok) {
    wipeFrameParts(split.value);
    return matched;
  }
  return ok({ parts: split.value, raw: matched.value.values, secrets: matched.value.secrets });
}

/**
 * The 32 bytes of the secret field `name` of a parsed frame (a grant's `vk`, an assisted recovery's
 * `uvk`), decoded straight from the statement bytes: no string is ever made of the key. The caller wipes
 * the result, and wipes the frame's parts when it is done with them (`wipeFrameParts`); after that this
 * throws. Throws `CryptoError` for a field that is not a secret field of this statement.
 */
export function secretOf(parsed: ParsedFrame, name: string): Uint8Array {
  const range = Object.prototype.hasOwnProperty.call(parsed.secrets, name) ? parsed.secrets[name] : undefined;
  const key = range === undefined ? null : fromB64Bytes(parsed.parts.statement, range[0], range[1]);
  if (key === null || key.length !== 32) {
    key?.fill(0);
    throw new CryptoError(`statement: ${name} is not a secret field that can be read here`);
  }
  return key;
}

/** How many objects and arrays may be open at once in JSON this directory reads with `JSON.parse` (core: `StrictJson.MAX_DEPTH`). */
export const MAX_JSON_DEPTH = 32;

/**
 * True when no more than {@link MAX_JSON_DEPTH} containers are ever open in `text` (brackets inside
 * strings do not count). It runs BEFORE `JSON.parse`, so that no text can make a parser nest deeper than
 * the bound. A closer with nothing open is refused too: such a text is not JSON, and it must not buy
 * depth back for what follows it.
 */
export function withinJsonDepth(text: string): boolean {
  let open = 0;
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (inString) {
      if (c === 0x5c) i++; // a backslash: skip what it escapes
      else if (c === 0x22) inString = false;
    } else if (c === 0x22) {
      inString = true;
    } else if (c === 0x7b || c === 0x5b) {
      if (++open > MAX_JSON_DEPTH) return false;
    } else if (c === 0x7d || c === 0x5d) {
      if (--open < 0) return false;
    }
  }
  return true;
}

/**
 * True when a key appears twice at the top level of the JSON object `text` (already known to be valid
 * JSON). `JSON.parse` silently keeps the last one, so the keys are read from the text itself: each key
 * token at depth 1 is decoded on its own, which also catches the same key written once with an escape.
 */
export function hasRepeatedTopLevelKey(text: string): boolean {
  const seen = new Set<string>();
  let depth = 0;
  let expectKey = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 0x22) {
      const start = i;
      for (i++; text.charCodeAt(i) !== 0x22; i++) if (text.charCodeAt(i) === 0x5c) i++;
      if (depth === 1 && expectKey) {
        const key = JSON.parse(text.slice(start, i + 1)) as string;
        if (seen.has(key)) return true;
        seen.add(key);
        expectKey = false;
      }
    } else if (c === 0x7b || c === 0x5b) {
      depth++;
      if (depth === 1 && c === 0x7b) expectKey = true;
    } else if (c === 0x7d || c === 0x5d) {
      depth--;
    } else if (c === 0x2c && depth === 1) {
      expectKey = true;
    }
  }
  return false;
}

/**
 * The strict parse of a host-minted offer (§6.4; §2.4 "Host JSON offer", VR-15), in order:
 * 1. printable ASCII and a JSON object with a string `purpose`, else `non_canonical`. A bare token,
 *    `NaN`, a trailing comma, trailing bytes, nesting deeper than 32 open containers, and a key that
 *    appears twice at the top level (whichever value comes last) are all `non_canonical`;
 * 2. a `purpose` other than `setup-offer` and `enrol-offer` is `unknown_format`;
 * 3. the template's own steps: `non_canonical`, then `bad_statement` when `v` is not 2.
 */
export function parseHostOffer(plaintext: Uint8Array): Checked<{ readonly purpose: HostOfferPurpose; readonly raw: RawStatement }, FrameVerdict> {
  if (!isPrintableAscii(plaintext)) return refused("non_canonical");
  const text = asciiOf(plaintext, 0, plaintext.length); // a host offer carries no key
  if (!withinJsonDepth(text)) return refused("non_canonical");
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return refused("non_canonical");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return refused("non_canonical");
  if (hasRepeatedTopLevelKey(text)) return refused("non_canonical");
  if (!Object.prototype.hasOwnProperty.call(parsed, "purpose")) return refused("non_canonical");
  const purpose = (parsed as Record<string, unknown>).purpose;
  if (typeof purpose !== "string") return refused("non_canonical");
  if (purpose !== "setup-offer" && purpose !== "enrol-offer") return refused("unknown_format");
  const matched = matchWhole(plaintext, HOST_TEMPLATES[purpose], HOST_PURPOSES);
  if (matched === null) return refused("non_canonical");
  if (matched.values.v !== "2") return refused("bad_statement");
  return ok({ purpose, raw: matched.values });
}

/**
 * The canonical bytes for `values` and `secrets` under `fields`. A plain value is written from its
 * string; a secret one is written from its bytes as base64url, through a byte array that is wiped, so
 * the key never becomes a string. A secret given as a plain value, or the reverse, is refused.
 */
function render(fields: readonly Field[], values: Readonly<Record<string, string>>, secrets: Readonly<Record<string, Uint8Array>>): Uint8Array {
  const parts: Uint8Array[] = [];
  const keyTexts: Uint8Array[] = [];
  try {
    fields.forEach(([name, type], i) => {
      const lead = `${i === 0 ? "{" : ","}"${name}":`;
      if (type === "secret_b64_32") {
        const key = Object.prototype.hasOwnProperty.call(secrets, name) ? secrets[name] : undefined;
        if (key === undefined || key.length !== 32) throw new CryptoError(`statement: ${name} must be given as 32 secret bytes`);
        const text = toB64Bytes(key);
        keyTexts.push(text);
        parts.push(utf8(`${lead}"`), text, utf8('"'));
        return;
      }
      const v = Object.prototype.hasOwnProperty.call(values, name) ? values[name] : undefined;
      if (v === undefined) throw new CryptoError(`statement: missing field ${name}`);
      parts.push(utf8(isNumeric(type) ? `${lead}${v}` : `${lead}"${v}"`));
    });
    if (Object.keys(values).length + Object.keys(secrets).length !== fields.length) throw new CryptoError("statement: unexpected field for this template");
    parts.push(utf8("}"));
    return concat(...parts);
  } finally {
    for (const text of keyTexts) text.fill(0);
  }
}

/**
 * The canonical bytes of a framed statement of `purpose` with `fields` (everything but `v` and
 * `purpose`, as statement text) and `secrets` (a grant's `vk`: the 32 key bytes, never text). Throws
 * `CryptoError` for whatever {@link parseStatement} would refuse, so a statement this client signs
 * always parses back. A statement with a secret holds that key in the clear: the caller wipes the
 * result once it is framed and sealed.
 */
export function encodeStatement(
  purpose: Purpose,
  fields: Readonly<Record<string, string>>,
  secrets: Readonly<Record<string, Uint8Array>> = {},
  version: StatementVersion = 2,
): Uint8Array {
  let template: readonly Field[] | undefined;
  if (version === 3) {
    if (purpose !== "assisted-recovery") throw new CryptoError(`statement: no version-3 template for ${purpose}`);
    template = ASSISTED_V3;
  } else if (purpose === "vault-log") {
    const tail = LOG_TAIL[fields.kind as LogKindLiteral];
    if (tail === undefined || !Object.prototype.hasOwnProperty.call(LOG_TAIL, fields.kind ?? "")) throw new CryptoError("statement: unknown log kind");
    template = [...LOG_HEAD, ...tail];
  } else {
    template = TEMPLATES[purpose];
  }
  if (template === undefined) throw new CryptoError("statement: this purpose is not built here");
  const bytes = render(template, { ...fields, v: String(version), purpose }, secrets);
  const back = matchStatement(purpose, bytes, version);
  if (!back.ok) {
    bytes.fill(0);
    throw new CryptoError(`statement: ${purpose} is outside its grammar (${back.verdict})`);
  }
  return bytes;
}
