// Canonical statements: the templates of design §3.1, §4.1, §4.5, §5.1, §6.3-§6.5 and §9.3, the
// two inherited templates of spec 01 §5.1, and the strict parse of spec 01 §5.1 that §2.2 inherits.
//
// The parse is implemented twice, on purpose:
//   parseByJson  follows spec 01 §5.1 step by step (printable ASCII, no nesting, the platform JSON
//                parser, the key set, the value grammars, the re-encode byte-compare, then v /
//                purpose / rules);
//   parseByScan  never calls a JSON parser: it walks the bytes against the template.
// `parseStatement` runs both and throws if they ever disagree, so a row cannot rest on a quirk of
// one of them.
//
// No nesting (§2.2): a statement is one flat object, so a `[` anywhere, or a second `{`, is
// non_canonical, and it is refused on the bytes BEFORE the text reaches a general JSON parser (one
// that recurses once per level can be made to overflow its stack by a statement of a thousand
// brackets, which is a crash and not a verdict). parseByJson makes that check first; parseByScan has
// no general parser to protect and must reach the same verdict from the template alone.

import { isPrintableAscii, latin1 } from './bytes.mjs';
import {
  isUuid, isB64_16, isB64_32, isHex64, isMs, isInt, isRole, isHex64n, isOrigin, isName, isEmailB64n,
} from './grammar.mjs';

export const PURPOSE_CODES = {
  'vault-grant': 0x01,
  'escrow-uvk': 0x02,
  'vault-log': 0x03,
  'instance-card': 0x04,
  'account-genesis': 0x05,
  'link-offer': 0x06,
  'link-answer': 0x07,
  'recovery-rotation': 0x08,
  'assisted-recovery': 0x09,
  'recovery-veto': 0x0a,
};
export const PURPOSE_BY_CODE = Object.fromEntries(Object.entries(PURPOSE_CODES).map(([k, v]) => [v, k]));
export const HOST_OFFER_PURPOSES = ['setup-offer', 'enrol-offer'];

export const LOG_KINDS = ['genesis', 'add', 'role', 'remove', 'leave', 'offer', 'cancel', 'accept', 'delete', 'restore'];

const oneOf = (...values) => ({ kind: 'string', check: (v) => typeof v === 'string' && values.includes(v), values });
const T = {
  uuid: { kind: 'string', check: isUuid },
  b64_16: { kind: 'string', check: isB64_16 },
  b64_32: { kind: 'string', check: isB64_32 },
  hex64: { kind: 'string', check: isHex64 },
  hex64n: { kind: 'string', check: isHex64n },
  origin: { kind: 'string', check: isOrigin },
  name: { kind: 'string', check: isName },
  role: { kind: 'string', check: isRole },
  email_b64n: { kind: 'string', check: isEmailB64n },
  ms: { kind: 'number', check: isMs },
  int: { kind: 'number', check: isInt },
};
const typeName = (t) => Object.keys(T).find((k) => T[k] === t) ?? `one of ${t.values.join('|')}`;

const LOG_HEAD = [
  ['vaultId', T.uuid], ['seq', T.int], ['prev', T.hex64], ['kind', oneOf(...LOG_KINDS)], ['actor', T.uuid], ['at', T.ms],
];
const LOG_EXTRA = {
  genesis: [['ownerKey', T.b64_32], ['vkCommit', T.hex64]],
  add: [['member', T.uuid], ['memberKey', T.b64_32], ['role', T.role], ['grantId', T.b64_16]],
  role: [['member', T.uuid], ['role', T.role]],
  remove: [['member', T.uuid]],
  leave: [],
  offer: [['to', T.uuid], ['toKey', T.b64_32], ['offerId', T.b64_16], ['expiresAt', T.ms]],
  cancel: [['offerId', T.b64_16]],
  accept: [['offerId', T.b64_16]],
  delete: [['deleteId', T.b64_16]],
  restore: [['deleteId', T.b64_16]],
};

/** Field lists AFTER the fixed `"v":2,"purpose":…` pair, in template order. */
const FIELDS = {
  'vault-grant': [
    ['from', T.uuid], ['to', T.uuid], ['toKey', T.b64_32], ['vaultId', T.uuid], ['grantId', T.b64_16],
    ['issuedAt', T.ms], ['vk', T.b64_32],
  ],
  'escrow-uvk': [
    ['userId', T.uuid], ['identityKey', T.b64_32], ['recoveryFp', T.hex64], ['issuedAt', T.ms], ['key', T.b64_32],
  ],
  'instance-card': [
    ['instanceId', T.uuid], ['seq', T.int], ['prev', T.hex64], ['origin', T.origin], ['name', T.name],
    ['kind', oneOf('public', 'private')], ['operator', T.uuid], ['operatorSignKey', T.b64_32],
    ['recoveryFp', T.hex64n], ['issuedAt', T.ms],
  ],
  'account-genesis': [
    ['userId', T.uuid], ['identityKey', T.b64_32], ['instanceId', T.uuid], ['personalVaultId', T.uuid],
    ['createdAt', T.ms],
  ],
  'link-offer': [
    ['linkId', T.b64_16], ['kind', oneOf('connect', 'register')], ['origin', T.origin], ['instanceId', T.uuid],
    ['cardHash', T.hex64], ['from', T.uuid], ['fromKey', T.b64_32], ['name', T.name], ['commit', T.hex64],
    ['expiresAt', T.ms], ['issuedAt', T.ms],
  ],
  'link-answer': [
    ['linkId', T.b64_16], ['offerHash', T.hex64], ['to', T.uuid], ['toKey', T.b64_32], ['from', T.uuid],
    ['fromKey', T.b64_32], ['name', T.name], ['nonce', T.b64_32], ['issuedAt', T.ms],
  ],
  'recovery-rotation': [
    ['instanceId', T.uuid], ['fromFp', T.hex64], ['toFp', T.hex64], ['issuedAt', T.ms],
  ],
  'assisted-recovery': [
    ['instanceId', T.uuid], ['userId', T.uuid], ['requestId', T.b64_16], ['requestKey', T.b64_32],
    ['uvk', T.b64_32], ['issuedAt', T.ms],
  ],
  'recovery-veto': [
    ['requestId', T.b64_16], ['userId', T.uuid], ['issuedAt', T.ms],
  ],
  // Host-minted offers (§6.4): canonical JSON with no frame and no signature.
  'setup-offer': [
    ['linkId', T.b64_16], ['origin', T.origin], ['instanceId', T.uuid], ['name', T.name],
    ['kind', oneOf('public', 'private')], ['recoveryFp', T.hex64n], ['expiresAt', T.ms],
  ],
  'enrol-offer': [
    ['linkId', T.b64_16], ['origin', T.origin], ['instanceId', T.uuid], ['cardHash', T.hex64],
    ['email', T.email_b64n], ['expiresAt', T.ms],
  ],
};

/** The ordered field list for a template; a vault-log entry's list depends on its kind. Null if there is none. */
export function fieldsOf(purpose, logKind) {
  if (purpose === 'vault-log') {
    if (!Object.hasOwn(LOG_EXTRA, logKind)) return null;
    return [...LOG_HEAD, ...LOG_EXTRA[logKind]];
  }
  return Object.hasOwn(FIELDS, purpose) ? FIELDS[purpose] : null;
}

/** Template description for the vector files: [[key, type], …] including v and purpose. */
export function describeTemplate(purpose, logKind) {
  return [['v', '2'], ['purpose', JSON.stringify(purpose)], ...fieldsOf(purpose, logKind).map(([k, t]) => [k, typeName(t)])];
}

function encodeValue(type, value) {
  return type.kind === 'number' ? String(value) : '"' + value + '"';
}

function encode(v, purpose, fieldList, values) {
  let s = '{"v":' + String(v) + ',"purpose":"' + purpose + '"';
  for (const [key, type] of fieldList) s += ',"' + key + '":' + encodeValue(type, values[key]);
  return s + '}';
}

/**
 * Build a canonical statement. Throws unless every field is present, known and in its type: a
 * fixture that is meant to be malformed is spliced by hand with `rawStatement`, never built here.
 */
export function buildStatement(purpose, values) {
  const fieldList = fieldsOf(purpose, values.kind);
  if (!fieldList) throw new Error('no template for ' + purpose + ' / ' + values.kind);
  const known = new Set(fieldList.map(([k]) => k));
  for (const k of Object.keys(values)) if (!known.has(k)) throw new Error(`buildStatement(${purpose}): unknown field ${k}`);
  for (const [key, type] of fieldList) {
    if (!Object.hasOwn(values, key)) throw new Error(`buildStatement(${purpose}): missing field ${key}`);
    const value = values[key];
    if (typeof value !== type.kind || !type.check(value)) {
      throw new Error(`buildStatement(${purpose}): field ${key} is not a ${typeName(type)}: ${JSON.stringify(value)}`);
    }
  }
  return encode(2, purpose, fieldList, values);
}

/**
 * Hand-spliced statement text for malformed fixtures: `tokens` is an ordered list of [key, rawToken]
 * written out exactly as given, with no validation at all.
 */
export function rawStatement(tokens) {
  return '{' + tokens.map(([k, raw]) => '"' + k + '":' + raw).join(',') + '}';
}

/** The ordered [key, rawToken] list of a well-formed statement, as a starting point for mutations. */
export function tokensOf(purpose, values) {
  const fieldList = fieldsOf(purpose, values.kind);
  return [['v', '2'], ['purpose', '"' + purpose + '"'], ...fieldList.map(([k, t]) => [k, encodeValue(t, values[k])])];
}

const KNOWN_PURPOSES = (hostOffer) => (hostOffer ? HOST_OFFER_PURPOSES : Object.keys(PURPOSE_CODES));

const ZERO_PREV = '0'.repeat(64);

function sectionRules(purpose, values) {
  // Template rules: what a well-formed statement can still break (spec 01 §5.1 step 6, design §2.4).
  if (purpose === 'vault-grant' && values.from === values.to) return false;
  if (purpose === 'vault-log') {
    // §3.2 (VR-1): a genesis has seq 0 and a zero prev; every other kind has seq >= 1.
    if (values.kind === 'genesis') return values.seq === 0 && values.prev === ZERO_PREV;
    return values.seq >= 1;
  }
  return true;
}

/** §2.2, no nesting: no `[` anywhere, and at most one `{`. Counted on the bytes; nothing is parsed. */
export function isFlat(bytes) {
  let braces = 0;
  for (const b of bytes) {
    if (b === 0x5b) return false;
    if (b === 0x7b && ++braces > 1) return false;
  }
  return true;
}

// ---- implementation 1: spec 01 §5.1 steps 2-6, with the platform JSON parser ----

function parseByJson(expectedPurpose, bytes) {
  const hostOffer = HOST_OFFER_PURPOSES.includes(expectedPurpose);
  if (!isPrintableAscii(bytes)) return { verdict: 'non_canonical' };
  if (!isFlat(bytes)) return { verdict: 'non_canonical' };
  const text = latin1(bytes);
  let obj;
  try {
    obj = JSON.parse(text);
  } catch {
    return { verdict: 'non_canonical' };
  }
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) return { verdict: 'non_canonical' };
  const fieldList = fieldsOf(expectedPurpose, obj.kind);
  if (!fieldList) return { verdict: 'non_canonical' };
  const want = ['v', 'purpose', ...fieldList.map(([k]) => k)];
  const have = Object.keys(obj);
  if (have.length !== want.length || !want.every((k) => Object.hasOwn(obj, k))) return { verdict: 'non_canonical' };
  if (!isInt(obj.v)) return { verdict: 'non_canonical' };
  if (typeof obj.purpose !== 'string' || !KNOWN_PURPOSES(hostOffer).includes(obj.purpose)) return { verdict: 'non_canonical' };
  for (const [key, type] of fieldList) {
    if (typeof obj[key] !== type.kind || !type.check(obj[key])) return { verdict: 'non_canonical' };
  }
  if (encode(obj.v, obj.purpose, fieldList, obj) !== text) return { verdict: 'non_canonical' };
  if (obj.v !== 2 || obj.purpose !== expectedPurpose) return { verdict: 'bad_statement' };
  const values = Object.fromEntries(fieldList.map(([k]) => [k, obj[k]]));
  if (!sectionRules(expectedPurpose, values)) return { verdict: 'bad_statement' };
  return { verdict: 'ok', values };
}

// ---- implementation 2: a byte scanner with no JSON parser ----

function parseByScan(expectedPurpose, bytes) {
  const hostOffer = HOST_OFFER_PURPOSES.includes(expectedPurpose);
  if (!isPrintableAscii(bytes)) return { verdict: 'non_canonical' };
  const text = latin1(bytes);
  let pos = 0;
  const eat = (literal) => {
    if (text.startsWith(literal, pos)) {
      pos += literal.length;
      return true;
    }
    return false;
  };
  const readString = () => {
    // A JSON string with no escapes: the grammar's values never need one.
    if (text[pos] !== '"') return null;
    const end = text.indexOf('"', pos + 1);
    if (end === -1) return null;
    const value = text.slice(pos + 1, end);
    if (value.includes('\\')) return null;
    pos = end + 1;
    return value;
  };
  const readNumber = () => {
    const m = /^(0|[1-9][0-9]*)/.exec(text.slice(pos));
    if (!m) return null;
    const next = text[pos + m[0].length];
    if (next !== ',' && next !== '}') return null;
    const n = Number(m[0]);
    if (!Number.isSafeInteger(n)) return null;
    pos += m[0].length;
    return n;
  };
  const bad = { verdict: 'non_canonical' };

  if (!eat('{"v":')) return bad;
  const v = readNumber();
  if (v === null) return bad;
  if (!eat(',"purpose":')) return bad;
  const purpose = readString();
  if (purpose === null || !KNOWN_PURPOSES(hostOffer).includes(purpose)) return bad;

  // A vault-log entry's field list hangs on its kind, the fourth field of the head.
  let fieldList;
  if (expectedPurpose === 'vault-log') {
    const m = /^,"vaultId":"[^"]*","seq":[0-9]+,"prev":"[^"]*","kind":"([^"]*)"/.exec(text.slice(pos));
    if (!m) return bad;
    fieldList = fieldsOf('vault-log', m[1]);
  } else {
    fieldList = fieldsOf(expectedPurpose);
  }
  if (!fieldList) return bad;

  const values = {};
  for (const [key, type] of fieldList) {
    if (!eat(',"' + key + '":')) return bad;
    const value = type.kind === 'number' ? readNumber() : readString();
    if (value === null || !type.check(value)) return bad;
    values[key] = value;
  }
  if (!eat('}') || pos !== text.length) return bad;
  if (v !== 2 || purpose !== expectedPurpose) return { verdict: 'bad_statement' };
  if (!sectionRules(expectedPurpose, values)) return { verdict: 'bad_statement' };
  return { verdict: 'ok', values };
}

/**
 * Strict parse of statement bytes against the template of `expectedPurpose` (a purpose literal, or
 * `setup-offer` / `enrol-offer` for the host-minted offers of §6.4).
 * Returns { verdict: 'ok', values } or { verdict: 'non_canonical' | 'bad_statement' }.
 */
export function parseStatement(expectedPurpose, bytes) {
  const a = parseByJson(expectedPurpose, bytes);
  const b = parseByScan(expectedPurpose, bytes);
  if (a.verdict !== b.verdict || JSON.stringify(a.values) !== JSON.stringify(b.values)) {
    throw new Error(`oracle parsers disagree (${a.verdict} vs ${b.verdict}) on: ${latin1(bytes)}`);
  }
  return a;
}
