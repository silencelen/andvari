// Statements with more than one template: the version-3 templates of 0x02 (escrow-uvk) and 0x09
// (assisted-recovery) beside their version-2 ones (spec 01 §5.1 "Version-3 templates",
// 2026-11-16). Written from the specification text of 2026-11-16 alone, before that day's
// corrections.
//
// "Which templates a reader accepts is the owning section's rule ... Steps 2 to 5 below match a
// statement against the template its reader tries; a statement that matches none of them is
// non_canonical." A reader here is { tries, accepts }:
//   tries    the template versions steps 2 to 5 are matched against (the key set picks one: no two
//            templates of one purpose share a key set);
//   accepts  the versions step 6 lets through. A statement canonical under a template the reader
//            tries but does not accept is bad_statement: that is how "a statement canonical under the
//            version-2 template is bad_statement there" (the device's opener of an answer) is read.
//
// As in statement.mjs the parse is implemented twice (the platform JSON parser, and a byte scanner
// with no parser) and the two must agree on every input, or the oracle throws.

import { isPrintableAscii, latin1, utf8 } from './bytes.mjs';
import { isUuid, isB64_16, isB64_32, isHex64, isMs, isInt, isEmailB64 } from './grammar.mjs';
import { isFlat, PURPOSE_CODES } from './statement.mjs';
import { splitFrame, signFrame, frameHash } from './frame.mjs';

const str = (name, check) => ({ name, kind: 'string', check });
const num = (name, check) => ({ name, kind: 'number', check });
const T = {
  uuid: str('uuid', isUuid),
  b64_16: str('b64_16', isB64_16),
  b64_32: str('b64_32', isB64_32),
  hex64: str('hex64', isHex64),
  email_b64: str('email_b64', isEmailB64),
  ms: num('ms', isMs),
};

/** Field lists after the fixed `"v":N,"purpose":…` pair, per purpose and version, in template order. */
export const TEMPLATES = {
  'escrow-uvk': {
    2: [['userId', T.uuid], ['identityKey', T.b64_32], ['recoveryFp', T.hex64], ['issuedAt', T.ms], ['key', T.b64_32]],
    3: [['userId', T.uuid], ['email', T.email_b64], ['identityKey', T.b64_32], ['recoveryFp', T.hex64], ['issuedAt', T.ms], ['key', T.b64_32]],
  },
  'assisted-recovery': {
    2: [['instanceId', T.uuid], ['userId', T.uuid], ['requestId', T.b64_16], ['requestKey', T.b64_32], ['uvk', T.b64_32], ['issuedAt', T.ms]],
    3: [
      ['instanceId', T.uuid], ['userId', T.uuid], ['email', T.email_b64], ['requestId', T.b64_16], ['requestKey', T.b64_32],
      ['commit', T.b64_32], ['uvk', T.b64_32], ['issuedAt', T.ms],
    ],
  },
};

/** spec 04 §4 step 5: the opener of a recovery copy accepts both templates of 0x02, each under its own v. */
export const COPY_READER = { purpose: 'escrow-uvk', tries: [3, 2], accepts: [3, 2] };
/** spec 04 §7 step 4: the device takes only the version-3 template of 0x09; a version-2 one is bad_statement. */
export const ANSWER_READER = { purpose: 'assisted-recovery', tries: [3, 2], accepts: [3] };

export function describeTemplate(purpose, v) {
  return [['v', String(v)], ['purpose', JSON.stringify(purpose)], ...TEMPLATES[purpose][v].map(([k, t]) => [k, t.name])];
}

const encodeValue = (type, value) => (type.kind === 'number' ? String(value) : '"' + value + '"');

function encode(v, purpose, fields, values) {
  let s = '{"v":' + String(v) + ',"purpose":"' + purpose + '"';
  for (const [key, type] of fields) s += ',"' + key + '":' + encodeValue(type, values[key]);
  return s + '}';
}

/** A canonical statement of `purpose` under template `v`; throws unless every field is present and in its type. */
export function buildStatementV(purpose, v, values) {
  const fields = TEMPLATES[purpose]?.[v];
  if (!fields) throw new Error(`no template ${purpose} v${v}`);
  const known = new Set(fields.map(([k]) => k));
  for (const k of Object.keys(values)) if (!known.has(k)) throw new Error(`buildStatementV(${purpose} v${v}): unknown field ${k}`);
  for (const [key, type] of fields) {
    if (!Object.hasOwn(values, key)) throw new Error(`buildStatementV(${purpose} v${v}): missing field ${key}`);
    if (typeof values[key] !== type.kind || !type.check(values[key])) {
      throw new Error(`buildStatementV(${purpose} v${v}): field ${key} is not a ${type.name}: ${JSON.stringify(values[key])}`);
    }
  }
  return encode(v, purpose, fields, values);
}

/** The ordered [key, rawToken] list of a canonical statement, for hand mutation (rawStatement in build.mjs writes it out). */
export function tokensOfV(purpose, v, values) {
  return [['v', String(v)], ['purpose', '"' + purpose + '"'], ...TEMPLATES[purpose][v].map(([k, t]) => [k, encodeValue(t, values[k])])];
}

const KNOWN_PURPOSES = Object.keys(PURPOSE_CODES);

function finish(reader, version, v, purpose, fields, values) {
  if (v !== version || purpose !== reader.purpose) return { verdict: 'bad_statement' };
  if (!reader.accepts.includes(version)) return { verdict: 'bad_statement' };
  return { verdict: 'ok', version, values: Object.fromEntries(fields.map(([k]) => [k, values[k]])) };
}

function parseByJson(reader, bytes) {
  if (!isPrintableAscii(bytes) || !isFlat(bytes)) return { verdict: 'non_canonical' };
  const text = latin1(bytes);
  let obj;
  try {
    obj = JSON.parse(text);
  } catch {
    return { verdict: 'non_canonical' };
  }
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) return { verdict: 'non_canonical' };
  const have = Object.keys(obj);
  let version = null;
  for (const t of reader.tries) {
    const want = ['v', 'purpose', ...TEMPLATES[reader.purpose][t].map(([k]) => k)];
    if (have.length === want.length && want.every((k) => Object.hasOwn(obj, k))) version = t;
  }
  if (version === null) return { verdict: 'non_canonical' };
  const fields = TEMPLATES[reader.purpose][version];
  if (!isInt(obj.v)) return { verdict: 'non_canonical' };
  if (typeof obj.purpose !== 'string' || !KNOWN_PURPOSES.includes(obj.purpose)) return { verdict: 'non_canonical' };
  for (const [key, type] of fields) if (typeof obj[key] !== type.kind || !type.check(obj[key])) return { verdict: 'non_canonical' };
  if (encode(obj.v, obj.purpose, fields, obj) !== text) return { verdict: 'non_canonical' };
  return finish(reader, version, obj.v, obj.purpose, fields, obj);
}

function scanAs(text, fields) {
  let pos = 0;
  const eat = (literal) => {
    if (!text.startsWith(literal, pos)) return false;
    pos += literal.length;
    return true;
  };
  const readString = () => {
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
  if (!eat('{"v":')) return null;
  const v = readNumber();
  if (v === null || !eat(',"purpose":')) return null;
  const purpose = readString();
  if (purpose === null || !KNOWN_PURPOSES.includes(purpose)) return null;
  const values = {};
  for (const [key, type] of fields) {
    if (!eat(',"' + key + '":')) return null;
    const value = type.kind === 'number' ? readNumber() : readString();
    if (value === null || !type.check(value)) return null;
    values[key] = value;
  }
  if (!eat('}') || pos !== text.length) return null;
  return { v, purpose, values };
}

function parseByScan(reader, bytes) {
  if (!isPrintableAscii(bytes)) return { verdict: 'non_canonical' };
  const text = latin1(bytes);
  for (const t of reader.tries) {
    const fields = TEMPLATES[reader.purpose][t];
    const got = scanAs(text, fields);
    if (got) return finish(reader, t, got.v, got.purpose, fields, got.values);
  }
  return { verdict: 'non_canonical' };
}

/** Strict parse of statement bytes for `reader`: { verdict: 'ok', version, values } or non_canonical / bad_statement. */
export function parseStatementV(reader, bytes) {
  const a = parseByJson(reader, bytes);
  const b = parseByScan(reader, bytes);
  if (a.verdict !== b.verdict || a.version !== b.version || JSON.stringify(a.values) !== JSON.stringify(b.values)) {
    throw new Error(`versioned parsers disagree (${a.verdict} v${a.version} vs ${b.verdict} v${b.version}) on: ${latin1(bytes)}`);
  }
  return a;
}

/** spec 01 §5.1 step 1 (the frame, the expected purpose), then the strict parse for `reader`. */
export function parseFrameV(frame, reader) {
  const parts = splitFrame(frame, PURPOSE_CODES[reader.purpose]);
  if (parts.verdict !== 'ok') return parts;
  const parsed = parseStatementV(reader, parts.statementBytes);
  if (parsed.verdict !== 'ok') return { verdict: parsed.verdict };
  return { ...parts, version: parsed.version, values: parsed.values };
}

/** Build, sign and frame a canonical statement under template `v` with the joint key of `signer`. */
export function signedV(purpose, v, signer, values) {
  const statement = buildStatementV(purpose, v, values);
  const made = signFrame(PURPOSE_CODES[purpose], signer.seed, statement);
  return { purpose, v, signer, values, statement, statementBytes: utf8(statement), frame: made.frame, hash: frameHash(made.frame), signerPub: made.signerPub, signature: made.signature, message: made.message };
}
