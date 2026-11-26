// Construction helpers shared by the vector files. Builders only: every verdict in a vector file
// comes from a verifier module (statement.mjs, frame.mjs, vaultlog.mjs, …), never from here.

import { b64u, utf8, hex } from './bytes.mjs';
import { buildStatement, tokensOf, rawStatement, PURPOSE_CODES } from './statement.mjs';
import { signFrame, frameHash, assembleFrame } from './frame.mjs';
import { ZERO_HASH } from './vaultlog.mjs';

/** Build, sign and frame a canonical statement of `purpose` with the joint key of `signer` (an account or a recovery key). */
export function signed(purpose, signer, values) {
  const statement = buildStatement(purpose, values);
  const purposeCode = PURPOSE_CODES[purpose];
  const made = signFrame(purposeCode, signer.seed, statement);
  return {
    purpose,
    purposeCode,
    signer,
    values,
    statement,
    frame: made.frame,
    hash: frameHash(made.frame),
    signerPub: made.signerPub,
    signature: made.signature,
    message: made.message,
  };
}

/** Sign arbitrary statement text (well-formed or not) under a purpose code. */
export function signedRaw(purposeCode, signer, statementText) {
  const made = signFrame(purposeCode, signer.seed, statementText);
  return { purposeCode, signer, statement: statementText, frame: made.frame, hash: frameHash(made.frame), signerPub: made.signerPub, signature: made.signature };
}

/** The description of a signed frame that valid rows carry. */
export function describeSigned(s) {
  return {
    purposeCode: s.purposeCode,
    purpose: s.purpose,
    signer: s.signer.name,
    fields: s.values,
    statementUtf8: s.statement,
    messageHex: hex(s.message),
    signatureB64: b64u(s.signature),
    frameB64: b64u(s.frame),
    frameHash: s.hash,
  };
}

/** Ordered [key, rawToken] pairs of a well-formed statement, for hand mutation. */
export function tokens(purpose, values) {
  return tokensOf(purpose, values);
}

export const withToken = (list, key, raw) => list.map(([k, v]) => (k === key ? [k, raw] : [k, v]));
export const withoutKey = (list, key) => list.filter(([k]) => k !== key);
export const renameKey = (list, key, to) => list.map(([k, v]) => (k === key ? [to, v] : [k, v]));
export function insertAfter(list, key, pair) {
  const out = [];
  for (const item of list) {
    out.push(item);
    if (item[0] === key) out.push(pair);
  }
  return out;
}
export function swapKeys(list, a, b) {
  const ia = list.findIndex(([k]) => k === a);
  const ib = list.findIndex(([k]) => k === b);
  const out = list.slice();
  [out[ia], out[ib]] = [out[ib], out[ia]];
  return out;
}
export { rawStatement, assembleFrame };

export const quote = (s) => '"' + s + '"';
export const nameOf = (text) => b64u(utf8(text));

/**
 * Builds a vault log entry by entry. `append` adds a signed entry to the chain; `draft` returns the
 * entry that would come next without adding it, with any field overridden, for rejection rows.
 */
export class LogBuilder {
  constructor(vaultId) {
    this.vaultId = vaultId;
    this.entries = [];
  }

  get head() {
    const last = this.entries[this.entries.length - 1];
    return last ? { seq: last.values.seq, hash: last.hash, at: last.values.at } : null;
  }

  /** Statement values for the next position. `fields` holds kind, actor, at and the kind's own fields. */
  nextValues(fields, overrides = {}) {
    const head = this.head;
    return {
      vaultId: this.vaultId,
      seq: head ? head.seq + 1 : 0,
      prev: head ? head.hash : ZERO_HASH,
      ...fields,
      ...overrides,
    };
  }

  draft(signer, fields, overrides = {}) {
    const ordered = orderLogFields(this.nextValues(fields, overrides));
    return signed('vault-log', signer, ordered);
  }

  append(signer, fields) {
    const entry = this.draft(signer, fields);
    this.entries.push(entry);
    return entry;
  }

  /** A copy holding the first `count` entries. */
  prefix(count) {
    const copy = new LogBuilder(this.vaultId);
    copy.entries = this.entries.slice(0, count);
    return copy;
  }

  get frames() {
    return this.entries.map((e) => e.frame);
  }
}

const LOG_ORDER = [
  'vaultId', 'seq', 'prev', 'kind', 'actor', 'at',
  'ownerKey', 'vkCommit', 'member', 'memberKey', 'role', 'grantId', 'to', 'toKey', 'offerId', 'expiresAt', 'deleteId',
];
/** Put log fields in template order so `fields` reads like the statement. */
export function orderLogFields(values) {
  const out = {};
  for (const k of LOG_ORDER) if (Object.hasOwn(values, k)) out[k] = values[k];
  for (const k of Object.keys(values)) if (!Object.hasOwn(out, k)) out[k] = values[k];
  return out;
}
