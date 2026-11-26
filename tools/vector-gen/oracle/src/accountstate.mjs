// The UVK-sealed account state (design §5.4, spec 02 §9): the document, the decode that drops a
// bad record and refuses a foreign document, the merge of each record, and the acceptance answer.
//
// Where the two texts leave something open this module throws, so no vector row can rest on it.

import { isUuid, isB64_32, isHex64, isHex64n, isMs, isInt, isName } from './grammar.mjs';

class Undefined extends Error {}

export const accountStateAd = (userId) => `andvari/v1|account-state|${userId}`;

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
// A record must hold every field of its shape, each of its type. A field this build does not know
// is no fault: the record is kept and the field preserved as written.
const hasAll = (obj, keys) => isPlainObject(obj) && keys.every((k) => Object.hasOwn(obj, k));
const sortKeys = (map) => Object.fromEntries(Object.keys(map).sort().map((k) => [k, map[k]]));

const CONTACT_KEYS = ['userId', 'identityPub', 'label', 'method', 'verifiedAt', 'compared', 'madeOn'];
const contactOk = (key, c) => hasAll(c, CONTACT_KEYS) && isUuid(key) && c.userId === key && isB64_32(c.identityPub) && isName(c.label)
  && c.method === 'link' && isMs(c.verifiedAt) && typeof c.compared === 'boolean' && isUuid(c.madeOn);
const vaultOk = (key, r) => isUuid(key) && hasAll(r, ['genesisHash', 'seq', 'hash']) && isHex64(r.genesisHash) && isInt(r.seq) && isHex64(r.hash);
const acceptedOk = (key, r) => isUuid(key) && hasAll(r, ['owner', 'addSeq', 'at', 'decision']) && isUuid(r.owner) && isInt(r.addSeq) && isMs(r.at)
  && (r.decision === 'accept' || r.decision === 'decline');
const recoveryOk = (r) => hasAll(r, ['posture', 'fp', 'at']) && (r.posture === 'private' || r.posture === 'operator') && isHex64n(r.fp) && isMs(r.at);
const tombstoneOk = (key, at) => isUuid(key) && isMs(at);

const KNOWN = ['v', 'userId', 'seq', 'contacts', 'contactTombstones', 'vaults', 'accepted', 'recovery'];

/**
 * Decode the sealed plaintext for the account `userId`.
 * A document with another `v`, another account's userId, or a seq that is not an int is refused
 * whole. A document that lacks one of the four maps is read as having that map empty. A single
 * record that fails its own shape is dropped and counted, and the rest is used. Unknown top-level
 * keys are kept, and so is a field a record carries that this build does not know.
 * Returns { refused: true } or { refused: false, dropped, doc }.
 */
export function decodeAccountState(text, userId) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { refused: true };
  }
  if (!isPlainObject(parsed) || parsed.v !== 2 || parsed.userId !== userId) return { refused: true };
  if (!isInt(parsed.seq)) return { refused: true };
  const obj = { ...parsed };
  for (const k of ['contacts', 'contactTombstones', 'vaults', 'accepted']) {
    if (!Object.hasOwn(obj, k)) obj[k] = {};
    else if (!isPlainObject(obj[k])) throw new Undefined(`a document whose ${k} is present and is not an object`);
  }
  let dropped = 0;
  const keep = (map, ok) => {
    const out = {};
    for (const [key, value] of Object.entries(map)) {
      if (ok(key, value)) out[key] = value;
      else dropped++;
    }
    return sortKeys(out);
  };
  const doc = {
    v: 2,
    userId: obj.userId,
    seq: obj.seq,
    contacts: keep(obj.contacts, contactOk),
    contactTombstones: keep(obj.contactTombstones, tombstoneOk),
    vaults: keep(obj.vaults, vaultOk),
    accepted: keep(obj.accepted, acceptedOk),
  };
  if (Object.hasOwn(obj, 'recovery')) {
    if (recoveryOk(obj.recovery)) doc.recovery = obj.recovery;
    else dropped++;
  }
  for (const k of Object.keys(obj)) if (!KNOWN.includes(k)) doc[k] = obj[k];
  return { refused: false, dropped, doc };
}

// Ties are compared on the field's text exactly as stored, byte by byte (a label is its base64url
// string). Every such field is ASCII, so JavaScript's string order is the byte order.

function mergeContact(a, b, out) {
  if (a.identityPub !== b.identityPub) {
    // Never merged silently: the record with the key this device already uses stays, and the other
    // goes to the key-change prompt.
    out.keyChange.push({ userId: b.userId, identityPub: b.identityPub });
    return a;
  }
  let winner;
  if (a.verifiedAt !== b.verifiedAt) winner = a.verifiedAt > b.verifiedAt ? a : b;
  else if (a.label !== b.label) winner = a.label > b.label ? a : b; // the larger label, as stored
  else winner = a.madeOn >= b.madeOn ? a : b;
  return { ...winner, compared: a.compared || b.compared };
}

function mergeVault(vaultId, a, b, out) {
  if (a.genesisHash !== b.genesisHash) {
    out.genesisAnomalies.push(vaultId);
    return a;
  }
  if (a.seq !== b.seq) return a.seq > b.seq ? a : b;
  // The same seq with another hash is a fork: the local record stays and the fork is reported.
  if (a.hash !== b.hash) out.forks.push(vaultId);
  return a;
}

function mergeAccepted(a, b) {
  if (a.addSeq !== b.addSeq) return a.addSeq > b.addSeq ? a : b;
  // For the same addSeq, decline wins whatever `at` says: a leave is final for that add.
  if (a.decision !== b.decision) return a.decision === 'decline' ? a : b;
  if (a.at !== b.at) return a.at > b.at ? a : b;
  return a.owner >= b.owner ? a : b;
}

function mergeRecovery(a, b) {
  if (a.at !== b.at) return a.at > b.at ? a : b;
  if (a.posture !== b.posture) return a.posture === 'private' ? a : b;
  return a.fp <= b.fp ? a : b; // the smaller fp, as stored ("none" sorts after every fingerprint)
}

function mergeMap(a, b, both) {
  const out = {};
  for (const key of new Set([...Object.keys(a), ...Object.keys(b)])) {
    if (Object.hasOwn(a, key) && Object.hasOwn(b, key)) out[key] = both(key, a[key], b[key]);
    else out[key] = Object.hasOwn(a, key) ? a[key] : b[key];
  }
  return sortKeys(out);
}

/** The limits of §5.4. A merge takes them as an input, so the cap rules can be graded on small documents. */
export const LIMITS = { contacts: 1000, tombstones: 1000, sealedChars: 1048576 };

/**
 * The length of the sealed state as it is sent: unpadded base64url of the envelope (2 + 24 bytes of
 * header and nonce, the compact JSON document, 16 bytes of tag).
 */
export function sealedChars(doc) {
  const bytes = new TextEncoder().encode(JSON.stringify(doc)).length + 42;
  return Math.ceil((bytes * 4) / 3);
}

const NEAR = 0.1; // a size decision closer than this to the limit is not graded

function over(doc, limit) {
  const size = sealedChars(doc);
  if (Math.abs(size - limit) < NEAR * limit) throw new Undefined('a document within 10% of its size limit: the exact serialization would decide');
  return size > limit;
}

/** Keep the `cap` newest entries of a map (by `time`), and among equals the smaller userId. */
function capNewest(map, cap, time) {
  const ids = Object.keys(map);
  if (ids.length <= cap) return { kept: map, dropped: [] };
  ids.sort((x, y) => (time(map[y]) - time(map[x])) || (x < y ? -1 : 1));
  const keep = ids.slice(0, cap);
  return { kept: sortKeys(Object.fromEntries(keep.map((id) => [id, map[id]]))), dropped: ids.slice(cap) };
}

/**
 * Merge this device's copy with a served one. `local` and `served` are decoded documents or null;
 * `highWater` is this device's high-water mark of the IN-BLOB seq; `limits` are §5.4's caps.
 *
 * Two documents are merged record by record whatever their seq values, a rolled-back served copy
 * included; the result's seq is the larger of the two. An unknown key present in both stays as the
 * copy with the larger seq has it, and as the local copy has it when the two are equal. At the caps
 * the newest are kept. A merged document over its size limit drops unknown keys first, the largest
 * first, then the vaults and accepted records of vaults the account has left, the oldest first;
 * recovery is never dropped.
 * Returns { doc, rollback, keyChange, genesisAnomalies, forks }, with notWritten =
 * 'account_state_full' or 'account_state_damaged' when the merged document may only be read.
 */
export function mergeAccountState(local, served, highWater, limits = LIMITS) {
  const out = { rollback: false, keyChange: [], genesisAnomalies: [], forks: [] };
  out.rollback = served === null ? highWater > 0 : served.seq < highWater;
  if (local === null && served === null) throw new Undefined('no local copy and nothing served');
  const empty = { seq: 0, contacts: {}, contactTombstones: {}, vaults: {}, accepted: {} };
  const a = local ?? { ...empty };
  const b = served ?? { ...empty };
  const seq = Math.max(a.seq, b.seq);
  if (highWater > seq) throw new Undefined('a high-water mark above both documents');

  const allTombstones = mergeMap(a.contactTombstones, b.contactTombstones, (_k, x, y) => Math.max(x, y));
  const merged = mergeMap(a.contacts, b.contacts, (_k, x, y) => mergeContact(x, y, out));
  // A tombstone not older than a pin removes it.
  for (const [userId, c] of Object.entries(merged)) {
    if (Object.hasOwn(allTombstones, userId) && allTombstones[userId] >= c.verifiedAt) delete merged[userId];
  }
  // The caps come after that: a tombstone the cap then drops has still removed its contact in this merge.
  const contacts = capNewest(merged, limits.contacts, (c) => c.verifiedAt);
  const tombstones = capNewest(allTombstones, limits.tombstones, (removedAt) => removedAt);

  const doc = {
    v: 2,
    userId: (local ?? served).userId,
    seq,
    contacts: contacts.kept,
    contactTombstones: tombstones.kept,
    vaults: mergeMap(a.vaults, b.vaults, (k, x, y) => mergeVault(k, x, y, out)),
    accepted: mergeMap(a.accepted, b.accepted, (_k, x, y) => mergeAccepted(x, y)),
  };
  const ra = local?.recovery;
  const rb = served?.recovery;
  if (ra && rb) doc.recovery = mergeRecovery(ra, rb);
  else if (ra || rb) doc.recovery = ra ?? rb;

  // Unknown keys: kept; one present in both stays as the copy with the larger seq has it, and as the
  // local copy has it when the two seqs are equal.
  const unknown = {};
  for (const k of Object.keys(b)) if (!KNOWN.includes(k)) unknown[k] = b[k];
  for (const k of Object.keys(a)) {
    if (KNOWN.includes(k)) continue;
    if (!Object.hasOwn(unknown, k) || a.seq >= b.seq) unknown[k] = a[k];
  }
  for (const k of Object.keys(unknown).sort()) doc[k] = unknown[k];

  // The size limit. Unknown keys go first, the largest first.
  const sizeOf = (k) => JSON.stringify(k).length + 1 + JSON.stringify(doc[k]).length;
  while (over(doc, limits.sealedChars)) {
    const keys = Object.keys(doc).filter((k) => !KNOWN.includes(k)).sort((x, y) => sizeOf(y) - sizeOf(x));
    if (keys.length === 0) break;
    if (keys.length > 1 && sizeOf(keys[1]) > 0.8 * sizeOf(keys[0])) throw new Undefined('two unknown keys of nearly the same size: which is the largest depends on the measure');
    delete doc[keys[0]];
  }
  // Then the vaults and accepted records of vaults the account has left, the oldest first. "Left"
  // means accepted[vaultId].decision = decline; "oldest" is the smallest at of that record, then the
  // smaller vaultId.
  let dropped = Object.keys(unknown).some((k) => !Object.hasOwn(doc, k));
  let full = false;
  while (over(doc, limits.sealedChars)) {
    const left = Object.keys(doc.accepted).filter((v) => doc.accepted[v].decision === 'decline')
      .sort((x, y) => (doc.accepted[x].at - doc.accepted[y].at) || (x < y ? -1 : 1));
    if (left.length === 0) {
      full = true;
      break;
    }
    delete doc.accepted[left[0]];
    delete doc.vaults[left[0]];
    dropped = true;
  }
  // A document that still does not fit after every drop is not written (account_state_full), and one
  // whose seq cannot be advanced is not written either (account_state_damaged). The merged document
  // is still used for reading.
  const damaged = seq >= Number.MAX_SAFE_INTEGER;
  if (full && dropped) throw new Undefined('a document that does not fit even after drops: whether it is read with or without them is not stated');
  if (full && damaged) throw new Undefined('a document that is both full and damaged');
  if (full) return { doc, ...out, notWritten: 'account_state_full' };
  if (damaged) return { doc, ...out, notWritten: 'account_state_damaged' };
  return { doc, ...out };
}

/**
 * §3.6 (d), VR-16: an accepted record against the account's latest add in the verified log.
 * A record answers only the add whose seq it names; anything else answers nothing and the person is
 * asked.
 */
export function acceptance(record, latestAddSeq) {
  if (!Number.isInteger(latestAddSeq)) throw new Undefined('acceptance for an account the log never added');
  if (record === null || record.addSeq !== latestAddSeq) return 'ask';
  return record.decision;
}

/** The extension reads `decision` only (FN-1): it opens a wrap of the vault only on accept. */
export const extensionAccepts = (record) => record !== null && record.decision === 'accept';
