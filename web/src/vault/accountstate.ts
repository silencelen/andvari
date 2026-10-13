import { fromB64 } from "../crypto/bytes";

/**
 * The account-state document (security review 2026-10, root cause A §4.2) — twin of core
 * `AccountState.kt`. Sealed as `Envelope(UVK, JSON, adAccountState(userId))`, so the server can withhold
 * or roll it back but never add to it. The merge is pinned by `spec/test-vectors/accountstate.json`.
 */

export type ContactMethod = "qr" | "typed" | "enrol";
export const CONTACT_METHODS: readonly ContactMethod[] = ["qr", "typed", "enrol"];

/** A household member this account VERIFIED (a human compared a fingerprint). Pairwise only (Q4). */
export interface Contact {
  userId: string;
  /** base64url of the pinned 32-byte X25519 identity key. */
  identityPub: string;
  /** Cosmetic: the key, not the label, is what was verified. */
  label: string;
  verifiedAt: number;
  method: ContactMethod;
}

/** One consumed lifecycle nonce, wire form `["<nonce>", <issuedAt>]`. */
export type ConsumedNonce = [string, number];

/**
 * One vault grant THIS account signed (security review 2026-10, root cause A, branch A6b; core `IssuedGrant` twin):
 * the (vault, member) pair and hex SHA-256 of the identity key it was sealed to. A re-issue to a recorded pair, for
 * the SAME key, needs no prompt; anything else needs a human on the device to confirm it.
 */
export interface IssuedGrant {
  vaultId: string;
  userId: string;
  keyHash: string;
  at: number;
}

export interface AccountStateDoc {
  v: 1;
  userId: string;
  seq: number;
  contacts: Contact[];
  contactTombstones: Record<string, number>;
  orgRecoveryFp: string | null;
  consumedNonces: Record<string, ConsumedNonce[]>;
  /** A6b: every grant this account signed from A6b on. */
  issuedGrants: IssuedGrant[];
  /** A6b: `"<vaultId>|<userId>"` → ms; written when the owner removes the member. */
  issuedTombstones: Record<string, number>;
  /** A6b: vaults this account OWNS by its own evidence (created, accepted by transfer, or confirmed with a password
   *  reauth), vaultId → ms. The server's `role=owner` label is never an input. */
  ownedVaults: Record<string, number>;
  /** A6b: vaultId → ms; written when the account transfers the vault away or leaves it. */
  ownedTombstones: Record<string, number>;
}

export class AccountStateError extends Error {}

export const ACCOUNT_STATE_VERSION = 1;
export const NONCE_CAP = 256;
export const ACCOUNT_STATE_SEALED_MAX = 65536;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const DOC_KEYS = ["v", "userId", "seq", "contacts", "contactTombstones", "orgRecoveryFp", "consumedNonces", "issuedGrants", "issuedTombstones", "ownedVaults", "ownedTombstones"];
const CONTACT_KEYS = ["userId", "identityPub", "label", "verifiedAt", "method"];
const ISSUED_KEYS = ["vaultId", "userId", "keyHash", "at"];

export function emptyAccountState(userId: string): AccountStateDoc {
  return { v: 1, userId, seq: 0, contacts: [], contactTombstones: {}, orgRecoveryFp: null, consumedNonces: {}, issuedGrants: [], issuedTombstones: {}, ownedVaults: {}, ownedTombstones: {} };
}

/** The tombstone key for an issued grant. */
export const pairKey = (vaultId: string, userId: string): string => `${vaultId}|${userId}`;

const byPair = (a: IssuedGrant, b: IssuedGrant): number =>
  a.vaultId < b.vaultId ? -1 : a.vaultId > b.vaultId ? 1 : a.userId < b.userId ? -1 : a.userId > b.userId ? 1 : 0;

/** The issued-grant record for (vaultId, userId), when one is in force (core `AccountStateDoc.issued`). */
export function issuedFor(doc: AccountStateDoc, vaultId: string, userId: string): IssuedGrant | null {
  const g = doc.issuedGrants.find((x) => x.vaultId === vaultId && x.userId === userId);
  return g && g.at > (doc.issuedTombstones[pairKey(vaultId, userId)] ?? -1) ? g : null;
}

/** True when this account's own evidence says it owns `vaultId` (core `AccountStateDoc.owns`). */
export function ownsVault(doc: AccountStateDoc, vaultId: string): boolean {
  const at = doc.ownedVaults[vaultId];
  return at !== undefined && at > (doc.ownedTombstones[vaultId] ?? -1);
}

/** True when there is nothing in the document worth writing. */
export function isBlankAccountState(doc: AccountStateDoc): boolean {
  return doc.contacts.length === 0 && Object.keys(doc.consumedNonces).length === 0 && doc.orgRecoveryFp === null &&
    doc.issuedGrants.length === 0 && Object.keys(doc.issuedTombstones).length === 0 &&
    Object.keys(doc.ownedVaults).length === 0 && Object.keys(doc.ownedTombstones).length === 0;
}

/** Deterministic encoding: fixed key order, contacts by userId, sorted maps. */
export function encodeAccountState(doc: AccountStateDoc): string {
  const sortedRecord = <T>(r: Record<string, T>): Record<string, T> =>
    Object.fromEntries(Object.keys(r).sort().map((k) => [k, r[k]!]));
  return JSON.stringify({
    v: doc.v,
    userId: doc.userId,
    seq: doc.seq,
    contacts: [...doc.contacts]
      .sort((a, b) => (a.userId < b.userId ? -1 : a.userId > b.userId ? 1 : 0))
      .map((c) => ({ userId: c.userId, identityPub: c.identityPub, label: c.label, verifiedAt: c.verifiedAt, method: c.method })),
    contactTombstones: sortedRecord(doc.contactTombstones),
    orgRecoveryFp: doc.orgRecoveryFp,
    consumedNonces: sortedRecord(doc.consumedNonces),
    issuedGrants: [...doc.issuedGrants].sort(byPair).map((g) => ({ vaultId: g.vaultId, userId: g.userId, keyHash: g.keyHash, at: g.at })),
    issuedTombstones: sortedRecord(doc.issuedTombstones),
    ownedVaults: sortedRecord(doc.ownedVaults),
    ownedTombstones: sortedRecord(doc.ownedTombstones),
  });
}

function intRecord(raw: unknown, what: string): Record<string, number> {
  const r = (raw ?? {}) as Record<string, unknown>;
  if (typeof r !== "object" || Array.isArray(r)) throw new AccountStateError(`${what} is not an object`);
  const out: Record<string, number> = {};
  for (const [k, t] of Object.entries(r)) {
    if (!isInt(t)) throw new AccountStateError(`${what} entry is not an integer`);
    out[k] = t;
  }
  return out;
}

const isInt = (n: unknown): n is number => typeof n === "number" && Number.isSafeInteger(n);

/**
 * Strict decode of an OPENED blob (core `AccountState.decode` twin): a v1 document for `userId`, known keys
 * only, well-formed contacts. Throws {@link AccountStateError} otherwise.
 */
export function decodeAccountState(userId: string, plaintext: string): AccountStateDoc {
  let raw: unknown;
  try {
    raw = JSON.parse(plaintext);
  } catch {
    throw new AccountStateError("account state is not JSON");
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new AccountStateError("account state is not an object");
  const o = raw as Record<string, unknown>;
  for (const k of Object.keys(o)) if (!DOC_KEYS.includes(k)) throw new AccountStateError(`unknown key ${k}`);
  if (o.v !== ACCOUNT_STATE_VERSION) throw new AccountStateError(`account state version ${String(o.v)} is not supported`);
  if (o.userId !== userId) throw new AccountStateError("account state belongs to another user");
  if (!isInt(o.seq) || o.seq < 0) throw new AccountStateError("account state seq is invalid");
  const contacts: Contact[] = [];
  for (const c of (o.contacts ?? []) as unknown[]) {
    if (!c || typeof c !== "object" || Array.isArray(c)) throw new AccountStateError("contact is not an object");
    const r = c as Record<string, unknown>;
    for (const k of Object.keys(r)) if (!CONTACT_KEYS.includes(k)) throw new AccountStateError(`unknown contact key ${k}`);
    if (typeof r.userId !== "string" || !UUID_RE.test(r.userId)) throw new AccountStateError("contact userId is not a uuid");
    let key: Uint8Array | null = null;
    try {
      key = typeof r.identityPub === "string" ? fromB64(r.identityPub) : null;
    } catch {
      key = null;
    }
    if (!key || key.length !== 32) throw new AccountStateError("contact key is not 32 bytes");
    if (typeof r.label !== "string") throw new AccountStateError("contact label is not a string");
    if (!isInt(r.verifiedAt) || r.verifiedAt < 0) throw new AccountStateError("contact verifiedAt is invalid");
    if (typeof r.method !== "string" || !CONTACT_METHODS.includes(r.method as ContactMethod)) throw new AccountStateError("contact method is unknown");
    contacts.push({ userId: r.userId, identityPub: r.identityPub as string, label: r.label, verifiedAt: r.verifiedAt, method: r.method as ContactMethod });
  }
  if (new Set(contacts.map((c) => c.userId)).size !== contacts.length) throw new AccountStateError("duplicate contact");
  const tombstones: Record<string, number> = {};
  const rawT = (o.contactTombstones ?? {}) as Record<string, unknown>;
  if (typeof rawT !== "object" || Array.isArray(rawT)) throw new AccountStateError("tombstones are not an object");
  for (const [u, t] of Object.entries(rawT)) {
    if (!isInt(t)) throw new AccountStateError("tombstone is not an integer");
    tombstones[u] = t;
  }
  const fp = o.orgRecoveryFp ?? null;
  if (fp !== null && (typeof fp !== "string" || !HEX64_RE.test(fp))) throw new AccountStateError("orgRecoveryFp is not 64 hex");
  const nonces: Record<string, ConsumedNonce[]> = {};
  const rawN = (o.consumedNonces ?? {}) as Record<string, unknown>;
  if (typeof rawN !== "object" || Array.isArray(rawN)) throw new AccountStateError("nonces are not an object");
  for (const [vaultId, list] of Object.entries(rawN)) {
    if (!Array.isArray(list)) throw new AccountStateError("nonce list is not an array");
    nonces[vaultId] = list.map((e) => {
      if (!Array.isArray(e) || e.length !== 2 || typeof e[0] !== "string" || !isInt(e[1])) throw new AccountStateError("nonce entry is malformed");
      return [e[0], e[1]] as ConsumedNonce;
    });
  }
  // A6b: the issued-grants and owned-vaults records (absent in older documents: empty).
  const issuedGrants: IssuedGrant[] = [];
  const rawI = o.issuedGrants ?? [];
  if (!Array.isArray(rawI)) throw new AccountStateError("issued grants are not an array");
  for (const e of rawI as unknown[]) {
    if (!e || typeof e !== "object" || Array.isArray(e)) throw new AccountStateError("issued grant is not an object");
    const r = e as Record<string, unknown>;
    for (const k of Object.keys(r)) if (!ISSUED_KEYS.includes(k)) throw new AccountStateError(`unknown issued grant key ${k}`);
    if (typeof r.vaultId !== "string" || !UUID_RE.test(r.vaultId) || typeof r.userId !== "string" || !UUID_RE.test(r.userId)) {
      throw new AccountStateError("issued grant id is not a uuid");
    }
    if (typeof r.keyHash !== "string" || !HEX64_RE.test(r.keyHash)) throw new AccountStateError("issued grant keyHash is not 64 hex");
    if (!isInt(r.at) || r.at < 0) throw new AccountStateError("issued grant at is invalid");
    issuedGrants.push({ vaultId: r.vaultId, userId: r.userId, keyHash: r.keyHash, at: r.at });
  }
  if (new Set(issuedGrants.map((x) => pairKey(x.vaultId, x.userId))).size !== issuedGrants.length) throw new AccountStateError("duplicate issued grant");
  const issuedTombstones = intRecord(o.issuedTombstones, "issued tombstones");
  const ownedVaults = intRecord(o.ownedVaults, "owned vaults");
  for (const [k, t] of Object.entries(ownedVaults)) {
    if (!UUID_RE.test(k)) throw new AccountStateError("owned vault id is not a uuid");
    if (t < 0) throw new AccountStateError("owned vault at is negative");
  }
  const ownedTombstones = intRecord(o.ownedTombstones, "owned tombstones");
  return {
    v: 1, userId, seq: o.seq, contacts, contactTombstones: tombstones, orgRecoveryFp: fp as string | null, consumedNonces: nonces,
    issuedGrants, issuedTombstones, ownedVaults, ownedTombstones,
  };
}

export interface MergedAccountState {
  doc: AccountStateDoc;
  rollback: boolean;
}

/**
 * Root cause A §4.2 merge (core `AccountState.merge` twin): contacts union by userId, newest verifiedAt
 * wins (tie: the smaller identityPub string); tombstones union (max), a tombstone not older than a pin
 * removes it; orgRecoveryFp from the higher-seq document (local on a tie or a rollback); nonces union per
 * vault, newest {@link NONCE_CAP} kept; seq = max(local, served, highWater). A served seq below the
 * high-water mark, or a withheld blob once one was seen, is a ROLLBACK: the flag changes ONE field,
 * `orgRecoveryFp`, which then comes from the local copy; contacts, tombstones and nonces are still the
 * union of both (UVK-authenticated) copies, and seq stays at the high-water mark.
 */
export function mergeAccountState(
  userId: string,
  local: AccountStateDoc | null,
  served: AccountStateDoc | null,
  highWater: number,
): MergedAccountState {
  const rollback = (served === null && highWater > 0) || (served !== null && served.seq < highWater);
  const docs = [local, served].filter((d): d is AccountStateDoc => d !== null);
  const byUser = new Map<string, Contact>();
  for (const c of docs.flatMap((d) => d.contacts)) {
    const cur = byUser.get(c.userId);
    if (!cur || c.verifiedAt > cur.verifiedAt || (c.verifiedAt === cur.verifiedAt && c.identityPub < cur.identityPub)) byUser.set(c.userId, c);
  }
  const tombstones: Record<string, number> = {};
  for (const d of docs) for (const [u, t] of Object.entries(d.contactTombstones)) tombstones[u] = Math.max(tombstones[u] ?? t, t);
  const contacts = [...byUser.values()]
    .filter((c) => (tombstones[c.userId] ?? Number.MIN_SAFE_INTEGER) < c.verifiedAt)
    .sort((a, b) => (a.userId < b.userId ? -1 : a.userId > b.userId ? 1 : 0));
  const nonceMaps = new Map<string, Map<string, number>>();
  for (const d of docs) {
    for (const [vaultId, list] of Object.entries(d.consumedNonces)) {
      const m = nonceMaps.get(vaultId) ?? new Map<string, number>();
      for (const [n, t] of list) m.set(n, Math.max(m.get(n) ?? t, t));
      nonceMaps.set(vaultId, m);
    }
  }
  const consumedNonces: Record<string, ConsumedNonce[]> = {};
  for (const vaultId of [...nonceMaps.keys()].sort()) {
    consumedNonces[vaultId] = [...nonceMaps.get(vaultId)!.entries()]
      .map(([n, t]) => [n, t] as ConsumedNonce)
      .sort((a, b) => (b[1] !== a[1] ? b[1] - a[1] : a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
      .slice(0, NONCE_CAP);
  }
  const localSeq = local?.seq ?? -1;
  const servedSeq = served?.seq ?? -1;
  const preferServed = served !== null && !rollback && servedSeq > localSeq;
  const fp = preferServed ? (served!.orgRecoveryFp ?? local?.orgRecoveryFp ?? null) : (local?.orgRecoveryFp ?? served?.orgRecoveryFp ?? null);
  const sortedTomb = Object.fromEntries(Object.keys(tombstones).sort().map((k) => [k, tombstones[k]!]));
  // A6b (core twin): issued grants union by pair, newest `at` wins (tie: the smaller keyHash), a tombstone not older
  // removes; owned vaults union (max), a tombstone not older removes. A rollback cannot shrink either.
  const unionMax = (pick: (d: AccountStateDoc) => Record<string, number>): Record<string, number> => {
    const out: Record<string, number> = {};
    for (const d of docs) for (const [k, t] of Object.entries(pick(d))) out[k] = Math.max(out[k] ?? t, t);
    return Object.fromEntries(Object.keys(out).sort().map((k) => [k, out[k]!]));
  };
  const issuedTombstones = unionMax((d) => d.issuedTombstones);
  const pairs = new Map<string, IssuedGrant>();
  for (const gr of docs.flatMap((d) => d.issuedGrants)) {
    const k = pairKey(gr.vaultId, gr.userId);
    const cur = pairs.get(k);
    if (!cur || gr.at > cur.at || (gr.at === cur.at && gr.keyHash < cur.keyHash)) pairs.set(k, gr);
  }
  const issuedGrants = [...pairs.entries()]
    .filter(([k, gr]) => (issuedTombstones[k] ?? Number.MIN_SAFE_INTEGER) < gr.at)
    .map(([, gr]) => gr)
    .sort(byPair);
  const ownedTombstones = unionMax((d) => d.ownedTombstones);
  const ownedAll = unionMax((d) => d.ownedVaults);
  const ownedVaults = Object.fromEntries(Object.entries(ownedAll).filter(([k, t]) => (ownedTombstones[k] ?? Number.MIN_SAFE_INTEGER) < t));
  return {
    doc: {
      v: 1, userId, seq: Math.max(localSeq, servedSeq, highWater, 0), contacts, contactTombstones: sortedTomb, orgRecoveryFp: fp, consumedNonces,
      issuedGrants, issuedTombstones, ownedVaults, ownedTombstones,
    },
    rollback,
  };
}

/** Record a grant this account just signed (A6b; core `AccountState.withIssued` twin). */
export function withIssued(doc: AccountStateDoc, vaultId: string, userId: string, keyHash: string, at: number): AccountStateDoc {
  const k = pairKey(vaultId, userId);
  const prev = doc.issuedGrants.find((x) => x.vaultId === vaultId && x.userId === userId);
  const t = Math.max(at, (doc.issuedTombstones[k] ?? -1) + 1, prev?.at ?? -1);
  return { ...doc, issuedGrants: [...doc.issuedGrants.filter((x) => !(x.vaultId === vaultId && x.userId === userId)), { vaultId, userId, keyHash, at: t }].sort(byPair) };
}

/** Tombstone the issued grant for (vaultId, userId): the owner removed the member (A6b). */
export function withoutIssued(doc: AccountStateDoc, vaultId: string, userId: string, at: number): AccountStateDoc {
  const k = pairKey(vaultId, userId);
  const prev = doc.issuedGrants.find((x) => x.vaultId === vaultId && x.userId === userId);
  const t = Math.max(at, prev?.at ?? -1, doc.issuedTombstones[k] ?? -1);
  return {
    ...doc,
    issuedGrants: doc.issuedGrants.filter((x) => !(x.vaultId === vaultId && x.userId === userId)),
    issuedTombstones: { ...doc.issuedTombstones, [k]: t },
  };
}

/** Record that this account owns `vaultId` (created, accepted, or confirmed with a reauth; A6b). */
export function withOwned(doc: AccountStateDoc, vaultId: string, at: number): AccountStateDoc {
  const t = Math.max(at, (doc.ownedTombstones[vaultId] ?? -1) + 1, doc.ownedVaults[vaultId] ?? -1);
  return { ...doc, ownedVaults: { ...doc.ownedVaults, [vaultId]: t } };
}

/** Tombstone ownership of `vaultId`: the account transferred it away or left it (A6b). */
export function withoutOwned(doc: AccountStateDoc, vaultId: string, at: number): AccountStateDoc {
  const t = Math.max(at, doc.ownedVaults[vaultId] ?? -1, doc.ownedTombstones[vaultId] ?? -1);
  const owned = { ...doc.ownedVaults };
  delete owned[vaultId];
  return { ...doc, ownedVaults: owned, ownedTombstones: { ...doc.ownedTombstones, [vaultId]: t } };
}

/**
 * Fold this device's consumed removal nonces (root cause A §6.2, branch A7) into `doc` by the merge rule (union per
 * vault, the larger issuedAt for a repeated nonce, newest NONCE_CAP kept). Core `AccountState.withConsumed` twin.
 */
export function withConsumedNonces(doc: AccountStateDoc, extra: Record<string, ConsumedNonce[]>): AccountStateDoc {
  const maps = new Map<string, Map<string, number>>();
  for (const src of [doc.consumedNonces, extra]) {
    for (const [vaultId, list] of Object.entries(src)) {
      const m = maps.get(vaultId) ?? new Map<string, number>();
      for (const [n, t] of list) m.set(n, Math.max(m.get(n) ?? t, t));
      maps.set(vaultId, m);
    }
  }
  const consumedNonces: Record<string, ConsumedNonce[]> = {};
  for (const vaultId of [...maps.keys()].sort()) {
    consumedNonces[vaultId] = [...maps.get(vaultId)!.entries()]
      .map(([n, t]) => [n, t] as ConsumedNonce)
      .sort((a, b) => (b[1] !== a[1] ? b[1] - a[1] : a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
      .slice(0, NONCE_CAP);
  }
  return { ...doc, consumedNonces };
}

/** Same content ignoring seq (no write needed). */
export function sameAccountStateContent(a: AccountStateDoc | null, b: AccountStateDoc | null): boolean {
  if (!a || !b) return false;
  return encodeAccountState({ ...a, seq: 0 }) === encodeAccountState({ ...b, seq: 0 });
}

export function withContact(doc: AccountStateDoc, c: Contact): AccountStateDoc {
  const tomb = { ...doc.contactTombstones };
  delete tomb[c.userId];
  return { ...doc, contacts: [...doc.contacts.filter((x) => x.userId !== c.userId), c].sort((a, b) => (a.userId < b.userId ? -1 : 1)), contactTombstones: tomb };
}

export function withoutContact(doc: AccountStateDoc, userId: string, at: number): AccountStateDoc {
  return {
    ...doc,
    contacts: doc.contacts.filter((x) => x.userId !== userId),
    contactTombstones: { ...doc.contactTombstones, [userId]: Math.max(at, doc.contactTombstones[userId] ?? at) },
  };
}
