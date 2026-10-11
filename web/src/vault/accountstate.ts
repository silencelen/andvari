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

export interface AccountStateDoc {
  v: 1;
  userId: string;
  seq: number;
  contacts: Contact[];
  contactTombstones: Record<string, number>;
  orgRecoveryFp: string | null;
  consumedNonces: Record<string, ConsumedNonce[]>;
}

export class AccountStateError extends Error {}

export const ACCOUNT_STATE_VERSION = 1;
export const NONCE_CAP = 256;
export const ACCOUNT_STATE_SEALED_MAX = 65536;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const DOC_KEYS = ["v", "userId", "seq", "contacts", "contactTombstones", "orgRecoveryFp", "consumedNonces"];
const CONTACT_KEYS = ["userId", "identityPub", "label", "verifiedAt", "method"];

export function emptyAccountState(userId: string): AccountStateDoc {
  return { v: 1, userId, seq: 0, contacts: [], contactTombstones: {}, orgRecoveryFp: null, consumedNonces: {} };
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
  });
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
  return { v: 1, userId, seq: o.seq, contacts, contactTombstones: tombstones, orgRecoveryFp: fp as string | null, consumedNonces: nonces };
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
  return {
    doc: { v: 1, userId, seq: Math.max(localSeq, servedSeq, highWater, 0), contacts, contactTombstones: sortedTomb, orgRecoveryFp: fp, consumedNonces },
    rollback,
  };
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
