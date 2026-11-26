import { utf8 } from "../crypto/bytes";
import { INT_CEILING, isB64_32, isHex64, isHex64n, isName, isUuid } from "../crypto/trust/grammar";
import { boolOf, intOf, type JValue, objOf, parseJValue, strOf, writeJValue } from "./jsonlex";

/**
 * The UVK-sealed account-state document after the cut-over (design §5.4, spec 02 §9): its records, the
 * strict decode, the writer (map keys in ascending byte order), the pure merge with its caps and size
 * shedding, and the acceptance answer of §3.6 (d). Graded by accountdoc.vectors.test.ts against
 * spec/test-vectors/next/accountstate.json. Behaviour twin of core `state/AccountRecords.kt` and
 * `state/AccountDocumentCodec.kt`.
 *
 * Who can write this document: any holder of the account's UVK (R35), the web bundle included. So a
 * record here can only REFUSE (a vault record refuses a log; a key-change contact goes to a prompt);
 * nothing in it makes anything pass on its own, and nothing the server serves is adopted unmerged.
 */

export type Extra = ReadonlyMap<string, JValue>;

/** A contact (design §6.9). `label` is the `name` type as stored (base64url). `compared` merges as OR. */
export interface ContactRecord {
  readonly userId: string;
  readonly identityPub: string;
  readonly label: string;
  readonly method: "link";
  readonly verifiedAt: number;
  readonly compared: boolean;
  readonly madeOn: string;
  readonly extra: Extra;
}

/** `vaults[vaultId]` (§3.6 (e)): the immutable genesis hash and the highest verified head any device recorded. */
export interface VaultRecord {
  readonly vaultId: string;
  readonly genesisHash: string;
  readonly seq: number;
  readonly hash: string;
  readonly extra: Extra;
}

export type Decision = "accept" | "decline";

/** `accepted[vaultId]` (§3.6): the person's answer to the `add` at `addSeq` (0 stands for the genesis of a vault this account created). */
export interface AcceptedRecord {
  readonly vaultId: string;
  readonly owner: string;
  readonly addSeq: number;
  readonly at: number;
  readonly decision: Decision;
  readonly extra: Extra;
}

/** `recovery` (§4.5): the person's own recovery choice, the only one a client acts on. */
export interface RecoveryRecord {
  readonly posture: "private" | "operator";
  readonly fp: string;
  readonly at: number;
  readonly extra: Extra;
}

/**
 * The whole document. `seq` is the AUTHENTICATED in-blob counter (FI-B14), never the server's CAS token.
 * `unknown` keeps every top-level key this build does not know, as written.
 */
export interface AccountDocument {
  readonly seq: number;
  readonly contacts: ReadonlyMap<string, ContactRecord>;
  readonly contactTombstones: ReadonlyMap<string, number>;
  readonly vaults: ReadonlyMap<string, VaultRecord>;
  readonly accepted: ReadonlyMap<string, AcceptedRecord>;
  readonly recovery: RecoveryRecord | null;
  readonly unknown: Extra;
}

export const DOCUMENT_VERSION = 2;
export const MAX_CONTACTS = 1000;
export const MAX_TOMBSTONES = 1000;
/** `ACCOUNT_STATE_SEALED_MAX` (spec 03 §3): the sealed state as sent, 1 MiB of base64. */
export const SEALED_MAX = 1_048_576;
/** The largest in-blob seq (2^53 − 1): a document at it cannot be advanced. */
export const MAX_SEQ = INT_CEILING - 1;
/** Envelope version and suite (2) + nonce (24) + Poly1305 tag (16). */
export const ENVELOPE_OVERHEAD = 42;

export const ACCOUNT_STATE_FULL = "account_state_full";
export const ACCOUNT_STATE_DAMAGED = "account_state_damaged";

export const EMPTY_DOCUMENT: AccountDocument = Object.freeze({
  seq: 0,
  contacts: new Map(),
  contactTombstones: new Map(),
  vaults: new Map(),
  accepted: new Map(),
  recovery: null,
  unknown: new Map(),
});

/** The three limits of §5.4. The pure merge takes them so the vectors can grade the caps on small documents. */
export interface AccountLimits {
  readonly contacts: number;
  readonly tombstones: number;
  readonly sealedChars: number;
}

export const DEFAULT_LIMITS: AccountLimits = Object.freeze({ contacts: MAX_CONTACTS, tombstones: MAX_TOMBSTONES, sealedChars: SEALED_MAX });

// ---------------------------------------------------------------------------------------------------
// Byte order

/** Unsigned lexicographic comparison of the UTF-8 bytes of two strings (design §5.4 "Ties", "byte order"). */
export function compareBytes(a: string, b: string): number {
  if (a === b) return 0;
  const x = utf8(a);
  const y = utf8(b);
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i++) {
    const d = x[i]! - y[i]!;
    if (d !== 0) return d;
  }
  return x.length - y.length;
}

const inByteOrder = <V>(m: ReadonlyMap<string, V>): [string, V][] => [...m].sort((p, q) => compareBytes(p[0], q[0]));

// ---------------------------------------------------------------------------------------------------
// Codec

const KNOWN = new Set(["v", "userId", "seq", "contacts", "contactTombstones", "vaults", "accepted", "recovery"]);
const CONTACT_FIELDS = new Set(["userId", "identityPub", "label", "method", "verifiedAt", "compared", "madeOn"]);
const VAULT_FIELDS = new Set(["genesisHash", "seq", "hash"]);
const ACCEPTED_FIELDS = new Set(["owner", "addSeq", "at", "decision"]);
const RECOVERY_FIELDS = new Set(["posture", "fp", "at"]);

function extraOf(o: ReadonlyMap<string, JValue>, known: ReadonlySet<string>): Extra {
  const out = new Map<string, JValue>();
  for (const [k, v] of o) if (!known.has(k)) out.set(k, v);
  return out;
}

export interface Decoded {
  readonly document: AccountDocument;
  /** Records that failed their own shape and were dropped (never trusted, never written back). */
  readonly dropped: number;
}

/**
 * Decodes [text] as [userId]'s document; null when it is refused whole: not a JSON object, another `v`,
 * another account's `userId`, or a `seq` that is not an `int`. A record that fails its own shape is dropped
 * and counted, and the rest is used. A missing map reads as empty; unknown keys and fields are kept.
 */
export function decodeDocument(userId: string, text: string): Decoded | null {
  const root = parseJValue(text);
  const o = objOf(root ?? undefined);
  if (!o) return null;
  if (intOf(o.get("v")) !== DOCUMENT_VERSION) return null;
  if (strOf(o.get("userId")) !== userId) return null;
  const seq = intOf(o.get("seq"));
  if (seq === null) return null;
  let dropped = 0;

  function records<T>(key: string, f: (id: string, r: ReadonlyMap<string, JValue>) => T | null): Map<string, T> {
    const out = new Map<string, T>();
    const m = objOf(o!.get(key));
    if (!m) return out;
    for (const [id, e] of m) {
      const r = objOf(e);
      const rec = r ? f(id, r) : null;
      if (rec === null) dropped++;
      else out.set(id, rec);
    }
    return out;
  }

  const contacts = records<ContactRecord>("contacts", (id, c) => {
    const uid = strOf(c.get("userId"));
    if (uid === null || uid !== id || !isUuid(uid)) return null;
    const identityPub = strOf(c.get("identityPub"));
    if (identityPub === null || !isB64_32(identityPub)) return null;
    const label = strOf(c.get("label"));
    if (label === null || !isName(label)) return null;
    if (strOf(c.get("method")) !== "link") return null;
    const verifiedAt = intOf(c.get("verifiedAt"));
    if (verifiedAt === null) return null;
    const compared = boolOf(c.get("compared"));
    if (compared === null) return null;
    const madeOn = strOf(c.get("madeOn"));
    if (madeOn === null || !isUuid(madeOn)) return null;
    return { userId: uid, identityPub, label, method: "link", verifiedAt, compared, madeOn, extra: extraOf(c, CONTACT_FIELDS) };
  });

  const contactTombstones = new Map<string, number>();
  const tm = objOf(o.get("contactTombstones"));
  if (tm) {
    for (const [id, e] of tm) {
      const at = intOf(e);
      if (at === null || !isUuid(id)) dropped++;
      else contactTombstones.set(id, at);
    }
  }

  const vaults = records<VaultRecord>("vaults", (id, v) => {
    if (!isUuid(id)) return null;
    const genesisHash = strOf(v.get("genesisHash"));
    const s = intOf(v.get("seq"));
    const hash = strOf(v.get("hash"));
    if (genesisHash === null || !isHex64(genesisHash) || s === null || hash === null || !isHex64(hash)) return null;
    return { vaultId: id, genesisHash, seq: s, hash, extra: extraOf(v, VAULT_FIELDS) };
  });

  const accepted = records<AcceptedRecord>("accepted", (id, a) => {
    if (!isUuid(id)) return null;
    const owner = strOf(a.get("owner"));
    const addSeq = intOf(a.get("addSeq"));
    const at = intOf(a.get("at"));
    const decision = strOf(a.get("decision"));
    if (owner === null || !isUuid(owner) || addSeq === null || at === null) return null;
    if (decision !== "accept" && decision !== "decline") return null;
    return { vaultId: id, owner, addSeq, at, decision, extra: extraOf(a, ACCEPTED_FIELDS) };
  });

  let recovery: RecoveryRecord | null = null;
  const rm = objOf(o.get("recovery"));
  if (rm) {
    const posture = strOf(rm.get("posture"));
    const fp = strOf(rm.get("fp"));
    const at = intOf(rm.get("at"));
    if ((posture === "private" || posture === "operator") && fp !== null && isHex64n(fp) && at !== null) {
      recovery = { posture, fp, at, extra: extraOf(rm, RECOVERY_FIELDS) };
    } else dropped++;
  }

  return { document: { seq, contacts, contactTombstones, vaults, accepted, recovery, unknown: extraOf(o, KNOWN) }, dropped };
}

const q = (s: string): string => JSON.stringify(s);

function withExtra(known: string[], extra: Extra, fields: ReadonlySet<string>): string {
  const parts = [...known];
  for (const [k, v] of inByteOrder(extra)) if (!fields.has(k)) parts.push(`${q(k)}:${writeJValue(v)}`);
  return "{" + parts.join(",") + "}";
}

function mapOf<V>(m: ReadonlyMap<string, V>, one: (v: V) => string): string {
  return "{" + inByteOrder(m).map(([k, v]) => `${q(k)}:${one(v)}`).join(",") + "}";
}

/** Compact JSON for [doc] as [userId]'s document: known fields in the layout's order, every map's keys in ascending byte order. */
export function encodeDocument(userId: string, doc: AccountDocument): string {
  const parts = [`"v":${DOCUMENT_VERSION}`, `"userId":${q(userId)}`, `"seq":${doc.seq}`];
  parts.push(
    `"contacts":` +
      mapOf(doc.contacts, (c) =>
        withExtra(
          [`"userId":${q(c.userId)}`, `"identityPub":${q(c.identityPub)}`, `"label":${q(c.label)}`, `"method":"link"`, `"verifiedAt":${c.verifiedAt}`, `"compared":${c.compared}`, `"madeOn":${q(c.madeOn)}`],
          c.extra,
          CONTACT_FIELDS,
        ),
      ),
  );
  parts.push(`"contactTombstones":` + mapOf(doc.contactTombstones, (at) => String(at)));
  parts.push(`"vaults":` + mapOf(doc.vaults, (v) => withExtra([`"genesisHash":${q(v.genesisHash)}`, `"seq":${v.seq}`, `"hash":${q(v.hash)}`], v.extra, VAULT_FIELDS)));
  parts.push(
    `"accepted":` +
      mapOf(doc.accepted, (a) => withExtra([`"owner":${q(a.owner)}`, `"addSeq":${a.addSeq}`, `"at":${a.at}`, `"decision":${q(a.decision)}`], a.extra, ACCEPTED_FIELDS)),
  );
  if (doc.recovery) {
    const r = doc.recovery;
    parts.push(`"recovery":` + withExtra([`"posture":${q(r.posture)}`, `"fp":${q(r.fp)}`, `"at":${r.at}`], r.extra, RECOVERY_FIELDS));
  }
  for (const [k, v] of inByteOrder(doc.unknown)) if (!KNOWN.has(k)) parts.push(`${q(k)}:${writeJValue(v)}`);
  return "{" + parts.join(",") + "}";
}

// ---------------------------------------------------------------------------------------------------
// Merge

export type MergeAnomaly =
  /** A served contact with another key for a pinned userId: kept aside for the key-change prompt (§6.8 step 6). */
  | { readonly kind: "contact_key_change"; readonly local: ContactRecord; readonly served: ContactRecord }
  /** A served vault record names another genesis: the local record stays. */
  | { readonly kind: "vault_genesis_mismatch"; readonly local: VaultRecord; readonly served: VaultRecord }
  /** The same seq with another hash: a fork of that vault's log (§3.9). The local record stays. */
  | { readonly kind: "vault_record_fork"; readonly local: VaultRecord; readonly served: VaultRecord }
  /** The served document's in-blob seq is below this device's high-water mark. */
  | { readonly kind: "rollback"; readonly servedSeq: number; readonly highWater: number }
  /** The server served no document after this device had seen one. */
  | { readonly kind: "withheld" };

export interface MergeResult {
  readonly document: AccountDocument;
  readonly anomalies: readonly MergeAnomaly[];
  /** False when the document is still over the sealed size after every drop §5.4 names. */
  readonly fits: boolean;
}

/** Why a merged document is for reading only (§5.4 "Edges"), or null when it may be written. */
export function notWritten(r: MergeResult): string | null {
  if (r.document.seq >= MAX_SEQ) return ACCOUNT_STATE_DAMAGED;
  if (!r.fits) return ACCOUNT_STATE_FULL;
  return null;
}

/** Contacts with the same key: the newest verifiedAt, then the larger label, then the larger madeOn; `compared` is OR. */
function pickContact(l: ContactRecord, s: ContactRecord): ContactRecord {
  let newer: ContactRecord;
  if (l.verifiedAt !== s.verifiedAt) newer = l.verifiedAt > s.verifiedAt ? l : s;
  else {
    const byLabel = compareBytes(l.label, s.label);
    newer = byLabel !== 0 ? (byLabel > 0 ? l : s) : compareBytes(l.madeOn, s.madeOn) >= 0 ? l : s;
  }
  return { ...newer, compared: l.compared || s.compared };
}

/** The higher addSeq; for the same addSeq a decline whatever `at` says; then the newest at; then the larger owner. */
export function pickAccepted(a: AcceptedRecord, b: AcceptedRecord): AcceptedRecord {
  if (a.addSeq !== b.addSeq) return a.addSeq > b.addSeq ? a : b;
  if (a.decision !== b.decision) return a.decision === "decline" ? a : b;
  if (a.at !== b.at) return a.at > b.at ? a : b;
  return compareBytes(a.owner, b.owner) >= 0 ? a : b;
}

/** The newest at; a tie goes to private, then to the smaller fp (`none` sorts after every fingerprint, byte for byte). */
export function pickRecovery(a: RecoveryRecord | null, b: RecoveryRecord | null): RecoveryRecord | null {
  if (a === null) return b;
  if (b === null) return a;
  if (a.at !== b.at) return a.at > b.at ? a : b;
  if (a.posture !== b.posture) return a.posture === "private" ? a : b;
  return compareBytes(a.fp, b.fp) <= 0 ? a : b;
}

const keysOf = (...maps: ReadonlyMap<string, unknown>[]): Set<string> => new Set(maps.flatMap((m) => [...m.keys()]));

/**
 * Merges [served] into [local], record by record whatever their seq values (design §5.4). The result's seq is
 * the larger of the two; a write uses that plus one. Commutative in its records.
 */
export function mergeDocuments(local: AccountDocument, served: AccountDocument, limits: AccountLimits = DEFAULT_LIMITS): MergeResult {
  const anomalies: MergeAnomaly[] = [];

  const tombs = new Map<string, number>();
  for (const m of [local.contactTombstones, served.contactTombstones]) {
    for (const [id, at] of m) {
      const cur = tombs.get(id);
      if (cur === undefined || at > cur) tombs.set(id, at);
    }
  }

  const contacts = new Map<string, ContactRecord>();
  for (const id of keysOf(local.contacts, served.contacts)) {
    const l = local.contacts.get(id);
    const s = served.contacts.get(id);
    let merged: ContactRecord;
    if (!l) merged = s!;
    else if (!s) merged = l;
    else if (l.identityPub !== s.identityPub) {
      anomalies.push({ kind: "contact_key_change", local: l, served: s });
      merged = l;
    } else merged = pickContact(l, s);
    // A tombstone not older than the pin removes it, from both copies, before any cap drops the tombstone.
    const t = tombs.get(id);
    if (t !== undefined && t >= merged.verifiedAt) continue;
    contacts.set(id, merged);
  }

  const vaults = new Map<string, VaultRecord>();
  for (const id of keysOf(local.vaults, served.vaults)) {
    const l = local.vaults.get(id);
    const s = served.vaults.get(id);
    if (!l) vaults.set(id, s!);
    else if (!s) vaults.set(id, l);
    else if (l.genesisHash !== s.genesisHash) {
      anomalies.push({ kind: "vault_genesis_mismatch", local: l, served: s });
      vaults.set(id, l);
    } else if (l.seq === s.seq && l.hash !== s.hash) {
      anomalies.push({ kind: "vault_record_fork", local: l, served: s });
      vaults.set(id, l);
    } else vaults.set(id, s.seq > l.seq ? s : l);
  }

  const accepted = new Map<string, AcceptedRecord>();
  for (const id of keysOf(local.accepted, served.accepted)) {
    const l = local.accepted.get(id);
    const s = served.accepted.get(id);
    accepted.set(id, !l ? s! : !s ? l : pickAccepted(l, s));
  }

  const recovery = pickRecovery(local.recovery, served.recovery);

  // Unknown keys: the union; a key in both stays as the larger-seq copy has it, the local copy's on a tie.
  const [low, high] = served.seq > local.seq ? [local, served] : [served, local];
  const unknown = new Map<string, JValue>([...low.unknown, ...high.unknown]);

  const doc: AccountDocument = { seq: Math.max(local.seq, served.seq), contacts, contactTombstones: tombs, vaults, accepted, recovery, unknown };
  const bounded = boundDocument(doc, limits);
  return { document: bounded.document, anomalies, fits: bounded.fits };
}

/** The sealed length of [doc] as sent: unpadded base64 of the envelope, the compact plaintext plus 42 bytes. */
export function sealedChars(doc: AccountDocument): number {
  // The document's userId is always a 36-character UUID, so any one of that length gives the exact size.
  const n = utf8(encodeDocument("00000000-0000-4000-8000-000000000000", doc)).length + ENVELOPE_OVERHEAD;
  return Math.floor((n * 4 + 2) / 3);
}

/**
 * Holds [doc] to [limits], on merge and on write alike (§5.4): the contact and tombstone caps keep the newest,
 * among equals the smaller userId; over the sealed size, unknown top-level keys go first, the largest first;
 * then the `vaults` and `accepted` records of vaults the account has left (decline), the smallest `at` first,
 * then the smaller vaultId. `recovery` is never dropped. `fits` is false when it is still over after all that.
 */
export function boundDocument(doc: AccountDocument, limits: AccountLimits): { document: AccountDocument; fits: boolean } {
  let d = doc;
  if (d.contactTombstones.size > limits.tombstones) {
    const kept = [...d.contactTombstones].sort((a, b) => b[1] - a[1] || compareBytes(a[0], b[0])).slice(0, Math.max(limits.tombstones, 0));
    d = { ...d, contactTombstones: new Map(kept) };
  }
  if (d.contacts.size > limits.contacts) {
    const kept = [...d.contacts.values()].sort((a, b) => b.verifiedAt - a.verifiedAt || compareBytes(a.userId, b.userId)).slice(0, Math.max(limits.contacts, 0));
    d = { ...d, contacts: new Map(kept.map((c) => [c.userId, c])) };
  }
  if (sealedChars(d) <= limits.sealedChars) return { document: d, fits: true };

  const size = (k: string, v: JValue) => utf8(k).length + utf8(writeJValue(v)).length;
  // The largest first; between equal sizes the larger key first, so every device sheds the same one.
  const unknownOrder = [...d.unknown].sort((a, b) => size(b[0], b[1]) - size(a[0], a[1]) || compareBytes(b[0], a[0])).map(([k]) => k);
  for (const k of unknownOrder) {
    const unknown = new Map(d.unknown);
    unknown.delete(k);
    d = { ...d, unknown };
    if (sealedChars(d) <= limits.sealedChars) return { document: d, fits: true };
  }

  const left = [...d.accepted.values()].filter((a) => a.decision === "decline").sort((a, b) => a.at - b.at || compareBytes(a.vaultId, b.vaultId));
  for (const a of left) {
    const vaults = new Map(d.vaults);
    vaults.delete(a.vaultId);
    const accepted = new Map(d.accepted);
    accepted.delete(a.vaultId);
    d = { ...d, vaults, accepted };
    if (sealedChars(d) <= limits.sealedChars) return { document: d, fits: true };
  }
  return { document: d, fits: false };
}

// ---------------------------------------------------------------------------------------------------
// Answers and edits

export type Acceptance = "accept" | "decline" | "ask";

/** The `accepted` record that answers the account's latest add at [latestAddSeq], or null: a record for another add answers nothing (FS-R6). */
export function acceptedFor(doc: AccountDocument, vaultId: string, latestAddSeq: number): AcceptedRecord | null {
  const a = doc.accepted.get(vaultId);
  return a && a.addSeq === latestAddSeq ? a : null;
}

/** §2.4 "Acceptance" (VR-16): accept, decline, or ask. */
export function acceptance(doc: AccountDocument, vaultId: string, latestAddSeq: number): Acceptance {
  return acceptedFor(doc, vaultId, latestAddSeq)?.decision ?? "ask";
}

/**
 * The time a record that supersedes another is stamped with (§5.4): this device's clock, or one past the held
 * record's time when the clock says otherwise. So a device whose clock runs behind still writes a record that wins
 * the merge against the one it was meant to replace.
 */
export function supersedingStamp(nowMs: number, heldAt: number | null | undefined): number {
  return heldAt === null || heldAt === undefined ? nowMs : Math.max(nowMs, heldAt + 1);
}

/**
 * Removing a contact writes a tombstone stamped later than the pin and than any tombstone already held for it
 * (§5.4), so the newest human act wins whatever the clocks say.
 */
export function removeContact(doc: AccountDocument, userId: string, nowMs: number): AccountDocument {
  const pin = doc.contacts.get(userId);
  const contacts = new Map(doc.contacts);
  contacts.delete(userId);
  const contactTombstones = new Map(doc.contactTombstones);
  const held = Math.max(pin?.verifiedAt ?? -1, doc.contactTombstones.get(userId) ?? -1);
  contactTombstones.set(userId, supersedingStamp(nowMs, held < 0 ? null : held));
  return { ...doc, contacts, contactTombstones };
}

/** Sets one `accepted` record, kept only if it wins against the one already held (the merge rule, so a write never undoes a decline). */
export function withAccepted(doc: AccountDocument, rec: Omit<AcceptedRecord, "extra">): AccountDocument {
  const next: AcceptedRecord = { ...rec, extra: new Map() };
  const held = doc.accepted.get(rec.vaultId);
  const accepted = new Map(doc.accepted);
  accepted.set(rec.vaultId, held ? pickAccepted(held, next) : next);
  return { ...doc, accepted };
}

/**
 * Records a verified head for a vault (§3.6 (e)). The genesis hash is immutable: a record for another genesis
 * is not replaced (the caller has already refused that log). A lower or equal seq changes nothing.
 */
export function withVaultHead(doc: AccountDocument, vaultId: string, genesisHash: string, seq: number, hash: string): AccountDocument {
  const held = doc.vaults.get(vaultId);
  if (held && (held.genesisHash !== genesisHash || held.seq >= seq)) return doc;
  const vaults = new Map(doc.vaults);
  vaults.set(vaultId, { vaultId, genesisHash, seq, hash, extra: held?.extra ?? new Map() });
  return { ...doc, vaults };
}

/**
 * Records the person's explicit recovery choice (§4.5). It must win the merge on every device, so its `at` is
 * past the held record's even when this device's clock is behind (the newest `at` wins, §5.4).
 */
export function withRecovery(doc: AccountDocument, rec: Omit<RecoveryRecord, "extra">): AccountDocument {
  const at = supersedingStamp(rec.at, doc.recovery?.at);
  return { ...doc, recovery: { ...rec, at, extra: new Map() } };
}

/**
 * The vault-record batching rule (§5.4, SR-2): a new vault's record is written at once, later heads at most once
 * every 10 minutes per device. A stale record is still a valid lower bound.
 */
export const VAULT_RECORD_INTERVAL_MS = 10 * 60 * 1000;

export function vaultRecordDue(existing: VaultRecord | undefined, candidateSeq: number, lastWriteAtMs: number | null, nowMs: number): boolean {
  if (!existing) return true;
  if (candidateSeq <= existing.seq) return false;
  if (lastWriteAtMs === null) return true;
  return nowMs - lastWriteAtMs >= VAULT_RECORD_INTERVAL_MS || nowMs < lastWriteAtMs;
}
