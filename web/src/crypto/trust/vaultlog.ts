import { ctEquals, toHexLower } from "../bytes";
import { hkdfSha256 } from "../hkdf";
import { allZero, requireKey } from "../keyfloor";
import type { KeyPairBytes } from "../provider";
import { CryptoError } from "../sodium";
import { type Checked, ok, refused } from "./checked";
import { encodeStatement, type LogKindLiteral, parseFrame, type RawStatement } from "./codec";
import { type FrameParts, frameHash, type FrameVerdict, signatureValid, signerMapsTo, signFrame } from "./frame";
import { fromB64Exact, isB64_16, isB64_32, isHex64, isInt, isMs, isUuid, ZERO_HASH } from "./grammar";

/**
 * The shared vault log (design 2026-11-15 §3): templates (§3.1), chain (§3.2), state and transitions
 * (§3.3) and the key commitment (§3.4). Twin of core `VaultLog`, written on its own and graded off the
 * same `vaultlog.json`: the transition rules live in one table ({@link RULES}), one row per kind, as
 * the design writes them.
 *
 * Verifying needs no contact pins: every signer key comes from the log itself. Whether the web ADOPTS
 * a vault (§3.6) is decided in `web/src/vault`, on top of the state this returns.
 */

export type MemberRole = "writer" | "reader";
export type VaultRole = "owner" | MemberRole;

interface EntryHead {
  readonly vaultId: string;
  /** 0 for `genesis`, the previous entry's plus one otherwise. */
  readonly seq: number;
  /** 64 zeros for `genesis`, `H(previous frame)` otherwise. */
  readonly prev: string;
  /** The account that signed the entry. */
  readonly actor: string;
  /** The signer's own clock, used only for the time rules of §3.3. */
  readonly at: number;
}

/**
 * One entry as its statement says it (§3.1). Ids, keys and hashes are the canonical statement text. An
 * entry read from a frame is trusted only as the `entry` of a {@link VaultLogStep}.
 */
export type LogEntry =
  | (EntryHead & { readonly kind: "genesis"; readonly ownerKey: string; readonly vkCommit: string })
  | (EntryHead & { readonly kind: "add"; readonly member: string; readonly memberKey: string; readonly role: MemberRole; readonly grantId: string })
  | (EntryHead & { readonly kind: "role"; readonly member: string; readonly role: MemberRole })
  | (EntryHead & { readonly kind: "remove"; readonly member: string })
  | (EntryHead & { readonly kind: "leave" })
  | (EntryHead & { readonly kind: "offer"; readonly to: string; readonly toKey: string; readonly offerId: string; readonly expiresAt: number })
  | (EntryHead & { readonly kind: "cancel"; readonly offerId: string })
  | (EntryHead & { readonly kind: "accept"; readonly offerId: string })
  | (EntryHead & { readonly kind: "delete"; readonly deleteId: string })
  | (EntryHead & { readonly kind: "restore"; readonly deleteId: string });

export type LogKind = LogEntry["kind"];
type EntryOf<K extends LogKind> = Extract<LogEntry, { kind: K }>;

/**
 * One member in the state. `addSeq` is the `seq` of the `add` entry that made this account a member
 * (what an `accepted` record answers, FS-R6); it is null only for the genesis creator who never left
 * or was removed, which is §3.6 (d)'s "the log has no `add` of this account" (FN-2).
 */
export interface VaultMember {
  readonly key: string;
  readonly role: VaultRole;
  readonly addSeq: number | null;
}

export interface PendingOffer {
  readonly offerId: string;
  readonly to: string;
  readonly toKey: string;
  readonly expiresAt: number;
}

/**
 * One `add` entry of the verified log: `actor` is the owner who signed it and `ownerKey` the owner key AT
 * that entry (§3.5 step 6). The state keeps ONE per account, its latest ({@link VaultState.latestAdds}):
 * a grant binds to an account's latest `add` only, so earlier ones are not kept.
 */
export interface AddRecord {
  readonly seq: number;
  readonly actor: string;
  readonly ownerKey: string;
  readonly member: string;
  readonly memberKey: string;
  readonly role: MemberRole;
  readonly grantId: string;
}

declare const verifiedState: unique symbol;

/**
 * The vault state S that replaying entries 0..n yields (§3.3), plus what the design derives from the
 * same entries: `at` (the head entry's), `genesisHash` (the wrap AD of §2.3 and the vault record of
 * §3.6 (e)), `creator` (§3.6 (d), FN-2) and `latestAdds` (§3.5 step 6).
 *
 * The brand means a value of this type came from {@link verifyLogEntry}, {@link replayLog} or
 * {@link decodeVaultState} (this browser's own stored copy). Nothing a server sends is ever a state.
 */
export interface VaultState {
  readonly [verifiedState]: true;
  readonly vaultId: string;
  readonly head: { readonly seq: number; readonly hash: string };
  readonly at: number;
  readonly genesisHash: string;
  readonly creator: string;
  readonly owner: string;
  readonly ownerKey: string;
  readonly vkCommit: string;
  readonly members: Readonly<Record<string, VaultMember>>;
  readonly pending: PendingOffer | null;
  /** The `deleteId` of the deletion in force, or null. */
  readonly deleteId: string | null;
  /**
   * Each account's LATEST `add` entry, by userId (§3.5 step 6), also for an account that left or was
   * removed since: one record per account ever added, however often it was added again. So the state
   * grows with the accounts a vault has had, never with the length of its log.
   */
  readonly latestAdds: Readonly<Record<string, AddRecord>>;
}

type StateFields = Omit<VaultState, typeof verifiedState>;

/**
 * The brand is a type, and a type is erased at run time: what keeps a verified state verified is that
 * nothing can change it. So it is frozen at EVERY level: the state, its head, its pending offer, the
 * member map and every member, the add records and each of them. (Freezing the state alone left
 * `state.members` open to any caller, which could then add an owner to a "verified" state.)
 */
function brand(s: StateFields): VaultState {
  for (const userId of Object.keys(s.members)) Object.freeze(s.members[userId]);
  for (const userId of Object.keys(s.latestAdds)) Object.freeze(s.latestAdds[userId]);
  Object.freeze(s.members);
  Object.freeze(s.latestAdds);
  Object.freeze(s.head);
  if (s.pending !== null) Object.freeze(s.pending);
  return Object.freeze(s) as VaultState;
}

/**
 * What a client already holds for a log's positions, for fork detection (§3.9): the frame hash it holds
 * for `seq` (an entry it verified, a checkpoint, the account's vault record), or null for none.
 * {@link verifyLogEntry} and {@link replayLog} cannot be called without one: a caller that left it out
 * used to get a verifier with fork detection silently off.
 */
export type KnownHashes = (seq: number) => string | null | undefined;

/**
 * For a verifier that holds NO hash of its own for any position, so that the `fork` verdict cannot
 * arise: a caller that verifies a log it has never seen before with nothing to compare it to. A client
 * that has verified entries of the log, or has the account's vault record for it, never passes this: it
 * passes what it holds.
 */
export const NONE_HELD: KnownHashes = () => null;

/** The types are erased at run time: a caller without them that passes no `known` is refused at once, before any frame is read. */
function requireKnown(known: KnownHashes): void {
  if (typeof known !== "function") throw new CryptoError("known: pass what this client holds for the log's positions, or NONE_HELD");
}

/** The latest `add` of `userId` in a verified state, or null when the log never added that account. */
export function latestAddOf(state: VaultState, userId: string): AddRecord | null {
  return has(state.latestAdds, userId) ? state.latestAdds[userId]! : null;
}

/**
 * The state while entries are applied to it: the same fields, with the two maps changed IN PLACE. A
 * replay works on one of these from its first frame to its last and freezes it once, so its cost is one
 * step per entry; copying the member map for every entry made a replay quadratic in the log's length.
 * A member or add record inside is never changed, only replaced: it may be shared with a frozen state.
 */
interface Working {
  vaultId: string;
  head: { readonly seq: number; readonly hash: string };
  at: number;
  genesisHash: string;
  creator: string;
  owner: string;
  ownerKey: string;
  vkCommit: string;
  members: Record<string, VaultMember>;
  pending: PendingOffer | null;
  deleteId: string | null;
  latestAdds: Record<string, AddRecord>;
}

/** A working copy of a verified state: the maps are copied once, so the state itself is never touched. */
const thaw = (s: VaultState): Working => ({
  vaultId: s.vaultId, head: s.head, at: s.at, genesisHash: s.genesisHash, creator: s.creator, owner: s.owner, ownerKey: s.ownerKey,
  vkCommit: s.vkCommit, members: { ...s.members }, pending: s.pending, deleteId: s.deleteId, latestAdds: { ...s.latestAdds },
});

/** §3.3 "Verdicts, in check order". `not_authorized` and `fork` are client verdicts and never reach the wire. */
export type VaultLogVerdict =
  | FrameVerdict
  | "wrong_vault"
  | "bad_seq"
  | "bad_prev"
  | "not_authorized"
  | "bad_signature"
  | "precondition"
  | "fork";

/** An entry that passed the strict parse only: NOT authenticated and not placed in any chain. */
export interface UnverifiedLogEntry {
  readonly entry: LogEntry;
  readonly hash: string;
  readonly parts: FrameParts;
}

/** One verified step: `entry` verified against the state before it, and `state` after it. */
export interface VaultLogStep {
  readonly state: VaultState;
  readonly entry: LogEntry;
  readonly hash: string;
}

/** §3.3 `offer`: `expiresAt <= at + 14 d + 10 min`. */
export const MAX_OFFER_WINDOW_MS = 14 * 24 * 60 * 60 * 1000 + 10 * 60 * 1000;

// ---- §3.4 key commitment ---------------------------------------------------------------------------

/** `vkCommit = hexLower(HKDF-SHA-256(ikm = VK, salt = empty, info = "andvari/v2|vk-commit|" + vaultId, L = 32))`. */
export async function vkCommit(vk: Uint8Array, vaultId: string): Promise<string> {
  if (vk.length !== 32) throw new CryptoError("vault key must be 32 bytes");
  if (!isUuid(vaultId)) throw new CryptoError("vaultId is not a lowercase uuid");
  requireKey(vk); // spec 01 rule 4: no commitment is computed from a key of zeros (KeysGoneError), before the HKDF
  return toHexLower(await hkdfSha256(vk, new Uint8Array(0), new TextEncoder().encode(`andvari/v2|vk-commit|${vaultId}`), 32));
}

/**
 * §3.4: every vault key a client obtains, from any source, is checked against the state's `vkCommit`
 * before use. False means the key is REFUSED: nothing is decrypted or written under it.
 */
export async function keyMatches(vaultId: string, commit: string, vk: Uint8Array): Promise<boolean> {
  // A key of zeros matches no commitment (spec 01 rule 4): a served one is refused here, and nothing is derived from it.
  if (vk.length !== 32 || allZero(vk) || !isUuid(vaultId)) return false;
  const enc = new TextEncoder();
  return ctEquals(enc.encode(await vkCommit(vk, vaultId)), enc.encode(commit));
}

// ---- parse -----------------------------------------------------------------------------------------

function entryOf(raw: RawStatement): LogEntry {
  const head: EntryHead = { vaultId: raw.vaultId!, seq: Number(raw.seq), prev: raw.prev!, actor: raw.actor!, at: Number(raw.at) };
  switch (raw.kind as LogKindLiteral) {
    case "genesis": return { ...head, kind: "genesis", ownerKey: raw.ownerKey!, vkCommit: raw.vkCommit! };
    case "add": return { ...head, kind: "add", member: raw.member!, memberKey: raw.memberKey!, role: raw.role as MemberRole, grantId: raw.grantId! };
    case "role": return { ...head, kind: "role", member: raw.member!, role: raw.role as MemberRole };
    case "remove": return { ...head, kind: "remove", member: raw.member! };
    case "leave": return { ...head, kind: "leave" };
    case "offer": return { ...head, kind: "offer", to: raw.to!, toKey: raw.toKey!, offerId: raw.offerId!, expiresAt: Number(raw.expiresAt) };
    case "cancel": return { ...head, kind: "cancel", offerId: raw.offerId! };
    case "accept": return { ...head, kind: "accept", offerId: raw.offerId! };
    case "delete": return { ...head, kind: "delete", deleteId: raw.deleteId! };
    case "restore": return { ...head, kind: "restore", deleteId: raw.deleteId! };
  }
}

/**
 * The §2 parse of one entry and nothing more (§3.3 verdict 1): the frame, purpose 0x03, the strict
 * parse of §3.1's template for its `kind`, and §3.2's template rules. No chain, no signer, no signature.
 */
export function parseLogEntry(frame: Uint8Array): Checked<UnverifiedLogEntry, VaultLogVerdict> {
  const parsed = parseFrame(frame, "vault-log");
  if (!parsed.ok) return parsed;
  return ok({ entry: entryOf(parsed.value.raw), hash: frameHash(frame), parts: parsed.value.parts });
}

// ---- §3.3 the transition table ---------------------------------------------------------------------

type Signer = { readonly key: string } | { readonly verdict: "not_authorized" | "precondition" };

/**
 * One row of §3.3's table. All three read the state BEFORE the entry, with an expired offer already
 * cleared (`pending`). `holds` and `apply` are apart so that a refused entry changes nothing: every
 * check of the row, and the fork check after it, passes before `apply` touches the working state.
 */
interface Rule<K extends LogKind> {
  /** Step 5: the key the row names as signer. `precondition` when the state holds no such key (FI-B1). */
  signer(s: Working, e: EntryOf<K>, pending: PendingOffer | null): Signer;
  /** Step 7: the row's conditions. */
  holds(s: Working, e: EntryOf<K>, pending: PendingOffer | null): boolean;
  /** The effect, IN PLACE, one step whatever the size of the state. `s.pending` is already the cleared `pending`. */
  apply(s: Working, e: EntryOf<K>, pending: PendingOffer | null): void;
}

/** "Signer key must be `S.ownerKey`, with `actor = S.owner`". */
const byOwner = (s: Working, e: EntryHead): Signer => (e.actor === s.owner ? { key: s.ownerKey } : { verdict: "not_authorized" });
/** "if `pending.to = member`, then `pending = none`". */
const unlessTo = (pending: PendingOffer | null, userId: string): PendingOffer | null => (pending !== null && pending.to === userId ? null : pending);
const has = (record: Readonly<Record<string, unknown>>, userId: string): boolean => Object.prototype.hasOwnProperty.call(record, userId);

const RULES: { readonly [K in Exclude<LogKind, "genesis">]: Rule<K> } = {
  add: {
    signer: byOwner,
    holds: (s, e) => s.deleteId === null && !has(s.members, e.member),
    apply: (s, e) => {
      s.members[e.member] = { key: e.memberKey, role: e.role, addSeq: e.seq };
      // This account's latest add replaces any earlier one: a grant binds to the latest only (§3.5 step 6).
      s.latestAdds[e.member] = { seq: e.seq, actor: e.actor, ownerKey: s.ownerKey, member: e.member, memberKey: e.memberKey, role: e.role, grantId: e.grantId };
    },
  },
  role: {
    signer: byOwner,
    holds: (s, e) => s.deleteId === null && has(s.members, e.member) && e.member !== s.owner,
    apply: (s, e, pending) => {
      s.members[e.member] = { ...s.members[e.member]!, role: e.role };
      s.pending = unlessTo(pending, e.member);
    },
  },
  remove: {
    signer: byOwner,
    holds: (s, e) => s.deleteId === null && has(s.members, e.member) && e.member !== s.owner,
    apply: (s, e, pending) => {
      delete s.members[e.member];
      s.pending = unlessTo(pending, e.member);
    },
  },
  leave: {
    // The leaving member's own key. Someone who is not a member has no key in the state: `precondition`.
    signer: (s, e) => (has(s.members, e.actor) ? { key: s.members[e.actor]!.key } : { verdict: "precondition" }),
    // Allowed while the vault is deleted (B2). The owner cannot leave.
    holds: (s, e) => e.actor !== s.owner,
    apply: (s, e, pending) => {
      delete s.members[e.actor];
      s.pending = unlessTo(pending, e.actor);
    },
  },
  offer: {
    signer: byOwner,
    holds: (s, e, pending) => {
      if (s.deleteId !== null || !has(s.members, e.to) || e.to === s.owner || s.members[e.to]!.key !== e.toKey) return false;
      // at < expiresAt <= at + 14 d + 10 min, as a difference: both are below 2^53, so it is exact.
      if (e.expiresAt <= e.at || e.expiresAt - e.at > MAX_OFFER_WINDOW_MS) return false;
      // "pending = none, or pending.expiresAt < at": an expired offer was already cleared.
      return pending === null;
    },
    apply: (s, e) => {
      s.pending = { offerId: e.offerId, to: e.to, toKey: e.toKey, expiresAt: e.expiresAt };
    },
  },
  cancel: {
    signer: (s, e, pending) => {
      if (e.actor === s.owner) return { key: s.ownerKey };
      if (pending === null) return { verdict: "precondition" };
      return e.actor === pending.to ? { key: pending.toKey } : { verdict: "not_authorized" };
    },
    holds: (_s, e, pending) => pending !== null && pending.offerId === e.offerId,
    apply: (s) => {
      s.pending = null;
    },
  },
  accept: {
    signer: (_s, e, pending) => {
      if (pending === null) return { verdict: "precondition" };
      return e.actor === pending.to ? { key: pending.toKey } : { verdict: "not_authorized" };
    },
    holds: (s, e, pending) =>
      s.deleteId === null && pending !== null && pending.offerId === e.offerId && e.at <= pending.expiresAt &&
      has(s.members, s.owner) && has(s.members, pending.to),
    apply: (s, _e, pending) => {
      const target = pending!; // `holds` established it
      s.members[s.owner] = { ...s.members[s.owner]!, role: "writer" };
      s.members[target.to] = { ...s.members[target.to]!, role: "owner" };
      s.owner = target.to;
      s.ownerKey = target.toKey;
      s.pending = null;
    },
  },
  delete: {
    signer: byOwner,
    holds: (s) => s.deleteId === null,
    apply: (s, e) => {
      s.deleteId = e.deleteId;
      s.pending = null;
    },
  },
  restore: {
    signer: byOwner,
    holds: (s, e) => s.deleteId !== null && s.deleteId === e.deleteId,
    apply: (s) => {
      s.deleteId = null;
    },
  },
};

function signerBinds(parts: FrameParts, keyB64: string): boolean {
  const key = fromB64Exact(keyB64, 32);
  return key !== null && signerMapsTo(parts, key);
}

/**
 * Verify ONE entry against the state before it (§3.3). `prior` is the state after the previous entry,
 * or null when `frame` must be the genesis; `vaultId` is the vault being verified. Clock-free.
 *
 * The first failure is the verdict, in this order: the §2 parse; `wrong_vault`; `bad_seq`; `bad_prev`;
 * `not_authorized` (before it, an offer whose `expiresAt` is below the entry's `at` is cleared, and a
 * row whose signer key does not exist in the state is `precondition`, FI-B1); `bad_signature`;
 * `precondition` (the time rule `at >= previous.at`, then the row's conditions); `fork` when `known`
 * holds another hash for this `seq` (a verified entry, a checkpoint, the account's vault record).
 * `known` has no default: a caller says what it holds, or says {@link NONE_HELD}.
 */
export function verifyLogEntry(
  vaultId: string,
  prior: VaultState | null,
  frame: Uint8Array,
  known: KnownHashes,
): Checked<VaultLogStep, VaultLogVerdict> {
  requireKnown(known);
  // One entry: the state it is judged against is copied once, and the copy becomes the state after it.
  const step = advance(vaultId, prior === null ? null : thaw(prior), frame, known);
  if (!step.ok) return step;
  return ok(Object.freeze({ state: brand(step.value.working), entry: Object.freeze(step.value.entry), hash: step.value.hash }));
}

/**
 * Steps 1 to 8 for one frame against the working state `w` (null: the frame must be the genesis). On
 * success `w` has become the state after the entry (for a genesis, a new one is made). On ANY refusal
 * `w` is exactly as it was: every check, the fork check included, comes before the first change.
 */
function advance(
  vaultId: string,
  w: Working | null,
  frame: Uint8Array,
  known: KnownHashes,
): Checked<{ readonly working: Working; readonly entry: LogEntry; readonly hash: string }, VaultLogVerdict> {
  const parsed = parseLogEntry(frame);
  if (!parsed.ok) return parsed;
  const { entry: e, hash, parts } = parsed.value;

  if (e.vaultId !== vaultId || (w !== null && w.vaultId !== vaultId)) return refused("wrong_vault");
  if (e.seq !== (w === null ? 0 : w.head.seq + 1)) return refused("bad_seq");
  if (w !== null && e.prev !== w.head.hash) return refused("bad_prev");
  const forked = (): boolean => {
    const seen = known(e.seq);
    return seen !== null && seen !== undefined && seen !== hash;
  };

  if (w === null) {
    // A first entry sits at seq 0, which the template rules tie to `genesis`. It signs itself (VR-2).
    if (e.kind !== "genesis") return refused("bad_seq");
    if (!signerBinds(parts, e.ownerKey)) return refused("not_authorized");
    if (!signatureValid(parts)) return refused("bad_signature");
    if (forked()) return refused("fork");
    const working: Working = {
      vaultId: e.vaultId, head: { seq: 0, hash }, at: e.at, genesisHash: hash, creator: e.actor, owner: e.actor,
      ownerKey: e.ownerKey, vkCommit: e.vkCommit, members: { [e.actor]: { key: e.ownerKey, role: "owner", addSeq: null } },
      pending: null, deleteId: null, latestAdds: {},
    };
    return ok({ working, entry: e, hash });
  }

  if (e.kind === "genesis") return refused("bad_seq");
  // T-R1, FI-B1: clear an expired offer before step 5; everything below sees the state without it.
  const pending = w.pending !== null && e.at <= w.pending.expiresAt ? w.pending : null;
  const rule = RULES[e.kind] as Rule<typeof e.kind>;
  const signer = rule.signer(w, e as never, pending);
  if ("verdict" in signer) return refused(signer.verdict);
  if (!signerBinds(parts, signer.key)) return refused("not_authorized");
  if (!signatureValid(parts)) return refused("bad_signature");
  if (e.at < w.at) return refused("precondition");
  if (!rule.holds(w, e as never, pending)) return refused("precondition");
  if (forked()) return refused("fork");
  // Every check passed: only now is the state changed.
  w.pending = pending;
  rule.apply(w, e as never, pending);
  w.head = { seq: e.seq, hash };
  w.at = e.at;
  return ok({ working: w, entry: e, hash });
}

/** The result of {@link replayLog}: the state after the last GOOD entry, how many frames verified, and the first failing frame's verdict (null: all verified). */
export interface VaultLogReplay {
  readonly state: VaultState | null;
  readonly accepted: number;
  readonly verdict: VaultLogVerdict | null;
}

/**
 * Verify `frames` in order from `from` (null: from the genesis), stopping at the first that fails (§3.9).
 *
 * The cost is one step per entry, whatever the vault's size: the state is built in place and frozen
 * once, at the end or at the first frame that fails. (Calling {@link verifyLogEntry} in a loop copies the
 * member map for every entry; a caller with many frames uses this.)
 *
 * Neither `from` nor `known` has a default: a caller says where it starts (null for the genesis) and
 * what it holds ({@link NONE_HELD} for nothing).
 */
export function replayLog(vaultId: string, frames: readonly Uint8Array[], from: VaultState | null, known: KnownHashes): VaultLogReplay {
  requireKnown(known);
  let working = from === null ? null : thaw(from);
  let applied = 0;
  // Nothing applied yet: the state is `from` itself. After that, the working state, frozen.
  const stateNow = (): VaultState | null => (applied === 0 ? from : brand(working!));
  for (let i = 0; i < frames.length; i++) {
    const step = advance(vaultId, working, frames[i]!, known);
    if (!step.ok) return { state: stateNow(), accepted: i, verdict: step.verdict };
    working = step.value.working;
    applied++;
  }
  return { state: stateNow(), accepted: frames.length, verdict: null };
}

// ---- building --------------------------------------------------------------------------------------

/** Where the entry after `state`'s head sits, with `at = max(clockMs, state.at)` (§3.3, T-R1). */
export function logPosition(state: VaultState, clockMs: number): { seq: number; prev: string; at: number } {
  return { seq: state.head.seq + 1, prev: state.head.hash, at: Math.max(clockMs, state.at) };
}

/** Where the entry after a SERVED head sits (§3.11): for the leaves of an account deletion. */
export function logPositionAfter(headSeq: number, headHash: string, headAt: number, clockMs: number): { seq: number; prev: string; at: number } {
  return { seq: headSeq + 1, prev: headHash, at: Math.max(clockMs, headAt) };
}

/** The first position of a log: a genesis has `seq = 0` and `prev` = 64 zeros (§3.2). */
export const GENESIS_POSITION = Object.freeze({ seq: 0, prev: ZERO_HASH });

function fieldsOf(e: LogEntry): Record<string, string> {
  const { kind, seq, at, ...rest } = e as LogEntry & Record<string, string | number>;
  const out: Record<string, string> = { kind, seq: String(seq), at: String(at) };
  for (const [k, v] of Object.entries(rest)) out[k] = String(v);
  return out;
}

/**
 * Encode `entry` and sign it with `signer`, the account's joint Ed25519 key. Throws `CryptoError` for
 * an entry outside the grammar. It does NOT check the entry against a state: use
 * {@link signLogEntryChecked}. A client keeps the returned bytes in its pending-append record and
 * re-posts THESE bytes; it never re-signs with a new `at` (§3.7, T-R2).
 */
export function signLogEntry(signer: KeyPairBytes, entry: LogEntry): Uint8Array {
  return signFrame(signer, "vault-log", encodeStatement("vault-log", fieldsOf(entry)));
}

/** {@link signLogEntry}, then {@link verifyLogEntry} against `prior`: the frame comes back only if this client's own verifier accepts it there. */
export function signLogEntryChecked(
  signer: KeyPairBytes,
  prior: VaultState | null,
  entry: LogEntry,
): Checked<{ readonly frame: Uint8Array; readonly step: VaultLogStep }, VaultLogVerdict> {
  const frame = signLogEntry(signer, entry);
  // Judged against `prior` alone: it is this client's own new entry, signed at the head it verified.
  const step = verifyLogEntry(entry.vaultId, prior, frame, NONE_HELD);
  return step.ok ? ok({ frame, step: step.value }) : step;
}

// ---- the stored form of a state ---------------------------------------------------------------------

/**
 * The version of the stored form. 2 keeps one latest `add` per account (`latestAdds`); 1 kept every
 * `add` of the log (`adds`). A stored state of another version decodes to null, and the client replays
 * the log from its genesis, which is the rule for any state it cannot read.
 */
const STATE_VERSION = 2;

/** This browser's stored form of a state. Not a wire format. */
export function encodeVaultState(state: VaultState): string {
  return JSON.stringify({ v: STATE_VERSION, ...(state as StateFields) });
}

const STATE_KEYS = ["v", "vaultId", "head", "at", "genesisHash", "creator", "owner", "ownerKey", "vkCommit", "members", "pending", "deleteId", "latestAdds"];
const isObject = (x: unknown): x is Record<string, unknown> => typeof x === "object" && x !== null && !Array.isArray(x);
const exactKeys = (o: Record<string, unknown>, keys: readonly string[]): boolean =>
  Object.keys(o).length === keys.length && keys.every((k) => Object.prototype.hasOwnProperty.call(o, k));

/**
 * Restore a state this browser stored with {@link encodeVaultState}. Null when `text` is not one
 * (damaged, or from another build): the client then replays the log from its genesis. Never call this
 * on a value that came from a server.
 */
export function decodeVaultState(text: string): VaultState | null {
  let d: unknown;
  try {
    d = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isObject(d) || !exactKeys(d, STATE_KEYS) || d.v !== STATE_VERSION) return null;
  const head = d.head;
  if (!isObject(head) || !exactKeys(head, ["seq", "hash"]) || typeof head.seq !== "number" || !isInt(head.seq)) return null;
  if (typeof head.hash !== "string" || !isHex64(head.hash) || typeof d.at !== "number" || !isMs(d.at)) return null;
  const str = (x: unknown, check: (s: string) => boolean): x is string => typeof x === "string" && check(x);
  if (!str(d.vaultId, isUuid) || !str(d.genesisHash, isHex64) || !str(d.creator, isUuid) || !str(d.owner, isUuid)) return null;
  if (!str(d.ownerKey, isB64_32) || !str(d.vkCommit, isHex64)) return null;

  if (!isObject(d.members)) return null;
  const members: Record<string, VaultMember> = {};
  for (const [userId, m] of Object.entries(d.members)) {
    if (!isUuid(userId) || !isObject(m) || !exactKeys(m, ["key", "role", "addSeq"]) || !str(m.key, isB64_32)) return null;
    if (m.role !== "owner" && m.role !== "writer" && m.role !== "reader") return null;
    let addSeq: number | null = null;
    if (m.addSeq !== null) {
      if (typeof m.addSeq !== "number" || !isInt(m.addSeq) || m.addSeq < 1 || m.addSeq > head.seq) return null;
      addSeq = m.addSeq;
    }
    if ((m.role === "owner") !== (userId === d.owner)) return null;
    members[userId] = { key: m.key, role: m.role, addSeq };
  }
  if (members[d.owner]?.key !== d.ownerKey) return null;

  let pending: PendingOffer | null = null;
  if (d.pending !== null) {
    const p = d.pending;
    if (!isObject(p) || !exactKeys(p, ["offerId", "to", "toKey", "expiresAt"])) return null;
    if (!str(p.offerId, isB64_16) || !str(p.to, isUuid) || !str(p.toKey, isB64_32) || typeof p.expiresAt !== "number" || !isMs(p.expiresAt)) return null;
    pending = { offerId: p.offerId, to: p.to, toKey: p.toKey, expiresAt: p.expiresAt };
  }
  if (d.deleteId !== null && !str(d.deleteId, isB64_16)) return null;

  if (!isObject(d.latestAdds)) return null;
  const latestAdds: Record<string, AddRecord> = {};
  for (const [member, a] of Object.entries(d.latestAdds)) {
    if (!isObject(a) || !exactKeys(a, ["seq", "actor", "ownerKey", "member", "memberKey", "role", "grantId"])) return null;
    if (typeof a.seq !== "number" || !isInt(a.seq) || a.seq < 1 || a.seq > head.seq) return null;
    if (!str(a.actor, isUuid) || !str(a.ownerKey, isB64_32) || !str(a.member, isUuid) || !str(a.memberKey, isB64_32) || !str(a.grantId, isB64_16)) return null;
    if (a.role !== "writer" && a.role !== "reader") return null;
    if (a.member !== member) return null; // filed under the account it adds
    latestAdds[member] = { seq: a.seq, actor: a.actor, ownerKey: a.ownerKey, member: a.member, memberKey: a.memberKey, role: a.role, grantId: a.grantId };
  }
  // A member's `addSeq` is its latest add; only the creator, while never added, has none (FN-2).
  for (const [userId, m] of Object.entries(members)) {
    const add = has(latestAdds, userId) ? latestAdds[userId]! : null;
    if (m.addSeq === null ? userId !== d.creator || add !== null : add === null || add.seq !== m.addSeq || add.memberKey !== m.key) return null;
  }
  return brand({
    vaultId: d.vaultId, head: { seq: head.seq, hash: head.hash }, at: d.at, genesisHash: d.genesisHash, creator: d.creator,
    owner: d.owner, ownerKey: d.ownerKey, vkCommit: d.vkCommit, members, pending, deleteId: d.deleteId as string | null, latestAdds,
  });
}
