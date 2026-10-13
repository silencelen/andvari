import type { ApiClient } from "../api/client";
import { ApiError } from "../api/client";
import type {
  AttachmentRef,
  ItemDoc,
  Mutation,
  PendingTransfer,
  PersonalWrap,
  PushResponse,
  RemovedGrantInfo,
  UserLookupResponse,
  VaultMemberSummary,
  WireGrant,
  WireItem,
  WireVault,
} from "../api/types";
import { HEADER_BYTES, decryptAttachment, encryptAttachment, wireLength } from "../crypto/attachments";
import { concat, fromB64, toB64, toHexLower, utf8 } from "../crypto/bytes";
import {
  acceptProof,
  acceptProofFromHash,
  decideRemoval,
  deleteProof,
  leaveProof,
  newRemovalNonce,
  offerProof,
  removeV2Proof,
  restoreProof,
  verifyProof,
} from "../crypto/lifecycleproof";
import { randomBytes, sha256, sha256Sync } from "../crypto/provider";
import type { ImportProjections } from "../import/csv";
import { ITEM_FORMAT_VERSION, type Account, type ItemUpload, type LegacyVouchKind, ReauthFailedError, ReauthStaleSessionError, VaultKeyNotVerifiedError } from "./account";
import { type ConsumedNonce, type Contact, withIssued, withMemberReceived, withoutIssued, withOwned, withoutOwned, withPersonal } from "./accountstate";
import {
  admitRow,
  chosenProvenance,
  conflictDecision,
  editDecision,
  editorProvenance,
  envelopeProvenance,
  ItemChangedVaultsError,
  sealDecision,
  type SealProvenance,
  serverItemDecision,
  WrongVaultTally,
} from "./itemhome";
import { pinFromQr, pinFromTyped, pinState } from "./contacts";
import { AccountStateSync, type ClientStateStore, localClientState } from "./accountstatesync";
import { type CoHolder, type PersonalCandidate, type PersonalChange, type PersonalChoiceInfo, type PersonalVaultProposal, personalVaultChoices } from "./personalvault";
import { type HeldVaultRecord, NullCache, type PullBatch, type QueuedPreEdit, type VaultCache } from "./idbcache";

/**
 * H37's fold, and (R32) everything needed to UNDO it.
 *
 * `baseItemRev`/`pre` are what the folded put rides: the oldest folded row's base rev, and the
 * burst's original pre-edit value. `rows` is the fold itself — the dequeued mutations with their
 * durable pre-edit blobs, in their original FIFO order — kept so the one path that throws the
 * folding save away can put the member's offline backlog back instead of destroying it.
 */
type FoldedPuts = {
  baseItemRev: number;
  pre: VaultItem | null;
  rows: Array<{ mutation: Mutation; preEdit?: QueuedPreEdit }>;
};

export interface VaultItem {
  itemId: string;
  vaultId: string;
  rev: number;
  updatedAt: number;
  /** The fv the live row is STORED at (wire fv at decrypt; the upload's fv at local apply)
   *  — record/display only (backups enumerate it, spec 07 §3; Android parity: the stored
   *  fv, not the doc floor). The seal-time authority is Account's monotonic per-item map. */
  formatVersion: number;
  doc: ItemDoc;
}

/** A vault we hold the key for — for pickers, badges, and the Sharing view. */
export interface VaultInfo {
  vaultId: string;
  type: string;
  name: string;
  role: string | null;
}

/** Minimal identity of an item we hold the vault key for but could not decrypt —
 *  spec 07 §2.4's `skipped.undecryptable` shape (structurally export.ts's
 *  BackupSkippedItem; declared here so vault/ doesn't import from export/). */
export interface UndecryptableItem {
  itemId: string;
  vaultId: string;
  formatVersion: number;
}

/** A UUIDv4-shaped id deterministically derived from a label's sha256 (spec 03 §5 shape). */
async function uuidFromLabel(label: string): Promise<string> {
  const h = (await sha256(utf8(label))).slice(0, 16);
  h[6] = (h[6]! & 0x0f) | 0x40; // version nibble 4
  h[8] = (h[8]! & 0x3f) | 0x80; // variant 10
  const hex = toHexLower(h);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * UUIDv4-shaped id from sha256("conflict|itemId|rev") (spec 03 §5): concurrent
 * materializers across members/devices converge on ONE copy id, absorbed by the
 * server's idempotent existing-item path. Mirrors core SyncEngine byte-for-byte.
 */
export function conflictCopyId(itemId: string, rev: number): Promise<string> {
  return uuidFromLabel(`conflict|${itemId}|${rev}`);
}

/** PDD-1: a server-returned displaced value, the winner's rev, and the vault the losing put was pushed to (A1b). */
interface Displaced {
  item: WireItem;
  winnerRev: number;
  pushedVaultId: string;
}

/** The reason a grant went away (spec 03 §11), as delivered in removedGrantsInfo. */
export type RemovedReason = "removed" | "left" | "deleted" | "transferred";

/**
 * A lifecycle notice the UI renders (spec 03 §11 / design §11). Fired ONLY for vaults held
 * locally before the pull — never on since=0 / fresh-device pulls. Attribution ("by its
 * owner") is EARNED by a verified proof; unverified events get calm/anomaly wording.
 */
export interface LifecycleNotice {
  id: string;
  vaultId: string;
  vaultName: string;
  kind:
    | "deleted"
    | "removed"
    | "left"
    | "anomaly"
    | "restored"
    | "added"
    | "transfer-complete"
    | "transfer-anomaly"
    | "replay-denied"
    | "write-refused"
    | "write-rejected"
    | "meta-regression"
    // Root cause A §3.1 (security review 2026-10): a grant row carried a seal whose key differs from
    // our own UVK wrap (ours was kept), or our UVK wrap is present and does not open (no seal fallback).
    | "vk-mismatch"
    | "key-unreadable"
    // Root cause A §1.4 (A6): a v2 grant failed a check that only a misbehaving server explains; nothing was
    // adopted. `reason` carries the verdict code; vaultName is "" (no authenticated key, no name).
    | "grant-anomaly"
    // Root cause A §5.1 INV-HOME (A1b): the server sent an item under another vault than the one this device holds it
    // in (or a conflict row disagreeing about its vault); NOT applied. One per pull; vaultId = the first offending
    // row's vault, parkedCount = how many rows were refused; vaultName "".
    | "wrong-vault";
  /** verified delete: the server-erase deadline (for the "kept sealed until…" line). */
  purgeAt?: number;
  /** verified delete: N of the member's edits parked for replay on restore (F21).
   *  Doubles as the count for "replay-denied" (recovered edits refused on the restored
   *  vault) and "write-refused" (offline edits genuinely denied at classification). */
  parkedCount?: number;
  /** write-refused only (M3 — the copy must not claim a restore that didn't happen):
   *  how many of the refused edits were actually REVERTED to their last synced value
   *  (a pre-edit snapshot existed and was still safe to apply) ... */
  revertedCount?: number;
  /** ... and how many targeted an item the SERVER itself deleted meanwhile (M1 — the
   *  denied local delete is moot; nothing is restored, the item stays removed). The
   *  remainder (parkedCount − reverted − removed) had no applicable snapshot: the
   *  banner hedges ("may be out of date") instead of claiming a revert. */
  removedCount?: number;
  /** write-rejected (H03/H19): the server's refusal reason for the (first) dropped row —
   *  `unknown_attachment` / `attachment_mismatch` (the referenced attachment is gone),
   *  `item_attachment_quota` / `body_too_large` (too large), else unspecified. Picks the
   *  explanation clause; parkedCount/revertedCount/removedCount carry the counts as for
   *  write-refused. Core twin: LifecycleNotice.reason. */
  reason?: string;
  /** transfer-complete: who now owns the vault, and whether that is us. */
  newOwnerUserId?: string;
  becameMine?: boolean;
  /** `added` from a VERIFIED v2 grant (root cause A §1.6): the PINNED contact's label, for "…by <contact>". */
  byLabel?: string;
}

/** §1.6: a v2 grant from someone not verified on this device. Not adopted; no vault name (it would decrypt under
 *  a key nobody authenticated). `fromUserId` is unverified routing data: whom to verify. Core `PendingInvitation`. */
export interface PendingInvitation {
  vaultId: string;
  fromUserId: string;
  grantIdB64: string;
}

/** §8.2 "Review your shared vaults": a vault readable only through a v1 seal nobody vouched for yet. */
export interface LegacyVaultReview {
  vaultId: string;
  name: string | null;
  itemCount: number;
}

/** How a served identity relates to this device's pins, for add-member (§1.5, §7.2; core `MemberPinState`). */
export type MemberPinState = "pinned" | "key-changed" | "needs-verification";

/** add-member refused a member not pinned (or not current) on this device (§1.5): verify them first. */
/** A6b: an owner-only signing action on a vault this account has no evidence of owning (the server's `role=owner`
 *  label is not evidence). The UI asks "You own <vault>?" (confirmOwnership) first. */
export class OwnershipNotConfirmedError extends Error {
  constructor(readonly vaultId: string) {
    super("Confirm that you own this vault first — this device has no record that you created it or accepted it.");
    this.name = "OwnershipNotConfirmedError";
  }
}

/** A6b review MEDIUM-1: the vault's key reached this browser as a MEMBER; claiming it needs the explicit
 *  "This vault's owner transferred it to me" on top of the password. */
export class OwnershipTransferAckRequiredError extends Error {
  constructor(readonly vaultId: string) {
    super("This device received this vault as a member: confirm that its owner transferred it to you.");
    this.name = "OwnershipTransferAckRequiredError";
  }
}

/** What "You own <vault>?" shows (A6b review MEDIUM-1; core `OwnershipClaim` twin). All but `receivedAsMember` is AS
 *  REPORTED BY THE SERVER. */
export interface OwnershipClaim {
  vaultId: string;
  vaultName: string | null;
  reportedOwner: CoHolder | null;
  lastTransferTo: CoHolder | null;
  lastTransferSeq: number | null;
  coHolders: CoHolder[];
  origin: "created" | "received";
  receivedAsMember: boolean;
}

// The reauth errors live in account.ts since A9 (M-1 / the review's LOW-1), beside the one fenced derivation that raises
// them; re-exported here for the UI's existing imports.
export { ReauthFailedError, ReauthStaleSessionError };

/** A9 review LOW-2: a save, import or copy with no explicit destination while no personal vault is in force (the
 *  designation is still a proposal, or none exists). Core twin `NoPersonalVaultException` / `HouseholdCopy.NO_PERSONAL_VAULT`,
 *  byte-equal (vault-copy.test.ts). */
export class NoPersonalVaultError extends Error {
  constructor() {
    super("Choose a vault for this item.");
    this.name = "NoPersonalVaultError";
  }
}

export { ItemChangedVaultsError } from "./itemhome";

/**
 * One row of the "Legacy grants" list (§8.2 step 4, A6b; core `LegacyGrantRow` twin). Everything but `verifiedLabel`
 * and `pinState` is what the SERVER reports: the list itself comes from the server, so the owner confirms each row.
 */
export interface LegacyGrantRow {
  vaultId: string;
  /** Decrypted under the held key (null when it does not decrypt). */
  vaultName: string | null;
  userId: string;
  /** Server-reported. */
  displayName: string;
  /** Server-reported. */
  email: string;
  /** The key the server serves for the member; must equal the pin for a confirmation. */
  identityPub: string;
  /** The label of this device's CURRENT pin for the member (a human verified it); null when not pinned here. */
  verifiedLabel: string | null;
  pinState: MemberPinState;
  /** False when this account has no evidence of owning the vault yet ("You own <vault>?" first). */
  ownershipConfirmed: boolean;
  /** A9 (M-3): when this account's issued-grants record says it once signed this vault to this member, the ms it did
   *  (the hint "you shared this vault with them on …"). DISPLAY ONLY: it pre-ticks nothing and never re-issues; every
   *  signing is the owner's tap. Null when there is no record, or when THIS browser removed the member (its own durable
   *  tombstone outranks a record a rolled-back account state brought back). */
  previouslySharedAt: number | null;
}

export class MemberNotVerifiedError extends Error {
  constructor(readonly userId: string) {
    super("Verify this member before sharing with them — their identity code is not confirmed on this device.");
    this.name = "MemberNotVerifiedError";
  }
}

/** A5b review LOW-1/LOW-2 (closed in A6): what "Use the new personal vault" means, loaded BEFORE it is offered.
 *  Co-holders and origin are what the SERVER reports. Core `PersonalChangeDetails` twin. */
export interface PersonalChangeDetails {
  currentVaultId: string;
  currentName: string | null;
  servedVaultId: string;
  servedName: string | null;
  servedCoHolders: CoHolder[];
  servedOrigin: "created" | "received";
}

// Root cause A §8.2 (A6) client-state keys (per user, survive a reload). Core SyncEngine twins. The legacy vouches
// are lines "vaultId|tag|kind" (tag = hex SHA-256 of the vouched key, kind = frozen | confirmed; A6 review HIGH-1).
// The freeze marker lives in the durable cache itself (VaultCache.freezeDone, A6 review LOW-1).
const LEGACY_AUTHORIZED_KEY = "grant.legacy.authorized";
const DECLINED_KEY = "grant.declined";
/** Branch A7: the per-vault held-key memory, `vaultId|sha256(VK)` lines, stored beside the vouches (core twin). */
export const HELD_KEYS_KEY = "grant.held.keys";
/** A6b review MEDIUM-1: vaults this browser first adopted a key for as a MEMBER (durable provenance). */
export const MEMBER_GRANTED_KEY = "grant.member.granted";
/** A9 (M-3): `"<vaultId>|<userId>|<ms>"` lines, one per member THIS browser removed (durable client state). */
export const ISSUED_TOMBSTONES_KEY = "grant.issued.tombstones";
/** LifecycleNotice.reason on a `left` notice whose leave carried no proof (in-window, §8.6). Core `LEFT_UNPROVEN`. */
export const LEFT_UNPROVEN = "unproven";
/** LifecycleNotice.reason on a `replay-denied` raised by a consumed removal nonce (§6.3 step 5). Core `REMOVAL_REPLAY`. */
export const REMOVAL_REPLAY = "removal";
/** LifecycleNotice.reason on a removed/left notice whose nonce another of this user's devices already consumed (only in
 *  account state; A7 review MEDIUM-2). Core `ALREADY_RECORDED`. */
export const ALREADY_RECORDED = "already-recorded";
/** LifecycleNotice.reason on a `removed` notice attributed by a v1 (legacy) proof, in-window (A7 review LOW-3). */
export const REMOVED_LEGACY = "legacy";

/** A restorable in-grace deleted vault (GET /vaults/deleted), name decrypted locally. */
export interface DeletedVaultInfo {
  vaultId: string;
  name: string;
  deletedAt: number;
  purgeAt: number;
  deleteId: string;
}

/** A verified incoming ownership offer TO this user — the accept consent screen renders
 *  only after the offer proof verifies under the held VK (spec 03 §11). */
export interface IncomingTransfer {
  vaultId: string;
  vaultName: string;
  offerId: string;
  seq: number;
  expiresAt: number;
}

/** A move/copy gesture (F19, design §8). Minted ONCE (fresh newItemId + per-attachment fresh
 *  fileKeys); a RETRY of the SAME gesture converges via server mutation-dedup — never a fresh
 *  gesture, which would collide-or-duplicate. `sourceRev` is the rev of the content copied,
 *  so the delete leg's baseItemRev catches a source that changed mid-move. */
export interface MoveGesture {
  gestureId: string;
  sourceItemId: string;
  sourceVaultId: string;
  sourceRev: number;
  targetVaultId: string;
  newItemId: string;
  del: boolean; // true = move (copy then delete source); false = copy only
  attachments: { oldId: string; newId: string; newFileKey: string; name: string; size: number }[];
}

/** F19: the target vault denied the copy — source untouched, gesture aborted (design §8). */
export class CopyDeniedError extends Error {
  readonly code = "copy_denied";
  constructor() {
    super("The copy to the target vault was denied — you may not have write access there.");
    this.name = "CopyDeniedError";
  }
}

/** F19: the source changed since we read it — the move is aborted, nothing deleted (design §8). */
export class ItemChangedError extends Error {
  readonly code = "item_changed";
  constructor() {
    super("This item changed while moving — review and retry.");
    this.name = "ItemChangedError";
  }
}

interface HeldVault {
  vault: WireVault;
  grant: WireGrant | null; // ciphertext grant retained (normative) so reinstate can re-open VK
  items: WireItem[]; // re-sealed ciphertext snapshot (ciphertext-only at rest)
  reason: RemovedReason;
  verified: boolean;
  cachedName: string;
  purgeAt?: number;
  deleteId?: string;
  parked: Mutation[];
  expungeAt: number;
}

/** A newly attached file awaiting upload: plaintext bytes + the id its doc entry carries. */
export interface PendingUpload {
  id: string;
  data: Uint8Array;
}

/**
 * §D.3 / breaker #3: a denied mutation awaiting its park-vs-genuine verdict, tagged with
 * the pull-start epoch at staging time — the web twin of core `SyncEngine.StagedDenial`.
 * `surfaceStagedDenials` may classify it ONLY once a pull that STARTED after `stagedBefore`
 * has completed, so a verdict can never come from a stale snapshot that predates the denial
 * (e.g. a save's `sync()` that JOINED an older in-flight pull). A too-fresh entry stays
 * durably staged (the queue row's `staged` flag) for the next cycle.
 */
interface StagedDenial {
  mutation: Mutation;
  stagedBefore: number;
  /** Core `StagedDenial.wasReplay` twin: this edit was itself a reinstate replay (F21), so a
   *  GENUINE denial of it surfaces as the calm "replay-denied" notice, never a thrown sync
   *  failure — the member's role may simply have changed across the grace. Not durable: a
   *  restart reloads it as false (core LC-1 hydrate note) — that costs a harsher notice at
   *  worst, never the edit. */
  wasReplay?: boolean;
}

/**
 * C2 (2026-07-14 review): the pre-edit truth captured at enqueue time, keyed by mutationId.
 * save()/remove() apply OPTIMISTICALLY (memory + disk envelope) before the verdict exists;
 * if the write is later classified a GENUINE denial, surfaceStagedDenials restores exactly
 * this snapshot — a delta server never re-delivers an unchanged row, so without it the
 * refused value (or a refused local delete) would sit in memory and on disk forever.
 * M2 (2026-07-14 re-review): this map is the FAST PATH; each snapshot also rides its queue
 * row durably (QueuedPreEdit, sealed — A2) and hydrate restores it, so the ORDINARY restart
 * flow (edit offline → close → reopen → reconnect → denied) reverts exactly too. A snapshot
 * that can't be restored (pre-M2 row, undecryptable seal) keeps the old posture: the
 * "write-refused" notice still fires, and the stale optimistic row heals at the next full
 * resync. `pre === null` marks a NEW item with no prior (revert = delete it). For op "put",
 * the optimistic (rev, updatedAt) pair gates the revert so a fresher server row that landed
 * meanwhile is never regressed.
 */
interface PreEditSnapshot {
  pre: VaultItem | null;
  op: "put" | "delete";
  optimisticRev: number;
  optimisticUpdatedAt: number;
}

/**
 * F31 (spec 05 T1 / core `rev_regression` parity): the server's sync response failed a
 * rollback guard — nothing was applied and the cursor did not move. Typed so callers'
 * existing catch paths (Vault's syncNow flips the offline dot) absorb it without
 * mistaking it for a transport error, and distinct from ApiError because the server
 * DID answer — we refused the answer.
 */
export class SyncIntegrityError extends Error {
  readonly code = "rev_regression";
  constructor(message: string) {
    super(message);
    this.name = "SyncIntegrityError";
  }
}

/** §D.5: a cache commit waits at most this long for the cross-tab Web Lock before
 *  proceeding UNLOCKED (client.ts's refresh-lock posture — availability over strictness;
 *  the §D.5.1 cursor check keeps even unlocked commits convergent, breaker #7). */
const CACHE_LOCK_WAIT_MS = 10_000;

/** AbortSignal.timeout where available (twin of client.ts's module-local helper). */
function timeoutSignal(ms: number): AbortSignal | undefined {
  return typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function"
    ? AbortSignal.timeout(ms)
    : undefined;
}

/**
 * Client sync store: pulls deltas since a cursor, decrypts, materializes conflict
 * copies (spec 03 §5 — the CLIENT does this, the server can't re-encrypt), and pushes
 * mutations with stable mutationIds. Web MVP keeps decrypted items in memory only.
 */
export class VaultStore {
  /** Server rejects a push batch larger than this (Service.push → batch_too_large). */
  private static readonly SERVER_BATCH_MAX = 200;
  private cursor = 0;
  private itemsById = new Map<string, VaultItem>();
  private vaultsById = new Map<string, WireVault>();
  /** spec 07 §2.4: HELD-key decrypt failures retained at sync time (see [undecryptable]).
   *  Mutually exclusive with itemsById AND missingVkById — an itemId lives in exactly one of the three. */
  private undecryptableById = new Map<string, UndecryptableItem>();
  /** spec 07 §2.4: items whose vault VK we CANNOT open (a missing/undecryptable grant) — skipped
   *  from list() but ENUMERATED into a backup (mirrors the Kotlin ExportPlanner), never silently
   *  omitted. Kept separate from undecryptableById (held-but-failed); merged in [undecryptable]. */
  private missingVkById = new Map<string, UndecryptableItem>();
  /** The wire rows behind missingVkById (A6): a pending invitation accepted later, or a re-issued grant, makes
   *  these readable without a re-pull. Memory only; every entry is ciphertext. */
  private missingVkWire = new Map<string, WireItem>();
  private _lastSyncAt: number | null = null;

  // ---- vault lifecycle state (spec 03 §11) ----
  /** Soft-hidden removed vaults (ciphertext-only), keyed by vaultId — the holding area. */
  private holding = new Map<string, HeldVault>();
  /** deleteIds we have seen consumed by a restore — a later tombstone bearing one is stale. */
  private consumedDeleteIds = new Set<string>();
  /** Root cause A §6.2 (branch A7): this device's consumed removal nonces, vaultId → nonce → issuedAt. Durable twin:
   *  the cache's kv rows (PullBatch.addConsumedNonce, in the pull tx that moves the vault to holding). */
  private consumedNonces = new Map<string, Map<string, number>>();
  /** Root cause A §6.3 (branch A7): this device's own first sight of each live vault. Never a server value. */
  private liveSince = new Map<string, number>();
  /** liveSince stamps already in the durable cache (a stamp made outside a pull is persisted by the next pull). */
  private liveSincePersisted = new Set<string>();
  /** Notices awaiting the UI banner. */
  private noticeList: LifecycleNotice[] = [];
  /** Vaults this device just deleted/left — drop them cleanly on the reconcile pull (no
   *  banner). One-shot AND scoped to the action's own reconcile (removed in a finally
   *  there), so a failed reconcile can never leave a stale entry that would misread a
   *  LATER genuine removal as self-initiated and bypass the holding area. */
  private suppressDrop = new Set<string>();
  /** Denied edits awaiting their park-vs-genuine verdict, keyed by vault (F21 / breaker #3).
   *  In-memory INDEX only — the DURABLE truth is the queue row's staged-denied flag
   *  (cache.markStagedDenied), reloaded here by hydrate after a restart. Each entry carries
   *  the pull-start epoch it was staged at, so surfaceStagedDenials only classifies it
   *  against a pull that STARTED later (the core SyncEngine epoch guard, carried explicitly). */
  private preParkedByVault = new Map<string, StagedDenial[]>();
  /** The last wire grant seen per vault — retained so a held vault's grant blob survives (§6). */
  private grantWireByVault = new Map<string, WireGrant>();
  /** Verified incoming ownership offers TO us, recomputed every pull from vault rows. */
  private incomingByVault = new Map<string, IncomingTransfer>();
  /** Highest transfer seq we have already surfaced a completion notice for (dedup). */
  private lastTransferSeqSeen = new Map<string, number>();
  /** F20: vaults an "added to vault" notice has already fired for — fires once per store lifetime
   *  (mirrors the transfer-complete seq dedup) so a dismissed notice never re-surfaces on a re-pull. */
  private addedNoticed = new Set<string>();
  /** H03/H19: queue rows the server DEFINITIVELY refused this session (per-row `rejected`,
   *  or a whole-batch 400/413 the drain bisected down to one row) — durably dropped and
   *  reverted in flushChunk; kept here (mutationId → reason) so save()/remove() can learn
   *  their own row's fate and throw the honest editor error instead of reporting success. */
  private rejectedMutationIds = new Map<string, string>();
  /** H38: the highest rev a live bell has announced. A bell that rings while a pull is in
   *  flight JOINS that pull (single-flight) — whose GET /sync was issued before the bell's
   *  commit — so its rev would otherwise be discarded and the change stay invisible until
   *  the next unrelated bell. sync() compares this against the cursor after the pull and
   *  re-pulls once when the bell is still ahead. */
  private bellRev = 0;

  /** H38: record a live bell's rev (Vault.tsx onRev) — see sync(). */
  noteRev(rev: number): void {
    if (rev > this.bellRev) this.bellRev = rev;
  }
  /** F20: shared vaults whose grant this device can't open (sealed to a key we don't hold, or a
   *  newer grant format). A PERSISTENT, non-dismissable warning — distinct from the dismissable
   *  lifecycle notices; cleared automatically when a later pull opens the grant, the grant is
   *  revoked, or a resync no longer re-delivers it. */
  private undecryptableGrants = new Set<string>();
  /** "kind|vaultId" key anomalies already surfaced this session (root cause A §3.1: show once). */
  private readonly keyAnomaliesShown = new Set<string>();

  // ---- item home (security review 2026-10, root cause A §5.1 INV-HOME; branch A1b; core SyncEngine twin) ----
  /** itemId → the vaultId of the FIRST envelope this device applied for it (or this device's own first seal of a new
   *  id). Never cleared by a resync; rebuilt from the cache's kv rows on hydrate. */
  private readonly homes = new Map<string, string>();
  /** Homes recorded outside a pull (hydrate, a save): persisted by the next pull's tx. */
  private readonly homesUnpersisted = new Set<string>();
  /** Rows refused by INV-HOME, itemId → the newest refused row (ciphertext; never listed, searched, exported or filled). */
  private readonly quarantinedRows = new Map<string, WireItem>();
  /** This pull's refusals (INV-HOME and INV-CONFLICT), surfaced as ONE "wrong vault" notice. */
  private wrongVault = new WrongVaultTally();

  // ---- durable offline cache (design 2026-07-13 §D) ----
  /** §D.1: the in-flight pull's buffered cache ops. Helpers reached from the pull
   *  (moveToHolding, hardDropLocal, applyTransferState) record their durable twin here
   *  via recordPullOp; called outside a pull they record nothing (the next successful
   *  pull trues disk up). Only the CURRENT pull's buffer is ever committed, exactly
   *  once, at the end of a fully-applied pull — if an apply throws mid-way the buffer
   *  is orphaned uncommitted (disk keeps the old cursor, A1) and the next pullOnce
   *  starts a fresh one. */
  private pullOps: Array<(b: PullBatch) => void> | null = null;
  /** §D.1 stuck-cache breaker fired this session: 3 consecutive failed commit txs →
   *  wipe + demote to NullCache. The S5 settings row reads [cacheDemoted] to show
   *  "offline copy unavailable — storage error". */
  private _cacheDemoted = false;
  /** §D.1 stuck-cache tally (store-local): consecutive pull commits that did NOT land
   *  on disk — a thrown commit tx, a rejecting cursor read, or a silent no-op (a
   *  force-closed cache resolves writes without writing, §D.2a) — so demotion fires
   *  even for failure shapes idbcache's own throw-counter never sees. Reset by a
   *  landed commit or a legitimate §D.5.1 already-newer skip; a contiguity REFUSE
   *  (disk behind but coherent) neither counts nor resets. */
  private cacheFailStreak = 0;

  // ---- durable offline WRITES: queue + epoch guard (design 2026-07-13 §D.3, slice S4) ----
  /** §D.3 flush single-flight: concurrent flushQueue() callers coalesce onto ONE drain so
   *  the queue is never double-pushed. Separate from the pull's single-flight so a save's
   *  flush can stage a denial WHILE an older pull is still in flight — exactly the case the
   *  epoch counters below classify correctly. */
  private flushInFlight: Promise<void> | null = null;
  /** Core SyncEngine.pullStartCounter twin: the monotonic id handed to each pull as it STARTS. */
  private pullStartCounter = 0;
  /** Core SyncEngine.freshestCompletedPullStart twin: the largest start-id among COMPLETED
   *  pulls — "a pull started at X has finished". surfaceStagedDenials classifies a staged
   *  denial ONLY once this exceeds the denial's stagedBefore. */
  private freshestCompletedPullStart = 0;
  /** §D.3 UI affordance: itemIds with an UNSYNCED (pending, not-yet-flushed) queue row — the
   *  editor/list renders a "pending sync" mark for these. Maintained in memory alongside the
   *  durable queue (repopulated from cache.pending() on hydrate). */
  private pendingSyncItemIds = new Set<string>();
  /** Core `replayedMutationIds` twin (C1): mutationIds re-enqueued by a reinstate replay —
   *  flushChunk tags their denial `wasReplay` so it drains into a calm notice, never a throw. */
  private replayedMutationIds = new Set<string>();
  /** C2: pre-edit snapshots for in-flight/queued mutations (see PreEditSnapshot). Entries are
   *  dropped on every settle path — applied/conflict, parked (fold or late-arrival), genuine
   *  drop, and the refuse-not-degrade unwind — so the map never outlives its queue rows.
   *  (Rows a SIBLING tab settles never report back here — the L2 prune at sync end sweeps
   *  entries whose durable row is gone.) */
  private preEditByMutation = new Map<string, PreEditSnapshot>();
  /** M1 (2026-07-14 re-review): itemIds whose SERVER tombstone this session has applied
   *  (any pull — the epoch guard can defer a denial's classification past the pull that
   *  delivered the tombstone). Gates revertDeniedMutation's op:"delete" branch: a
   *  genuinely-denied local delete racing another member's ACCEPTED delete must NOT
   *  resurrect the item from its snapshot — the delta server never re-delivers a
   *  rev-passed tombstone, so the resurrected credential would show live forever.
   *  An id leaves the set when a LIVE row for it arrives (undelete/restore). In-memory
   *  only: across a restart the set starts empty, but the classifying pull after a
   *  restart re-runs applyWireItem on any tombstone it delivers, repopulating it for
   *  exactly the rows that need it (a tombstone consumed AND classified-past entirely
   *  before the restart is the accepted residual — it requires a joined-pull deferral
   *  plus an immediate shutdown, and costs what every pre-M1 build did). */
  private serverTombstoned = new Set<string>();

  /** Wall-clock time of the last SUCCESSFUL sync, or null before the first one —
   *  the export flow's "vault as of last sync <time>" banner reads this (spec 07). */
  get lastSyncAt(): number | null {
    return this._lastSyncAt;
  }

  /** True while a DURABLE cache is attached — false on NullCache (per-device opt-out,
   *  unsupported IndexedDB, or post-demotion). The §B.5 cache-less signal for the UI. */
  get cacheDurable(): boolean {
    return this.cache.durable;
  }

  /** §D.1: the stuck-cache breaker fired this session (cache wiped + demoted). */
  get cacheDemoted(): boolean {
    return this._cacheDemoted;
  }

  /** §D.3 UI affordance: this item has an UNSYNCED (queued, not-yet-flushed) offline edit —
   *  the editor/list renders a "pending sync" mark instead of claiming the write is live. */
  hasPendingSync(itemId: string): boolean {
    return this.pendingSyncItemIds.has(itemId);
  }

  /** §E.4 (breaker #9): total unsynced queue rows (pending + staged-denied) this wipe would
   *  destroy. Post-H135 the ASKING and the wiping are two seams: SignOutLink arms the inline
   *  confirm carrying this count before a USER sign-out, and App.signOut is the unconditional
   *  wipe choke point that surfaces the count on a definitive-401 it cannot block. (Corrected
   *  by R07: this comment still described App.signOut raising a confirm it no longer raises.) */
  async queuedMutationCount(): Promise<number> {
    const [pending, staged] = await Promise.all([this.cache.pending(), this.cache.stagedDenied()]);
    return pending.length + staged.length;
  }

  // ---- personal vault identity + account state (security review 2026-10, root cause A §4, §8.5) ----

  /** The account-state blob (contact pins). Refreshed best-effort on every sync. */
  readonly accountState: AccountStateSync;
  private readonly clientState: ClientStateStore;

  /** Non-null while the human must answer "Which vault is your Personal vault?" (no wrap anywhere). */
  personalVaultChoices: PersonalCandidate[] | null = null;

  /** The question's choices, from the synced rows and this client's own key provenance. The server's
   *  `type` label and `role` are not read (A5 review H-1). */
  personalCandidates(): PersonalCandidate[] {
    const counts = new Map<string, number>();
    for (const it of this.itemsById.values()) counts.set(it.vaultId, (counts.get(it.vaultId) ?? 0) + 1);
    const out: PersonalCandidate[] = [];
    for (const v of this.vaultsById.values()) {
      if (!this.account.hasVault(v.vaultId)) continue;
      const g = this.grantWireByVault.get(v.vaultId);
      out.push({
        vaultId: v.vaultId,
        ownUvkWrap: this.account.keyFromOwnUvkWrap(v.vaultId) && !!g && g.userId === this.account.userId && !g.sealedVk,
        name: this.account.decryptVaultName(v.vaultId, v.metaBlob),
        itemCount: counts.get(v.vaultId) ?? 0,
      });
    }
    return out;
  }

  /** The wrap this browser cached the last time it authenticated one (UVK-sealed; null if none). */
  private cachedPersonalWrap(): PersonalWrap | null {
    try {
      const raw = this.clientState.get("personal.wrap");
      const o = raw ? (JSON.parse(raw) as Partial<PersonalWrap>) : null;
      return o && typeof o.vaultId === "string" && typeof o.wrappedVk === "string" ? { vaultId: o.vaultId, wrappedVk: o.wrappedVk } : null;
    } catch {
      return null;
    }
  }

  private rememberPersonalWrap(w: PersonalWrap): void {
    this.clientState.set("personal.wrap", JSON.stringify({ vaultId: w.vaultId, wrappedVk: w.wrappedVk }));
    this.clientState.set("personal.last", w.vaultId);
  }

  /** A9 (M-2): record the designation in this browser's account-state copy now; sync() writes it to the server. */
  private designationDirty = false;

  private recordDesignationLocally(vaultId: string): void {
    try {
      this.accountState.updateLocal((d) => withPersonal(d, vaultId, Date.now()));
      this.designationDirty = true;
    } catch {
      /* a newer client owns the format: nothing to record */
    }
  }

  /** The account's own personal-vault designation (account state, A9), or null when none was ever recorded. */
  designatedPersonalVaultId(): string | null {
    return this.accountState.doc.personal?.vaultId ?? null;
  }

  /** A9 review LOW-2: the default destination, or {@link NoPersonalVaultError} while no personal vault is in force (§4.3:
   *  no default destination), so the refusal says "Choose a vault for this item." instead of reaching the seal with an
   *  empty vault id (which surfaced as "wrong master password"). */
  private personalVaultOrRefuse(): string {
    if (!this.account.personalVaultId) throw new NoPersonalVaultError();
    return this.account.personalVaultId;
  }

  /**
   * Root cause A §4.3 as amended by the A5 review (H-1) and re-review (A5b), local only, never minting (core
   * twin). confirmed + a cached wrap for ANOTHER vault → "changed": the device keeps its own until the human
   * confirms (also an older wrap replayed, L-2); confirmed otherwise → cache the wrap; absent + cached →
   * "withheld"; absent + nothing cached → ask; unreadable + a cached wrap that opens → "unreadable-cached"
   * (L-1); unreadable otherwise → only a re-designation.
   */
  private decidePersonalLocally(mergedStateBefore: boolean = this.accountState.hasHighWater()): void {
    const cached = this.cachedPersonalWrap();
    const designation = this.accountState.doc.personal?.vaultId ?? null;
    switch (this.account.personalStatus) {
      case "confirmed": {
        this.personalVaultChoices = null;
        const served = this.account.personalWrap;
        if (!served) return;
        if (this.account.personalWrapMintedHere) {
          // A9 (M-2): the registering device minted this wrap itself: it is the designation from day one.
          this.account.personalWrapMintedHere = false;
          this.recordDesignationLocally(served.vaultId);
          this.rememberPersonalWrap(served);
        } else if (!cached) {
          // A9 review LOW-4: a browser that never confirmed a personal vault (no cached wrap) asks ONCE, whatever the
          // designation says: on such a browser the account state is as replayable as the wrap (no high-water mark can
          // tell an older authentic blob from the current one), so a matching designation proves nothing.
          this.account.holdPersonalProposal(designation);
        } else if (cached.vaultId === served.vaultId && (designation === null || designation === served.vaultId)) {
          // The cached wrap and the served one agree, and the designation (if any) does too: unchanged.
          this.rememberPersonalWrap(served);
        } else if (designation === served.vaultId && mergedStateBefore) {
          // A confirmed re-designation elsewhere (the account's own designation, UVK-sealed, newest wins) on a browser
          // that merged account state BEFORE this sync, so a rolled-back blob would have been detected.
          this.rememberPersonalWrap(served);
        } else if (cached.vaultId !== served.vaultId && (designation === null || designation === cached.vaultId)) {
          // A5b: the cached wrap stays in force; the served one waits for the human (also a replayed older wrap).
          this.account.holdPersonalChange(cached);
        } else {
          // A9 (M-2): nothing on this browser vouches for the served wrap (a designation for a third vault, or one this
          // browser has not merged state for): a proposal, never a silent adoption. Nothing is in force.
          this.account.holdPersonalProposal(designation);
        }
        return;
      }
      case "proposed":
        // A9 review LOW-4: a proposal is resolved only by the human (acceptPersonalChange after the co-holders were shown,
        // or a reauthed re-designation); a designation arriving later never confirms it on their behalf.
        this.personalVaultChoices = null;
        return;
      case "withheld":
      case "changed":
      case "unreadable-cached":
        this.personalVaultChoices = null;
        return;
      case "unreadable":
        if (cached) this.account.applyCachedPersonalWrap(cached);
        this.personalVaultChoices = (this.account.personalStatus as string) === "unreadable-cached" ? null : [];
        return;
      case "absent": {
        if (cached) {
          this.account.applyCachedPersonalWrap(cached);
          this.personalVaultChoices = (this.account.personalStatus as string) === "withheld" ? null : [];
          return;
        }
        this.personalVaultChoices = personalVaultChoices(this.personalCandidates(), this.clientState.get("personal.last"));
      }
    }
  }

  // ---- A5b (M-2): an informed, confirmed choice ----

  private readonly coHoldersByVault = new Map<string, CoHolder[]>();
  private pendingProposal: PersonalVaultProposal | null = null;

  /** The vault this browser already had as personal: its cached wrap, else the last one it used (L-1). */
  devicePersonalVaultId(): string | null {
    return this.cachedPersonalWrap()?.vaultId ?? this.clientState.get("personal.last");
  }

  /** One vault as the question and the Settings list show it (core `personalChoiceInfo` twin). `coHolders` is
   *  null until {@link refreshPersonalChoiceDetails} (or a proposal) loaded it. What the server reports. */
  personalChoiceInfo(vaultId: string): PersonalChoiceInfo {
    const row = this.vaultsById.get(vaultId);
    const name = row ? this.account.decryptVaultName(vaultId, row.metaBlob) : null;
    let itemCount = 0;
    for (const it of this.itemsById.values()) if (it.vaultId === vaultId) itemCount++;
    return {
      vaultId,
      name: name && name !== "(vault)" ? name : null,
      itemCount,
      origin: row?.lastTransfer?.newOwnerUserId === this.account.userId ? "received" : "created",
      coHolders: this.coHoldersByVault.get(vaultId) ?? null,
      onThisDevice: vaultId === this.devicePersonalVaultId(),
    };
  }

  private async loadCoHolders(vaultId: string): Promise<CoHolder[]> {
    const list = (await this.api.vaultMembers(vaultId))
      .filter((m) => m.userId !== this.account.userId)
      .map((m) => ({ userId: m.userId, displayName: m.displayName, email: m.email, role: m.role }));
    this.coHoldersByVault.set(vaultId, list);
    return list;
  }

  /** Best effort: who else holds each vault, for the lists (an unreachable server leaves null). */
  async refreshPersonalChoiceDetails(vaultIds: string[]): Promise<void> {
    for (const id of vaultIds) {
      try {
        await this.loadCoHolders(id);
      } catch {
        /* unknown stays null */
      }
    }
  }

  /**
   * Step 1 of a designation (core `proposePersonalVault` twin): describe the chosen vault for the confirmation.
   * Mints NOTHING. Refuses a vault not keyed from our own UVK wrap, and fails when the co-holders cannot be
   * loaded (the confirmation must name them). Supersedes any earlier proposal.
   */
  async proposePersonalVault(vaultId: string): Promise<PersonalVaultProposal> {
    this.pendingProposal = null;
    if (!this.account.keyFromOwnUvkWrap(vaultId)) throw new Error("that vault is not wrapped under this account's key");
    const coHolders = await this.loadCoHolders(vaultId);
    const info = this.personalChoiceInfo(vaultId);
    const p: PersonalVaultProposal = Object.freeze({ vaultId, name: info.name, origin: info.origin, coHolders, replacing: this.account.personalVaultId || null });
    this.pendingProposal = p;
    return p;
  }

  cancelPersonalProposal(): void {
    this.pendingProposal = null;
  }

  /**
   * Step 2: the human confirmed `proposal` after reading its name and co-holders. Only the pending proposal
   * this store issued is accepted, once. `currentAuthKey` (a FRESH password entry) is required by the server
   * to REPLACE an existing wrap (re-designation, Q9; keeping the current vault over a change).
   */
  async confirmPersonalVault(proposal: PersonalVaultProposal, currentAuthKey?: string): Promise<void> {
    if (proposal !== this.pendingProposal) throw new Error("that personal-vault choice was not confirmed here (or is stale)");
    this.pendingProposal = null;
    const wrap = this.account.buildPersonalWrap(proposal.vaultId);
    await this.api.putPersonalWrap(wrap, currentAuthKey);
    this.rememberPersonalWrap(wrap); // before applying, so the new wrap is never read as a change
    this.account.installDesignatedPersonalWrap(wrap); // the human named it: in force now, whatever was before
    // A9 (M-2): the human's choice is the account's designation, for every device (local first; the refresh writes it).
    await this.accountState.update((d) => withPersonal(d, wrap.vaultId, Date.now())).catch(() => {});
    this.decidePersonalLocally(); // clears the question
  }

  /**
   * Settings → "This is my personal vault" (owner decision Q9), confirmed: re-designation with a FRESH master-password
   * reauth (core `redesignatePersonalVault` twin). A9 (M-1): the proof is {@link Account.reauthAuthKey}, the ONE fenced
   * in-session derivation (the unlock KDF floor/ceiling: `KdfPolicyError`; only the salt this session unlocked with:
   * {@link ReauthStaleSessionError}); nothing else is ever derived or sent.
   */
  async redesignatePersonalVault(proposal: PersonalVaultProposal, password: string): Promise<void> {
    if (proposal !== this.pendingProposal) throw new Error("that personal-vault choice was not confirmed here (or is stale)");
    const keys = await this.api.accountKeys();
    const authKey = await this.account.reauthAuthKey(password, keys);
    await this.confirmPersonalVault(proposal, authKey);
  }

  /** Non-null while a served wrap waits for the human: "changed" (it names another vault than this browser's, which
   *  stays in force: `currentVaultId`) or "proposed" (A9: nothing is in force; `currentVaultId` is the account's
   *  designation the served wrap contradicts, or empty when the account has none). */
  personalChange(): PersonalChange | null {
    const served = this.account.pendingPersonalChange;
    if (!served) return null;
    if (this.account.personalStatus === "changed") return { currentVaultId: this.account.personalVaultId, servedVaultId: served.vaultId };
    if (this.account.personalStatus === "proposed") return { currentVaultId: this.account.proposedAgainstDesignation ?? "", servedVaultId: served.vaultId };
    return null;
  }

  /** The human confirmed the change: the served wrap (authenticated under our UVK) is in force and cached.
   *  Mints nothing. Keeping the current vault instead is a confirmed re-designation with the password. */
  acceptPersonalChange(): void {
    const change = this.personalChange();
    if (!change || this.personalChangeDescribed !== change.servedVaultId) {
      throw new Error('"Use the new personal vault" is offered only after its co-holders were loaded (describePersonalChange)');
    }
    this.personalChangeDescribed = null;
    this.account.acceptPersonalChange();
    const w = this.account.personalWrap;
    if (w) {
      this.rememberPersonalWrap(w);
      this.recordDesignationLocally(w.vaultId); // A9 (M-2): the human's confirmation is the account's designation
    }
    this.decidePersonalLocally();
  }

  private personalChangeDescribed: string | null = null;

  /**
   * A5b review LOW-1/LOW-2: load what "Use the new personal vault" would mean — the new vault's co-holders (as the
   * server reports them) and origin. REJECTS when the member lookup fails, and then {@link acceptPersonalChange}
   * stays refused: the human only switches to a vault whose co-holders they were shown. Keeping needs nothing.
   */
  async describePersonalChange(): Promise<PersonalChangeDetails> {
    this.personalChangeDescribed = null;
    const change = this.personalChange();
    if (!change) throw new Error("no personal-vault change is pending");
    const servedCoHolders = await this.loadCoHolders(change.servedVaultId);
    const nameOf = (id: string): string | null => {
      const row = this.vaultsById.get(id);
      if (!row || !this.account.hasVault(id)) return null;
      const n = this.account.decryptVaultName(id, row.metaBlob);
      return n && n !== "(vault)" ? n : null;
    };
    this.personalChangeDescribed = change.servedVaultId;
    return {
      currentVaultId: change.currentVaultId,
      currentName: nameOf(change.currentVaultId),
      servedVaultId: change.servedVaultId,
      servedName: nameOf(change.servedVaultId),
      servedCoHolders,
      servedOrigin: this.vaultsById.get(change.servedVaultId)?.lastTransfer?.newOwnerUserId === this.account.userId ? "received" : "created",
    };
  }

  // ---- signed grants (security review 2026-10, root cause A §1.4–§1.6, §3.2, §8.2; branch A6; core twin) ----

  private persistedSet(key: string): Set<string> {
    return new Set((this.clientState.get(key) ?? "").split("\n").filter((x) => x.length > 0));
  }

  private persistSet(key: string, set: Set<string>): void {
    this.clientState.set(key, set.size === 0 ? null : [...set].sort().join("\n"));
  }

  /**
   * §8.2 step 3, once per browser profile: a v1-only key is FROZEN (self-wrapped silently) when the opted-in
   * durable cache already held the vault's grant row AND an item that decrypted under it before this release ran
   * here (hydrate is the only caller, and only rows from disk are in memory then). Every v1-only vault that
   * arrives later is legacy-read-only until the human accepts it (or the owner re-issues).
   */
  private async freezeOnce(): Promise<void> {
    if (await this.cache.freezeDone()) return;
    const decrypted = new Set<string>();
    for (const it of this.itemsById.values()) decrypted.add(it.vaultId);
    for (const g of this.grantWireByVault.values()) {
      if (g.userId !== this.account.userId || !decrypted.has(g.vaultId) || this.account.keySource(g.vaultId) !== "legacy-seal") continue;
      // Bound to the key the evidence is about (HIGH-1), with kind "frozen" (LOW-3).
      this.vouch(g.vaultId, "frozen");
    }
    await this.cache.setFreezeDone();
  }

  /** Persisted vouches: lines "vaultId|tag|kind". A line with no tag is ignored; no kind reads as "confirmed". */
  private persistedVouches(): Map<string, { vaultId: string; tag: string; kind: LegacyVouchKind }> {
    const out = new Map<string, { vaultId: string; tag: string; kind: LegacyVouchKind }>();
    for (const line of this.persistedSet(LEGACY_AUTHORIZED_KEY)) {
      const [vaultId, tag, kind] = line.split("|");
      if (!vaultId || !tag || !/^[0-9a-f]{64}$/.test(tag)) continue;
      out.set(vaultId, { vaultId, tag, kind: kind === "frozen" ? "frozen" : "confirmed" });
    }
    return out;
  }

  private persistVouches(m: Map<string, { vaultId: string; tag: string; kind: LegacyVouchKind }>): void {
    this.persistSet(LEGACY_AUTHORIZED_KEY, new Set([...m.values()].map((v) => `${v.vaultId}|${v.tag}|${v.kind}`)));
  }

  /** Vouch for the key HELD for `vaultId` now (its tag is recorded, so no other key for the vault is covered). */
  private vouch(vaultId: string, kind: LegacyVouchKind): void {
    const tag = this.account.legacyKeyTag(vaultId);
    if (!tag) return;
    this.account.authorizeLegacyKey(vaultId, tag, kind);
    const m = this.persistedVouches();
    m.set(vaultId, { vaultId, tag, kind });
    this.persistVouches(m);
  }

  // ---- per-vault held-key memory (security review 2026-10, root cause A, branch A7; core SyncEngine twin) ----

  /** Push the persisted held-key tags into the account (the durable record wins). */
  private loadHeldKeys(): void {
    for (const line of this.persistedSet(HELD_KEYS_KEY)) {
      const [vaultId, tag] = line.split("|");
      if (vaultId && tag) this.account.rememberHeldKey(vaultId, tag);
    }
  }

  /** Persist the tag of every vault the account adopted a key for and this device has no tag for yet. A recorded
   *  tag is never overwritten here; only hardDropLocal removes one, with the vault. */
  private persistHeldKeys(): void {
    const persisted = this.persistedSet(HELD_KEYS_KEY);
    const known = new Set([...persisted].map((l) => l.split("|")[0]));
    let changed = false;
    for (const [vaultId, tag] of this.account.heldKeyTagsSnapshot()) {
      if (known.has(vaultId)) continue;
      persisted.add(`${vaultId}|${tag}`);
      changed = true;
    }
    if (changed) this.persistSet(HELD_KEYS_KEY, persisted);
    this.persistMemberGranted();
  }

  // ---- removal proofs v2 (security review 2026-10, root cause A §6; branch A7; core SyncEngine twin) ----

  /**
   * §6.3 liveSince: stamp every vault this device now holds a key for, outside the holding area, that has no stamp
   * yet, with the DEVICE clock; inside a pull, persist every stamp not yet on disk (same tx). Cleared when the vault
   * leaves the live view (hardDropLocal), so a re-add this device sees moves it past every earlier proof.
   */
  private markLiveVaults(): void {
    const now = Date.now();
    const ids = new Set<string>([...this.vaultsById.keys(), ...this.grantWireByVault.keys()]);
    for (const id of ids) {
      if (!this.account.hasVault(id) || this.holding.has(id) || this.liveSince.has(id)) continue;
      this.liveSince.set(id, now);
    }
    if (this.pullOps) {
      for (const [id, at] of this.liveSince) {
        if (this.liveSincePersisted.has(id)) continue;
        this.liveSincePersisted.add(id);
        this.recordPullOp((b) => b.setLiveSince(id, at));
      }
    }
  }

  /** §6.3 step 5: THIS device's consumed nonces for `vaultId`. */
  private consumedFor(vaultId: string): Set<string> {
    return new Set<string>(this.consumedNonces.get(vaultId)?.keys() ?? []);
  }

  /** A7 review MEDIUM-2: the account state's consumed nonces for `vaultId` (other devices of this user). */
  private accountConsumedFor(vaultId: string): Set<string> {
    return new Set((this.accountState.doc.consumedNonces[vaultId] ?? []).map(([n]) => n));
  }

  /** Re-run §1.4 for rows whose key is not held (pending, refused) or held only from a v1 seal; make the items of
   *  any vault that became readable visible. */
  private reevaluateGrants(): void {
    const newlyHeld = new Set<string>();
    for (const g of [...this.grantWireByVault.values()]) {
      if (g.userId !== this.account.userId || this.holding.has(g.vaultId)) continue;
      const held = this.account.hasVault(g.vaultId);
      const retry = !held || (this.account.keySource(g.vaultId) === "legacy-seal" && !!g.signedGrant);
      if (!retry) continue;
      try {
        this.account.addGrant(g);
      } catch {
        /* unchanged */
      }
      if (!held && this.account.hasVault(g.vaultId)) newlyHeld.add(g.vaultId);
    }
    if (newlyHeld.size === 0) return;
    for (const w of [...this.missingVkWire.values()]) {
      if (newlyHeld.has(w.vaultId) && this.missingVkById.has(w.itemId)) this.applyWireItem(w);
    }
  }

  /** §1.4 anomalies, once per vault+verdict per store ("the server may be misbehaving — tell your admin"). */
  private surfaceGrantStates(): void {
    for (const [vaultId, verdict] of this.account.grantAnomalies()) {
      const k = `grant-anomaly|${vaultId}|${verdict}`;
      if (this.keyAnomaliesShown.has(k)) continue;
      this.keyAnomaliesShown.add(k);
      this.pushNotice({ id: crypto.randomUUID(), vaultId, vaultName: "", kind: "grant-anomaly", reason: verdict });
    }
  }

  private readonly selfWrapsPosted = new Set<string>();

  private async postAuthorizedSelfWraps(): Promise<void> {
    for (const g of [...this.grantWireByVault.values()]) await this.postSelfWrapIfAuthorized(g);
  }

  /** §3.2: post the member self-wrap iff {@link Account.selfWrapAuthorized} vouches for the held key. Best effort. */
  private async postSelfWrapIfAuthorized(g: WireGrant): Promise<boolean> {
    if (this.selfWrapsPosted.has(g.vaultId) || !this.account.needsSelfWrap(g) || !this.account.selfWrapAuthorized(g.vaultId)) return false;
    try {
      await this.api.putGrantSelfWrap(g.vaultId, { wrappedVk: this.account.buildSelfWrap(g.vaultId) });
      this.selfWrapsPosted.add(g.vaultId);
      return true;
    } catch {
      return false;
    }
  }

  /** Pending invitations the human has not declined. */
  pendingInvitations(): PendingInvitation[] {
    const declined = this.persistedSet(DECLINED_KEY);
    return this.account
      .pendingGrants()
      // A held LEGACY key with a pending v2 grant is listed too: verifying the sender upgrades it.
      .filter((p) => !declined.has(p.grantIdB64) && (!this.account.hasVault(p.vaultId) || this.account.keySource(p.vaultId) === "legacy-seal"))
      .map((p) => ({ vaultId: p.vaultId, fromUserId: p.fromUserId, grantIdB64: p.grantIdB64 }));
  }

  /** Who the SERVER says sent `inv` (display name + the key a human must verify). Untrusted. */
  invitationSender(inv: PendingInvitation): Promise<UserLookupResponse> {
    return this.api.userIdentity(inv.fromUserId);
  }

  /** Pin `served` iff the human-typed code (THEIR 32 hex, read from THEIR screen) matches SHA-256 of the served
   *  key. Null (nothing pinned) on a mismatch. */
  async verifyMemberTyped(served: UserLookupResponse, typed: string): Promise<Contact | null> {
    const c = await pinFromTyped(typed, { userId: served.userId, identityPub: served.identityPub }, served.displayName, Date.now());
    if (!c) return null;
    await this.accountState.pin(c);
    return c;
  }

  /** Pin `served` iff a scanned identity QR matches the served key at FULL length. */
  async verifyMemberQr(served: UserLookupResponse, qrPayload: string): Promise<Contact | null> {
    const c = await pinFromQr(qrPayload, { userId: served.userId, identityPub: served.identityPub }, served.displayName, Date.now());
    if (!c) return null;
    await this.accountState.pin(c);
    return c;
  }

  /** Accept `inv` (§1.6): the verification ceremony for its sender, then §1.4 again. True only when adopted. */
  async acceptInvitation(inv: PendingInvitation, typedCode: string): Promise<boolean> {
    const served = await this.api.userIdentity(inv.fromUserId);
    if (served.userId !== inv.fromUserId) return false;
    if (!(await this.verifyMemberTyped(served, typedCode))) return false;
    return this.afterInvitationPin(inv);
  }

  /** As {@link acceptInvitation}, with a scan of the sender's identity QR. */
  async acceptInvitationQr(inv: PendingInvitation, qrPayload: string): Promise<boolean> {
    const served = await this.api.userIdentity(inv.fromUserId);
    if (served.userId !== inv.fromUserId) return false;
    if (!(await this.verifyMemberQr(served, qrPayload))) return false;
    return this.afterInvitationPin(inv);
  }

  private async afterInvitationPin(inv: PendingInvitation): Promise<boolean> {
    this.reevaluateGrants();
    this.surfaceGrantStates();
    const adopted = this.account.hasVault(inv.vaultId) && this.account.keySource(inv.vaultId) === "signed-grant";
    const g = this.grantWireByVault.get(inv.vaultId);
    if (adopted && g) await this.postSelfWrapIfAuthorized(g);
    return adopted;
  }

  /** "Decline": hide `inv` on this browser (by grantId, so a re-issued grant asks again). */
  declineInvitation(inv: PendingInvitation): void {
    const d = this.persistedSet(DECLINED_KEY);
    d.add(inv.grantIdB64);
    this.persistSet(DECLINED_KEY, d);
  }

  /** §8.2 "Review your shared vaults": vaults readable only through an unconfirmed v1 seal. */
  legacyReviewVaults(): LegacyVaultReview[] {
    const ids = new Set(this.account.legacyReadOnlyVaultIds());
    if (ids.size === 0) return [];
    const counts = new Map<string, number>();
    for (const it of this.itemsById.values()) counts.set(it.vaultId, (counts.get(it.vaultId) ?? 0) + 1);
    const out: LegacyVaultReview[] = [];
    for (const v of this.vaultsById.values()) {
      if (!ids.has(v.vaultId)) continue;
      // LOW-2: never offer trust-on-first-use over a v2 grant that is pending verification or failed it.
      if (this.account.hasPendingGrant(v.vaultId) || this.account.hasGrantAnomaly(v.vaultId)) continue;
      if (this.account.heldKeyContradictsVouch(v.vaultId)) continue; // round 3: the vouch gate
      const n = this.account.decryptVaultName(v.vaultId, v.metaBlob);
      out.push({ vaultId: v.vaultId, name: n && n !== "(vault)" ? n : null, itemCount: counts.get(v.vaultId) ?? 0 });
    }
    return out.sort((a, b) => (a.vaultId < b.vaultId ? -1 : a.vaultId > b.vaultId ? 1 : 0));
  }

  /** The owner the SERVER reports for `vaultId` (the review card labels it as server-reported). */
  async reportedOwner(vaultId: string): Promise<CoHolder | null> {
    const o = (await this.api.vaultMembers(vaultId)).find((m) => m.role === "owner");
    return o ? { userId: o.userId, displayName: o.displayName, email: o.email, role: o.role } : null;
  }

  /** "Accept anyway" on the review card (Q7, trust on first use): vouch for the v1-only key, post the self-wrap. */
  async acceptLegacyVault(vaultId: string): Promise<void> {
    if (!this.account.isLegacyReadOnly(vaultId)) throw new Error("that vault is not awaiting review");
    if (this.account.heldKeyContradictsVouch(vaultId)) throw new Error("that vault holds a key this device's earlier vouch contradicts");
    if (this.account.hasPendingGrant(vaultId) || this.account.hasGrantAnomaly(vaultId)) {
      throw new Error("that vault has a newer-format grant waiting on verification, or one that failed it: verify the sender instead");
    }
    this.vouch(vaultId, "confirmed");
    const g = this.grantWireByVault.get(vaultId);
    if (g) await this.postSelfWrapIfAuthorized(g);
  }

  // ---- owner side (§1.5, §8.2 step 4) ----

  memberPinState(userId: string, servedIdentityPub: string): MemberPinState {
    if (!this.accountState.currentPin(userId)) return "needs-verification";
    switch (pinState(this.accountState.doc, { userId, identityPub: servedIdentityPub })) {
      case "pinned-match":
        return "pinned";
      case "pinned-mismatch":
        return "key-changed";
      default:
        return "needs-verification";
    }
  }

  // ---- grant authority (security review 2026-10, root cause A, branch A6b; core SyncEngine twin) ----
  //
  // THE INVARIANT: this client never signs or seals a vault key to a user unless (a) a human in this browser
  // confirmed that (vault, user) pair now (addVaultMember from the add-member form, confirmReissue from the "Legacy
  // grants" list), or (b) the pair is in this account's UVK-authenticated issued-grants record for the SAME identity
  // key (reissueGrant). No owner-only signing action (add member, re-issue, transfer offer) runs on the strength of
  // the server's `role=owner` label: it needs this account's owned-vaults record (ownsVault), written at creation,
  // at transfer accept, or by a password-reauthed "You own <vault>?" (confirmOwnership). The server's member list and
  // `legacyGrant` flag only decide what is SHOWN.

  /** True when this account's own evidence (account state, UVK-authenticated) says it owns `vaultId`. */
  ownsVault(vaultId: string): boolean {
    return this.accountState.owns(vaultId);
  }

  /** The server reports this account as the owner, but this account has no evidence of it: ask "You own <vault>?". */
  ownershipNeedsConfirmation(vaultId: string): boolean {
    return this.account.hasVault(vaultId) && this.account.serverRoleFor(vaultId) === "owner" && !this.ownsVault(vaultId) &&
      vaultId !== this.account.personalVaultId;
  }

  private requireOwned(vaultId: string): void {
    if (!this.ownsVault(vaultId)) throw new OwnershipNotConfirmedError(vaultId);
  }

  private pendingOwnershipClaim: OwnershipClaim | null = null;

  /** A6b review MEDIUM-1: this browser first adopted `vaultId`'s key as a MEMBER, now or in an earlier session. */
  receivedAsMember(vaultId: string): boolean {
    return this.account.keyArrivedByMemberGrant(vaultId) || this.persistedSet(MEMBER_GRANTED_KEY).has(vaultId) ||
      this.accountState.doc.memberReceived[vaultId] !== undefined;
  }

  /**
   * A6b carry-forward LOW-R (A1b; core `flushMemberReceived` twin): every vault THIS browser recorded as received-as-member
   * joins the account state too (UVK-sealed, union-merged, add-only), so a fresh device of the same account whose first
   * served row is owner-shaped still asks for the transfer acknowledgement. Best effort; retried next sync.
   */
  private async flushMemberReceived(): Promise<void> {
    const local = [...this.persistedSet(MEMBER_GRANTED_KEY)].filter((id) => this.accountState.doc.memberReceived[id] === undefined);
    if (local.length === 0) return;
    const at = Date.now();
    await this.accountState.update((d) => withMemberReceived(d, local, at)).catch(() => {});
  }

  private persistMemberGranted(): void {
    const persisted = this.persistedSet(MEMBER_GRANTED_KEY);
    let changed = false;
    for (const vaultId of this.vaultsById.keys()) {
      if (persisted.has(vaultId) || !this.account.keyArrivedByMemberGrant(vaultId)) continue;
      persisted.add(vaultId);
      changed = true;
    }
    if (changed) this.persistSet(MEMBER_GRANTED_KEY, persisted);
  }

  private ownershipBasisOk(vaultId: string): boolean {
    return this.account.hasVault(vaultId) && this.account.keyFromOwnUvkWrap(vaultId) && !this.account.isLegacyReadOnly(vaultId) &&
      !this.account.heldKeyContradictsVouch(vaultId);
  }

  /**
   * Step 1 of "You own <vault>?" (A6b review MEDIUM-1; core twin): what the confirmation shows, loaded BEFORE it is
   * offered. All but `receivedAsMember` is AS REPORTED BY THE SERVER. Mints nothing; throws when the members cannot be
   * loaded. Supersedes any earlier claim.
   */
  async describeOwnership(vaultId: string): Promise<OwnershipClaim> {
    this.pendingOwnershipClaim = null;
    if (!this.ownershipBasisOk(vaultId)) throw new VaultKeyNotVerifiedError(vaultId);
    const members = (await this.api.vaultMembers(vaultId)).map((m) => ({ userId: m.userId, displayName: m.displayName, email: m.email, role: m.role }));
    const row = this.vaultsById.get(vaultId);
    const lt = row?.lastTransfer ?? null;
    let vaultName: string | null = null;
    if (row) {
      const n = this.account.decryptVaultName(vaultId, row.metaBlob);
      vaultName = n && n !== "(vault)" ? n : null;
    }
    const claim: OwnershipClaim = {
      vaultId,
      vaultName,
      reportedOwner: members.find((m) => m.role === "owner") ?? null,
      lastTransferTo: lt ? (members.find((m) => m.userId === lt.newOwnerUserId) ?? { userId: lt.newOwnerUserId, displayName: "", email: "", role: "" }) : null,
      lastTransferSeq: lt ? lt.seq : null,
      coHolders: members.filter((m) => m.userId !== this.account.userId),
      origin: lt?.newOwnerUserId === this.account.userId ? "received" : "created",
      receivedAsMember: this.receivedAsMember(vaultId),
    };
    this.pendingOwnershipClaim = claim;
    return claim;
  }

  cancelOwnershipClaim(): void {
    this.pendingOwnershipClaim = null;
  }

  /**
   * Step 2, "You own <vault>?" confirmed (A6b): only the claim this store described and still holds; a fresh
   * master-password reauth checked in this browser against the session's UVK; and, for a vault this browser received
   * as a MEMBER, the explicit `transferredToMe` acknowledgement ("This vault's owner transferred it to me"; a genuine
   * pre-A6b transfer recipient is in exactly this state, so it is not refused outright). Records the ownership.
   */
  async confirmOwnership(claim: OwnershipClaim, password: string, transferredToMe = false): Promise<void> {
    if (claim !== this.pendingOwnershipClaim) throw new Error("that ownership confirmation was not described here (or is stale)");
    const vaultId = claim.vaultId;
    if (!this.ownershipBasisOk(vaultId)) throw new VaultKeyNotVerifiedError(vaultId);
    if (this.receivedAsMember(vaultId) && !transferredToMe) throw new OwnershipTransferAckRequiredError(vaultId);
    const keys = await this.api.accountKeys();
    // A6b carry-forward (A1b): a salt this session did not unlock with can never verify; say how to recover.
    if (!this.account.sessionSaltCurrent(keys)) throw new ReauthStaleSessionError();
    if (!(await this.account.verifyPassword(password, keys))) throw new ReauthFailedError();
    this.pendingOwnershipClaim = null;
    await this.accountState.update((d) => withOwned(d, vaultId, Date.now()));
  }

  /** Create a shared vault (owner): this account's own evidence that it owns it is recorded at once. */
  async createSharedVault(name: string): Promise<string> {
    const { request, vaultId } = this.account.buildCreateSharedVault(name);
    try {
      await this.api.createVault(request);
    } catch (e) {
      this.account.removeVault(vaultId); // roll back the optimistic local registration
      throw e;
    }
    await this.accountState.update((d) => withOwned(d, vaultId, Date.now())).catch(() => {});
    await this.sync();
    return vaultId;
  }

  private static keyHash(identityPub: string): string {
    return toHexLower(sha256Sync(fromB64(identityPub)));
  }

  private async recordIssued(vaultId: string, pin: Contact): Promise<void> {
    await this.accountState.update((d) => withIssued(d, vaultId, pin.userId, VaultStore.keyHash(pin.identityPub), Date.now())).catch(() => {});
  }

  /** Add `userId` to `vaultId` (owner, §1.5). A human picked this vault and member on the add form (rule a). Only a
   *  vault this account OWNS by its own evidence ({@link OwnershipNotConfirmedError}) and a member PINNED and current
   *  here ({@link MemberNotVerifiedError}); the v2 grant and the dual-sent v1 seal are both sealed to the PIN key, and
   *  the pair is recorded. */
  async addVaultMember(vaultId: string, userId: string, role: string): Promise<void> {
    this.requireOwned(vaultId);
    const pin = this.accountState.currentPin(userId);
    if (!pin) throw new MemberNotVerifiedError(userId);
    const signedGrant = this.account.buildSignedGrant(vaultId, pin);
    const sealedVk = this.account.wrapVkForMember(fromB64(pin.identityPub), vaultId);
    await this.api.addVaultMember(vaultId, { userId, role, sealedVk, signedGrant });
    await this.recordIssued(vaultId, pin);
  }

  private async postReissue(vaultId: string, pin: Contact): Promise<void> {
    await this.api.reissueGrant(vaultId, pin.userId, { signedGrant: this.account.buildSignedGrant(vaultId, pin) });
    await this.recordIssued(vaultId, pin);
  }

  private readonly legacyRowsByVault = new Map<string, LegacyGrantRow[]>();

  /**
   * The "Legacy grants" list for `vaultId` (§8.2 step 4, A6b): members the SERVER lists as still on a v1 grant (a hint),
   * each with the vault name and, when pinned and current here, the member's VERIFIED label. Loading it signs NOTHING
   * (security review 2026-10, A9, M-3): every re-issue is the owner's per-row confirmation ({@link confirmReissue}). The
   * former rule (b), a prompt-free renewal of pairs in the issued-grants record, is gone: the record is UVK-authentic
   * but relayed by the server, which can withhold the removal tombstone from a device that never saw it and then list
   * the removed member. The record now only annotates the row (`previouslySharedAt`). Never called by sync(). Throws
   * when the member list cannot be loaded.
   */
  async loadLegacyGrants(vaultId: string): Promise<LegacyGrantRow[]> {
    this.legacyRowsByVault.delete(vaultId);
    if (!this.account.hasVault(vaultId) || this.account.isLegacyReadOnly(vaultId)) return [];
    const members = await this.api.vaultMembers(vaultId);
    const v = this.vaultsById.get(vaultId);
    let vaultName: string | null = null;
    if (v) {
      const n = this.account.decryptVaultName(vaultId, v.metaBlob);
      vaultName = n && n !== "(vault)" ? n : null;
    }
    const owned = this.ownsVault(vaultId);
    const rows: LegacyGrantRow[] = [];
    for (const m of members) {
      if (m.legacyGrant !== true || m.role === "owner" || m.userId === this.account.userId) continue;
      const state = this.memberPinState(m.userId, m.identityPub);
      const pin = this.accountState.currentPin(m.userId);
      const recAt = this.accountState.issued(vaultId, m.userId)?.at ?? null;
      const tombAt = this.issuedTombstoneHere(vaultId, m.userId);
      rows.push({
        vaultId, vaultName, userId: m.userId, displayName: m.displayName, email: m.email, identityPub: m.identityPub,
        verifiedLabel: state === "pinned" && pin ? pin.label : null, pinState: state, ownershipConfirmed: owned,
        previouslySharedAt: recAt !== null && recAt > (tombAt ?? -1) ? recAt : null,
      });
    }
    this.legacyRowsByVault.set(vaultId, rows);
    return rows;
  }

  /** The rows the last {@link loadLegacyGrants} for `vaultId` returned (empty until one ran). */
  legacyGrantRows(vaultId: string): LegacyGrantRow[] {
    return this.legacyRowsByVault.get(vaultId) ?? [];
  }

  // ---- A9 (M-3): the removing browser's own durable tombstones ----

  /** The ms at which THIS browser removed `userId` from `vaultId` (durable client state), or null. */
  private issuedTombstoneHere(vaultId: string, userId: string): number | null {
    const ats = (this.clientState.get(ISSUED_TOMBSTONES_KEY) ?? "").split("\n").flatMap((line) => {
      const parts = line.split("|");
      return parts.length === 3 && parts[0] === vaultId && parts[1] === userId && Number.isSafeInteger(Number(parts[2])) ? [Number(parts[2])] : [];
    });
    return ats.length ? Math.max(...ats) : null;
  }

  private recordIssuedTombstoneHere(vaultId: string, userId: string, at: number): void {
    const lines = (this.clientState.get(ISSUED_TOMBSTONES_KEY) ?? "").split("\n").filter((l) => l && !l.startsWith(`${vaultId}|${userId}|`));
    this.clientState.set(ISSUED_TOMBSTONES_KEY, [...lines, `${vaultId}|${userId}|${at}`].sort().join("\n"));
  }

  /** The owner tapped "Re-share <vault> with <member>" on `row` (rule a). Only a row this store offered in the current
   *  list is accepted, once; the vault must be owned by this account's evidence and the member pinned and current
   *  here with the key the row shows. Signs and seals to the PIN key, then records the pair. */
  async confirmReissue(row: LegacyGrantRow): Promise<void> {
    const offered = this.legacyRowsByVault.get(row.vaultId) ?? [];
    if (!offered.includes(row)) throw new Error("that re-share was not offered here (or the list is stale)");
    this.requireOwned(row.vaultId);
    const pin = this.accountState.currentPin(row.userId);
    if (!pin || this.memberPinState(row.userId, row.identityPub) !== "pinned") throw new MemberNotVerifiedError(row.userId);
    await this.postReissue(row.vaultId, pin);
    this.legacyRowsByVault.set(row.vaultId, offered.filter((r) => r !== row));
  }

  /** Vaults a verified transfer moved away from this account during a pull; tombstoned at the end of sync(). */
  private readonly ownershipReleases = new Set<string>();

  private async flushOwnershipReleases(): Promise<void> {
    if (this.ownershipReleases.size === 0) return;
    const ids = [...this.ownershipReleases];
    const now = Date.now();
    // A9 (LOW): the set is cleared only once the record took (locally at least); a release the write could not even
    // adopt (a newer client owns the format) stays queued for the next sync instead of silently never retrying.
    try {
      await this.accountState.update((d) => ids.reduce((acc, id) => withoutOwned(acc, id, now), d));
      for (const id of ids) this.ownershipReleases.delete(id);
    } catch {
      /* retried next sync */
    }
  }

  /** Vaults a re-designation may offer: held, and keyed from our own UVK wrap (never a seal). */
  redesignationChoices(): VaultInfo[] {
    return this.vaults().filter((v) => this.account.keyFromOwnUvkWrap(v.vaultId));
  }

  constructor(
    private api: ApiClient,
    private account: Account,
    /** §D: the durable offline cache. Defaults to the no-op NullCache so existing
     *  callers keep today's memory-only behavior; S3 wires `openVaultCache(userId)`
     *  here at unlock. Deliberately NOT readonly — the §D.1 stuck-cache demotion swaps
     *  in a NullCache mid-session, keeping ONE code shape (every cache touch below goes
     *  through `this.cache` unconditionally; NullCache no-ops). The cross-tab lock name
     *  derives from `account.userId` (§D.5). */
    private cache: VaultCache = new NullCache(),
    clientState?: ClientStateStore,
  ) {
    this.clientState = clientState ?? localClientState(account.userId);
    this.accountState = new AccountStateSync(api, account, this.clientState);
    // Root cause A §1.4 step 7: the verifier picks the pin by the sender the statement NAMES, from this account's
    // human-verified contacts, and learns whether that pin is current on this device (L-3).
    this.account.grantPins = (uid) => {
      const c = this.accountState.doc.contacts.find((x) => x.userId === uid);
      if (!c) return null;
      try {
        return { identityPub: fromB64(c.identityPub), current: this.accountState.isCurrent(c) };
      } catch {
        return null;
      }
    };
    for (const v of this.persistedVouches().values()) this.account.authorizeLegacyKey(v.vaultId, v.tag, v.kind);
    this.loadHeldKeys();
    // A7: the device's consumed removal nonces merge into account state at each flush.
    this.accountState.deviceConsumed = () => {
      const out: Record<string, ConsumedNonce[]> = {};
      for (const [vaultId, m] of this.consumedNonces) out[vaultId] = [...m.entries()].map(([n, t]) => [n, t] as ConsumedNonce);
      return out;
    };
    // CR-01 (compliance 2026-07-15): the moment this cache's IndexedDB connection closes out
    // from under us — a browser-forced close (eviction/corruption) or a sibling tab / session-
    // level wipe firing deleteDatabase → versionchange — idbcache invokes onClosed. Demote to
    // NullCache so a closed handle can never linger with durable=true and silently swallow
    // (black-hole) an offline write. Set on construction; demoteCache re-points nothing (the
    // NullCache it swaps in never fires onClosed).
    this.cache.onClosed = () => this.demoteCache();
  }

  /**
   * CR-01 (breaker #1): sever the live store from a cache whose IndexedDB connection has CLOSED.
   * A closed IdbVaultCache keeps `durable=true` yet resolves every write as a guarded no-op
   * (§D.2a), so without this save()/remove() would enqueue into a black hole and report SUCCESS
   * while the mutation is neither pushed, queued, nor refused (the CR-01 offline-write black hole).
   * Demoting to NullCache flips durable=false, so offlineQueueAllowed() refuses the queue and the
   * write routes to the real flushChunk send (refuse-not-degrade). Wired two ways: the cache's
   * onClosed callback (idbcache versionchange/onclose — covers a sibling tab / setOfflineCopyEnabled
   * / wipeVaultCache / applyOrgOfflineCachePolicy, all of which deleteDatabase this live handle) AND
   * a direct call from the Settings offline-copy toggle/remove for a synchronous demote. Idempotent;
   * does NOT wipe (whoever closed the DB owns deleteDatabase) and does NOT set the stuck-cache
   * storage-error flag (this is a clean close, not the 3-strike breaker). Safe when already cache-less.
   */
  demoteCache(): void {
    if (!this.cache.durable) return; // already NullCache — nothing to demote
    const dead = this.cache;
    this.cache = new NullCache();
    dead.close(); // programmatic close never re-fires onClosed — no reentrancy
  }

  list(): VaultItem[] {
    return [...this.itemsById.values()].sort((a, b) => a.doc.name.localeCompare(b.doc.name));
  }

  get(itemId: string): VaultItem | undefined {
    return this.itemsById.get(itemId);
  }

  /**
   * The backup's `skipped.undecryptable` (spec 07 §2.4): every item that exists but can't be
   * decrypted right now — HELD-key decrypt failures (a newer formatVersion, spec 02 §3 fail-closed,
   * or a corrupt/mismatched blob) AND items whose vault VK we cannot open (a missing / undecryptable
   * grant). Both are skipped from the visible list()/get() surface but ENUMERATED here instead of
   * silently omitted from a backup — matching the Kotlin ExportPlanner (which enumerates missing-VK
   * items too; the earlier "not ours to enumerate" claim here was wrong). Sorted for deterministic
   * backup bytes.
   */
  undecryptable(): UndecryptableItem[] {
    return [...this.undecryptableById.values(), ...this.missingVkById.values()].sort(
      (a, b) => a.vaultId.localeCompare(b.vaultId) || a.itemId.localeCompare(b.itemId),
    );
  }

  /**
   * Held-key items whose formatVersion is newer than ITEM_FORMAT_VERSION (fail-closed,
   * spec 02 §3) — they exist but silently vanish from list(). Drives the "N items need
   * an app update" banner (core SyncEngine.needsUpdateCount parity). A corrupt blob at
   * a SUPPORTED fv is deliberately excluded: that is a data problem an update won't fix.
   */
  needsUpdateCount(): number {
    let n = 0;
    for (const u of this.undecryptableById.values()) if (u.formatVersion > ITEM_FORMAT_VERSION) n++;
    return n;
  }

  /**
   * Vaults whose key we hold, personal first then shared by name.
   *
   * `type` is DERIVED, not copied (security review 2026-10, root cause A §4.3; core vaultInfos twin):
   * "personal" iff the vault is `account.personalVaultId`, which only a UVK-authenticated personal wrap sets:
   * one the server served, one this browser cached, or one minted from the human's confirmed choice (there is
   * no automatic migration pick any more). The server's `type` label is ignored for every decision this feeds.
   */
  vaults(): VaultInfo[] {
    const out: VaultInfo[] = [];
    for (const v of this.vaultsById.values()) {
      if (!this.account.hasVault(v.vaultId)) continue; // no key → nothing usable
      const name = this.account.decryptVaultName(v.vaultId, v.metaBlob);
      const personal = v.vaultId === this.account.personalVaultId;
      out.push({
        vaultId: v.vaultId,
        type: personal ? "personal" : "shared",
        name: name && name !== "(vault)" ? name : personal ? "Personal" : "Shared",
        role: this.account.roleFor(v.vaultId),
      });
    }
    return out.sort((a, b) =>
      a.type === b.type ? a.name.localeCompare(b.name) : a.type === "personal" ? -1 : 1,
    );
  }

  private syncInFlight: Promise<void> | null = null;

  /**
   * §D.3 reconnect order (breaker #3, core SyncEngine.sync parity): flushQueue → pull →
   * surfaceStagedDenials, IN THAT ORDER. Flush runs BEFORE pull so a removedGrants entry
   * arriving in the same cycle can park a just-denied offline edit (F21); surface runs
   * AFTER pull so a denial is classified against a snapshot that postdates it. EVERY caller
   * — the WS bell, the F29 offline poll, Sync-now, a save()/remove(), and the lifecycle
   * reconciles — runs this whole cycle. A genuine (still-live-vault) denial is re-thrown by
   * surfaceStagedDenials so the Editor's failure UX is unchanged.
   */
  async sync(): Promise<void> {
    await this.flushQueue();
    await this.pull();
    // H38 (audit 2026-09-13): a bell that rang DURING that pull joined it and got a snapshot
    // fetched before the bell's commit. If the bell's rev is still ahead of the cursor the
    // change is not here yet — pull once more (a fresh single-flight cycle, since the joined
    // one has settled). Bounded: one extra pull per sync; a bell landing during THIS pull is
    // caught by its own syncNow's comparison after it joins.
    if (this.bellRev > this.cursor) await this.pull();
    // §4.2: best effort, never fails the sync. Then root cause A §4.3 (A5 review H-1): local, never mints — and since A9
    // (M-2) it reads the account's designation, so the refresh comes FIRST; a designation this browser recorded
    // (register, an accepted change) is written back by one more refresh.
    const mergedStateBefore = this.accountState.hasHighWater(); // A9 review LOW-4: before THIS sync's refresh could set it
    await this.accountState.refresh().catch(() => {});
    this.decidePersonalLocally(mergedStateBefore);
    if (this.designationDirty) {
      this.designationDirty = false;
      await this.accountState.refresh().catch(() => {});
    }
    // Root cause A (A6, core SyncEngine.sync twin): pins may have changed, so re-run §1.4 for rows not yet adopted;
    // then the member self-wrap (§3.2), minted ONLY for a key from a verified v2 grant or a v1 key this device
    // froze or the human confirmed (never an unconfirmed v1 seal: the A1 laundering bug). The owner's §8.2 step 4
    // re-issue is NOT run here (A6b): it needs the owner's confirmation, or the issued-grants record.
    this.reevaluateGrants();
    this.persistHeldKeys();
    this.markLiveVaults();
    this.surfaceGrantStates();
    await this.postAuthorizedSelfWraps();
    await this.flushOwnershipReleases();
    await this.flushMemberReceived();
    try {
      await this.surfaceStagedDenials();
    } finally {
      // L2: even when surface re-throws a genuine denial, sweep C2 snapshots whose queue
      // row a SIBLING tab already settled (their results never reach this tab's maps).
      await this.prunePreEditSnapshots();
    }
  }

  /**
   * L2 (2026-07-14 re-review): drop pre-edit snapshots whose queue row no longer exists in
   * ANY durable state — settled by a sibling tab's drain (this tab never sees the applied/
   * denied result for rows another tab pushed, so its C2 entries would leak per-session).
   * Durable caches only: NullCache persists no rows at all, so its in-flight snapshots must
   * not be swept (its queue is also tab-private — nothing can settle elsewhere). Candidates
   * are captured BEFORE the row reads so an entry set mid-prune is never swept: set AFTER
   * the capture ⇒ not a candidate; set before ⇒ its enqueue (awaited earlier still) is
   * visible to the later reads. Best-effort hygiene — never fails the sync.
   */
  private async prunePreEditSnapshots(): Promise<void> {
    if (!this.cache.durable || this.preEditByMutation.size === 0) return;
    const candidates = [...this.preEditByMutation.keys()];
    try {
      const [pending, staged] = await Promise.all([this.cache.pending(), this.cache.stagedDenied()]);
      const live = new Set([...pending, ...staged].map((m) => m.mutationId));
      for (const id of candidates) if (!live.has(id)) this.preEditByMutation.delete(id);
    } catch {
      /* a failed read skips one sweep — the next sync retries */
    }
  }

  /**
   * Pull everything new since the cursor. Handles 410 (resync from 0).
   *
   * SINGLE-FLIGHT: concurrent callers (WS bell, socket reopen, the offline poll, the
   * Sync-now button, save/remove reconciles) all join the ONE in-flight pull —
   * overlapping pulls could apply an older response after a newer one and move the
   * cursor backwards, the very corruption the rollback guards below exist to reject.
   * Kept SEPARATE from flushQueue's single-flight so a save's flush can stage a denial
   * while an older pull is still in flight — the epoch counters classify it correctly.
   */
  private pull(): Promise<void> {
    this.syncInFlight ??= this.pullOnce().then(() => this.surfaceKeyAnomalies()).finally(() => {
      this.syncInFlight = null;
    });
    return this.syncInFlight;
  }

  private async pullOnce(): Promise<void> {
    // §8.2 (A6 re-review LOW-D, core pull() parity): evidence is what THIS cache held before the upgrade. Every
    // pull marks the freeze as done first, so if no hydrate looked at the cache, nothing pulled from now on can
    // count as pre-upgrade evidence.
    if (!(await this.cache.freezeDone())) await this.cache.setFreezeDone();
    const since = this.cursor;
    // Epoch guard (breaker #3, core SyncEngine.pull #0 belt): stamp the START of this pull
    // BEFORE anything is fetched. surfaceStagedDenials only classifies a denial once a pull
    // whose start-id exceeds the denial's stagedBefore has completed — i.e. the verdict
    // always comes from a snapshot fetched AFTER the denial was staged.
    const myStart = ++this.pullStartCounter;
    // Capture the vaults we HOLD THE KEY FOR before applying this pull, with their decrypted
    // names (spec 03 §11: notices fire ONLY for locally-held vaults, and the pre-purge name
    // drives the copy). Nothing here fires on a since=0 / fresh-device pull — the set is empty.
    const prePullNames = new Map<string, string>();
    for (const [vaultId, v] of this.vaultsById) {
      if (this.account.hasVault(vaultId)) prePullNames.set(vaultId, this.account.decryptVaultName(vaultId, v.metaBlob));
    }
    let resyncing = false;
    let resp;
    try {
      resp = await this.api.sync(since);
    } catch (e) {
      if (e instanceof ApiError && e.status === 410) {
        // Fetch the replacement snapshot FIRST (core SyncEngine parity): the working
        // set is wiped only once the full response is in hand, so a failed or
        // rejected refetch never leaves an emptied store behind.
        resyncing = true;
        resp = await this.api.sync(0);
      } else {
        throw e;
      }
    }

    // Rollback guards BEFORE anything is applied (F31, mirrors core SyncEngine.pull /
    // spec 05 T1: warn, never overwrite local newer state; spec 03 §4). A non-full
    // response below our cursor, or a full snapshot we did not ask for via the 410
    // path, signals a server rollback/replay — reject it, keep the cursor and local
    // state, and let the caller's failure path (Vault's offline dot) surface it.
    if (resyncing && !resp.full) {
      // We were told our cursor is gone (410) — the ONLY valid continuation is a full
      // snapshot. Applying a partial one would first wipe the working set and then
      // repopulate a sliver of it: most of the vault silently vanishes.
      console.warn("sync rejected: 410 resync returned a non-full response — local state kept");
      throw new SyncIntegrityError("410 resync did not return a full snapshot — local state kept");
    }
    if (!resp.full && resp.rev < since) {
      console.warn(`sync rejected: server rev ${resp.rev} went backwards from cursor ${since} — possible rollback; local state kept`);
      throw new SyncIntegrityError("server rev went backwards — possible rollback; local state kept");
    }
    if (resp.full && since > 0 && !resyncing) {
      console.warn(`sync rejected: unsolicited full snapshot at cursor ${since} — possible rollback; local state kept`);
      throw new SyncIntegrityError("unsolicited full snapshot — possible rollback; local state kept");
    }

    // §D.1: from here on, every in-memory apply buffers its durable twin into `ops`; the
    // whole pull then commits as ONE cache transaction at the end (cursor last). The F31
    // guards above ran BEFORE this buffer exists, so nothing rejected ever touches disk
    // (§D.6). If the apply throws mid-way the buffer is simply never committed — disk
    // stays at the OLD cursor with OLD rows (coherent, A1). Memory then runs AHEAD of
    // disk, and since pulls are driven by the MEMORY cursor the lost delta is never
    // re-fetched this session — commitPull's contiguity guard therefore refuses every
    // later delta (disk never claims a rev whose rows it lacks) until the next session
    // hydrates from the DISK cursor and its first pull re-fetches the whole gap.
    const ops: Array<(b: PullBatch) => void> = [];
    this.pullOps = ops;
    // A1b: homes recorded outside a pull (hydrate of an upgraded cache, a save's first seal) land in this tx.
    for (const itemId of this.homesUnpersisted) {
      const vaultId = this.homes.get(itemId);
      if (vaultId) ops.push((b) => b.setItemHome(itemId, vaultId));
    }
    this.homesUnpersisted.clear();

    if (resyncing) {
      // resync-from-0 re-delivers everything — reset so nothing double-counts.
      this.cursor = 0;
      this.itemsById.clear();
      this.vaultsById.clear();
      this.undecryptableById.clear();
      this.missingVkById.clear(); // A1: a 410 resync-from-0 re-enumerates missing-VK items from scratch
      // F20: a resync re-delivers every current grant — drop the warning set so a vault no longer
      // granted (revoked while offline) doesn't leave a stale "can't open" row; still-bad grants
      // below re-populate it. (addedNoticed is left intact: since=0 never fires an added notice.)
      this.undecryptableGrants.clear();
    }
    // A full snapshot replaces the row stores wholesale: the §D.1 ENUMERATED clear (items/
    // grants/vaults + kv:cursor ONLY — queue/held/replay-floors/accountKeys survive, breaker
    // #2) rides the SAME tx as the snapshot apply, so stale rows the snapshot no longer
    // delivers can't linger and a failed commit strands neither half. Covers the 410 resync
    // AND the since=0 first pull (where memory is empty but disk might not be).
    if (resp.full) ops.push((b) => b.clear());

    // EVERY grant goes through addGrant: the role update always applies (a role change
    // re-delivers the grant while the VK is already held); the key-open only runs when
    // the VK is missing (sealed member grants or UVK-wrapped personal/owner grants).
    // A LIVE grant re-arriving for a vault in the holding area is a reinstate signal
    // (restore / re-add) — collected here, acted on after items apply.
    const reinstated = new Set<string>();
    const newlyAdded = new Set<string>(); // F20: grants for vaults not held before this pull
    for (const grant of resp.grants) {
      // §D.1: persist EVERY delivered grant row (wire/ciphertext — native parity), even one
      // this device can't open: it must survive restarts so hydrate re-attempts the open and
      // the F20 warning recomputes (§D.4) instead of the vault silently vanishing from disk.
      ops.push((b) => b.upsertGrant(grant));
      const heldBefore = this.account.hasVault(grant.vaultId); // BEFORE addGrant opens the key
      try {
        this.account.addGrant(grant);
        this.grantWireByVault.set(grant.vaultId, grant); // retain the grant blob (§6, normative)
        this.undecryptableGrants.delete(grant.vaultId); // opened now → clear any stale F20 warning
        if (this.holding.has(grant.vaultId)) reinstated.add(grant.vaultId);
        else if (!heldBefore && since > 0 && !resyncing) newlyAdded.add(grant.vaultId); // a genuine add
      } catch {
        // F20: undecryptable grant — sealed to an identity this device doesn't hold, or a newer
        // grant format. The vault's items stay skipped below; retain the id so the UI shows a
        // PERSISTENT "can't open this shared vault on this device" warning until a later pull opens
        // it. Guarded on !heldBefore so a re-delivered grant for a vault we ALREADY hold (a role
        // update whose sealedVk happens to fail to re-open) never fabricates a false warning.
        // A damaged UVK wrap (root cause A §3.1) is its own "key unreadable" notice, not F20's
        // "sealed to another device" — the copy for F20 would send the member to the wrong fix.
        if (this.account.keyUnreadable(grant.vaultId)) this.undecryptableGrants.delete(grant.vaultId);
        else if (!heldBefore) this.undecryptableGrants.add(grant.vaultId);
      }
    }
    for (const delivered of resp.vaults) {
      // spec 02 §4 warn-and-keep-newer: a delivered metaBlob whose metaV regressed keeps
      // the newer local blob (rev/lifecycle fields still apply).
      const vault = this.keepNewerMeta(delivered);
      this.vaultsById.set(vault.vaultId, vault);
      ops.push((b) => b.upsertVault(vault)); // the merged keepNewerMeta row — disk mirrors memory
      // Consumed-deleteId marker (spec 03 §11 / #4): a live vault that WAS restored carries
      // restoreProof over the deleteId it undid. Verifying it durably marks the deleteId
      // consumed so a later replayed old tombstone bearing it is recognized as stale — even
      // on a device that was offline across the whole delete→restore cycle.
      if (vault.restoreProof && vault.deleteId && this.account.hasVault(vault.vaultId)) {
        try {
          const key = await this.account.lifecycleKeyFor(vault.vaultId);
          if (verifyProof(vault.restoreProof, await restoreProof(key, vault.vaultId, vault.deleteId))) {
            const consumed = vault.deleteId;
            this.consumedDeleteIds.add(consumed);
            ops.push((b) => b.addConsumedDeleteId(consumed)); // replay floor — durable (§D.1)
          }
        } catch {
          /* no key / bad proof — leave unconsumed */
        }
      }
      // Transfer state (spec 03 §11): recompute the verified incoming offer + surface a
      // completion notice for a newly-seen accepted transfer.
      await this.applyTransferState(vault, prePullNames.has(vault.vaultId) && since > 0 && !resyncing);
    }

    // F20: a calm "you were added to <vault>" notice for each vault whose key we did NOT hold
    // before this pull but now do. Never on a since=0 / resync pull (newlyAdded is empty then —
    // the hazard: notices fire only for verifiable NEW state), never for a reinstated (restored /
    // re-added held) vault (that path emits "restored"), never for a personal vault, never for a
    // vault we OWN, and once per vault for the store's lifetime (mirrors the transfer-complete
    // dedup). Emitted AFTER vaults apply so the name decrypts under the freshly-opened key.
    for (const vaultId of newlyAdded) {
      if (reinstated.has(vaultId) || this.addedNoticed.has(vaultId)) continue;
      const v = this.vaultsById.get(vaultId);
      if (!v || vaultId === this.account.personalVaultId || !this.account.hasVault(vaultId)) continue;
      // An owner grant is our OWN wrappedVk (opened under the UVK), so a second active device sees
      // a vault THIS account just created as a brand-new grant. "You were added to X" would be a
      // lie there. Ownership handed TO us arrives on a vault we already held (promotion), so it is
      // already excluded by heldBefore — and it emits its own transfer-complete notice regardless.
      if (this.account.roleFor(vaultId) === "owner") continue;
      this.addedNoticed.add(vaultId);
      // §1.6: a verified grant names the PINNED contact who signed it; a legacy add names no one.
      const sender = this.account.signedGrantSender(vaultId);
      const byLabel = sender ? this.accountState.doc.contacts.find((c) => c.userId === sender)?.label : undefined;
      this.pushNotice({ id: crypto.randomUUID(), vaultId, vaultName: this.account.decryptVaultName(vaultId, v.metaBlob), kind: "added", ...(byLabel ? { byLabel } : {}) });
    }

    const conflictsToMaterialize: WireItem[] = [];
    for (const item of resp.items) {
      // INV-HOME first (A1b): a row under another vault than this item's home is not applied at all (not even a
      // tombstone) and never reaches the cache, the working set, search, export or autofill.
      if (!this.admitHome(item)) continue;
      // §D.1 disk twin first: tombstone ⇒ delete, else the WIRE row — persisted even when
      // the VK is missing or the decrypt fails (everything at rest is ciphertext; hydrate
      // re-runs the same tri-state below, retrying undecryptables — §D.4).
      if (item.deleted) ops.push((b) => b.deleteItem(item.itemId));
      else ops.push((b) => b.upsertItem(item));
      this.applyWireItem(item, conflictsToMaterialize);
    }

    this.cursor = resp.rev;

    // Reinstate (spec 03 §11): a live grant re-arrived for a held vault (restore / re-add) —
    // the vault + its items are back in the live set via the ordinary backfill above; here we
    // clear the holding record, re-enqueue parked mutations for replay, mark the deleteId
    // consumed, and notice it. Runs AFTER items apply so replay sees current state.
    const replayMutations: Mutation[] = [];
    for (const vaultId of reinstated) {
      const held = this.holding.get(vaultId);
      if (!held) continue;
      this.holding.delete(vaultId);
      ops.push((b) => b.removeHeld(vaultId)); // §D.1 holding-area move, disk twin
      if (held.deleteId) {
        const consumed = held.deleteId;
        this.consumedDeleteIds.add(consumed);
        ops.push((b) => b.addConsumedDeleteId(consumed));
      }
      // Belt: rehydrate any held ciphertext item the backfill did not re-deliver.
      for (const wi of held.items) {
        if (this.itemsById.has(wi.itemId) || !this.admitHome(wi)) continue;
        try {
          this.itemsById.set(wi.itemId, {
            itemId: wi.itemId,
            vaultId,
            rev: wi.rev,
            updatedAt: wi.updatedAt,
            formatVersion: wi.formatVersion,
            doc: this.account.decryptItem(wi),
          });
          ops.push((b) => b.upsertItem(wi)); // back into the live rows on disk too
        } catch {
          /* superseded by backfill or undecryptable — skip */
        }
      }
      // C1 (core SyncEngine.applyPull reinstate / LC-1 parity): the parked mutations RE-ENTER
      // the durable queue INSIDE this pull's one-tx commit — crash-safe, with their ORIGINAL
      // mutationIds (server dedup + the never-re-push-denied rule make replay converge). The
      // retired direct `push([m])` replay threw on a denied result AND on any transport/5xx
      // failure AFTER holding.delete/removeHeld above had already run, destroying the parked
      // edit from memory and disk. Queued rows instead ride the ordinary flushQueue (invoked
      // post-commit below): a transport failure leaves them durably queued — offline replay
      // failure ≠ pull failure — and a re-denial re-stages through flushChunk →
      // surfaceStagedDenials (re-parked if the vault is held again; the calm `wasReplay`
      // notice on a live vault), never a loss.
      for (const m of held.parked) {
        ops.push((b) => b.enqueue(m));
        this.replayedMutationIds.add(m.mutationId); // a denial of these is a calm notice, not a throw
        this.pendingSyncItemIds.add(m.itemId); // queued again — the affordance mark returns until it flushes
        replayMutations.push(m);
      }
      this.pushNotice({ id: crypto.randomUUID(), vaultId, vaultName: held.cachedName, kind: "restored" });
    }

    // Revoked memberships (spec 03 §11 tri-state). F21: this MUST NOT throw — a denied
    // mutation or a bad proof can never abort the pull that delivers removedGrants.
    const infoByVault = new Map<string, RemovedGrantInfo>();
    for (const info of resp.removedGrantsInfo ?? []) infoByVault.set(info.vaultId, info);
    for (const vaultId of resp.removedGrants) {
      try {
        await this.handleRemovedGrant(vaultId, infoByVault.get(vaultId), prePullNames.get(vaultId), since, resyncing);
      } catch (e) {
        console.warn(`removedGrant handling failed for ${vaultId} (non-fatal; pull continues)`, e);
        this.hardDropLocal(vaultId); // still ensure the vault leaves the live view
      }
    }

    // Materialize a visible conflict copy for each flagged item, then clear the flag.
    // This MUST NOT throw (F21 posture, same as the removedGrants loop above): it PUSHES,
    // and a failed push (network drop, a denied-role race) aborting the pull this late —
    // after the in-memory cursor advanced — would orphan the whole cache commit below.
    // Copy semantics on a failed push are unchanged from when this loop threw: the flag
    // stays set server-side and the copy waits for a later edit/device.
    for (const item of conflictsToMaterialize) {
      // A reader must not materialize — its push would be denied (spec 03 §5); the
      // flag waits for a writer/owner on some device.
      if (this.account.roleFor(item.vaultId) === "reader") continue;
      try {
        await this.materializeConflict(item);
      } catch (e) {
        console.warn(`conflict materialization failed for ${item.itemId} (non-fatal; pull continues)`, e);
      }
    }

    // A1b: this pull's INV-HOME / INV-CONFLICT refusals, as ONE "the server sent an item under the wrong vault" notice.
    this.surfaceWrongVault();
    // A7: liveSince for every vault that went live in this pull, and the held-key memory, before the cursor.
    this.markLiveVaults();
    this.persistHeldKeys();
    const syncedAt = Date.now();
    this._lastSyncAt = syncedAt;
    // §D.1 ordering: the cursor is the LAST write of the tx (nothing on disk ever claims a
    // rev its rows don't have), plus the lastSyncAt stamp hydrate restores (§D.4).
    ops.push((b) => {
      b.setCursor(resp.rev);
      b.setLastSyncAt(syncedAt);
    });
    this.pullOps = null;
    // Epoch guard: this pull has COMPLETED its (authoritative) in-memory apply — advance the
    // freshest-completed marker so surfaceStagedDenials may now classify any denial staged
    // BEFORE this pull started (stagedBefore < myStart). A pull that threw above never
    // reaches here, so a denial it might have classified stays durably staged for the next
    // cycle. Set from the in-memory apply (not the best-effort disk commit below) — the
    // snapshot this pull observed is what a verdict is drawn against.
    if (myStart > this.freshestCompletedPullStart) this.freshestCompletedPullStart = myStart;
    // In-memory apply is COMPLETE and authoritative from here — the disk commit mirrors it
    // and is allowed to fail (in-memory-ahead-of-disk is safe, §D.1); it never rolls back
    // memory and never fails the sync the caller already observed. `since` (captured at
    // the top, BEFORE the resync reset) rides along for the contiguity guard: this
    // response is a delta over (since, resp.rev] and may only land on a disk whose
    // cursor is ≥ since.
    await this.commitPull(ops, resp.rev, since, resyncing, resp.full);

    // C1: flush the reinstate replays through the ordinary queue path (core pull()'s
    // `runCatching { flushQueue() }`). Runs AFTER the commit so the drain reads the rows the
    // tx just landed. Any failure is contained: the rows stay durably queued for the next
    // sync (and if the commit itself did not land, the held record is still on disk — the
    // next session re-runs the reinstate idempotently). Their denials stage with
    // stagedBefore = this pull's start, so surfaceStagedDenials classifies them only against
    // a LATER pull — native semantics.
    if (replayMutations.length > 0) {
      try {
        if (this.cache.durable) {
          await this.flushQueue();
        } else {
          // NullCache: the buffered enqueue was a no-op — send the in-memory copies directly
          // through the same result-settling path (memory-only stores keep replay-on-restore;
          // a transport loss here is the pre-cache posture, nothing durable exists to keep).
          const displaced: Displaced[] = [];
          for (let i = 0; i < replayMutations.length; i += VaultStore.SERVER_BATCH_MAX) {
            await this.flushChunk(replayMutations.slice(i, i + VaultStore.SERVER_BATCH_MAX), displaced);
          }
          for (const d of displaced) await this.materializeConflictFromServerItem(d);
        }
      } catch (e) {
        console.warn("reinstate replay flush failed — the replayed edits stay queued for the next sync", e);
      }
    }
  }

  /**
   * §D.3 durable-queue drain (core SyncEngine.flushQueue twin). Sends queued mutations in
   * server-cap batches with their STABLE mutationIds (server dedup makes a retry idempotent,
   * D4). A `denied` result is durably STAGED (cache.markStagedDenied — cache.pending() then
   * stops returning it, so it is never blindly re-pushed) and indexed in preParkedByVault
   * with the CURRENT pull-start epoch: the reconnect-order pull that follows either folds it
   * into the holding area (its vault went in-grace → PARKED for restore replay, F21) or
   * surfaceStagedDenials concludes a genuine permission denial. NEVER throws for a denied
   * result — a denied flush must not abort the pull that delivers removedGrants. A transport
   * failure (api.push rejects) DOES propagate: the rows stay durably queued for the next
   * flush, and save()/remove() turn it into the success-as-QUEUED return (persist-gated).
   * Single-flight (flushInFlight) so concurrent callers never double-push the same rows.
   */
  private flushQueue(): Promise<void> {
    // §D.5 (C3): the drain runs under the SAME cross-tab Web Lock as the pull commit — the
    // design serializes "each pull-apply commit AND queue flush". Two tabs draining at once
    // would each push the same rows (server dedup absorbs that) but could each materialize
    // the displaced conflict value, duplicating the copy. Lock-wait timeout degrades to an
    // unlocked drain (availability posture, same as commitPull). Never nested: commitPull's
    // lock is released before the C1 replay flush runs, and the drain never pulls.
    this.flushInFlight ??= this.withCacheLock(() => this.flushQueueOnce()).finally(() => {
      this.flushInFlight = null;
    });
    return this.flushInFlight;
  }

  private async flushQueueOnce(): Promise<void> {
    const displaced: Displaced[] = []; // PDD-1: (losing serverItem, winner rev)
    for (;;) {
      const chunk = (await this.cache.pending()).slice(0, VaultStore.SERVER_BATCH_MAX);
      if (chunk.length === 0) break;
      const progressed = await this.flushChunk(chunk, displaced); // rejects offline → propagates
      if (!progressed) break; // defensive: the server returns one result per mutation
    }
    for (const d of displaced) await this.materializeConflictFromServerItem(d);
  }

  /**
   * Push ONE batch and settle each row's queue fate (the shared core of the queue drain and
   * of save()/remove()'s immediate send — the latter passes the just-created mutation so a
   * NullCache, whose enqueue is a no-op, still sends it). Returns whether any row settled
   * (the drain loop's no-progress guard). NEVER throws for a `denied` result (it stages);
   * a transport reject from api.push DOES propagate — the caller turns it into queued /
   * push-or-throw. Collects displaced conflict values into `displaced` (materialized by the
   * caller after the drain). On a NullCache, markStagedDenied/dequeue are no-ops, but the
   * in-memory preParkedByVault staging still drives surfaceStagedDenials the same way.
   */
  private async flushChunk(chunk: Mutation[], displaced: Displaced[]): Promise<boolean> {
    let resp: PushResponse;
    try {
      resp = await this.api.push(chunk); // rejects offline → propagates; rows stay queued
    } catch (e) {
      // H03/H19 (audit 2026-09-13, core SyncEngine.pushBatch twin): a DEFINITIVE whole-batch
      // refusal — 400 (a malformed request the client itself minted; on a pre-H03 server also
      // `unknown_attachment` / `attachment_mismatch`, which it still throws batch-wide) or 413
      // (`body_too_large`, fired before the handler) — must not leave the batch at the head of
      // the queue where every later sync would re-send it identically, fail BEFORE its pull,
      // and the tab would stop receiving anything (the sole "remedy" being a sign-out that
      // wipes every other queued edit). Nothing of a refused batch was applied and the dedup
      // window makes re-sends idempotent, so BISECT: re-send each half until the refusal
      // narrows to single rows, each of which is dropped durably as a poison row. Every other
      // failure — transport, 401/426, 403/409/410, 429, 5xx — propagates as before: the rows
      // stay queued for the next flush.
      if (!(e instanceof ApiError && (e.status === 400 || e.status === 413))) throw e;
      if (chunk.length === 1) {
        await this.rejectRow(chunk[0]!, e.code);
        return true;
      }
      const mid = Math.floor(chunk.length / 2);
      const a = await this.flushChunk(chunk.slice(0, mid), displaced);
      const b = await this.flushChunk(chunk.slice(mid), displaced);
      return a || b;
    }
    const byId = new Map(resp.results.map((r) => [r.mutationId, r]));
    let progressed = false;
    for (const m of chunk) {
      const r = byId.get(m.mutationId);
      if (!r) continue;
      // C1: settled either way — a reinstate-replayed row's denial gets the calm-notice tag
      // (core flushQueue's `replayedMutationIds.remove` shape).
      const wasReplay = this.replayedMutationIds.delete(m.mutationId);
      if (r.status === "rejected") {
        // H03: the server answered for THIS row alone — it can never apply as sent (its
        // attachment refs are gone, or it is over quota). Drop it, revert its optimistic
        // apply, tell the user; the sibling rows and the pull proceed.
        await this.rejectRow(m, r.reason ?? "rejected");
        progressed = true;
        continue;
      }
      if (r.status === "denied") {
        // Stage durably + index with the epoch (stagedBefore = the last pull that STARTED).
        // The reconnect pull that follows either parks it (vault in-grace, F21) or
        // surfaceStagedDenials classifies it a genuine denial. Dedup the index (a concurrent
        // flush racing a save's direct send could stage the same mutationId twice — the SAME
        // mutationId is idempotent server-side, D4).
        await this.cache.markStagedDenied(m.mutationId);
        const staged = this.preParkedByVault.get(m.vaultId) ?? [];
        if (!staged.some((s) => s.mutation.mutationId === m.mutationId)) {
          staged.push({ mutation: m, stagedBefore: this.pullStartCounter, wasReplay });
          this.preParkedByVault.set(m.vaultId, staged);
        }
        this.pendingSyncItemIds.delete(m.itemId); // no longer "pending sync" — it is staged-denied
      } else {
        // PDD-1: a conflicting PUT keeps OUR value live (LWW) and returns the DISPLACED
        // (losing) version — materialize the copy from THAT after the drain (the pull side
        // sees only the winner). Guard op==="put": a losing DELETE's serverItem is the
        // SURVIVING winner, not a displaced value — copying it would spawn a spurious dup.
        if (r.status === "conflict" && m.op === "put" && r.serverItem && r.newItemRev != null) {
          displaced.push({ item: r.serverItem, winnerRev: r.newItemRev, pushedVaultId: m.vaultId });
        }
        await this.cache.dequeue(m.mutationId); // applied / duplicate / handled conflict — definitive
        this.pendingSyncItemIds.delete(m.itemId);
        this.preEditByMutation.delete(m.mutationId); // committed — the C2 snapshot is obsolete
      }
      progressed = true;
    }
    return progressed;
  }

  /**
   * H03/H19 (core SyncEngine.rejectRow twin): durably drop ONE definitively-refused queue row.
   * Its optimistic apply is undone from the C2 snapshot exactly as a genuine denial's would be
   * (revertDeniedMutation: guarded so a fresher server row is never regressed) — the refused
   * value must not outlive its refusal, and a delta server never re-delivers the unchanged
   * row. The fate is recorded so save()/remove() can throw the honest editor error for their
   * own row, and the durable "write-rejected" notice is minted — accumulated per vault so a
   * batch that lost several rows reads as one banner with the true counts (pushNotice keeps
   * one notice per vault+kind, so the merged notice replaces the earlier one). This is NOT
   * the "write-refused" (permission) notice: nothing about the member's access changed.
   */
  private async rejectRow(m: Mutation, reason: string): Promise<void> {
    this.replayedMutationIds.delete(m.mutationId);
    const outcome = await this.revertDeniedMutation(m);
    try {
      await this.cache.dequeue(m.mutationId);
    } catch {
      /* best-effort durable drop — NullCache no-ops; a durable failure is retried by the next drain's re-verdict */
    }
    this.pendingSyncItemIds.delete(m.itemId);
    this.preEditByMutation.delete(m.mutationId);
    this.rejectedMutationIds.set(m.mutationId, reason);
    const prior = this.noticeList.find((x) => x.vaultId === m.vaultId && x.kind === "write-rejected");
    this.pushNotice({
      id: crypto.randomUUID(),
      vaultId: m.vaultId,
      vaultName: this.liveVaultName(m.vaultId),
      kind: "write-rejected",
      reason: prior?.reason ?? reason,
      parkedCount: (prior?.parkedCount ?? 0) + 1,
      revertedCount: (prior?.revertedCount ?? 0) + (outcome === "reverted" ? 1 : 0),
      removedCount: (prior?.removedCount ?? 0) + (outcome === "removed" ? 1 : 0),
    });
  }

  /**
   * §D.3 denial classification (core SyncEngine.surfaceStagedDenials twin), run AFTER the
   * pull in every sync() cycle. A staged denial whose vault landed in the holding area was
   * already PARKED (folded by moveToHolding, or a late arrival for an already-held vault is
   * folded here); anything else on a still-LIVE vault is a genuine denial: a REPLAYED one
   * (C1) drains into the calm "replay-denied" notice, a first-hand one REVERTS its optimistic
   * apply from the C2 snapshot, mints the durable "write-refused" notice, is durably dropped,
   * and is then re-thrown so the Editor's failure UX is unchanged.
   * EPOCH GUARD (breaker #3): an entry may be classified ONLY once a pull that STARTED after
   * it was staged has COMPLETED (freshestCompletedPullStart > stagedBefore) — a verdict must
   * never be drawn from a stale snapshot that predates the denial (a save's sync() that
   * JOINED an older in-flight pull). A too-fresh entry stays durably staged for the next cycle.
   */
  private async surfaceStagedDenials(): Promise<void> {
    if (this.preParkedByVault.size === 0) return;
    let genuine = 0;
    for (const [vaultId, entries] of [...this.preParkedByVault]) {
      const ripe = entries.filter((e) => this.freshestCompletedPullStart > e.stagedBefore);
      const tooFresh = entries.filter((e) => !(this.freshestCompletedPullStart > e.stagedBefore));
      if (ripe.length === 0) continue; // nothing yet classified against a post-staging pull
      const held = this.holding.get(vaultId);
      if (held) {
        // Late arrival for an already-held vault: PARK it (survives the next restore) and
        // drop its queue row — both in ONE tx so a crash can't double-load it (once via
        // stagedDenied→preParkedByVault, once via held.parked; the S2 double-load note).
        for (const e of ripe) {
          if (!held.parked.some((m) => m.mutationId === e.mutation.mutationId)) held.parked.push(e.mutation);
          this.pendingSyncItemIds.delete(e.mutation.itemId);
          this.preEditByMutation.delete(e.mutation.mutationId); // parked — restore replay owns it now
        }
        try {
          await this.cache.applyPull((b) => {
            b.putHeld(held);
            for (const e of ripe) b.dequeue(e.mutation.mutationId);
          });
        } catch (err) {
          console.warn(`surfaceStagedDenials: persisting parked-into-holding for ${vaultId} failed (in-memory kept; next sync retries)`, err);
        }
      } else {
        // Vault is LIVE → a genuine refusal (spec 03 §5), classified against a fresh snapshot.
        // C1 (core LC-1): a reinstate-REPLAYED edit refused here — the member's role changed
        // across the grace — drains into the calm "replay-denied" notice, never a thrown sync
        // failure (core drainReplayDenied); only first-hand denials escalate to the caller.
        const replays = ripe.filter((e) => e.wasReplay);
        const firstHand = ripe.filter((e) => !e.wasReplay);
        if (replays.length > 0) {
          this.pushNotice({
            id: crypto.randomUUID(),
            vaultId,
            vaultName: this.liveVaultName(vaultId),
            kind: "replay-denied",
            parkedCount: replays.length,
          });
        }
        if (firstHand.length > 0) {
          genuine += firstHand.length;
          // C2: the S4 optimistic apply must not outlive its refusal — restore the pre-edit
          // truth (memory AND disk) from the enqueue-time snapshot BEFORE the durable drop
          // (a delta server never re-delivers the unchanged row). REVERSE staging order so
          // chained edits of one item unwind back to the true pre-edit value; each revert is
          // guarded so a fresher server row is never regressed. Then a DURABLE notice: the
          // throw below often lands in a background sync() the UI swallows — the user must
          // learn of the refusal from the banner, not the throw. M3: the notice carries what
          // ACTUALLY happened (reverted / removed-by-server / kept) so its copy never claims
          // a restore that didn't run.
          let reverted = 0;
          let removed = 0;
          for (const e of [...firstHand].reverse()) {
            const outcome = await this.revertDeniedMutation(e.mutation);
            if (outcome === "reverted") reverted++;
            else if (outcome === "removed") removed++;
          }
          this.pushNotice({
            id: crypto.randomUUID(),
            vaultId,
            vaultName: this.liveVaultName(vaultId),
            kind: "write-refused",
            parkedCount: firstHand.length,
            revertedCount: reverted,
            removedCount: removed,
          });
        }
        for (const e of ripe) {
          try {
            await this.cache.dequeue(e.mutation.mutationId);
          } catch {
            /* best-effort durable drop — the row is excluded from pending() by its staged flag anyway */
          }
          this.pendingSyncItemIds.delete(e.mutation.itemId);
          this.preEditByMutation.delete(e.mutation.mutationId);
        }
      }
      if (tooFresh.length === 0) this.preParkedByVault.delete(vaultId);
      else this.preParkedByVault.set(vaultId, tooFresh);
    }
    if (genuine > 0) throw new ApiError(403, "denied", `write denied for ${genuine} mutation(s)`);
  }

  /**
   * The tri-state apply of ONE wire row into the in-memory maps — decryptable
   * (itemsById) / held-key-undecryptable (undecryptableById) / missing-VK
   * (missingVkById), with a tombstone ending every enumeration. Shared by the pull
   * loop and §D.4 hydrate so the two can NEVER diverge; `conflicts` collects flagged
   * rows for materialization on the pull path only (hydrate is offline by contract —
   * materializing pushes).
   */
  private applyWireItem(item: WireItem, conflicts?: WireItem[]): void {
    // M1: record every SERVER tombstone this session applies (and un-record on a live
    // row — an undelete/restore re-delivers one) so a denied local delete of the same
    // item never resurrects it from its C2 snapshot. Kept OUTSIDE the tri-state below:
    // a tombstone is authoritative whether or not we hold the vault key. (Hydrate also
    // runs through here but only ever sees live rows — tombstones delete their disk
    // envelope rather than persist, so this set is populated by pulls alone.)
    if (item.deleted) this.serverTombstoned.add(item.itemId);
    else this.serverTombstoned.delete(item.itemId);
    if (!this.account.hasVault(item.vaultId)) {
      // spec 07 §2.4: an item whose vault VK we cannot open is SKIPPED but ENUMERATED into
      // skipped.undecryptable (mirroring the Kotlin ExportPlanner), never silently omitted from a
      // backup. A tombstone ends the enumeration. (A grant that OPENS mid-session does not
      // re-deliver these unchanged items, so they stay enumerated-as-skipped until the next full
      // sync reloads + clears them below — over-reporting, which for a BACKUP is safe: an item
      // named as "skipped" beats a silent omission, which is spec 07 §2.4's whole point.)
      if (item.deleted) {
        this.missingVkById.delete(item.itemId);
        this.missingVkWire.delete(item.itemId);
      } else {
        this.missingVkById.set(item.itemId, { itemId: item.itemId, vaultId: item.vaultId, formatVersion: item.formatVersion });
        this.missingVkWire.set(item.itemId, item);
      }
      return;
    }
    this.missingVkWire.delete(item.itemId);
    // The vault VK is held now — clear any prior missing-VK enumeration for this item. This one
    // line covers became-decryptable (below), held-but-newer-fv (the catch), and held-tombstone,
    // and prevents a missing-VK→held-newer-fv item being counted in BOTH maps (double-count).
    this.missingVkById.delete(item.itemId);
    if (item.deleted) {
      this.itemsById.delete(item.itemId);
      this.undecryptableById.delete(item.itemId); // a tombstone ends the enumeration too
      return;
    }
    try {
      const doc = this.account.decryptItem(item);
      this.itemsById.set(item.itemId, {
        itemId: item.itemId,
        vaultId: item.vaultId,
        rev: item.rev,
        updatedAt: item.updatedAt,
        formatVersion: item.formatVersion,
        doc,
      });
      this.undecryptableById.delete(item.itemId); // became decryptable (e.g. rewritten at v1)
      this.homeApplied(item); // A9 (L-1): applied, so the first such row is the home
      if (item.conflict) conflicts?.push(item);
    } catch {
      // Undecryptable under a HELD key (formatVersion > supported — decryptItem
      // fails closed BEFORE opening the envelope, so capture the wire field here —
      // or a corrupt/mismatched blob). Stays out of the visible list, but its
      // identity is RETAINED so a backup can enumerate it (spec 07 §2.4) instead of
      // silently omitting a credential. The newer rev supersedes any older
      // plaintext we held (Kotlin's upsertItem(wire, null) drops the decrypted twin).
      this.itemsById.delete(item.itemId);
      this.undecryptableById.set(item.itemId, {
        itemId: item.itemId,
        vaultId: item.vaultId,
        formatVersion: item.formatVersion,
      });
    }
  }

  /**
   * §D.4 hydrate: rebuild the in-memory working set from the durable cache with NO
   * server call — called once post-unlock, BEFORE the first sync (S3 wires it into the
   * unlock flow; on NullCache every enumerator is empty, so this is a cold start and
   * the store behaves exactly as today). Grants re-open best-effort (the role applies
   * unconditionally inside addGrant; failures repopulate the F20 warning set), the
   * personal vault is rediscovered from its row, envelopes re-run the EXACT pull
   * tri-state via applyWireItem — undecryptable ones are RETRIED every hydrate (an app
   * upgrade or later-opened grant may make them readable, core parity) — the holding
   * area returns with its display name re-derived from the retained grant (the
   * persisted record carries no plaintext name, A2), the replay floors
   * (consumedDeleteIds / lastVerifiedTransferSeq) and S4's durably staged denials
   * reload, and the cursor (§D.6: the F31 rollback guards now protect ACROSS restarts)
   * plus the "vault as of last sync <t>" stamp restore.
   */
  async hydrate(): Promise<void> {
    // Grants first: keys must open before vault names or items can decrypt.
    for (const grant of await this.cache.grants()) {
      try {
        this.account.addGrant(grant);
        this.grantWireByVault.set(grant.vaultId, grant);
        this.undecryptableGrants.delete(grant.vaultId);
      } catch {
        // F20 recompute: the same persistent "can't open this shared vault" warning a
        // pull maintains; cleared when a later pull delivers an openable grant. A damaged UVK
        // wrap is the separate "key unreadable" notice instead (root cause A §3.1).
        if (!this.account.keyUnreadable(grant.vaultId)) this.undecryptableGrants.add(grant.vaultId);
      }
    }
    for (const vault of await this.cache.vaults()) {
      this.vaultsById.set(vault.vaultId, vault);
    }
    // Root cause A §4.3: the personal vault came from the personal wrap at unlock; only without one does
    // the §8.5 rule run, offline, over the replayed provenance (core hydrate parity).
    this.decidePersonalLocally();
    // A1b INV-HOME: the recorded homes first, then every cached row is admitted against them (an upgraded cache records
    // its homes here, persisted by the next pull); a cached row contradicting a home is quarantined, never applied.
    for (const h of await this.cache.itemHomes()) this.homes.set(h.itemId, h.vaultId);
    for (const q of await this.cache.quarantined()) this.quarantinedRows.set(q.itemId, q);
    for (const item of await this.cache.envelopes()) {
      if (this.admitHome(item)) this.applyWireItem(item);
    }
    await this.freezeOnce();
    for (const rec of await this.cache.heldVaults()) {
      this.holding.set(rec.vault.vaultId, { ...rec, cachedName: this.peekHeldName(rec) });
    }
    for (const id of await this.cache.consumedDeleteIds()) this.consumedDeleteIds.add(id);
    // A7: the consumed removal nonces and this device's liveSince stamps (never server values).
    for (const c of await this.cache.consumedNonces()) {
      const m = this.consumedNonces.get(c.vaultId) ?? new Map<string, number>();
      m.set(c.nonce, c.issuedAt);
      this.consumedNonces.set(c.vaultId, m);
    }
    for (const l of await this.cache.liveSinces()) {
      this.liveSince.set(l.vaultId, l.at);
      this.liveSincePersisted.add(l.vaultId);
    }
    this.persistHeldKeys();
    this.markLiveVaults(); // a vault live here with no stamp yet (an upgrade, or no durable cache): first sight is now
    for (const t of await this.cache.transferSeqs()) this.lastTransferSeqSeen.set(t.vaultId, t.seq);
    // Rebuild incoming-transfer state (spec 03 §11, core hydrate parity): a pending-offer
    // row is NOT re-delivered while the offer merely pends (only cancel/expiry/
    // re-designate/accept re-deliver it), so the verified consent surface must be
    // recomputed from the cached rows or a reload mid-offer loses the offer until the
    // owner acts. Runs AFTER the transferSeqs load so the replay floor is in force;
    // noticeable=false never re-fires completion/anomaly notices for rows already seen
    // before the reload. Idempotent per row (it starts by clearing the vault's entry).
    for (const vault of this.vaultsById.values()) {
      try {
        await this.applyTransferState(vault, false);
      } catch {
        /* no key / crypto failure — the next pull retries (core runCatching parity) */
      }
    }
    // S4's durable queue stages denials; reload them into the F21 pre-park staging so a
    // removal arriving on the next pull can fold them into the holding record. stagedBefore=0
    // (core SyncEngine.hydrate LC-1 parity): the FIRST completed pull after this restart —
    // whose start-id is ≥1 — is fresh enough to classify them.
    for (const m of await this.cache.stagedDenied()) {
      const staged = this.preParkedByVault.get(m.vaultId) ?? [];
      staged.push({ mutation: m, stagedBefore: 0 });
      this.preParkedByVault.set(m.vaultId, staged);
    }
    // M2 (2026-07-14 re-review): rebuild the C2 pre-edit snapshots from their durable
    // queue-row twins (pending AND staged rows — either may yet be classified a genuine
    // denial), so the ORDINARY restart flow — edit offline → close → reopen → reconnect →
    // denied — still reverts exactly instead of leaving the refused value on display
    // forever. Grants loaded above, so the sealed snapshot decrypts here; one that won't
    // open (rotated VK, lost grant) is skipped and that denial keeps the pre-M2 posture
    // (notice without revert). Rows enqueued before M2 carry no snapshot — same fallback.
    for (const r of await this.cache.queuedPreEdits()) {
      try {
        const p = r.preEdit;
        this.preEditByMutation.set(r.mutationId, {
          op: p.op,
          optimisticRev: p.optimisticRev,
          optimisticUpdatedAt: p.optimisticUpdatedAt,
          pre:
            p.pre === null
              ? null
              : {
                  itemId: r.itemId,
                  vaultId: r.vaultId,
                  rev: p.pre.rev,
                  updatedAt: p.pre.updatedAt,
                  formatVersion: p.pre.formatVersion,
                  doc: this.account.decryptItem({
                    itemId: r.itemId,
                    vaultId: r.vaultId,
                    rev: p.pre.rev,
                    createdAt: 0,
                    updatedAt: p.pre.updatedAt,
                    deleted: false,
                    conflict: false,
                    formatVersion: p.pre.formatVersion,
                    attachmentIds: p.pre.attachmentIds,
                    blob: p.pre.blob,
                  }),
                },
        });
      } catch {
        /* undecryptable snapshot — this denial reverts nothing (pre-M2 posture) */
      }
    }
    // §D.3 UI affordance: un-flushed (pending, not staged-denied) offline edits made before
    // the restart still show a "pending sync" mark; the first flushQueue sends them.
    for (const m of await this.cache.pending()) this.pendingSyncItemIds.add(m.itemId);
    this.cursor = await this.cache.cursor();
    this._lastSyncAt = await this.cache.lastSyncAt();
    this.surfaceKeyAnomalies();
  }

  /**
   * A held vault's display name, re-derived from its RETAINED grant without retaining
   * the key (core `peekVaultName` parity; invariant A2 — the persisted HeldVaultRecord
   * has no plaintext name): open the grant, decrypt the metaBlob, then forget the key
   * again so a held vault never reads as live. Placeholder when the grant won't open.
   */
  private peekHeldName(rec: HeldVaultRecord): string {
    const vaultId = rec.vault.vaultId;
    const hadKey = this.account.hasVault(vaultId); // never true for a genuinely held vault — belt
    try {
      if (!hadKey && rec.grant) this.account.addGrant(rec.grant);
      return this.account.decryptVaultName(vaultId, rec.vault.metaBlob);
    } catch {
      return "(vault)";
    } finally {
      if (!hadKey) this.account.removeVault(vaultId);
    }
  }

  /** §D.1: buffer one cache op into the current pull's one-tx commit — records nothing
   *  outside a pull (the next successful pull's rows true disk up instead). */
  private recordPullOp(op: (b: PullBatch) => void): void {
    this.pullOps?.push(op);
  }

  /**
   * §D.1/§D.5: commit ONE pull's buffered ops as a single atomic cache transaction,
   * serialized across tabs by the `andvari-cache-<userId>` Web Lock. Two guards run
   * INSIDE the lock, against the stored cursor read via cache.cursor() just before the
   * tx (the S1 PullBatch is write-only):
   *  - §D.5.1 cursor-skip — a sibling tab already committed rev ≥ ours (and this isn't
   *    a 410 resync, whose clear+rewrite must always land): SKIP. The sibling applied
   *    the same server rows contiguously, so nothing is lost; this tab's memory keeps
   *    ITS OWN cursor at resp.rev, so its next pull re-fetches the gap and rows hidden
   *    by the skipped commit reappear (breaker #7 convergence — the durable twin of
   *    the F31 monotonic-cursor guard).
   *  - contiguity guard — a DELTA whose base (`since`) is ahead of the disk cursor
   *    would stamp a cursor whose (disk, since] rows disk lacks: rows a strict-delta
   *    server never re-sends once the cursor passes them, so tombstoned items would
   *    resurrect and revoked grants stay live on every later hydrate. REFUSE it: disk
   *    keeps its old coherent cursor+rows, memory is NOT rolled back
   *    (in-memory-ahead-of-disk is safe, §D.1), and it self-heals because hydrate
   *    resumes from the DISK cursor — the next session's first pull re-fetches the
   *    whole gap. A `full` snapshot (410 resync / since=0) is a self-contained
   *    clear+rewrite — always exempt.
   * A commit that ran is then VERIFIED to have landed (the re-read cursor reached
   * rev): a force-closed cache resolves every write as a silent guarded no-op (§D.2a),
   * which must count as a failure, not a success. 3 consecutive non-landing commits —
   * thrown tx, rejecting cursor read, or silent no-op ([cacheFailStreak]) — wipe +
   * demote to NullCache (§D.1 stuck cache); a deliberate contiguity REFUSE is
   * disk-behind-but-coherent, not a storage failure, and neither advances nor resets
   * the streak.
   */
  private async commitPull(
    ops: Array<(b: PullBatch) => void>,
    rev: number,
    since: number,
    resyncing: boolean,
    full: boolean,
  ): Promise<void> {
    if (!this.cache.durable) {
      // NullCache (opt-out, unsupported IndexedDB, post-demotion): keep the ONE code
      // shape — the buffering closures still run against the no-op batch — but none of
      // the guards or fail-streak accounting below means anything for a cache that
      // persists nothing.
      await this.cache.applyPull((b) => {
        for (const op of ops) op(b);
      });
      return;
    }
    let outcome: "landed" | "skipped" | "refused" | "failed" = "failed"; // a throw anywhere below leaves "failed"
    try {
      await this.withCacheLock(async () => {
        // The disk-cursor read here and the applyPull commit below are separate IDB txs; the
        // andvari-cache Web Lock serializes them across tabs. On the degraded UNLOCKED path
        // (no navigator.locks / lock-wait timeout, §D.5) this read↔commit is non-atomic, so a
        // sibling could in principle regress the disk cursor between them and this commit would
        // stamp a cursor over a gap (review, LOW). Unreachable against andvari: the server's rev
        // is monotonic (Repo.kt currentRev), so a resync snapshot's rev is always >= any
        // concurrent delta's base — no gap can form. Accepted best-effort residual (§D.5); it
        // would need a Byzantine server serving inconsistent revs across connections.
        const disk = await this.cache.cursor(); // a rejecting read is itself a non-landing — nothing below could be trusted
        if (!resyncing && disk >= rev) {
          outcome = "skipped"; // §D.5.1 cursor-skip — a sibling already committed these rows
          return;
        }
        if (!full && disk < since) {
          // Contiguity REFUSE (doc above). disk=0 is the exception: a disk WITH rows
          // always has a nonzero cursor (A1), so a 0 read under a nonzero delta base is
          // a cache that has landed NOTHING — most likely force-closed, its reads
          // falling back to 0 (§D.2a) — and counts as a non-landing so a dead cache
          // still reaches demotion instead of hiding behind the refuse forever.
          outcome = disk === 0 ? "failed" : "refused";
          console.warn(
            `pull commit refused: disk cursor ${disk} is behind this delta's base ${since} — committing would stamp a gap the server never re-sends; disk keeps its coherent state and the next session re-pulls from it`,
          );
          return;
        }
        await this.cache.applyPull((b) => {
          for (const op of ops) op(b); // pure synchronous buffering — no awaits in here
        });
        // Landing verification: applyPull resolving is not proof — a force-closed cache
        // no-ops silently (§D.2a). Only the cursor actually reaching rev is.
        outcome = (await this.cache.cursor()) >= rev ? "landed" : "failed";
      });
    } catch (e) {
      console.warn("pull applied in memory but its offline-cache commit failed — disk keeps the old cursor (coherent; the next session re-pulls the gap from it)", e);
    }
    if (outcome === "failed") this.cacheFailStreak++;
    else if (outcome !== "refused") this.cacheFailStreak = 0; // landed/skipped — demonstrably live
    // §D.1 stuck cache (breaker #6): a PERSISTENTLY non-landing cache must not silently
    // freeze disk at an old cursor forever — treat 3 straight non-landings as a §B.4
    // coherence failure: attempt the wipe, run cache-less for the rest of the session.
    if (this.cacheFailStreak >= 3 && !this._cacheDemoted) {
      this._cacheDemoted = true;
      const stuck = this.cache;
      this.cache = new NullCache(); // ONE code shape — everything below keeps working
      console.warn("offline cache demoted after 3 consecutive non-landing commits — wiping (§D.1); offline copy unavailable this session");
      await stuck.wipe(); // an ATTEMPT — wipe() never rejects (idbcache contract)
    }
  }

  /**
   * §D.5 rule 1: serialize cache commits across tabs with a Web Lock, mirroring
   * client.ts's refreshExclusive ("andvari-refresh") posture — bounded wait, and where
   * Web Locks are missing (older browsers, non-window contexts) or the wait times out,
   * proceed UNLOCKED: per-tab single-flight still holds and the §D.5.1 cursor check
   * keeps unlocked commits convergent.
   */
  private async withCacheLock<T>(fn: () => Promise<T>): Promise<T> {
    const locks = typeof navigator !== "undefined" ? navigator.locks : undefined;
    if (!locks?.request) return fn();
    // `granted` disambiguates a rejected lock WAIT from a failure of fn itself:
    // post-grant errors must propagate untouched (client.ts pattern).
    let granted = false;
    try {
      return (await locks.request(
        `andvari-cache-${this.account.userId}`,
        { signal: timeoutSignal(CACHE_LOCK_WAIT_MS) },
        () => {
          granted = true;
          return fn();
        },
      )) as T;
    } catch (e) {
      if (granted) throw e; // fn's own failure — not a lock problem
      return fn(); // the wait timed out / locks glitched — proceed unlocked
    }
  }

  /**
   * spec 02 §4 warn-and-keep-newer: the metaBlob plaintext carries the monotonic `metaV`
   * counter (bumped by every rename write), and a DELIVERED blob whose counter regresses
   * below the locally-held one is a replayed/rolled-back row — warn and keep the newer
   * local blob, never silently apply (the metaBlob-level sibling of the rollback guards
   * above; an absent or non-integral metaV reads as 0, the pre-rename floor, matching
   * buildRenameMeta — see metaVOf).
   * Comparable only when the VK is held, a previous row exists (never on a since=0 /
   * resync pull — vaultsById was just cleared), and BOTH blobs decrypt; anything
   * unverifiable applies the delivered row as-is (this guard is anti-replay, not
   * availability). ONLY the metaBlob is kept — rev and the lifecycle fields always apply.
   * Core twin: SyncEngine.keepNewerMeta.
   */
  private keepNewerMeta(delivered: WireVault): WireVault {
    const held = this.vaultsById.get(delivered.vaultId);
    if (!held || held.metaBlob === delivered.metaBlob || !this.account.hasVault(delivered.vaultId)) return delivered;
    try {
      const heldV = this.metaVOf(delivered.vaultId, held.metaBlob);
      const deliveredV = this.metaVOf(delivered.vaultId, delivered.metaBlob);
      if (deliveredV < heldV) {
        console.warn(
          `vault ${delivered.vaultId}: delivered metaV ${deliveredV} regressed below held ${heldV} — replayed metaBlob; keeping the newer local one`,
        );
        // Surface the keep-newer to the user (non-alarming) alongside the console warn — held
        // decrypts (metaVOf just read it above), so decryptVaultName can't throw here.
        this.pushNotice({
          id: crypto.randomUUID(),
          vaultId: delivered.vaultId,
          vaultName: this.account.decryptVaultName(delivered.vaultId, held.metaBlob),
          kind: "meta-regression",
        });
        return { ...delivered, metaBlob: held.metaBlob };
      }
    } catch {
      /* VK missing or a blob doesn't open — unverifiable, apply the delivered row as-is */
    }
    return delivered;
  }

  /** The row's plaintext `metaV` (spec 02 §4): counts ONLY as a non-negative integer ≤ 2^53
   *  (Number.MAX_SAFE_INTEGER, via Number.isSafeInteger), else 0 — the SAME rule buildRenameMeta
   *  applies, and it MUST read identically on every client (else one impl pins while another
   *  applies, forking the fleet in the adversarial anti-replay path this guard exists for). The
   *  safe-integer cap keeps a >2^63 literal reading 0 here AND on Kotlin (core Account.parseMetaV
   *  reads the raw JSON token as a Double under the same ceiling). Core twin: SyncEngine.metaV. */
  private metaVOf(vaultId: string, metaBlob: string): number {
    const meta = this.account.decryptVaultMeta(vaultId, metaBlob);
    const v = meta.metaV;
    return typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? v : 0;
  }

  private async materializeConflict(item: WireItem): Promise<void> {
    // INV-WRITE-KEY: never under a key we may not seal with (a reader was already skipped by the caller).
    if (!this.account.canSealUnder(item.vaultId)) return;
    // INV-CONFLICT (root cause A §5.1, A1b; the campaign HIGH A-4): the in-memory twin and the home must both agree
    // with the flagged row's vault, or NOTHING is pushed and the pull raises its wrong-vault anomaly. (INV-HOME already
    // keeps a wrong-vault row out; this is the second lock.)
    const twin = this.itemsById.get(item.itemId);
    if (conflictDecision(twin?.vaultId, item.vaultId, this.homes.get(item.itemId)) === "abort") {
      this.wrongVault.note(item.vaultId);
      return;
    }
    // BOTH mutations come from decrypt(flagged), sealed under flagged.vaultId (provenance (a)) — never from a twin
    // looked up by itemId, which is exactly how the locally held plaintext of another vault used to be re-sealed here.
    let doc: ItemDoc;
    try {
      doc = this.account.decryptItem(item);
    } catch {
      return; // undecryptable here — the flag waits
    }
    const provenance = envelopeProvenance(item.vaultId);
    // PDD-1: the CORRECT conflict copy is built from the DISPLACED (losing) version, which
    // only the pushing client receives (materializeConflictFromServerItem, below). On a plain
    // pull we hold only the flagged value, so this path is a FALLBACK plus the flag-clearer: if
    // the push side already materialized the copy (deterministic id over (itemId, rev), spec 03
    // §5), skip re-creating it and just clear the flag; otherwise (the conflict was caused by a
    // client that didn't materialize) preserve at least this value so clearing the flag doesn't
    // erase the only trace.
    const copyId = await conflictCopyId(item.itemId, item.rev);
    const mutations: Mutation[] = [];
    if (!this.itemsById.has(copyId)) {
      const stamp = new Date(item.updatedAt).toISOString().slice(0, 10);
      const copyDoc: ItemDoc = { ...doc, name: `${doc.name} (conflict ${stamp})` };
      mutations.push(this.putMutation(provenance, copyId, copyDoc, 0));
    }
    mutations.push(this.putMutation(provenance, item.itemId, doc, item.rev)); // clears conflict flag
    await this.push(mutations);
  }

  /**
   * Materialize the conflict copy from the server-returned LOSING version (spec 03 §5, PDD-1).
   * The pushing client is the ONLY party that receives the displaced value (as
   * MutationResult.serverItem); the pull side sees only the winner. Creates just the copy —
   * the conflict flag is cleared by the pull-side materializeConflict on the reconcile pull,
   * which holds the live winner (at push time our own itemsById still holds the pre-edit
   * value). The copy id is deterministic over (itemId, winnerRev) — the same derivation the
   * pull side uses — so a copy already present (our retry, a peer, or the pull fallback) is a
   * no-op.
   */
  private async materializeConflictFromServerItem(d: Displaced): Promise<void> {
    const losing = d.item;
    if (this.account.roleFor(losing.vaultId) === "reader" || !this.account.canSealUnder(losing.vaultId)) return; // a reader's push would be denied
    // INV-CONFLICT (A1b): the displaced value must be the item we wrote, in the vault we wrote it to and its home; its
    // AD vault is then the vault the copy is sealed under (provenance (a)).
    if (serverItemDecision(d.pushedVaultId, losing.vaultId, this.homes.get(losing.itemId)) === "abort") {
      this.wrongVault.note(losing.vaultId);
      return;
    }
    let losingDoc: ItemDoc;
    try {
      losingDoc = this.account.decryptItem(losing);
    } catch {
      return; // losing version under a held key (formatVersion too new) — nothing safe to copy
    }
    const copyId = await conflictCopyId(losing.itemId, d.winnerRev);
    if (this.itemsById.has(copyId)) return; // already materialized
    const stamp = new Date(losing.updatedAt).toISOString().slice(0, 10);
    const copyDoc: ItemDoc = { ...losingDoc, name: `${losingDoc.name} (conflict ${stamp})` };
    await this.push([this.putMutation(envelopeProvenance(losing.vaultId), copyId, copyDoc, 0)]);
  }

  /**
   * INV-HOME (security review 2026-10, root cause A §5.1; branch A1b): admit one served or cached row against
   * `home(itemId)`. The first row for an itemId records its home; a later row (live or tombstone) under another vault is
   * NOT applied: it is quarantined and counted for this pull's single "wrong vault" anomaly.
   */
  private admitHome(item: WireItem): boolean {
    const verdict = admitRow(this.homes.get(item.itemId), item.vaultId, !item.deleted && item.blob !== null && this.account.hasVault(item.vaultId));
    // A9 (L-1): the home is recorded by homeApplied once the row IS applied (it decrypted), never at admission: a row
    // that cannot be applied here ("skip") records nothing and a later genuine row takes the home.
    if (verdict === "new_home" || verdict === "skip" || verdict === "home") return true;
    this.quarantinedRows.set(item.itemId, item);
    this.recordPullOp((b) => b.addQuarantined(item));
    this.wrongVault.note(item.vaultId);
    return false;
  }

  /** INV-HOME (A9 L-1): `item` was just APPLIED (decrypted into the working set): the first such row is the home. */
  private homeApplied(item: WireItem): void {
    if (!this.homes.has(item.itemId)) this.recordHome(item.itemId, item.vaultId);
  }

  private recordHome(itemId: string, vaultId: string): void {
    this.homes.set(itemId, vaultId);
    if (this.pullOps) this.pullOps.push((b) => b.setItemHome(itemId, vaultId));
    else this.homesUnpersisted.add(itemId);
  }

  private surfaceWrongVault(): void {
    const t = this.wrongVault;
    this.wrongVault = new WrongVaultTally();
    if (t.anomalies() === 0) return;
    this.pushNotice({ id: crypto.randomUUID(), vaultId: t.firstVaultId ?? "", vaultName: "", kind: "wrong-vault", parkedCount: t.refused });
  }

  /** Rows refused by INV-HOME on this device (ciphertext, never applied), for diagnosis. */
  quarantinedItems(): WireItem[] {
    return [...this.quarantinedRows.values()];
  }

  /**
   * INV-SEAL (root cause A §5.1; branch A1b; core `SyncEngine.sealFor` twin): the ONE item seal for a push.
   * `provenance` names where the plaintext came from, and so the only vault it may be sealed under; the item must live
   * there (its home), or have no home yet (a fresh id: a copy, an import row, a new item), which this seal then
   * records. `Account.sealItem` adds INV-WRITE-KEY. A refusal throws {@link ItemChangedVaultsError}; nothing is
   * re-targeted.
   */
  private sealFor(provenance: SealProvenance, itemId: string, doc: ItemDoc): ItemUpload {
    const home = this.homes.get(itemId);
    if (sealDecision(home, provenance.vaultId) === "refuse") throw new ItemChangedVaultsError();
    const upload = this.account.sealItem(provenance, itemId, doc);
    if (home === undefined) this.recordHome(itemId, provenance.vaultId);
    return upload;
  }

  // ==== vault lifecycle: sync-time handling (spec 03 §11) ====

  /**
   * One removedGrants entry, tri-state (spec 03 §4/§11):
   *  - vault NOT held before the pull → unverifiable / unknown → silent no-op (no banner);
   *  - a replayed tombstone whose deleteId is already consumed → recognized, kept live, no warn;
   *  - this device initiated the delete/leave → drop cleanly, no banner;
   *  - held VK → verify the relayed proof: VALID → soft-hide + attributed notice; INVALID or a
   *    bare revocation → soft-hide + anomaly warning; 'left' → soft-hide + calm "you left".
   * Never hard-purges before purgeAt even on a valid proof (bounds tombstone-replay to a
   * self-healing ≤7d soft-hide). The vault always leaves the LIVE view; holding retains it.
   */
  private async handleRemovedGrant(
    vaultId: string,
    info: RemovedGrantInfo | undefined,
    cachedName: string | undefined,
    since: number,
    resyncing: boolean,
  ): Promise<void> {
    // One-shot self-initiation marker (#4): consumed on the FIRST removedGrant processed
    // for this vault, no matter which branch runs below — a stale entry must never
    // linger to misread a LATER genuine removal as self-initiated and bypass holding.
    const selfInitiated = this.suppressDrop.delete(vaultId);

    // A stale/replayed tombstone of an already-restored vault: keep it live, do not re-warn.
    if (info?.reason === "deleted" && info.deleteId && this.consumedDeleteIds.has(info.deleteId)) return;

    // Unverifiable: the VK was not held before this pull (fresh device, F20-hidden grant, or a
    // since=0 / resync pull) → silent no-op. Drop any stray unusable row.
    if (cachedName === undefined || since === 0 || resyncing) {
      this.hardDropLocal(vaultId, selfInitiated);
      return;
    }

    // This device initiated the delete/leave — drop cleanly, no banner (§4 / §13). The user's own action is the one
    // drop that clears this device's key memory for the vault (A7 review MEDIUM-1).
    if (selfInitiated) {
      this.hardDropLocal(vaultId, true);
      return;
    }

    const reason: RemovedReason = info?.reason ?? "removed";
    if (reason === "removed" || reason === "left") {
      await this.handleRemovalOrLeave(vaultId, reason, info, cachedName);
      return;
    }
    const verdict: "valid" | "anomaly" = (await this.verifyRemoval(vaultId, reason, info)) ? "valid" : "anomaly";

    // Snapshot ciphertext + move to holding BEFORE forgetting the VK.
    const parkedCount = this.moveToHolding(vaultId, reason, info, verdict === "valid", cachedName);

    if (verdict === "anomaly") {
      this.pushNotice({ id: crypto.randomUUID(), vaultId, vaultName: cachedName, kind: "anomaly" });
    } else if (reason === "deleted") {
      this.pushNotice({
        id: crypto.randomUUID(),
        vaultId,
        vaultName: cachedName,
        kind: "deleted",
        purgeAt: info?.purgeAt ?? undefined,
        parkedCount: parkedCount || undefined,
      });
    } else {
      this.pushNotice({ id: crypto.randomUUID(), vaultId, vaultName: cachedName, kind: "removed" });
    }
  }

  /**
   * `removed` / `left` on a vault this device held, not self-initiated (root cause A §6.3, §8.6; branch A7; core
   * SyncEngine.handleRemovalOrLeave twin). decideRemoval runs the verification order against the held VK, this
   * device's liveSince and the consumed set (device ∪ account state); its verdict picks the banner. A valid verdict's
   * `(vaultId, nonce, issuedAt)` is consumed in the SAME pull tx that moves the vault to holding (both are PullBatch
   * ops). The data handling is the same for every verdict: holding area, 30 days.
   */
  private async handleRemovalOrLeave(vaultId: string, reason: "removed" | "left", info: RemovedGrantInfo | undefined, cachedName: string): Promise<void> {
    let decision: Awaited<ReturnType<typeof decideRemoval>>;
    try {
      decision = await decideRemoval({
        lifecycleKey: await this.account.lifecycleKeyFor(vaultId),
        vaultId,
        myUserId: this.account.userId,
        reason,
        proofV: info?.proofV ?? null,
        proof: info?.removeProof ?? null,
        nonce: info?.removeNonce ?? null,
        issuedAt: info?.issuedAt ?? null,
        consumed: this.consumedFor(vaultId),
        consumedAccount: this.accountConsumedFor(vaultId),
        liveSince: this.liveSince.get(vaultId) ?? null,
        now: Date.now(),
      });
    } catch {
      decision = { verdict: "anomaly", step: "error" };
    }
    if (decision.consume) {
      const [nonce, at] = decision.consume;
      const m = this.consumedNonces.get(vaultId) ?? new Map<string, number>();
      m.set(nonce, at);
      this.consumedNonces.set(vaultId, m);
      this.recordPullOp((b) => b.addConsumedNonce(vaultId, nonce, at));
    }
    this.moveToHolding(vaultId, reason, info, false, cachedName);
    const base = { id: crypto.randomUUID(), vaultId, vaultName: cachedName };
    switch (decision.verdict) {
      case "valid":
        this.pushNotice({ ...base, kind: reason === "left" ? "left" : "removed" });
        break;
      case "valid_legacy":
        // A7 review LOW-3: a v1 proof is qualified ("sent by an older app version"), never shown as fully genuine.
        this.pushNotice({ ...base, kind: "removed", reason: REMOVED_LEGACY });
        break;
      case "already_recorded":
        // A7 review MEDIUM-2: another of this user's devices already consumed this genuine proof. Calm.
        this.pushNotice({ ...base, kind: reason === "left" ? "left" : "removed", reason: ALREADY_RECORDED });
        break;
      case "left_unproven":
        this.pushNotice({ ...base, kind: "left", reason: LEFT_UNPROVEN });
        break;
      case "replay_denied":
        this.pushNotice({ ...base, kind: "replay-denied", reason: REMOVAL_REPLAY });
        break;
      default:
        this.pushNotice({ ...base, kind: "anomaly" });
    }
  }

  /** Verify the relayed delete proof under the still-held VK (spec 03 §11). `removed` / `left` go through
   *  handleRemovalOrLeave instead (branch A7). */
  private async verifyRemoval(vaultId: string, reason: RemovedReason, info: RemovedGrantInfo | undefined): Promise<boolean> {
    if (!info || reason !== "deleted") return false; // a bare revocation of a held vault is never "valid"
    try {
      const key = await this.account.lifecycleKeyFor(vaultId);
      if (!info.deleteProof || !info.deleteId) return false;
      return verifyProof(info.deleteProof, await deleteProof(key, vaultId, info.deleteId));
    } catch {
      return false;
    }
  }

  /**
   * Move a removed vault's rows into the ciphertext-only holding area (§6), then drop it from
   * the live view. Returns the count of parked mutations recoverable on restore (F21). The
   * item snapshot is RE-SEALED from the held plaintext (plaintext is never retained at rest).
   */
  private moveToHolding(
    vaultId: string,
    reason: RemovedReason,
    info: RemovedGrantInfo | undefined,
    verifiedDelete: boolean,
    cachedName: string,
  ): number {
    const items: WireItem[] = [];
    for (const it of this.itemsById.values()) {
      if (it.vaultId !== vaultId) continue;
      // The snapshot's wire fv MUST be the fv the blob was just re-sealed at (the AD binds
      // it) — any restatement here would make reinstate's rehydrate decryptItem throw and
      // silently drop the item. encryptItem returns its fv for exactly this reason.
      const upload = this.account.resealForHolding(vaultId, it.itemId, it.doc); // local, never pushed (A6)
      items.push({
        itemId: it.itemId,
        vaultId,
        rev: it.rev,
        createdAt: 0,
        updatedAt: it.updatedAt,
        deleted: false,
        conflict: false,
        formatVersion: upload.formatVersion,
        attachmentIds: it.doc.attachments?.map((a) => a.id) ?? [],
        blob: upload.blob,
      });
    }
    // Fold in any edits that were denied while this vault was going in-grace (F21). Their
    // durable queue rows are dequeued BY EXPLICIT mutationId below, in the SAME pull tx as
    // putHeld, so they live ONLY in held.parked from here — no double-load on a later hydrate
    // (the S2 fix, now id-scoped).
    const stagedEntries = this.preParkedByVault.get(vaultId) ?? [];
    this.preParkedByVault.delete(vaultId);
    const staged = stagedEntries.map((s) => s.mutation);
    for (const s of stagedEntries) this.preEditByMutation.delete(s.mutation.mutationId); // parked — replay owns them
    const parked = [...(this.holding.get(vaultId)?.parked ?? []), ...staged];
    // Verified deletes expunge at purgeAt (the server erases then); everything else at +30d.
    const expungeAt = verifiedDelete && reason === "deleted" && info?.purgeAt ? info.purgeAt : Date.now() + 30 * 86_400_000;
    const record: HeldVault = {
      vault: this.vaultsById.get(vaultId) ?? { vaultId, type: "shared", rev: 0, metaBlob: "", createdAt: 0 },
      grant: this.grantWireByVault.get(vaultId) ?? null,
      items,
      reason,
      verified: verifiedDelete,
      cachedName,
      purgeAt: info?.purgeAt ?? undefined,
      deleteId: info?.deleteId ?? undefined,
      parked,
      expungeAt,
    };
    this.holding.set(vaultId, record);
    // §D.1 holding-area move, disk twin: putHeld strips the plaintext cachedName at the
    // boundary (A2); hardDropLocal below records the live-row drop in the same tx.
    this.recordPullOp((b) => b.putHeld(record));
    // C4: drop EXACTLY the queue rows this fold moved into held.parked — never a vault-wide
    // dropPending, which at commit time would also erase a row staged AFTER the fold-read
    // above but before the tx lands (the pull awaits between here and commitPull, so a
    // concurrent save can interleave). Such a late row survives, is denied on its own flush,
    // and folds into held.parked on a later cycle instead of being silently destroyed.
    const foldedIds = staged.map((m) => m.mutationId);
    if (foldedIds.length > 0) {
      this.recordPullOp((b) => {
        for (const id of foldedIds) b.dequeue(id);
      });
    }
    this.hardDropLocal(vaultId);
    return parked.length;
  }

  /** Drop a vault from the LIVE view: its items, undecryptables, vault row, wire grant, key,
   *  AND its queued mutations.
   *
   *  A7 review MEDIUM-1 (core twin): the device's KEY MEMORY for the vault (the §8.2 vouch and the held-key tag)
   *  survives every server-driven drop — every removal verdict, the silent resync drop — or the server could reset it
   *  and re-add the vault under a key it chose. Only a drop the USER initiated here (`forgetKeyMemory`: their own leave
   *  or delete) clears it, keeping "leave it and ask its owner to add you again" a working vk_mismatch recovery. */
  private hardDropLocal(vaultId: string, forgetKeyMemory = false): void {
    for (const it of [...this.itemsById.values()]) if (it.vaultId === vaultId) this.itemsById.delete(it.itemId);
    for (const it of [...this.undecryptableById.values()]) if (it.vaultId === vaultId) this.undecryptableById.delete(it.itemId);
    for (const it of [...this.missingVkById.values()]) if (it.vaultId === vaultId) this.missingVkById.delete(it.itemId);
    this.vaultsById.delete(vaultId);
    this.grantWireByVault.delete(vaultId);
    this.incomingByVault.delete(vaultId);
    this.undecryptableGrants.delete(vaultId); // F20: access gone → the "can't open" warning is moot
    this.account.removeVault(vaultId);
    if (forgetKeyMemory) {
      this.account.forgetKeyMemory(vaultId);
      const vouches = this.persistedVouches();
      if (vouches.delete(vaultId)) this.persistVouches(vouches);
      const held = this.persistedSet(HELD_KEYS_KEY);
      const keep = new Set([...held].filter((l) => !l.startsWith(`${vaultId}|`)));
      if (keep.size !== held.size) this.persistSet(HELD_KEYS_KEY, keep);
    }
    // The vault is no longer live on this device (§6.3 liveSince).
    this.liveSince.delete(vaultId);
    if (this.liveSincePersisted.delete(vaultId)) this.recordPullOp((b) => b.setLiveSince(vaultId, null));
    // §D.1: inside a pull, mirror the drop to disk (grant + vault row + items — the
    // removedGrants purge, spec 03 §4). C4: queue rows are NOT dropped vault-wide here — a
    // commit-time dropPending also erased rows staged AFTER moveToHolding's fold-read but
    // before the tx landed, silently destroying a parkable edit. moveToHolding dequeues
    // EXACTLY the rows it folded (same tx as putHeld — the S2 double-load fix, id-scoped);
    // any row left behind for a never-held (hard-dropped) vault drains through its own
    // flush → denied → surfaceStagedDenials (spec 03 §4 accepts losing a revoked member's
    // queue — but through classification, never via a racing erase). Outside a pull this
    // records nothing; the next successful pull's removedGrants entry reaches here again
    // with a recording buffer and trues disk up.
    this.recordPullOp((b) => b.dropVault(vaultId));
  }

  /**
   * Recompute transfer state for one vault row (spec 03 §11). A pending offer TO us surfaces
   * ONLY after its proof verifies under the held VK, is unexpired, and its seq is not a replay
   * of a completed/earlier one. A newly-seen completed transfer emits a verified completion
   * notice (only when `noticeable` — a held vault on a delta pull, never on since=0).
   */
  private async applyTransferState(vault: WireVault, noticeable: boolean): Promise<void> {
    const vaultId = vault.vaultId;
    if (!this.account.hasVault(vaultId)) return;
    // Incoming offer: recomputed each pull, so a cancel/expiry/re-designate (all re-deliver the
    // row) clears a stale banner.
    this.incomingByVault.delete(vaultId);
    const pt = vault.pendingTransfer;
    const seenSeq = this.lastTransferSeqSeen.get(vaultId) ?? 0;
    if (pt && pt.toUserId === this.account.userId && pt.expiresAt > Date.now() && pt.seq > seenSeq) {
      try {
        const key = await this.account.lifecycleKeyFor(vaultId);
        const expected = await offerProof(key, vaultId, pt.offerId, pt.toUserId, pt.expiresAt, pt.seq);
        if (verifyProof(pt.proof, expected)) {
          this.incomingByVault.set(vaultId, {
            vaultId,
            vaultName: this.account.decryptVaultName(vaultId, vault.metaBlob),
            offerId: pt.offerId,
            seq: pt.seq,
            expiresAt: pt.expiresAt,
          });
        }
      } catch {
        /* no key / bad proof — no consent screen (spec 03 §11) */
      }
    }
    // Completed transfer: verify the seq-chained acceptProof via the relayed wrapHash.
    const lt = vault.lastTransfer;
    if (lt && lt.seq > seenSeq) {
      let verified = false;
      if (lt.wrapHash) {
        try {
          const key = await this.account.lifecycleKeyFor(vaultId);
          const expected = await acceptProofFromHash(key, vaultId, lt.offerId, lt.newOwnerUserId, lt.seq, lt.wrapHash);
          verified = verifyProof(lt.acceptProof, expected);
        } catch {
          verified = false;
        }
      }
      if (verified) {
        // Only a VERIFIED completion advances the seen-seq chain — an unverifiable row must
        // not suppress the notice when the genuine wrapHash arrives on a later pull, nor
        // (via a fabricated huge seq) mute all future incoming offers this session.
        this.lastTransferSeqSeen.set(vaultId, lt.seq);
        this.recordPullOp((b) => b.setLastVerifiedTransferSeq(vaultId, lt.seq)); // durable floor (§D.1)
        // A6b: a verified transfer to someone else ends this account's ownership evidence (only ever removes).
        if (lt.newOwnerUserId !== this.account.userId && this.ownsVault(vaultId)) this.ownershipReleases.add(vaultId);
        // A verified completion supersedes any earlier unverified-sighting warning for this
        // vault — the anomaly resolved (e.g. wrapHash arrived on a later pull).
        this.noticeList = this.noticeList.filter((x) => !(x.vaultId === vaultId && x.kind === "transfer-anomaly"));
        if (noticeable) {
          this.pushNotice({
            id: crypto.randomUUID(),
            vaultId,
            vaultName: this.account.decryptVaultName(vaultId, vault.metaBlob),
            kind: "transfer-complete",
            newOwnerUserId: lt.newOwnerUserId,
            becameMine: lt.newOwnerUserId === this.account.userId,
          });
        }
      } else if (noticeable) {
        // Invalid proof / missing wrapHash on a locally-held vault: retain-and-warn (design
        // §4 step 5) — the ownership change couldn't be verified as a real member action.
        this.pushNotice({
          id: crypto.randomUUID(),
          vaultId,
          vaultName: this.account.decryptVaultName(vaultId, vault.metaBlob),
          kind: "transfer-anomaly",
          newOwnerUserId: lt.newOwnerUserId,
        });
      }
    }
  }

  /**
   * Canonical-key precedence, the surfacing half (security review 2026-10, root cause A §3.1; core
   * `SyncEngine.surfaceKeyAnomalies` twin): Account.addGrant already kept our UVK-wrapped key and
   * refused the seal, or refused a damaged wrap outright; this raises the house "server may be
   * misbehaving" notice ONCE per vault per session. Rebuilt from the cached rows on every hydrate,
   * so a server that keeps serving the bad row is reported again next session.
   */
  private surfaceKeyAnomalies(): void {
    for (const vaultId of this.account.vkMismatchVaultIds()) {
      if (this.keyAnomaliesShown.has(`vk-mismatch|${vaultId}`)) continue;
      this.keyAnomaliesShown.add(`vk-mismatch|${vaultId}`);
      const v = this.vaultsById.get(vaultId);
      const vaultName = v ? this.account.decryptVaultName(vaultId, v.metaBlob) : "(vault)";
      this.pushNotice({ id: crypto.randomUUID(), vaultId, vaultName, kind: "vk-mismatch" });
    }
    for (const vaultId of this.account.keyUnreadableVaultIds()) {
      if (this.keyAnomaliesShown.has(`key-unreadable|${vaultId}`)) continue;
      this.keyAnomaliesShown.add(`key-unreadable|${vaultId}`);
      // No key, so the name cannot be decrypted: the copy falls back to "a vault".
      this.pushNotice({ id: crypto.randomUUID(), vaultId, vaultName: "", kind: "key-unreadable" });
    }
  }

  private pushNotice(n: LifecycleNotice): void {
    // Collapse a repeat notice for the same vault+kind (idempotent re-pulls).
    this.noticeList = this.noticeList.filter((x) => !(x.vaultId === n.vaultId && x.kind === n.kind));
    this.noticeList.push(n);
  }

  /**
   * H37 (audit 2026-09-13, spec 03 §5 "Queue coalescing"; core SyncEngine.coalesceQueuedPuts
   * twin): fold this item's UNSENT queued puts into the one save() is about to enqueue, and
   * answer the base rev — and the pre-edit truth — that one must carry.
   *
   * WHY. The server's conflict test is `baseItemRev < existing.rev` (Service.applyPut) against
   * a GLOBALLY monotonic rev: `nextRev` is the rowid of the `changes` table, so EVERY write by
   * anyone advances it. Two queued puts for one item therefore cannot both be clean — the
   * drain lands the first at a fresh global rev G, and the second (minted while offline, at
   * the pre-offline rev, or at our local optimistic counter which only ever equals G by
   * coincidence) is stale BY CONSTRUCTION. The server answers `conflict` and returns the
   * displaced value, which is the user's OWN intermediate draft, and the client dutifully
   * materializes "<name> (conflict YYYY-MM-DD)". Editing one login twice on a plane, or
   * creating an entry and fixing a typo before reconnecting, came back as a duplicate that
   * reads as a corrupt vault and then feeds Vault Health's duplicates cluster. Nothing was
   * lost — but nothing was in conflict either, and the client cannot tell its own draft from a
   * peer's edit. Coalescing removes the false premise rather than teaching it to guess.
   *
   * The base rev comes from the OLDEST folded row, never from `itemsById`: that map holds our
   * own optimistic rev, and if a PEER's edit arrived in between it holds the peer's — sending
   * at either would let this put apply "cleanly" over a change nobody displaced-copied.
   * The original base keeps a genuine cross-device conflict genuine.
   *
   * A FRESH mutationId, never a folded row's: replaying a folded id would let the server's
   * dedup window return that row's ORIGINAL stored result verbatim (spec 03 §5) and report
   * `applied` for content we never sent — trading a junk copy for silent loss of the newest
   * draft.
   *
   * Scope and the residual window. Only `put` rows, and only when no queued `delete` for the
   * same item stands in the way (an ordering the drain must keep as written). Staged-denied
   * rows are invisible to cache.pending() and so are never folded — their fate is F21's.
   * Unlike core (whose saveWithUploads holds syncMutex) this runs outside the drain's lock, so
   * a row already on the wire can be folded away; that degrades to exactly today's conflict
   * copy — never to loss, since the sent row still applies server-side and the new put simply
   * conflicts against it.
   */
  private async coalesceQueuedPuts(itemId: string): Promise<FoldedPuts | null> {
    if (!this.cache.durable) return null; // NullCache: enqueue is a no-op, nothing to fold
    let pending: Mutation[];
    try {
      pending = (await this.cache.pending()).filter((q) => q.itemId === itemId);
    } catch {
      return null; // a cache read failure must never fail a save — fall back to today's shape
    }
    if (pending.length === 0) return null;
    if (pending.some((q) => q.op !== "put")) return null; // a queued delete — never reorder around it
    const oldest = pending[0]!;
    // The burst's original pre-edit value. A row with NO snapshot (pre-M2, or one whose sealed
    // twin would not open at hydrate) falls back to today's shape — the live row — rather than
    // to null, which a revert would read as "this item never existed" and delete.
    const snap = this.preEditByMutation.get(oldest.mutationId);
    const pre = snap ? snap.pre : (this.itemsById.get(itemId) ?? null);
    // R32: read the DURABLE pre-edit blobs BEFORE dequeuing, so the fold can be undone. The fold
    // is only safe because the new put supersedes these rows — and it does, right up until the
    // save that folded them is itself thrown away. See the catch in save(): on a definitive
    // server error that path drops the new row and reverts, and without these the user's whole
    // offline backlog for this item would go with it (rows that, before H37, would simply have
    // stayed queued and flushed later). A cache read failure here is not fatal: it costs the
    // undo, not the fold, so it degrades to the shape this row shipped with rather than failing
    // a save.
    let blobs: Map<string, QueuedPreEdit>;
    try {
      blobs = new Map((await this.cache.queuedPreEdits()).map((r) => [r.mutationId, r.preEdit]));
    } catch {
      blobs = new Map();
    }
    const rows: Array<{ mutation: Mutation; preEdit?: QueuedPreEdit }> = pending.map((q) => ({
      mutation: q,
      preEdit: blobs.get(q.mutationId),
    }));
    for (const q of pending) {
      await this.cache.dequeue(q.mutationId);
      this.preEditByMutation.delete(q.mutationId);
      this.rejectedMutationIds.delete(q.mutationId);
    }
    return { baseItemRev: oldest.baseItemRev, pre, rows };
  }

  /**
   * R32: put the folded rows back, in their original FIFO order, when the save that folded them
   * is being thrown away. Called from exactly one place — save()'s definitive-error path — and
   * deliberately best-effort: it runs while an error is already propagating, so a cache that
   * refuses the re-enqueue must not replace the caller's real error with a cache error. The
   * worst case of a failure here is the pre-R32 behaviour (the backlog is gone), which is what
   * the caller was about to do anyway.
   *
   * NOT a core twin, deliberately: core's sendOrQueue leaves the folding mutation QUEUED on an
   * ApiException (only an IOException on a non-durable cache dequeues it), so the newest doc
   * still carries the burst and nothing is lost there. Web's refuse-not-degrade path is the one
   * that drops its own row, which is what makes the fold destructive here and only here.
   *
   * Re-enqueue puts each row back at the TAIL, so the group keeps its own relative order and
   * lands after anything queued in the meantime. That is the right order: these rows are older
   * than the rest of the queue by content but their send has not happened, and FIFO over the
   * whole queue is what the drain guarantees — not FIFO by authorship time.
   */
  private async restoreFoldedPuts(folded: FoldedPuts): Promise<void> {
    for (const r of folded.rows) {
      try {
        await this.cache.enqueue(r.mutation, r.preEdit);
      } catch {
        // keep going: a partial restore is strictly better than none, and the caller is
        // already throwing the error the user will actually see.
      }
    }
  }

  /** A put sealed through {@link sealFor} (INV-SEAL / INV-HOME / INV-WRITE-KEY): the vault IS the provenance's. */
  private putMutation(provenance: SealProvenance, itemId: string, doc: ItemDoc, baseItemRev: number): Mutation {
    // The wire fv is read back from the upload — ONE seal computes it (per-doc floor,
    // monotonic reseal) and binds it into the AD, so the two can never diverge.
    const upload = this.sealFor(provenance, itemId, doc);
    return {
      mutationId: crypto.randomUUID(),
      op: "put",
      itemId,
      vaultId: provenance.vaultId,
      baseItemRev,
      item: {
        formatVersion: upload.formatVersion,
        attachmentIds: doc.attachments?.map((a) => a.id) ?? [],
        blob: upload.blob,
      },
    };
  }

  deleteMutation(itemId: string, vaultId: string, baseItemRev: number): Mutation {
    return { mutationId: crypto.randomUUID(), op: "delete", itemId, vaultId, baseItemRev };
  }

  /**
   * §B.5/§D.3 persist-gate (breaker #1, LOAD-BEARING): the success-as-QUEUED offline-write
   * return is offered ONLY while durable persistence is granted. A NullCache (opt-out /
   * unsupported / demoted) has nothing durable to queue into, and a best-effort IndexedDB
   * bucket the browser may EVICT between enqueue and flush is unrecoverable user data — so an
   * offline save on either keeps today's push-or-throw (refuse-not-degrade). Feature-detect
   * navigator.storage.persisted(); any absence/exception reads as NOT persisted.
   */
  private async offlineQueueAllowed(): Promise<boolean> {
    if (!this.cache.durable) return false;
    try {
      const s = typeof navigator !== "undefined" ? navigator.storage : undefined;
      return typeof s?.persisted === "function" ? (await s.persisted()) === true : false;
    } catch {
      return false; // refuse-not-degrade
    }
  }

  /** §D.2a/§D.3: persist an item's optimistic WIRE envelope so a queued offline edit — or a
   *  committed edit whose reconcile pull failed — survives a restart (the queue row carries
   *  the mutation, not the item row; hydrate reads envelopes). The reconcile pull overwrites
   *  it with the true server row once flushed. Guarded: a cache write must never fail a save. */
  private async persistEnvelope(id: string, vaultId: string, updatedAt: number, rev: number, m: Mutation): Promise<void> {
    try {
      await this.cache.upsertItem({
        itemId: id,
        vaultId,
        rev,
        createdAt: 0, // unknown until the reconcile pull's row carries the real one
        updatedAt,
        deleted: false,
        conflict: false,
        formatVersion: m.item!.formatVersion,
        attachmentIds: m.item!.attachmentIds,
        blob: m.item!.blob,
      });
    } catch (e) {
      console.warn("offline-cache envelope persist failed (harmless — the row re-syncs / re-flushes)", e);
    }
  }

  /** M2: seal a mutation's pre-edit truth into its queue row's durable snapshot — the
   *  ciphertext twin (A2: nothing decrypted at rest) of the in-memory PreEditSnapshot,
   *  re-sealed here because the pre-edit envelope on disk is about to be overwritten by
   *  the optimistic apply. Best-effort: a failed seal degrades to NO durable snapshot
   *  (the pre-M2 posture — notice without revert after a restart), never a failed save. */
  private durablePreEdit(pre: VaultItem | null, op: "put" | "delete", optimisticRev: number, optimisticUpdatedAt: number): QueuedPreEdit | undefined {
    try {
      if (!pre) return { op, pre: null, optimisticRev, optimisticUpdatedAt };
      const up = this.account.resealLocal(pre.vaultId, pre.itemId, pre.doc); // local snapshot, never pushed
      return {
        op,
        pre: {
          rev: pre.rev,
          updatedAt: pre.updatedAt,
          formatVersion: up.formatVersion, // the AD-bound fv of THIS seal — what hydrate must decrypt against
          attachmentIds: pre.doc.attachments?.map((a) => a.id) ?? [],
          blob: up.blob,
        },
        optimisticRev,
        optimisticUpdatedAt,
      };
    } catch {
      return undefined;
    }
  }

  /** A live vault's display name for notice copy (best-effort — "(vault)" when the row or
   *  key is missing or the blob won't open). */
  private liveVaultName(vaultId: string): string {
    const v = this.vaultsById.get(vaultId);
    if (!v || !this.account.hasVault(vaultId)) return "(vault)";
    try {
      return this.account.decryptVaultName(vaultId, v.metaBlob) || "(vault)";
    } catch {
      return "(vault)";
    }
  }

  /**
   * C2 (b): undo ONE genuinely-denied mutation's optimistic apply from its enqueue-time
   * snapshot — memory and (best-effort) disk. Guarded four ways so a revert can never
   * destroy fresher state: (i) no snapshot (a pre-M2 row, or its durable seal wouldn't
   * open at hydrate) ⇒ leave the row — the "write-refused" notice still fires and the
   * next full resync trues it up; (ii) the vault left the live view ⇒ nothing to restore
   * into; (iii) M1: a SERVER tombstone for this item has been applied (another member's
   * delete was ACCEPTED while ours was denied) ⇒ the item is genuinely gone — restoring
   * the snapshot would resurrect a deleted credential forever (the delta server never
   * re-delivers a rev-passed tombstone), so DROP the snapshot and keep it deleted;
   * (iv) for a put, revert ONLY while OUR optimistic (rev, updatedAt) is still the live
   * value — for a delete, ONLY while the item is still locally deleted (a fresh server
   * row, e.g. edit-beats-delete, supersedes).
   * Returns what happened so the write-refused notice can tell the truth (M3):
   * "reverted" (snapshot restored), "removed" (the M1 tombstone case — stays deleted),
   * or "kept" (no snapshot / fresher state won — nothing was touched).
   */
  private async revertDeniedMutation(m: Mutation): Promise<"reverted" | "removed" | "kept"> {
    const snap = this.preEditByMutation.get(m.mutationId);
    if (!snap) return "kept";
    if (!this.vaultsById.has(m.vaultId)) return "kept";
    const cur = this.itemsById.get(m.itemId);
    if (snap.op === "delete") {
      if (this.serverTombstoned.has(m.itemId)) return "removed"; // M1: deleted server-side — never resurrect
      if (cur || !snap.pre) return "kept";
      await this.revertOptimisticSave(m.itemId, snap.pre); // restore the pre-delete item live
      return "reverted";
    }
    if (!cur || cur.rev !== snap.optimisticRev || cur.updatedAt !== snap.optimisticUpdatedAt) return "kept";
    await this.revertOptimisticSave(m.itemId, snap.pre ?? undefined);
    return "reverted";
  }

  /**
   * H03: the drain just DROPPED this very write as a poison row (per-row `rejected`, or a
   * whole-batch refusal bisected down to it). Its optimistic apply is already reverted and
   * the notice minted; the Editor must still hear "failed", not "saved" — so reconcile first
   * (the pull shows the server's truth for the item, e.g. a peer's tombstone; a failed
   * reconcile is not the point here) and then throw an ApiError carrying the server's reason
   * so the 413 row renders its upload sentence and everything else "Save failed — nothing
   * was changed." (true after the revert).
   */
  private async throwIfRejected(m: Mutation): Promise<void> {
    const reason = this.rejectedMutationIds.get(m.mutationId);
    if (reason === undefined) return;
    this.rejectedMutationIds.delete(m.mutationId);
    try {
      await this.sync();
    } catch {
      /* the rejection is the verdict that matters; a failed reconcile trues up later */
    }
    const status = reason === "item_attachment_quota" || reason === "body_too_large" ? 413 : 400;
    throw new ApiError(status, reason, `the server refused this write: ${reason}`);
  }

  /** C2 (d): m still awaits its epoch-guarded verdict — staged, but every completed pull so
   *  far STARTED before the staging, so surfaceStagedDenials declined to classify it. */
  private mutationStillStaged(m: Mutation): boolean {
    return (this.preParkedByVault.get(m.vaultId) ?? []).some((e) => e.mutation.mutationId === m.mutationId);
  }

  /** Undo the optimistic apply of a save that turned out to be a GENUINE denial or a
   *  refuse-not-degrade offline reject: restore the pre-edit value (existing) or drop a new
   *  item that never landed, in memory and (best-effort) on disk. */
  private async revertOptimisticSave(id: string, existing: VaultItem | undefined): Promise<void> {
    this.pendingSyncItemIds.delete(id);
    if (existing) {
      this.itemsById.set(id, existing);
      // L1: an itemId lives in exactly ONE of the three tri-state maps — a pull may have
      // parked this id as undecryptable/missing-VK meanwhile, and re-entering the live map
      // without clearing the others would double-enumerate it in backups.
      this.undecryptableById.delete(id);
      this.missingVkById.delete(id);
      try {
        const up = this.account.resealLocal(existing.vaultId, id, existing.doc); // re-seal the pre-edit value (local, never pushed)
        await this.cache.upsertItem({
          itemId: id,
          vaultId: existing.vaultId,
          rev: existing.rev,
          createdAt: 0,
          updatedAt: existing.updatedAt,
          deleted: false,
          conflict: false,
          formatVersion: up.formatVersion,
          attachmentIds: existing.doc.attachments?.map((a) => a.id) ?? [],
          blob: up.blob,
        });
      } catch {
        /* best-effort — the next successful pull re-delivers the true row */
      }
    } else {
      this.itemsById.delete(id);
      try {
        await this.cache.deleteItem(id);
      } catch {
        /* best-effort orphan drop */
      }
    }
  }

  /**
   * Create or update an item. New attachment blobs upload FIRST (spec 02 §6: blob before the
   * item that references it), so the itemId is fixed before any upload starts.
   *
   * §D.3 durable offline writes (slice S4): the mutation is ENQUEUED durably with its stable
   * mutationId (a retry converges on server dedup — D4), applied optimistically, then flushed.
   *  - flush + reconcile succeed ⇒ committed (the Editor clears normally);
   *  - the vault went in-grace ⇒ the edit is PARKED for restore replay (F21), no failure;
   *  - a GENUINE permission denial ⇒ re-thrown (the Editor's failure UX is unchanged);
   *  - OFFLINE ⇒ success-as-QUEUED — but ONLY while durable persistence is granted
   *    (breaker #1 persist-gate); otherwise, and for a save carrying `newFiles`, today's
   *    push-or-throw stands (attachments are online-only; we cache no blob bytes).
   *
   * An EXISTING item always stays in its own vault (the server enforces `vault_mismatch`): an edit passes the vault
   * its editor opened on as `vaultId` (INV-EDIT, required), and a home that differs now refuses the save with
   * {@link ItemChangedVaultsError}; a new item goes to `vaultId` when given, else the personal vault.
   */
  async save(
    itemId: string | null,
    doc: ItemDoc,
    newFiles: PendingUpload[] = [],
    onUploadProgress?: (done: number, total: number) => void,
    vaultId?: string,
  ): Promise<void> {
    const existing = itemId ? this.itemsById.get(itemId) : undefined;
    // Save guard (design §6): an edit to an itemId we no longer hold must NOT silently teleport
    // into the personal vault (the "teleport hole") — the item's vault may have been deleted or
    // its grant revoked mid-edit. Fail loudly; the server-side skeletal fence is the suspenders.
    if (itemId !== null && !existing) {
      throw new ApiError(409, "vault_state_changed", "This item is no longer here — it may have been removed or its vault deleted.");
    }
    // INV-EDIT / INV-SEAL (root cause A §5.1, A1b; core saveWithUploads twin). An EDIT is sealed under the vault its
    // editor was bound to when it OPENED (`vaultId`, provenance (b)); it is never looked up by itemId here. If the item's
    // home is another vault now, the save is refused ("reopen it"), never re-targeted. A NEW item goes to the
    // destination the user chose (`vaultId`, default the personal vault, provenance (c)).
    let provenance: SealProvenance;
    if (itemId !== null) {
      const verdict = editDecision(this.homes.get(itemId) ?? existing?.vaultId, vaultId);
      if (verdict === "unbound") throw new Error("an edit must name the vault its editor opened on");
      if (verdict === "changed_vaults") throw new ItemChangedVaultsError();
      provenance = editorProvenance(vaultId!);
    } else {
      provenance = chosenProvenance(vaultId ?? this.personalVaultOrRefuse());
    }
    const targetVaultId = provenance.vaultId;
    const id = itemId ?? this.account.newItemId();

    // Scope guard (§D.3): a save carrying new attachment blobs is ONLINE-ONLY in v1 — the
    // blobs upload FIRST (spec 02 §6) and we cache no attachment bytes, so such a save can
    // never be replayed from the queue and MUST NOT return success-as-QUEUED. The uploads
    // below throw on a dead network (before the mutation is even minted), so an offline
    // attachment save fails loudly — refusing to queue.
    let done = 0;
    for (const file of newFiles) {
      const ref = doc.attachments?.find((a) => a.id === file.id);
      if (!ref) throw new Error(`pending upload ${file.id} has no attachment entry in the doc`);
      onUploadProgress?.(done, newFiles.length);
      const enc = encryptAttachment(fromB64(ref.fileKey), file.data);
      await this.api.uploadAttachment(file.id, id, targetVaultId, concat(enc.header, enc.ciphertext));
      onUploadProgress?.(++done, newFiles.length);
    }

    // H37: fold this item's own unsent queued puts into THIS one first — the folded base rev
    // (and the folded pre-edit truth) then ride the mutation below. See coalesceQueuedPuts.
    const folded = await this.coalesceQueuedPuts(id);
    const m = this.putMutation(provenance, id, doc, folded ? folded.baseItemRev : (existing?.rev ?? 0));
    let mayQueue = newFiles.length === 0 && (await this.offlineQueueAllowed());

    const committedAt = Date.now();
    const optimisticRev = (existing?.rev ?? 0) + 1; // the reconcile pull trues the rev up
    // C2 snapshot: the value to restore if THIS write is later refused. When puts were folded
    // that is the burst's ORIGINAL pre-edit value, not the intermediate draft `existing` now
    // holds — reverting to a draft the user never confirmed would leave the refused edit half
    // standing. (optimisticRev / optimisticUpdatedAt stay THIS save's: they are the guard that
    // the live row is still ours to revert.)
    const preEdit = folded ? folded.pre : (existing ?? null);
    // Enqueue durably BEFORE the send (D4: a retry converges on server dedup — the fresh-
    // mutationId non-idempotent retry is gone). On NullCache this is a no-op (mayQueue already
    // false there), so the direct flushChunk branch below sends m instead. M2: the pre-edit
    // snapshot rides the row (sealed, local-only) so a denial classified only after a restart
    // still reverts — hydrate reloads it into preEditByMutation.
    // CR-01 (breaker #1): enqueue() now VERIFIES the row landed. A durable cache whose connection
    // closed mid-session (sibling wipe / force-close) keeps durable=true but no-ops every write
    // (§D.2a) — so an unverified enqueue would black-hole this save yet flushQueue would drain an
    // empty queue and report SUCCESS. When the row did NOT land, demote the dead handle and refuse
    // the queue so the send below routes to the REAL flushChunk (refuse-not-degrade), never silent.
    const enqueued = await this.cache.enqueue(m, this.durablePreEdit(preEdit, "put", optimisticRev, committedAt));
    if (!enqueued) {
      this.demoteCache(); // no-op if already cache-less; else sever the dead handle
      mayQueue = false; // this write can't be durably queued — do the real send or refuse
    }
    // Optimistic apply — memory AND disk — so the item renders immediately with a "pending
    // sync" mark and survives a restart (the queue row carries the mutation, not the envelope).
    // C2 (a): the pre-edit truth, keyed by mutationId — if this write is later classified a
    // GENUINE denial, surfaceStagedDenials restores exactly this (memory + disk) so the
    // refused value cannot outlive its refusal.
    this.preEditByMutation.set(m.mutationId, { pre: preEdit, op: "put", optimisticRev, optimisticUpdatedAt: committedAt });
    this.itemsById.set(id, { itemId: id, vaultId: targetVaultId, rev: optimisticRev, updatedAt: committedAt, formatVersion: m.item!.formatVersion, doc });
    this.undecryptableById.delete(id); // it decrypts by construction — we wrote it
    this.pendingSyncItemIds.add(id);
    await this.persistEnvelope(id, targetVaultId, committedAt, optimisticRev, m);

    // SEND m (breaker #3 ONE denial path; C3 FIFO): on a DURABLE cache the send goes through
    // flushQueue itself — the drain is FIFO over the WHOLE queue, single-flighted, and §D.5
    // lock-wrapped. R34: rows for OTHER items still flush before m in one FIFO batch (pinned by
    // C3b); this item's OWN older rows no longer exist to race it, because coalesceQueuedPuts
    // folded them into m eleven lines above — so there is no stale draft left for LWW to
    // enthrone. (The clause this replaced still promised same-item FIFO draining, a state H37
    // had just made impossible.) Only the
    // NullCache path (enqueue is a no-op) sends m directly via flushChunk. Either way a
    // `denied` result is STAGED (not thrown) and an OFFLINE reject propagates.
    const displaced: Displaced[] = [];
    try {
      if (this.cache.durable && enqueued) {
        await this.flushQueue(); // materializes its own displaced conflicts internally
      } else {
        // NullCache, or a durable row that did NOT land (CR-01 demoted handle): send m directly.
        await this.flushChunk([m], displaced);
      }
    } catch (e) {
      // m was NOT sent (transport reject). success-as-QUEUED only while durable persistence is
      // granted AND this is transport (never an ApiError — the server ANSWERED for those);
      // otherwise refuse-not-degrade → drop the row, undo the optimistic apply, rethrow.
      if (mayQueue && !(e instanceof ApiError)) return; // the item keeps its optimistic apply + pending-sync mark
      // R32: this save is being thrown away, so UNDO the fold before dropping it. H37 folds the
      // item's unsent queued puts into this one and dequeues them permanently — sound while the
      // fold's row survives to carry them, and destructive here, where it does not. Without the
      // restore, a member who edited offline for an hour and then hit a 429/5xx on the first save
      // after reconnecting lost the entire durable backlog for that item, back to the pre-burst
      // value, from rows that would simply have stayed queued before H37. Restore FIRST, so a
      // dequeue/revert failure below cannot leave the queue emptied.
      if (folded) await this.restoreFoldedPuts(folded);
      await this.cache.dequeue(m.mutationId);
      this.preEditByMutation.delete(m.mutationId);
      await this.revertOptimisticSave(id, preEdit ?? undefined); // H37: the burst's original value, not the folded draft
      throw e;
    }
    for (const d of displaced) await this.materializeConflictFromServerItem(d);
    await this.throwIfRejected(m);

    // m settled (applied → dequeued; or denied → staged) — or, if this call joined a drain
    // already past its row, it is still pending and the sync()'s own flushQueue sends it.
    // Reconcile (§D.3 order: flushQueue → pull → surfaceStagedDenials classifies m's staged
    // denial, epoch-guarded). A genuine denial throws here; an offline reconcile does not.
    try {
      await this.sync();
      // C2 (d): the reconcile's pull may have JOINED an older in-flight pull whose snapshot
      // predates m's denial — the epoch guard then leaves m staged-too-fresh, and returning
      // now would claim SUCCESS for a denied write. Run ONE more cycle so a pull that
      // STARTED after the staging classifies it (park, or the genuine throw below). Should a
      // wedged pull defer it yet again, the C2 drain-path revert + "write-refused" notice
      // still surface it on a later sync — deferred, never silent.
      if (this.mutationStillStaged(m)) await this.sync();
    } catch (e) {
      if (e instanceof ApiError && e.code === "denied") {
        // GENUINE permission denial — surfaceStagedDenials dropped the row durably AND
        // restored the pre-edit truth from the C2 snapshot (precisely: only where OUR
        // optimistic apply was still live). Rethrow — the Editor's failure UX is unchanged.
        throw e;
      }
      // The reconcile PULL failed but m was already applied/parked — a failed reconcile must
      // NOT fail the save (the Editor would wrongly claim "nothing was changed" about a live
      // write, and a retry would double-commit). Keep the apply; a later sync trues up.
      this.pendingSyncItemIds.delete(id);
      console.warn("save committed but the reconcile pull failed — local apply kept; a later sync trues up", e);
      return;
    }
    this.pendingSyncItemIds.delete(id); // applied/parked — no longer awaiting a first flush
  }

  /**
   * Item history (feature): fetch this item's archived versions (server keeps the last 10) and
   * decrypt each under the held VK, newest first. Versions that don't decrypt — e.g. sealed under a
   * superseded VK after a rotation — are dropped (history is bounded and resets at VK rotation; see
   * the design doc). Restore a chosen version with `save(itemId, doc)` — an ordinary put.
   */
  async itemVersions(itemId: string, vaultId: string): Promise<{ rev: number; archivedAt: number; doc: ItemDoc }[]> {
    const resp = await this.api.itemVersions(itemId);
    const out: { rev: number; archivedAt: number; doc: ItemDoc }[] = [];
    for (const v of resp.versions) {
      try {
        out.push({ rev: v.rev, archivedAt: v.archivedAt, doc: this.account.decryptItemVersion(vaultId, itemId, v) });
      } catch {
        /* undecryptable (post-rotation / held key) — bounded history, skip */
      }
    }
    return out;
  }

  /**
   * Item undelete (feature): the user's tombstoned items, each paired with its last archived version
   * decrypted for the name/preview (a tombstone's own blob is null, so the name lives in the archive).
   * An item with no archive or an undecryptable last version surfaces with doc=null — still restorable
   * by identity, just unnamed. Restore a chosen one with restoreDeleted.
   */
  async deletedItems(): Promise<{ itemId: string; vaultId: string; deletedAt: number; doc: ItemDoc | null }[]> {
    const resp = await this.api.deletedItems();
    const out: { itemId: string; vaultId: string; deletedAt: number; doc: ItemDoc | null }[] = [];
    for (const d of resp.items) {
      let doc: ItemDoc | null = null;
      try {
        const newest = (await this.api.itemVersions(d.itemId)).versions[0]; // newest first
        if (newest) doc = this.account.decryptItemVersion(d.vaultId, d.itemId, newest);
      } catch {
        /* no archive / undecryptable — surface as an unnamed deleted item */
      }
      out.push({ itemId: d.itemId, vaultId: d.vaultId, deletedAt: d.deletedAt, doc });
    }
    return out;
  }

  /**
   * Item undelete (feature): restore a tombstoned item by re-encrypting the chosen doc under the
   * current VK and POSTing to the dedicated restore route (the server un-tombstones cleanly — no
   * conflict, no spurious copy). Then sync so the item reappears live.
   */
  async restoreDeleted(itemId: string, vaultId: string, doc: ItemDoc): Promise<void> {
    // A deleted item's attachment BLOBS were hard-unlinked at tombstone (applyDelete) — only the
    // item ciphertext is archived, never attachment blobs. So a restore MUST drop the old
    // attachment refs; carrying them back would leave dangling/broken download links. The passwords,
    // notes, and other fields come back; attachments do not (design doc: undelete limitation).
    const restored: ItemDoc = { ...doc, attachments: undefined };
    // INV-SEAL (a): the doc was decrypted from this item's archived envelope under `vaultId`; INV-HOME: only at home.
    const upload = this.sealFor(envelopeProvenance(vaultId), itemId, restored);
    await this.api.restoreItem(itemId, {
      formatVersion: upload.formatVersion,
      attachmentIds: [],
      blob: upload.blob,
    });
    await this.sync();
  }

  /** Item undelete (F49): "Delete forever" — hard-delete a tombstoned item (+ its versions). */
  async purgeDeleted(itemId: string): Promise<void> {
    await this.api.purgeItem(itemId);
  }

  /**
   * F75 (guided importers): light projections of the PERSONAL vault for the vault-aware
   * import plan — the store-owned `existing` seam (design 2026-07-09 A8; core
   * SyncEngine.importProjections is the Kotlin twin). Personal vault ONLY — imports land
   * there, and a copy living in a shared vault is not the same item. Absent fields map
   * to ""/[]/null (A7) so the planner's keys are total; `names` carries ALL personal
   * display names (every item type) — the A9 rename-collision set. REFUSES (throws)
   * rather than silently planning against an empty projection when this device has
   * never completed a sync — the caller shows the honest "couldn't check your vault"
   * copy instead of quietly re-importing everything as new.
   */
  importProjections(vaultId?: string): ImportProjections {
    if (this._lastSyncAt === null) {
      throw new Error("vault not synced on this device yet — import would plan against an empty projection");
    }
    // S2: the destination vault's projections — the SAME vaultId must feed importDocs, or
    // the F75 dedupe fingerprints one vault while the rows land in another. Default personal.
    const target = vaultId ?? this.personalVaultOrRefuse();
    const logins: ImportProjections["logins"] = [];
    const notes: ImportProjections["notes"] = [];
    const names: string[] = [];
    for (const it of this.itemsById.values()) {
      if (it.vaultId !== target) continue;
      names.push(it.doc.name);
      if (it.doc.type === "login") {
        logins.push({
          name: it.doc.name,
          uris: it.doc.login?.uris ?? [],
          username: it.doc.login?.username ?? "",
          password: it.doc.login?.password ?? "",
          totp: it.doc.login?.totp ?? null,
        });
      } else if (it.doc.type === "note") {
        notes.push({ name: it.doc.name, notes: it.doc.notes ?? "" });
      }
    }
    return { logins, notes, names };
  }

  /**
   * Bulk CSV import (spec 06): push planned items into the personal vault in chunks of
   * SERVER_BATCH_MAX, then one sync at the end. Each mutation's mutationId IS its itemId
   * (minted once at plan time) so re-running the SAME plan after a mid-import failure
   * replays idempotently server-side (idempotency key = deviceId+mutationId) instead of
   * duplicating. Mirrors core SyncEngine.importAll. Re-PARSING the file mints new ids.
   */
  async importDocs(
    items: { itemId: string; doc: ItemDoc }[],
    onProgress?: (done: number, total: number) => void,
    destinationVaultId?: string,
  ): Promise<void> {
    const vaultId = destinationVaultId ?? this.personalVaultOrRefuse();
    const total = items.length;
    let done = 0;
    for (let start = 0; start < items.length; start += VaultStore.SERVER_BATCH_MAX) {
      const chunk = items.slice(start, start + VaultStore.SERVER_BATCH_MAX);
      const mutations: Mutation[] = chunk.map(({ itemId, doc }): Mutation => {
        const upload = this.sealFor(chosenProvenance(vaultId), itemId, doc); // INV-SEAL (c): the chosen destination
        return {
          mutationId: itemId, // stable id → idempotent retry of the same plan
          op: "put",
          itemId,
          vaultId,
          baseItemRev: 0,
          item: {
            formatVersion: upload.formatVersion,
            attachmentIds: doc.attachments?.map((a) => a.id) ?? [],
            blob: upload.blob,
          },
        };
      });
      await this.push(mutations);
      done += chunk.length;
      onProgress?.(done, total);
    }
    await this.sync();
  }

  /** Fetch + decrypt one attachment blob (24-byte secretstream header ‖ chunks). */
  async downloadAttachment(item: VaultItem, ref: AttachmentRef): Promise<Uint8Array> {
    if (!item.doc.attachments?.some((a) => a.id === ref.id)) throw new Error("attachment does not belong to this item");
    // ref.size is the item author's claim (a co-member's, in a shared vault — security review
    // 2026-10): the body must be exactly the length it implies, so the backup cap that budgets with
    // it holds what it says, and a lie is refused instead of decrypted. Core twin.
    const expected = wireLength(ref.size);
    if (expected === null) throw new Error("attachment does not match its declared size");
    const bytes = await this.api.downloadAttachment(ref.id);
    if (bytes.length !== expected) throw new Error("attachment does not match its declared size");
    return decryptAttachment(fromB64(ref.fileKey), bytes.subarray(0, HEADER_BYTES), bytes.subarray(HEADER_BYTES));
  }

  /**
   * §D.3 durable delete (save()'s twin): enqueue the delete durably, drop the item
   * optimistically, then flush + reconcile. OFFLINE ⇒ success-as-QUEUED while persistence is
   * granted (breaker #1), else push-or-throw; a GENUINE denial (a reader) re-thrown and the
   * item restored; a committed delete whose reconcile pull fails stays removed (the item is
   * gone fleet-wide — the UI must never claim "nothing was removed").
   */
  async remove(itemId: string): Promise<void> {
    const existing = this.itemsById.get(itemId);
    if (!existing) return;
    const m = this.deleteMutation(itemId, existing.vaultId, existing.rev);
    let mayQueue = await this.offlineQueueAllowed();
    // Durable, stable mutationId (idempotent retry); no-op on NullCache. M2: the pre-delete
    // snapshot rides the row (sealed, local-only) so a post-restart denial still restores.
    // CR-01 (breaker #1): as in save() — a verified-not-landed enqueue (a closed/force-wiped cache
    // that still reports durable=true) must refuse the queue and route to the real send, never
    // report a black-holed delete as success (a "deleted" item that silently resurrects on reload).
    const enqueued = await this.cache.enqueue(m, this.durablePreEdit(existing, "delete", 0, 0));
    if (!enqueued) {
      this.demoteCache();
      mayQueue = false;
    }
    // C2 (a): the pre-delete truth — a GENUINE denial restores the item live (memory + disk)
    // instead of leaving it locally-deleted forever while it stays live server-side.
    this.preEditByMutation.set(m.mutationId, { pre: existing, op: "delete", optimisticRev: 0, optimisticUpdatedAt: 0 });
    // Optimistic apply: drop from the live view + the on-disk envelope (guarded).
    this.itemsById.delete(itemId);
    this.pendingSyncItemIds.add(itemId);
    try {
      await this.cache.deleteItem(itemId);
    } catch (e) {
      console.warn("remove: optimistic offline-cache delete failed (harmless — a later sync trues up)", e);
    }
    // C3 FIFO: durable cache ⇒ the send rides flushQueue (older queued rows drain first,
    // single-flighted, lock-wrapped); direct flushChunk only on NullCache (no-op enqueue).
    const displaced: Displaced[] = [];
    try {
      if (this.cache.durable && enqueued) {
        await this.flushQueue();
      } else {
        await this.flushChunk([m], displaced); // send the delete; denied → staged; offline → throws
      }
    } catch (e) {
      // Never sent (offline). Persist-gated ⇒ success-as-QUEUED (the item stays removed, the
      // delete flushes on reconnect). Otherwise refuse-not-degrade: drop the queued delete,
      // RESTORE the item to the live view, rethrow (today's push-or-throw).
      if (mayQueue && !(e instanceof ApiError)) return;
      await this.cache.dequeue(m.mutationId);
      this.preEditByMutation.delete(m.mutationId);
      await this.restoreRemoved(itemId, existing);
      throw e;
    }
    for (const d of displaced) await this.materializeConflictFromServerItem(d);
    await this.throwIfRejected(m);
    try {
      await this.sync();
      // C2 (d): epoch-deferral — see save(). One more cycle so a joined stale pull can't
      // turn a denied delete into a silent success.
      if (this.mutationStillStaged(m)) await this.sync();
    } catch (e) {
      if (e instanceof ApiError && e.code === "denied") {
        // GENUINE denial (a reader's delete) — the row was dropped durably and the item
        // restored live from the C2 snapshot inside surfaceStagedDenials. Rethrow.
        throw e;
      }
      // COMMITTED server-side; only the reconcile pull failed — the item is gone fleet-wide,
      // keep it removed (the UI must never resurface it or report failure).
      this.pendingSyncItemIds.delete(itemId);
      console.warn("remove committed but the reconcile pull failed — item kept removed; a later sync trues up", e);
      return;
    }
    this.pendingSyncItemIds.delete(itemId);
  }

  /** Undo a remove()'s optimistic drop (a genuine denial or a refuse-not-degrade offline
   *  reject): restore the item to the live view + re-seal its pre-delete envelope on disk. */
  private async restoreRemoved(itemId: string, existing: VaultItem): Promise<void> {
    this.pendingSyncItemIds.delete(itemId);
    this.itemsById.set(itemId, existing);
    // L1: tri-state mutual exclusion — same rule as revertOptimisticSave above.
    this.undecryptableById.delete(itemId);
    this.missingVkById.delete(itemId);
    try {
      const up = this.account.resealLocal(existing.vaultId, itemId, existing.doc); // local, never pushed
      await this.cache.upsertItem({ itemId, vaultId: existing.vaultId, rev: existing.rev, createdAt: 0, updatedAt: existing.updatedAt, deleted: false, conflict: false, formatVersion: up.formatVersion, attachmentIds: existing.doc.attachments?.map((a) => a.id) ?? [], blob: up.blob });
    } catch {
      /* best-effort — the next successful pull re-delivers the true row */
    }
  }

  // ==== vault lifecycle: notices + transfer state (read) ====

  /** The pending lifecycle notices for the UI banner (spec 03 §11). */
  notices(): LifecycleNotice[] {
    return [...this.noticeList];
  }

  dismissNotice(id: string): void {
    this.noticeList = this.noticeList.filter((n) => n.id !== id);
  }

  clearNotices(): void {
    this.noticeList = [];
  }

  /** F20: shared vaults this device was granted but cannot open (grant sealed to a key we don't
   *  hold, or a newer format). A PERSISTENT, non-dismissable warning surface (the Sharing view),
   *  distinct from the dismissable lifecycle notices; clears itself once a later pull opens the
   *  grant or the grant is revoked. The name can't be decrypted, so only the id is exposed. */
  undecryptableGrantVaults(): string[] {
    return [...this.undecryptableGrants].sort();
  }

  /** Vaults soft-hidden in the holding area (surfaced on Sharing under the trash icon,
   *  "Recently removed" — read-only; recovery is automatic on restore/re-add). */
  heldVaults(): { vaultId: string; name: string; reason: RemovedReason; verified: boolean; purgeAt?: number; expungeAt: number }[] {
    return [...this.holding.entries()].map(([vaultId, h]) => ({
      vaultId,
      name: h.cachedName,
      reason: h.reason,
      verified: h.verified,
      purgeAt: h.purgeAt,
      expungeAt: h.expungeAt,
    }));
  }

  /** Verified incoming ownership offers TO us — the accept consent screen renders per entry. */
  incomingTransfers(): IncomingTransfer[] {
    return [...this.incomingByVault.values()];
  }

  /** The pending offer on an owned vault (for the owner's "Ownership offer to …" chip), or null. */
  pendingTransferFor(vaultId: string): PendingTransfer | null {
    return this.vaultsById.get(vaultId)?.pendingTransfer ?? null;
  }

  // ==== vault lifecycle: actions (spec 03 §11) ====

  /** DELETE (soft, 7d grace). Mints a fresh deleteId + delete proof under the held VK.
   *  This device initiated it, so the reconcile pull drops the vault cleanly (no banner);
   *  the owner restores it from the Sharing trash icon. Returns the server-erase deadline. */
  async deleteSharedVault(vaultId: string): Promise<{ purgeAt: number }> {
    const deleteId = crypto.randomUUID();
    const key = await this.account.lifecycleKeyFor(vaultId);
    const proof = await deleteProof(key, vaultId, deleteId);
    const resp = await this.api.deleteVault(vaultId, { deleteId, proof });
    this.suppressDrop.add(vaultId);
    try {
      try {
        await this.sync();
      } catch {
        this.hardDropLocal(vaultId, true);
      }
    } finally {
      this.suppressDrop.delete(vaultId); // #4: never outlives the action's own reconcile
    }
    return { purgeAt: resp.purgeAt };
  }

  /** REMOVE a member (spec 03 §11 removal proof; skipti design §49). Mints a fresh nonce + remove
   *  proof under the held VK and sends both with the DELETE, the way deleteSharedVault above mints
   *  its deleteId + delete proof before the call. The proof is the ONLY thing that lets the removed
   *  member's client tell an owner action from a server forgery: both sync engines classify a
   *  removal that arrives without one as "anomaly" by design (verifyRemoval below; core
   *  SyncEngine.verifyRemoval), which renders the danger-tone "the server may be misbehaving —
   *  tell your admin" banner. H06 (audit 2026-09-13): the web Sharing screen — the only production
   *  caller of member removal on any client — called the route with no body, so every legitimate
   *  removal reached the victim as that forgery warning and the one signal that exists to catch a
   *  real forgery cried wolf 100% of the time. The owner is unlocked by construction here (VK in
   *  hand), so minting is free; this is the one sanctioned way to remove a member from the web app
   *  — never call api.removeVaultMember bodyless from a UI (store.lifecycle.test.ts pins both the
   *  minted body and that a victim lands it as "removed", not "anomaly"). */
  async removeVaultMember(vaultId: string, userId: string): Promise<void> {
    // Root cause A §6.2 (branch A7): a v2 proof — a fresh 16-byte nonce and this device's clock, bound in the MAC.
    const nonce = newRemovalNonce();
    const issuedAt = Date.now();
    const key = await this.account.lifecycleKeyFor(vaultId);
    const proof = await removeV2Proof(key, vaultId, userId, nonce, issuedAt);
    // A9 (M-3): this browser's own durable record of the removal, written BEFORE the request so no later rollback of
    // account state can make this browser offer the pair as "previously shared" again.
    this.recordIssuedTombstoneHere(vaultId, userId, issuedAt);
    await this.api.removeVaultMember(vaultId, userId, { proofV: 2, proof, nonce, issuedAt });
    // A6b: a removed member's pair leaves the issued-grants record (tombstoned) on every device of the owner.
    await this.accountState.update((d) => withoutIssued(d, vaultId, userId, Date.now())).catch(() => {});
  }

  /** The caller's own in-grace deleted vaults — re-opens each VK from the wrappedVk it already
   *  owned so the name shows AND restore can mint its proof (ZK-clean). */
  async listDeleted(): Promise<DeletedVaultInfo[]> {
    const raw = await this.api.deletedVaults();
    const out: DeletedVaultInfo[] = [];
    for (const d of raw) {
      let name = "(vault)";
      try {
        this.account.addGrant({ vaultId: d.vaultId, userId: this.account.userId, role: "owner", wrappedVk: d.wrappedVk, rev: 0, sealedVk: null });
        name = this.account.decryptVaultName(d.vaultId, d.metaBlob);
      } catch {
        /* can't open — placeholder; restore will fail loudly if truly lost */
      }
      out.push({ vaultId: d.vaultId, name, deletedAt: d.deletedAt, purgeAt: d.purgeAt, deleteId: d.deleteId });
    }
    return out;
  }

  /** RESTORE (within grace). Requires the VK held (listDeleted re-opened it). */
  async restoreSharedVault(vaultId: string, deleteId: string): Promise<void> {
    const key = await this.account.lifecycleKeyFor(vaultId);
    const proof = await restoreProof(key, vaultId, deleteId);
    await this.api.restoreVault(vaultId, { deleteId, proof });
    this.consumedDeleteIds.add(deleteId);
    try {
      await this.sync();
    } catch (e) {
      console.warn("restore committed; reconcile pull failed — a later sync trues up", e);
    }
  }

  /** LEAVE (self-removal). This device initiated it → drop cleanly (no "you left" banner here). Carries a v2 leave
   *  proof (root cause A §6.2, branch A7) so this member's OTHER devices can verify the leave. */
  async leaveSharedVault(vaultId: string): Promise<void> {
    const nonce = newRemovalNonce();
    const issuedAt = Date.now();
    const proof = await leaveProof(await this.account.lifecycleKeyFor(vaultId), vaultId, this.account.userId, nonce, issuedAt);
    await this.api.leaveVault(vaultId, { proofV: 2, proof, nonce, issuedAt });
    // A6b: leaving ends this account's ownership evidence for the vault (if it had any).
    if (this.ownsVault(vaultId)) await this.accountState.update((d) => withoutOwned(d, vaultId, Date.now())).catch(() => {});
    this.suppressDrop.add(vaultId);
    try {
      try {
        await this.sync();
      } catch {
        this.hardDropLocal(vaultId, true);
      }
    } finally {
      this.suppressDrop.delete(vaultId); // #4: never outlives the action's own reconcile
    }
  }

  /** TRANSFER offer. seq = transferSeq+1 (= the vault's lastTransfer.seq + 1). */
  async offerTransfer(vaultId: string, toUserId: string): Promise<void> {
    this.requireOwned(vaultId); // A6b: an owner-only action, never on the server's role label alone
    const vault = this.vaultsById.get(vaultId);
    const seq = (vault?.lastTransfer?.seq ?? 0) + 1;
    const offerId = crypto.randomUUID();
    const expiresAt = Date.now() + 14 * 86_400_000;
    const key = await this.account.lifecycleKeyFor(vaultId);
    const proof = await offerProof(key, vaultId, offerId, toUserId, expiresAt, seq);
    await this.api.offerTransfer(vaultId, { toUserId, offerId, expiresAt, proof });
    try {
      await this.sync();
    } catch (e) {
      console.warn("transfer offer committed; reconcile failed", e);
    }
  }

  /** TRANSFER cancel (owner) or decline (target). */
  async cancelTransfer(vaultId: string): Promise<void> {
    await this.api.cancelTransfer(vaultId);
    this.incomingByVault.delete(vaultId);
    try {
      await this.sync();
    } catch (e) {
      console.warn("transfer cancel committed; reconcile failed", e);
    }
  }

  /**
   * TRANSFER accept (design §4 TRANSFER 3). Re-verifies the offer proof under the held VK
   * BEFORE acting, mints + round-trip-verifies the owner wrap (same construction as vault
   * creation), and posts acceptProof over sha256(wrappedVk). Fails loudly rather than
   * post an unopenable wrap.
   */
  async acceptTransfer(vaultId: string): Promise<void> {
    const vault = this.vaultsById.get(vaultId);
    const pt = vault?.pendingTransfer;
    if (!pt || pt.toUserId !== this.account.userId) throw new ApiError(409, "transfer_not_pending", "no ownership offer pending for you");
    if (pt.expiresAt <= Date.now()) throw new ApiError(409, "transfer_not_pending", "this ownership offer has expired");
    const key = await this.account.lifecycleKeyFor(vaultId);
    if (!verifyProof(pt.proof, await offerProof(key, vaultId, pt.offerId, pt.toUserId, pt.expiresAt, pt.seq))) {
      throw new ApiError(400, "not_transfer_target", "the offer could not be verified with the vault's key");
    }
    const wrappedVk = this.account.buildOwnerWrap(vaultId); // throws if it fails round-trip
    const proof = await acceptProof(key, vaultId, pt.offerId, this.account.userId, pt.seq, wrappedVk);
    await this.api.acceptTransfer(vaultId, { offerId: pt.offerId, wrappedVk, proof });
    this.incomingByVault.delete(vaultId);
    // A6b: this account accepted the vault, verified under its key: its own evidence of ownership.
    await this.accountState.update((d) => withOwned(d, vaultId, Date.now())).catch(() => {});
    try {
      await this.sync();
    } catch (e) {
      console.warn("transfer accept committed; reconcile failed", e);
    }
  }

  /** RENAME. Read-modify-write metaBlob (name only, unknown fields preserved, metaV bumped),
   *  with the current vault rev as the stale-write guard. A 409 stale_meta (a concurrent change)
   *  auto-resyncs and retries ONCE on top of the fresh row (never a silent last-write-wins). */
  async renameVault(vaultId: string, newName: string, retry = true): Promise<void> {
    const vault = this.vaultsById.get(vaultId);
    if (!vault) throw new Error("vault not found");
    const metaBlob = this.account.buildRenameMeta(vaultId, vault.metaBlob, newName);
    try {
      await this.api.updateVaultMeta(vaultId, { metaBlob, baseVaultRev: vault.rev });
    } catch (e) {
      if (retry && e instanceof ApiError && e.code === "stale_meta") {
        await this.sync(); // pull the newer row, then rebuild the rename on top of it
        return this.renameVault(vaultId, newName, false);
      }
      throw e;
    }
    try {
      await this.sync();
    } catch (e) {
      console.warn("rename committed; reconcile failed", e);
    }
  }

  // ==== F19: move / copy an item into another vault (design §8) ====

  /** Mint a move/copy gesture: fresh newItemId + per-attachment fresh fileKeys, captured ONCE.
   *  A retry MUST reuse the SAME gesture (server dedup converges); a new deliberate copy gets a
   *  fresh one. `del=true` = move (copy then delete source); `del=false` = copy only. */
  newMoveGesture(itemId: string, targetVaultId: string, del: boolean): MoveGesture {
    const src = this.itemsById.get(itemId);
    if (!src) throw new Error("the item to move is no longer here");
    const attachments = (src.doc.attachments ?? []).map((r) => ({
      oldId: r.id,
      newId: crypto.randomUUID(),
      newFileKey: toB64(randomBytes(32)), // FRESH fileKey — breaks the sha256(ciphertext) linkage
      name: r.name,
      size: r.size,
    }));
    return {
      gestureId: crypto.randomUUID(),
      sourceItemId: itemId,
      sourceVaultId: src.vaultId,
      sourceRev: src.rev, // the rev of the content copied — the delete leg's stale-write guard
      targetVaultId,
      newItemId: crypto.randomUUID(),
      del,
      attachments,
    };
  }

  private gestureMutationId(gestureId: string, leg: string): Promise<string> {
    return uuidFromLabel(`gesture|${gestureId}|${leg}`);
  }

  /**
   * Run a move/copy gesture (design §8 safe shape): COPY LEG FIRST (fresh ids, attachments
   * re-encrypted under fresh fileKeys), wait applied/conflict, THEN — for a move — delete the
   * SOURCE with the baseRev of the content actually copied. Copy denied → CopyDeniedError,
   * source untouched. Delete conflict (source changed) → resync + ItemChangedError, never a
   * blind retry. Idempotent per gesture (mutationIds derive from gestureId).
   */
  async runGesture(g: MoveGesture, onProgress?: (done: number, total: number) => void, finalSync = true): Promise<void> {
    const src = this.itemsById.get(g.sourceItemId);
    if (!src) throw new Error("The item to move is no longer here — it may have changed or been removed.");
    // INV-HOME (A1b; core twin): the gesture was minted for the source in its vault; never run against another's copy.
    if (src.vaultId !== g.sourceVaultId) throw new ItemChangedVaultsError();

    // --- COPY LEG ---
    const newDoc: ItemDoc = structuredClone(src.doc);
    if (g.attachments.length) {
      const newRefs: AttachmentRef[] = [];
      let done = 0;
      onProgress?.(0, g.attachments.length);
      for (const a of g.attachments) {
        const srcRef = src.doc.attachments?.find((r) => r.id === a.oldId);
        if (!srcRef) throw new Error("an attachment vanished from the source item");
        const plain = await this.downloadAttachment(src, srcRef);
        const enc = encryptAttachment(fromB64(a.newFileKey), plain);
        await this.api.uploadAttachment(a.newId, g.newItemId, g.targetVaultId, concat(enc.header, enc.ciphertext));
        newRefs.push({ id: a.newId, name: a.name, size: a.size, fileKey: a.newFileKey });
        onProgress?.(++done, g.attachments.length);
      }
      newDoc.attachments = newRefs;
    }
    const copyUpload = this.sealFor(chosenProvenance(g.targetVaultId), g.newItemId, newDoc); // INV-SEAL (c): the chosen destination
    const copyResp = await this.api.push([
      {
        mutationId: await this.gestureMutationId(g.gestureId, "copy"),
        op: "put",
        itemId: g.newItemId,
        vaultId: g.targetVaultId,
        baseItemRev: 0,
        item: {
          formatVersion: copyUpload.formatVersion,
          attachmentIds: newDoc.attachments?.map((a) => a.id) ?? [],
          blob: copyUpload.blob,
        },
      },
    ]);
    const copyResult = copyResp.results[0];
    if (copyResult?.status === "denied") throw new CopyDeniedError(); // ABORT — source untouched
    // POSITIVE confirmation required (design §8): only `applied`, or `conflict` (put-over-
    // existing on a crash-window retry: our copy won, content is present), may proceed to the
    // delete leg. A missing result or an unknown/future status is NOT a durable copy — abort
    // with the source untouched rather than delete against an unconfirmed copy.
    if (copyResult?.status !== "applied" && copyResult?.status !== "conflict") {
      throw new ApiError(0, "copy_unconfirmed", "The copy could not be confirmed — nothing was moved. Try again.");
    }
    if (this.account.hasVault(g.targetVaultId)) {
      this.itemsById.set(g.newItemId, {
        itemId: g.newItemId,
        vaultId: g.targetVaultId,
        rev: copyResult?.newItemRev ?? 1,
        updatedAt: Date.now(),
        formatVersion: copyUpload.formatVersion,
        doc: newDoc,
      });
    }

    // --- DELETE LEG (move only) ---
    if (g.del) {
      const delResp = await this.api.push([
        {
          mutationId: await this.gestureMutationId(g.gestureId, "delete"),
          op: "delete",
          itemId: g.sourceItemId,
          vaultId: g.sourceVaultId,
          baseItemRev: g.sourceRev, // the rev of the content actually copied — NOT the cache rev
        },
      ]);
      const delResult = delResp.results[0];
      if (delResult?.status === "conflict") {
        await this.sync().catch(() => {}); // resync so the user sees the newer source
        throw new ItemChangedError();
      }
      if (delResult?.status === "denied") {
        throw new ApiError(403, "denied", "The source item could not be deleted — your access may have changed. The copy was made.");
      }
      this.itemsById.delete(g.sourceItemId);
    }

    if (finalSync) {
      try {
        await this.sync();
      } catch (e) {
        console.warn("move/copy committed; reconcile failed", e);
      }
    }
  }

  /**
   * Bulk "copy all to Personal" (design §8) — the delete dialog's rescue step. COPY LEGS ONLY:
   * originals are NEVER deleted (abort mid-bulk is non-destructive; the vault delete itself ends
   * access, and grace-retains the originals so a restore genuinely returns everything). One
   * gesture per item (attachments force per-item); one reconcile at the end.
   */
  /** Bulk-copy gestures memoized per (source item → target) so a RETRY after a mid-run
   *  failure reuses the SAME gestureId/newItemId/fileKeys — the copy mutationIds converge on
   *  the server dedup instead of double-writing every already-copied item (design §8). */
  private bulkGestures = new Map<string, MoveGesture>();

  async copyAllToPersonal(vaultId: string, onProgress?: (done: number, total: number) => void): Promise<{ copied: number }> {
    const items = [...this.itemsById.values()].filter((it) => it.vaultId === vaultId);
    let copied = 0;
    for (const it of items) {
      const gKey = `${vaultId}|${it.itemId}|${this.account.personalVaultId}`;
      let g = this.bulkGestures.get(gKey);
      if (!g || g.sourceRev !== it.rev) {
        // New gesture only for a first attempt or when the source content changed since the
        // memoized attempt (a different rev IS different content — copy that instead).
        g = this.newMoveGesture(it.itemId, this.account.personalVaultId, false);
        this.bulkGestures.set(gKey, g);
      }
      await this.runGesture(g, undefined, false);
      onProgress?.(++copied, items.length);
    }
    try {
      await this.sync();
    } catch (e) {
      console.warn("bulk copy committed; reconcile failed", e);
    }
    return { copied };
  }

  private async push(mutations: Mutation[]): Promise<PushResponse> {
    const resp = await this.api.push(mutations);
    // PDD-1: on a conflicting PUT the server keeps OUR value live (LWW) and returns the
    // DISPLACED (losing) version as serverItem. Materialize the conflict copy from THAT here,
    // synchronously — the pull side only ever sees the winner and would otherwise copy the
    // wrong (surviving) value (spec 03 §5). Collect first, then materialize, so the loop over
    // resp.results isn't re-entered by the nested copy push. Guard on op==="put": a DELETE that
    // loses to a newer edit (edit-beats-delete) ALSO returns conflict+serverItem, but there
    // serverItem is the SURVIVING winner, not a losing value — copying it would spawn a
    // spurious duplicate of the still-live item.
    const byId = new Map(mutations.map((m) => [m.mutationId, m]));
    const displaced: Displaced[] = [];
    for (const r of resp.results) {
      if (r.status === "denied") throw new ApiError(403, "denied", "write denied");
      const m = byId.get(r.mutationId);
      if (r.status === "conflict" && m?.op === "put" && r.serverItem && r.newItemRev != null) {
        displaced.push({ item: r.serverItem, winnerRev: r.newItemRev, pushedVaultId: m.vaultId });
      }
    }
    for (const d of displaced) await this.materializeConflictFromServerItem(d);
    return resp;
  }
}
