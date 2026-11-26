import type { ApiClient } from "../api/client";
import { answerLimitOf, ApiError } from "../api/client";
import type { QuotaUse } from "../api/wire";
import { copySize, QuotaShortError, quotaRoom, sealedBlobLength, storedAttachmentSize } from "./quota";
import { sanitizeSync } from "../api/wireids";
import type {
  AttachmentMeta,
  AttachmentRef,
  DeletedItemsResponse,
  ItemDoc,
  ItemRestoreResponse,
  ItemUpload as WireItemUpload,
  ItemVersion,
  ItemVersionsResponse,
  Mutation,
  PendingTransfer,
  PushResponse,
  RemovedGrantInfo,
  SyncResponse,
  VaultMemberSummary,
  WireGrant,
  WireItem,
  WireVault,
} from "../api/types";
import { HEADER_BYTES, decryptAttachment, encryptAttachment, fileKeyOf, wireLength } from "../crypto/attachments";
import { concat, fromB64, toB64, toHexLower, utf8 } from "../crypto/bytes";
import { randomBytes, sha256, sha256Sync } from "../crypto/provider";
import type { ImportProjections } from "../import/csv";
import { ITEM_FORMAT_VERSION, type Account, type ItemUpload, ReauthFailedError, ReauthStaleSessionError, VaultKeyNotVerifiedError } from "./account";
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
import type { ClientStateStore } from "./accountstatesync";
import { type Roster, type SharedLogSession, vaultNameUnder } from "./sharedlogs";
import { itemLogHead } from "./itemhead";
import type { AppendOpts, AppendOutcome, HeldChange, HeldKnown, LogAction, LogStatus, MoveRecord, ResendOutcome, WatchFinding } from "./logstore";
import { VAULT_META_MOVE_OF } from "./logstore";
import type { VaultState } from "../crypto/trust/vaultlog";
import { heldRowKey, NullCache, type PullBatch, type QueuedPreEdit, type VaultCache } from "./idbcache";
import { SessionClosedError, type SessionFence } from "./sessionfence";
import { CopyBeingRemovedError, copyIsBeingRemoved, copyRemovalBlocked } from "./policywipe";

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
  /** When the server says the vault was made (shown only to tell apart two vaults of one name). */
  createdAt?: number;
}

/**
 * What this browser held of one shared vault just before a 410 resync replaced its working set: the vault row and the
 * item entries of every kind, as they were. A vault the fresh list no longer grants is handled from these.
 */
interface TakenVault {
  vault: WireVault;
  items: VaultItem[];
  undecryptable: UndecryptableItem[];
  missing: UndecryptableItem[];
  missingWire: WireItem[];
}

/** The log head a served vault row names (a hint to fetch, never a verdict), or null when it names none. */
function logHeadOf(v: WireVault): { seq: number; hash: string } | null {
  return (v as { logHead?: { seq: number; hash: string } | null }).logHead ?? null;
}

/**
 * Whether a vault's verified log no longer names this account as a member: it shows the account's removal (or its own
 * leave), the vault's purge, or a `delete` in force. A log not verified at this moment (frozen, withheld, failed, not
 * read yet) says neither: it is never read as a removal here.
 */
function logNoLongerNames(st: LogStatus): boolean {
  return st.kind === "removed" || st.kind === "purged" || (st.kind === "verified" && st.state.deleteId !== null);
}

/** [v] as JSON with every object's keys in one order, so that two opened items compare by content alone. */
function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  if (v !== null && typeof v === "object") {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o)
      .filter((k) => o[k] !== undefined)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(v) ?? "null";
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
 * A lifecycle notice the UI renders (spec 03 §11 / design §11). Fired for vaults held
 * locally before the pull, a 410 resync included (what was held before it is taken first) — on a
 * since=0 / fresh-device pull only the nameless "unchecked-gone". Attribution ("by its
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
    // A removal of a vault frozen on this browser, learned at a sync after this account's own leave of it, which the
    // server answered naming it: the person left it here, but the browser cannot check what else happened since. Held
    // as the anomaly is.
    | "left-frozen"
    // A full pull that holds nothing of the vault (the first after a sign-in, a reload with no offline copy, a 410 resync
    // with nothing of it left) no longer grants a shared vault that this account's records on this browser hold as frozen
    // here, or as left here by the person: nothing is held, and vaultName is "" (the name is not known).
    | "unchecked-gone"
    | "restored"
    | "added"
    | "transfer-complete"
    | "transfer-anomaly"
    | "replay-denied"
    | "write-refused"
    | "write-rejected"
    | "meta-regression"
    // Root cause A §3.1 (security review 2026-10): the personal vault's row carried a wrap of ours that opens to
    // another key than the one held (the held key was kept).
    | "vk-mismatch"
    // Root cause A §5.1 INV-HOME (A1b): the server sent an item under another vault than the one this device holds it
    // in (or a conflict row disagreeing about its vault); NOT applied. One per pull; vaultId = the first offending
    // row's vault, parkedCount = how many rows were refused; vaultName "".
    | "wrong-vault"
    // Security review 2026-10 plugin scan F1 (A10): the server sent rows whose ids are not UUIDs; they were dropped at
    // the wire (api/wireids.ts). vaultId and vaultName are "" (no id of theirs is trusted), reason = the endpoint,
    // parkedCount = how many ids were refused.
    | "bad-id"
    // A sync answer named the personal vault as removed. Nothing was changed (it has no members, so no
    // removal of it can be genuine).
    | "personal-kept"
    // Design §3.13 as decided on 2026-11-17: a move's signed delete of the old vault was stored by the server outside a
    // run of the move. The copy is in the holding area; lateAdded / lateChanged count what it holds that was added or
    // changed after the move copied it, which can be copied into the new vault (newVaultId, newVaultName) from there.
    | "move-stored"
    // A change of this vault that was kept to be sent again (its answer was lost, or the server asked to slow down) did
    // not happen when it was sent again: heldKind and memberName say what it was, reason why (the server's code,
    // `head_moved`, `not_made`, `given_up`...).
    | "held-not-made"
    // The same, a change of who may read the vault that waited a day and was given up, and whether it was made cannot be told.
    | "held-given-up"
    // Design §3.13 as decided on 2026-11-18: the half-made vault of a stopped move, due for deletion, holds something the
    // move did not make (parkedCount: how many items), so it was NOT deleted and stays a vault of its own.
    | "half-made-kept"
    // A change this browser withdrew or gave up without knowing whether the server had it is in the vault's log after all
    // (heldKind, memberName: what it was); the notice says how to undo it.
    | "held-found-made"
    // A change this browser withdrew while it could not tell whether it was made: the log, read since, does not hold it.
    | "held-found-not-made"
    // The person's own deletion of this vault waits (its answer was lost, or the server asked to slow down): it is sent
    // again only at their word, so the unlock asks, with the two acts (delete it now; keep the vault, which withdraws it).
    | "held-delete-ask"
    // The person's own deletion of this vault, held because its answer was lost, was found in the vault's log before they
    // were asked about it: it was made, and the vault is deleted (purgeAt: the end of its grace, while it can be restored).
    | "held-delete-made"
    // Spec 03 §5: a put of this browser over an item that had been deleted elsewhere brought the item back (the server
    // answered `conflict` with the deletion's mark). parkedCount: how many such changes in this vault; itemName: the
    // item's name where it is one.
    | "item-brought-back"
    // A full list (a 410 resync) neither carried nor marked as deleted items this browser held of the personal vault, or
    // of a shared vault it still lists: they were set aside, sealed, for 30 days (keptUntil), and leave the vault's list.
    // parkedCount: how many in this answer; frozen: the vault is frozen here, so this browser cannot check its history.
    | "items-set-aside"
    // Items set aside that the server has since sent again, in their own vault, with other content than the copy kept
    // here: the copy stays set aside (told once per item). parkedCount: how many in this answer or reload; personal: the
    // items are the personal vault's.
    | "items-set-aside-other";
  /** items-set-aside: the vault is frozen on this browser. */
  frozen?: true;
  /** items-set-aside: the items are the personal vault's. */
  personal?: true;
  /** item-brought-back: the item's name, where the notice is about one item. */
  itemName?: string;
  /** held-not-made / held-given-up: the log entry's kind of the change (`add`, `remove`, `role`, `offer`, `delete`...). */
  heldKind?: string;
  /**
   * held-not-made / held-given-up: the id of the change's settled record, kept at rest until this notice is dismissed
   * (vault/logstore.ts `settledChanges`): a tab closed before then shows the notice again at the next unlock.
   */
  settledId?: string;
  /** held-found-made / held-found-not-made: the change's frame hash (two such notices of one vault are two). */
  watchId?: string;
  /**
   * held-found-made: the change is the deletion of a stopped move's half-made vault that this browser dropped unsent or
   * gave up (never one the person withdrew); signedAt is when it was signed, purgeAt the end of the vault's grace.
   */
  halfMade?: boolean;
  signedAt?: number;
  /** held-not-made / held-given-up: the person it named, as a current contact's label here; absent when there is none. */
  memberName?: string;
  /** move-stored: the move's new vault, and its name as this browser reads it ("" when it can't). */
  newVaultId?: string;
  newVaultName?: string;
  /** move-stored: items the held copy has that the move never copied, and items changed after their copy. */
  lateAdded?: number;
  lateChanged?: number;
  /** verified delete: the server-erase deadline (shown only where the person can still restore). */
  purgeAt?: number;
  /** verified delete: the day this device's own copy leaves the holding area (design §3.8: 30 days from the verification). */
  keptUntil?: number;
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
}


/**
 * How long a copy stays in the holding area (design §3.8, §3.12, spec 02 §10.6): 30 days from the moment this browser
 * verified why the vault left, for a delete as for a removal. Never the vault's own purge time: the purge is the moment
 * the copy goes INTO holding, so a server that withholds a `restore` and purges anyway cannot make the copy go with it.
 */
export const HOLDING_MS = 30 * 86_400_000;

/**
 * The closed list of reasons for which a vault's rows leave this browser without a held copy (VaultStore's
 * dropWithoutHeldCopy, the one function that does it). Every other road out makes the held copy, or keeps the rows.
 */
export const DROP_REASONS = ["held-copy-made", "held-copy-removed-by-person", "own-leave", "nothing-opened", "not-log-governed"] as const;
export type DropReason = (typeof DROP_REASONS)[number];

/**
 * A sharing action on a log-governed vault that the signed vault log did not take (design §3.7): the browser refused
 * it before signing (`not_allowed`: not a current contact, not compared, no key, a pending append...), the log is
 * not verified here (`read_only`), another entry won the position (`head_moved`), this clock runs ahead (`clock_ahead`)
 * or the server refused it (`refused`, with its code), or this browser's traffic gate stopped it before it was sent
 * (`not_sent`). Nothing of THIS action is held when this is thrown; a refusal `append_pending` or `append_unread` says
 * that an EARLIER change of this vault is held.
 */
export class LogActionError extends Error {
  constructor(readonly outcome: Exclude<AppendOutcome, { kind: "appended" } | { kind: "pending" }>) {
    super(
      outcome.kind === "not_sent"
        ? "This change was not sent: this browser stopped before sending it."
        : outcome.kind === "not_allowed"
        ? `This change was not made: ${outcome.reason.replace(/_/g, " ")}.`
        : outcome.kind === "refused"
          ? `The server refused this change (${outcome.code}).`
          : outcome.kind === "read_only"
            ? outcome.frozen !== undefined
              ? "The server's record of this vault contradicts itself, so this browser no longer changes it."
              : "This vault's history could not be checked on this browser, so it can't be changed here right now."
            : outcome.kind === "head_moved"
              ? "Someone else changed this vault at the same moment. Try again."
              : outcome.kind === "not_made"
                ? "The server's answer named no record of this change, and the vault as read from it now doesn't hold it: the change was not made."
              : outcome.kind === "items_moved"
                ? "The vault's items changed after they were read, so it was not deleted."
              : "Your device's clock is ahead. Set the correct time and try again.", // §3.3's words, as ui/copy LOG_CLOCK_AHEAD
    );
    this.name = "LogActionError";
  }
}

/** One remaining member of a vault being moved (design §3.13), from its verified log. */
export interface MoveMember {
  readonly userId: string;
  readonly role: "writer" | "reader";
  /** The current contact's label here, or null (the UI names the server's name as unverified, §3.9). */
  readonly label: string | null;
  /** A contact current on this browser whose codes were compared: the web adds no one else (§6.9; it has no release choice). */
  readonly canBeAdded: boolean;
}

/** What "Move everything to a new vault" would do with one vault (design §3.13). */
export interface MovePlan {
  readonly vaultId: string;
  /** Frozen or failed (§3.9): the old vault stays where it is, nothing is signed on its log, and no member is ticked (FS-R3). */
  readonly sourceStays: boolean;
  readonly members: readonly MoveMember[];
  readonly itemCount: number;
  /** Items of the vault this browser cannot read, so cannot copy; while there are any the old vault is not deleted. */
  readonly uncopyable: number;
  /** A move of this vault this session started and that stopped: the next run carries on into the same new vault. */
  readonly resume: { readonly name: string; readonly newVaultId: string; readonly copied: number } | null;
}

/** The steps of a move, in order (design §3.13). */
export type MoveStage = "remove" | "create" | "copy" | "add" | "delete";

export interface MoveResult {
  readonly newVaultId: string;
  readonly name: string;
  readonly copied: number;
  /** The old vault's grace end when it was deleted; null when it was kept. */
  /** The old vault's deletion was stored; purgeAt: the grace end the server served, null where it served none. */
  readonly oldDeleted: { readonly purgeAt: number | null } | null;
  /**
   * Why the old vault was kept: frozen or failed, a member not added, items this browser could not copy, the new
   * vault's key holders are not the plan's (`members_differ`), or an item new or changed in it since its copy
   * (`changed_meanwhile`; with `changed` 0 where the move's own read saw none and the server refused the delete because an
   * item changed after that read), or every check passed and the old vault's log moved on before its delete was signed (a member
   * left, another change: `moved_on`; nothing was signed).
   */
  readonly oldKept: "source_stays" | "not_added" | "uncopyable" | "members_differ" | "changed_meanwhile" | "moved_on" | null;
  readonly notAdded: readonly string[];
  /** How many people this move added to the new vault (each is asked to accept it); 0 when it holds only the owner. */
  readonly added: number;
  readonly uncopyable: number;
  /** Items of the old vault new or changed since they were copied, read again after the members were added. */
  readonly changed: number;
  /**
   * A half-made new vault of an earlier, stopped run that this move did not carry on into, because someone in it is not
   * among the people this move adds (they hold its key): it held only copies, and it is deleted once this move finished.
   * `deleted` is false when that delete is not known to be stored; then `waiting` is true when it is signed and held
   * (it may already be stored; the next unlock reads the vault again and sends it only while the vault holds nothing
   * but the copies), absent when it was not made. Null when there was none.
   */
  readonly discarded: DiscardOutcome | null;
}

/**
 * What became of the half-made vault of an earlier, stopped run (design §3.13; it is read from the server first):
 *  - `deleted`: it held nothing but the copies that run made, unchanged, and the server stored its deletion (or said so);
 *  - `waiting`: the same, its deletion signed and held (read again at the next unlock, and sent again only if the vault
 *    still holds nothing but the copies);
 *  - `kept`: it holds something the move did not make (an item someone saved there or put in its trash, a copy changed
 *    since, an item this browser cannot read) or a copy whose revision is not known, so it was NOT deleted: it stays a
 *    vault of its own; `foreign` counts those items;
 *  - `unread`: it could not be read from the server (the vault or its trash), so it was not deleted (and nothing is said
 *    of what it holds); it is read again later;
 *  - `notHeld`: as read just now, it is no longer among this account's vaults: nothing was deleted, nothing is due;
 *  - none of these: it held only copies and its deletion was not made (refused, not sent).
 */
export interface DiscardOutcome {
  readonly vaultId: string;
  readonly name: string;
  readonly deleted: boolean;
  readonly waiting?: boolean;
  readonly kept?: true;
  readonly foreign?: number;
  readonly unread?: true;
  readonly notHeld?: true;
  /**
   * Dealt with before a run copied anything, and not deleted: the people the move leaves out who can still open it (each
   * by their contact's label, null where this browser has none), and the number of copies the earlier run made in it.
   */
  readonly holders?: readonly (string | null)[];
  readonly copies?: number;
  /**
   * A target found by the entry in its own sealed meta (no record of the run that made it): what is in it is not known
   * to be copies, and [copies] then counts everything the read from the server found in it (its items, the rows of its
   * trash, what this browser cannot read); absent where that read failed.
   */
  readonly found?: true;
}

/**
 * How many times one dealing with a half-made vault reads it and judges it again after the server refused its deletion
 * because the vault's items changed after the read (`vault_items_moved`). Past that it is read again at the next sync.
 */
const HALF_MADE_READS_MAX = 3;

/** The half-made vault of an earlier, stopped run of a move (design §3.13), and the copies that run made in it. */
interface HalfMade {
  readonly vaultId: string;
  readonly name: string;
  /**
   * Each copy the run made in it, by the copy's id: the copy's revision at the server as the server answered it (null:
   * the answer named none, or it never came). Null when no record of them is kept (one kept before they were).
   */
  readonly copies: ReadonlyMap<string, number | null> | null;
}

interface MoveRun {
  readonly name: string;
  readonly newVaultId: string;
  /**
   * Each item copied, by the old item's id: the revision of the old vault's item the copy was made from,
   * and the copy's id in the new vault, so that a changed item replaces its own copy.
   */
  readonly copied: Map<string, { readonly rev: number; readonly copyId: string; readonly copyRev: number | null }>;
  /** Everyone this run added to the new vault (they hold its key, whatever its log says later). */
  readonly added: Set<string>;
  /**
   * The half-made vault of an earlier run this one replaces, deleted when this one finishes, but only where it holds
   * nothing but the copies that run made, each at the revision it made it ({@link discardHalfMade}).
   */
  readonly discard: HalfMade | null;
  /** A removal this move signed on the old vault is stored: the old vault was changed, so no line says it "wasn't". */
  removed: boolean;
  /**
   * The old vault's `delete` was signed by this run and its answer never came: the frame is held for re-posting, so the
   * old vault is NOT deleted until the server's log shows it, and it cannot be taken back. Only the move re-posts it (the
   * re-posting at an unlock leaves it alone), after the old vault was read again and what is new or changed in it was
   * copied. The run is kept beside the held frame (VaultLogStore.moveRecord), so it survives a reload.
   */
  deleteHeld: boolean;
}

/** A move whose old vault's deletion is signed and waiting for the server (design §3.13): the first screen offers to finish it. */
export interface UnfinishedMove {
  readonly vaultId: string;
  /** The old vault's name, or null where this browser cannot read it any more. */
  readonly name: string | null;
  readonly newVaultId: string | null;
  readonly newName: string | null;
  /** Everyone the move added to the new vault: what finishing it passes again. */
  readonly added: readonly string[];
  /**
   * The old vault froze while the move's deletion of it was held: the deletion was dropped, and the move can never be
   * finished (its own line says so, never "finish the move"); the person dismisses it ({@link VaultStore.dismissFrozenMove}).
   */
  readonly oldFrozen?: true;
}

/**
 * The old vault of a move froze on this browser while the move's deletion of it was held (the server's record of that
 * vault contradicts itself): the deletion was dropped and can never be sent, so the move stops for good. The items are in
 * the new vault; the old one stays as it is here, read-only.
 */
export class OldVaultFrozenError extends Error {
  constructor(readonly vaultId: string) {
    super("the move's old vault is frozen on this browser");
    this.name = "OldVaultFrozenError";
  }
}

/**
 * A signed vault-log change whose answer never came (design §3.7, spec 03 §10.3): its frame is held in the pending-append
 * record and re-posted byte for byte later. It is not done: the server may or may not hold it, so nothing may show it
 * as made. [action] is the log entry's kind.
 */
/**
 * Design §3.13 as decided on 2026-11-17: a vault whose deletion a move signed and that waits for the server is read-only
 * in this browser. Nothing new is put into it (it may vanish with the deletion) and nothing else is signed on its log,
 * until the move is finished. Refused before anything is sealed, signed or sent.
 */
export class MoveWaitingError extends Error {
  constructor(readonly vaultId: string) {
    super("this vault's deletion is signed and waiting: finish the move first");
    this.name = "MoveWaitingError";
  }
}

/**
 * A signed vault-log change whose frame is held in the pending-append record, so nothing may show it as made here yet.
 * [known] is what is known of it, from the answers this browser had (vault/logstore.ts {@link HeldKnown}):
 *  - `unknown`: whether the server stored it cannot be told (no answer, an answer cut off, a 5xx, an answer that is not
 *    the server's); it is sent again, byte for byte, the next time the person unlocks, and it is never made twice;
 *  - `not_stored`: the server refused it for now (`429`, or another entry took its place and this browser has not read
 *    it yet): it is not made, and it is sent again the next time the person unlocks;
 *  - `stored`: the server's own complete answer said it is stored; this browser could not read the vault back yet.
 */
export class ChangeNotStoredError extends Error {
  constructor(
    readonly vaultId: string,
    readonly action: LogAction["kind"],
    readonly known: HeldKnown = "unknown",
    /** False when, after "cannot tell", the vault could not be read from the server again: what the screen shows may be old. */
    readonly listRead: boolean = true,
  ) {
    super(known === "stored" ? `the ${action} is stored on the server and not read back yet` : `the ${action} is not confirmed as stored on the server yet`);
    this.name = "ChangeNotStoredError";
  }
}

/**
 * A move stopped part-way (design §3.13). [stage] is the step that did not complete; every step before it did.
 * Whatever stage: every item is still in the old vault, which nothing before the last step changes, and the
 * [copied] ones are also in the new vault. Running the move again for the same vault carries on from here.
 */
export class MoveStoppedError extends Error {
  constructor(
    readonly stage: MoveStage,
    readonly copied: number,
    readonly total: number,
    readonly newName: string,
    readonly newVaultId: string | null,
    override readonly cause: unknown,
    /** The old vault's deletion is signed and waiting for the server: it cannot be taken back, so the move must be finished. */
    readonly deleteWaiting = false,
    /** A removal this move signed on the old vault is stored: the old vault was changed (its items were not). */
    readonly oldChanged = false,
    /** The half-made vault of an earlier run, dealt with before this run copied anything (null: none was). */
    readonly discarded: DiscardOutcome | null = null,
  ) {
    super(`the move stopped at its ${stage} step`);
    this.name = "MoveStoppedError";
  }
}

/**
 * A save made while the server can't be reached that this browser could not keep queued (design 2026-07-13 §B.5's
 * persist gate): nothing was changed. [reason] says why it could not wait here: attachments upload only online; there is
 * no offline copy in this browser; or the browser has not granted lasting storage, so a queued change could be evicted.
 */
export class OfflineNotSavedError extends Error {
  constructor(readonly reason: "attachments" | "no_offline_copy" | "not_persistent", override readonly cause: unknown) {
    super(`not saved while offline: ${reason}`);
    this.name = "OfflineNotSavedError";
  }
}

/** A save into a vault whose key this browser does not hold right now (after an anomaly): refused before anything is sealed. */
export class VaultNotOpenError extends Error {
  constructor(readonly vaultId: string) {
    super("this browser does not hold that vault's key right now");
    this.name = "VaultNotOpenError";
  }
}

/** A vault in the holding area whose key this browser no longer holds (a copy kept before the key was), so nothing can be copied out. */
export class HeldKeyGoneError extends Error {
  constructor() {
    super("this browser no longer holds the key for that vault");
    this.name = "HeldKeyGoneError";
  }
}

/**
 * A vault in the holding area while this browser shows an invitation to it that its person can answer (decided on 23
 * November 2026): the copy kept since the removal is closed until the invitation is answered, so nothing is copied out.
 */
export class HeldClosedWhileAskedError extends Error {
  constructor(readonly vaultId: string) {
    super("this browser shows an invitation to that vault: the copy it kept stays closed until the invitation is answered");
    this.name = "HeldClosedWhileAskedError";
  }
}

/** A sharing action on a session without a log layer: every shared-vault change is a signed log entry (design §3.7). */
const NOT_LOG_GOVERNED = (): LogActionError => new LogActionError({ kind: "not_allowed", reason: "not_log_governed" });

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


// Design §15's web row: the device-local legacy trust records (vouches and the freeze marker, held-key tags,
// member-granted ids, declined invitations, issued tombstones; vault/trustrecords.ts) are gone. A shared vault's key
// comes from its verified log alone (design §3.6) and the personal vault from the wrap that opened at unlock (§5.3).
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
  /** The copy leg replaces an earlier copy at [newItemId], whose revision is this (a move's changed item, design §3.13). */
  replacesRev?: number;
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
  /** This account's own UVK wrap of the vault's key, taken before the key left the ring (logstore.wrapForHolding). */
  ownWrap?: string;
  /** This account deleted the vault itself (design §3.8 keeps its copy too): no "deleted by its owner" line. */
  byMe?: true;
  /** Items set aside from a vault this browser still has ({@link VaultStore.itemsSetAside}), not a removed vault's copy. */
  setAside?: true;
  /** Items set aside only: the ids the server sent again in their vault with other content than the copy kept; each told once. */
  otherContentTold?: string[];
  /**
   * The ids of items of this copy whose deletion a pull applied while the copy was held (the vault's own row, after the
   * log named the account again), each taken out again when a live row of the item is applied. The copy keeps these
   * items; putting the vault back leaves them out. Absent where there is none, and on records made before it was kept.
   */
  deletedServed?: string[];
}

/**
 * The ids a held copy's record names as served deletions. A value at rest that is no list (a damaged record) reads as
 * none: it never stops a sync, and a string is never matched as a part of an id.
 */
function deletedServedOf(held: HeldVault): string[] {
  return Array.isArray(held.deletedServed) ? held.deletedServed : [];
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
/**
 * Approved wording (decided on 2026-11-17): what a write on the read-only
 * copy says. The design gives §4.4's rule but no wording for the refusal; a copy pass is writing it.
 */
export const READ_ONLY_COPY_REFUSED = "Not saved: this server's identity changed in a way andvari can't verify, so this copy is read-only. You can still read, copy and export it.";
/**
 * Approved wording (decided on 2026-11-17): what a write says on the copy of a session the server ended (design §4.4,
 * which gives the rule but no wording).
 */
export const READ_ONLY_ENDED_REFUSED = "Not saved: the server signed this browser out, so this copy is read-only until you sign in again. You can still read, copy and export it.";

/** Why a session is a read-only copy (design §4.4): its pin is forked, or the server ended the session. */
export type ReadOnlyReason = "forked" | "ended";

/** A write on a read-only copy (design §4.4): nothing is written, sent or accepted. */
export class ReadOnlyCopyError extends Error {
  constructor(readonly reason: ReadOnlyReason = "forked") {
    super(reason === "ended" ? READ_ONLY_ENDED_REFUSED : READ_ONLY_COPY_REFUSED);
    this.name = "ReadOnlyCopyError";
  }
}

/**
 * An attachment whose file key, as its item names it, is no key (all zeros, the wrong length, not base64url): damaged
 * content (core `ItemFailure.Corrupt("content")`), refused before anything is downloaded. Never a lock.
 */
export class DamagedAttachmentError extends Error {
  constructor() {
    super("the attachment's file key is damaged");
    this.name = "DamagedAttachmentError";
  }
}

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

/** How long a sync waits for the pin refresh beside it before it sends its queue (design §4.4; see pinChecked). */
const PIN_CHECK_WAIT_MS = 3_000;

/** AbortSignal.timeout where available (twin of client.ts's module-local helper). */
function timeoutSignal(ms: number): AbortSignal | undefined {
  return typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function"
    ? AbortSignal.timeout(ms)
    : undefined;
}

/** The routes the item layer calls (spec 03 §4, §5, §5.1, §9), as `WireApi` has them. */
export interface ItemWire {
  sync(since: number): Promise<SyncResponse>;
  /** `POST /sync/push`. Named so that it can be searched for: an array's `push` would hide it (see api/sends.ts). */
  pushMutations(mutations: Mutation[]): Promise<PushResponse>;
  itemVersions(itemId: string): Promise<ItemVersionsResponse>;
  deletedItems(): Promise<DeletedItemsResponse>;
  restoreItem(itemId: string, upload: WireItemUpload): Promise<ItemRestoreResponse>;
  purgeItem(itemId: string): Promise<ItemRestoreResponse>;
  uploadAttachment(id: string, itemId: string, vaultId: string, body: Uint8Array): Promise<AttachmentMeta>;
  downloadAttachment(id: string): Promise<Uint8Array>;
}

/** The item wire of a store given none: every item route refuses. The transport has no item routes of its own; a
 *  session passes its wire client (api/wireclient.ts), a test its fake. */
function noItemWire(): ItemWire {
  const refuse = (): Promise<never> => Promise.reject(new Error("no item wire: this store was opened without the session's wire client"));
  return { sync: refuse, pushMutations: refuse, itemVersions: refuse, deletedItems: refuse, restoreItem: refuse, purgeItem: refuse, uploadAttachment: refuse, downloadAttachment: refuse };
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
  /** The wire rows behind missingVkById: a key the log adopts later (an answered ask, a sender who became current)
   *  makes these readable without a re-pull. Memory only; every entry is ciphertext. */
  private missingVkWire = new Map<string, WireItem>();
  private _lastSyncAt: number | null = null;

  // ---- vault lifecycle state (spec 03 §11) ----
  /** Soft-hidden removed vaults (ciphertext-only), keyed by vaultId — the holding area. */
  private holding = new Map<string, HeldVault>();
  /**
   * Items set aside, by vault: items of the personal vault, or of a shared vault still listed (frozen or not), that this
   * browser held and that a full list neither carried nor marked as deleted. Sealed as a held copy is, kept 30 days from
   * the answer that left them out; an item a later answer serves again leaves this set (it is in its vault again).
   */
  private setAside = new Map<string, HeldVault>();
  /**
   * The adoption record of each shared vault this browser holds (design §3.6, as decided on 2026-11-21): the `add` of
   * its verified log under which this browser adopted it ([carried] false) or last carried a removal of it out ([carried]
   * true). Read from the offline copy at hydrate and changed only together with what it describes, in the same pull
   * commit ({@link putLogRecord}). What decides whether a removal is still owed, with the `add` beside each key of the
   * session's ring; never the log as stored, which other roads move ahead of the removal's effects.
   */
  private readonly logRecords = new Map<string, { readonly addSeq: number; readonly carried: boolean }>();
  /** Records made at hydrate for an offline copy from before records were kept: written with the next pull's commit. */
  private readonly recordsUnpersisted = new Set<string>();
  /** At the start of a pull: the queued changes of each shared vault this browser may not write to now (never sent). */
  private unsentByVault = new Map<string, Mutation[]>();
  /** deleteIds we have seen consumed by a restore — a later tombstone bearing one is stale. */
  private consumedDeleteIds = new Set<string>();
  /** Notices awaiting the UI banner. */
  private noticeList: LifecycleNotice[] = [];
  /** Vaults this device just deleted/left — drop them cleanly on the reconcile pull (no
   *  banner). One-shot AND scoped to the action's own reconcile (removed in a finally
   *  there), so a failed reconcile can never leave a stale entry that would misread a
   *  LATER genuine removal as self-initiated and bypass the holding area. */
  private suppressDrop = new Set<string>();
  /**
   * The shared-vault layer (design §3), when the session runs on the post-cut-over server: shared vaults' keys and
   * roles then come from the signed vault logs, never from a served grant row (see {@link attachSharedLogs}).
   */
  private shared: SharedLogSession | null = null;
  /** Design §4.4 "A fork stops traffic, not reading": this session reads a cached copy under a forked pin. */
  private readOnlyCopy = false;
  /** Why the copy is read-only: `forked` (the pin), or `ended` (the server ended the session, §4.4). */
  private readOnlyReason: ReadOnlyReason | null = null;

  /**
   * Under a forked pin, or after the server ended the session (design §4.4), the copy stays readable (read, copy,
   * fill, export), but nothing is sent to the origin, nothing from it is accepted and nothing is written: sync does
   * nothing, every write refuses with {@link ReadOnlyCopyError}, and the store's transports refuse every call. One way
   * only: a frozen session never thaws. A fork found in an ended copy replaces the reason (the fork says more).
   */
  freezeAsReadOnlyCopy(reason: ReadOnlyReason = "forked"): void {
    this.readOnlyCopy = true;
    if (this.readOnlyReason !== "forked") this.readOnlyReason = reason;
    const refuse = new Proxy({}, { get: () => () => Promise.reject(new ReadOnlyCopyError(this.readOnlyReason ?? "forked")) });
    this.api = refuse as ApiClient;
    this.wire = refuse as ItemWire;
  }

  isReadOnlyCopy(): boolean {
    return this.readOnlyCopy;
  }

  private fence: SessionFence | null = null;
  private closed = false;

  /** The fence of the session this store belongs to (ui/opensession.ts enterVault wraps every transport in it). */
  attachFence(fence: SessionFence): void {
    this.fence = fence;
  }

  /**
   * The one way a lock or a sign-out ends this session's work. The session's fence closes (every later
   * call of the store, its log layer, the settings flows and the usage ledger refuses before anything is sent), and
   * the store's own transports are swapped for refusing ones, as {@link freezeAsReadOnlyCopy} does. A sync asked for
   * afterwards does nothing. Nothing is wiped: keys are left to the collector.
   */
  close(): void {
    this.closed = true;
    this.fence?.close();
    const refuse = new Proxy({}, { get: () => () => Promise.reject(new SessionClosedError()) });
    this.api = refuse as ApiClient;
    this.wire = refuse as ItemWire;
  }

  isClosed(): boolean {
    return this.closed;
  }

  /** [fn] runs once when a lock or a sign-out overtakes this session's work (see SessionFence). */
  onInterrupted(fn: () => void): void {
    if (this.fence) this.fence.onInterrupted = fn;
  }

  /** Why this session is a read-only copy, or null when it is not one. */
  readOnlyCopyReason(): ReadOnlyReason | null {
    return this.readOnlyReason;
  }

  private pinRefresh: (() => Promise<unknown>) | null = null;
  private pinRefreshInFlight: Promise<unknown> | null = null;

  /**
   * Design §4.4: the pinned card chain is refreshed on every sync, beside it and never blocking it (one at a time).
   * The pin store reports each newly verified card, so a card that names this account as the operator signs the
   * session out whatever screen is open (§12.2 rule 7), not only when the recovery-choice card fetched an offer.
   */
  attachPinRefresh(refresh: () => Promise<unknown>): void {
    this.pinRefresh = refresh;
  }

  private kickPinRefresh(): Promise<unknown> | null {
    if (this.pinRefresh === null || this.readOnlyCopy) return null;
    if (this.pinRefreshInFlight !== null) return this.pinRefreshInFlight;
    this.pinRefreshInFlight = this.pinRefresh()
      .catch(() => null)
      .finally(() => {
        this.pinRefreshInFlight = null;
      });
    return this.pinRefreshInFlight;
  }

  /**
   * Design §4.4: before a sync sends anything, the pin refresh beside it gets up to {@link PIN_CHECK_WAIT_MS} to land,
   * so a fork it finds stops the queue before the queue is sent (the session's refresh freezes the store). A refresh
   * that fails, or is slower than that, never fails or stalls the sync; the transport's gate still refuses every
   * request after a late fork mark.
   */
  private async pinChecked(): Promise<void> {
    const inFlight = this.kickPinRefresh();
    if (inFlight === null) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    await Promise.race([inFlight, new Promise<void>((r) => (timer = setTimeout(r, PIN_CHECK_WAIT_MS)))]);
    clearTimeout(timer);
  }

  private assertWritable(): void {
    if (this.readOnlyCopy) throw new ReadOnlyCopyError(this.readOnlyReason ?? "forked");
  }

  /**
   * Decided on 2026-11-17: once a server's policy that forbids the offline copy is read for THIS account (in any tab), the
   * copy this store still holds open is being removed: its one attempt sends what waits, counts what could not be sent,
   * and wipes it. A change made then would be queued into a copy that is about to go and counted by nobody, so it is
   * refused, with its reason ({@link CopyBeingRemovedError}). Once the copy is gone the store runs without one and changes
   * are sent as on any browser without an offline copy. Only the copy being removed is closed: a store of another account
   * in the same browser goes on as before, until its own policy read removes its copy.
   */
  private refuseWhileCopyIsRemoved(): void {
    if (this.copyBeingRemoved()) throw new CopyBeingRemovedError(copyRemovalBlocked(this.account.userId));
  }

  /** While the copy is being removed, its queue is the policy's one attempt's to send: the store's drain stays out. */
  private copyBeingRemoved(): boolean {
    return this.cache.durable && copyIsBeingRemoved(this.account.userId);
  }
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
  /** The held vaults whose record of served deletions the in-flight pull changed: each one's record is written once, as it
   *  stands at the end of the pull, in the pull's commit (one write per vault, however many rows the answer serves). */
  private heldNotedInPull = new Set<string>();
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

  /** Set once a pull of this session has run the removal's rule on the server's answer and committed (memory only). */
  private pulledThisSession = false;

  /**
   * Whether a pull of this session has run the removal's rule on what the server served now. Before it, what the store
   * knows of a shared vault's log is what was verified at rest, which a removal made while this browser was away has
   * not reached: the one attempt before a policy's wipe then sends only the personal vault's changes
   * (ui/session.ts policyWipeQuestion).
   */
  pulledInThisSession(): boolean {
    return this.pulledThisSession;
  }

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

  /** Design §4.4 (decided on 2026-11-17): the changes made here that were not sent, as the shared code counts them
   *  before an act that deletes this browser's copy: the queue's rows ({@link queuedMutationCount}) and every change
   *  parked with a vault held back, never the number of held vaults, which would say too few (session.ts
   *  unsentChangeCount reads the same from IndexedDB while locked). */
  async unsentChangeCount(): Promise<number> {
    let parked = 0;
    for (const h of this.holding.values()) parked += Array.isArray(h.parked) ? h.parked.length : 0;
    return (await this.queuedMutationCount()) + parked;
  }

  /** Try to send what waits (one {@link sync} cycle), then count again; the count after it. A failure to reach the
   *  server is not thrown: what was not sent is still counted. */
  async sendBeforeDelete(): Promise<number> {
    try {
      await this.sync();
    } catch {
      /* not every change could be sent: the count says what remains */
    }
    return this.unsentChangeCount();
  }

  // ---- personal vault identity + account state (security review 2026-10, root cause A §4, §8.5) ----

  // Design §5.3: the personal vault is the genesis vault, put in force at unlock only when its served wrap opened;
  // otherwise there is none (the anomaly, NoPersonalVaultNotice). Nothing here designates, proposes or re-designates one.

  /** A9 review LOW-2: the default destination, or {@link NoPersonalVaultError} while no personal vault is in force (§4.3:
   *  no default destination), so the refusal says "Choose a vault for this item." instead of reaching the seal with an
   *  empty vault id (which surfaced as "wrong master password"). */
  private personalVaultOrRefuse(): string {
    if (!this.account.personalVaultId) throw new NoPersonalVaultError();
    return this.account.personalVaultId;
  }

  /** A11 (q56): this vault's key is one this account sealed for itself (its own UVK wrap). Only a session without a log
   *  layer reads it; a log-governed vault's owner is the log's. */
  private isOwnCreatedKey(vaultId: string): boolean {
    return this.account.keyFromOwnUvkWrap(vaultId);
  }

  /**
   * True when this account owns `vaultId`: for a shared vault, when its verified log (design §3.3) names this account
   * as the owner; the personal vault is always the account's own (§3.10, §5.3). Nothing else is owned: a shared vault
   * exists only through its log, so a session without a log layer owns none (the old owned-vaults
   * record of account state no longer decides anything).
   */
  ownsVault(vaultId: string): boolean {
    if (this.logGoverns(vaultId)) return this.shared!.logs.roleOf(vaultId) === "owner";
    return vaultId !== "" && vaultId === this.account.personalVaultId;
  }

  /** Create a shared vault (owner): this account's own evidence that it owns it is recorded at once. */
  async createSharedVault(name: string): Promise<string> {
    if (this.shared !== null) {
      // Design §3.7: a signed genesis with the owner's self-wrap and sealed meta; the log decides ownership.
      // A genesis whose answer never came is held and re-posted later: the vault is not made until the server stored it.
      const out = await this.storedLogAction(null, { kind: "create", name });
      await this.reconcileAfterLogAction();
      return out.vaultId;
    }
    throw NOT_LOG_GOVERNED();
  }

  /**
   * Add `userId` to `vaultId` (design §3.7, §6.9): a signed `add` that reaches only a CURRENT contact, sealed to that
   * contact's key. No server lookup or typed address decides anything. An uncompared contact is refused (the web
   * offers no release choice).
   */
  async addVaultMember(vaultId: string, userId: string, role: string): Promise<void> {
    if (!this.logGoverns(vaultId)) throw NOT_LOG_GOVERNED();
    if (role !== "writer" && role !== "reader") throw new LogActionError({ kind: "not_allowed", reason: "bad_role" });
    await this.storedLogAction(vaultId, { kind: "add", contactUserId: userId, role, releaseUncompared: false });
    await this.reconcileAfterLogAction();
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
    /**
     * Unused: it fed the old account-state sync, which is gone (the account state is the
     * session's AccountStateStore, design §5.4). Kept so the callers' argument order stands.
     */
    _clientState?: ClientStateStore,
    /**
     * The item layer's wire (spec 03 §4 to §9): sync pull and push, item history and trash, attachments. A session
     * passes the strict wire client (api/wireclient.ts); without one every item route refuses.
     */
    private wire: ItemWire = noItemWire(),
  ) {
    // A10: a served row with a malformed id was dropped at the wire (api/wireids.ts); say so once per pull.
    this.api.onRefusedIds = (endpoint, refused) => {
      this.pushNotice({ id: this.account.newItemId(), vaultId: "", vaultName: "", kind: "bad-id", parkedCount: refused.length, reason: endpoint });
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

  /**
   * The items shown. An item of a shared vault whose key does not work now (Account.keyWorks: its verified log moved
   * past the `add` the key was adopted under, by a road after which the removal's rule has not run yet) is not shown.
   */
  list(): VaultItem[] {
    return this.openedItems().sort((a, b) => a.doc.name.localeCompare(b.doc.name));
  }

  get(itemId: string): VaultItem | undefined {
    return this.openedItem(itemId);
  }

  /**
   * THE guarded read of the working set: the opened items of the vaults whose key works now ({@link Account.keyWorks}).
   * Every screen and every gesture reads its items through this or {@link openedItem}; the functions that read the set
   * directly are a closed list, each with its reason (store.write-gate.test.ts).
   */
  private openedItems(): VaultItem[] {
    const works = new Map<string, boolean>();
    const shown = (vaultId: string): boolean => {
      let w = works.get(vaultId);
      if (w === undefined) works.set(vaultId, (w = this.account.keyWorks(vaultId)));
      return w;
    };
    return [...this.itemsById.values()].filter((it) => shown(it.vaultId));
  }

  /** One item through the guarded read ({@link openedItems}): undefined where it is not here or its vault's key does not work. */
  private openedItem(itemId: string): VaultItem | undefined {
    const it = this.itemsById.get(itemId);
    return it === undefined || !this.account.keyWorks(it.vaultId) ? undefined : it;
  }

  /**
   * Whether a change of an item of [vaultId] may leave this browser now: asked by the one sender of item changes, by an
   * attachment's upload, before every other request that changes the vault's items on the server ("Delete forever", a
   * restore, a rename), by the queue's drain, and in each gesture before anything is uploaded or queued. Two things
   * must hold:
   * - the vault's key is held and works ({@link Account.mayWrite}): a shared vault's key that no longer works (another
   *   tab, a chase of an item's head or a read outside a pull moved its log) sends nothing until the removal's rule has
   *   run;
   * - for a shared vault, its log's standing here lets anyone write: verified. A vault frozen here, withheld (served
   *   below what this browser verified or the account recorded) or whose log did not verify can be read and copied out
   *   of, and no item of it is written or deleted (decided on 23 November 2026); a withheld one takes writes again once
   *   its log has been read through. The account's own role is the seal's question (Account.canSealUnder), as before.
   * The vault's own log actions (a leave among them) are asked {@link Account.mayWrite} alone, and the log store
   * refuses them on its own standing with its own words.
   */
  mayWrite(vaultId: string): boolean {
    if (!this.account.mayWrite(vaultId)) return false;
    const logs = this.shared?.logs;
    if (logs === undefined || vaultId === this.account.personalVaultId || !this.account.isLogGoverned(vaultId)) return true;
    return logs.status(vaultId).kind === "verified";
  }

  /** The refusal a save gets ({@link VaultKeyNotVerifiedError}) for a change of a vault that may not be written now ({@link mayWrite}). */
  private refuseUnlessMayWrite(vaultId: string | null | undefined): void {
    if (vaultId !== null && vaultId !== undefined && !this.mayWrite(vaultId)) throw new VaultKeyNotVerifiedError(vaultId);
  }

  /**
   * The same refusal where an item of [vaultId] is only read (a file's download, a copy out of the vault, the start of
   * moving everything out of it): only the key is asked ({@link Account.mayWrite}), so a vault that may be read but not
   * written still gives up its items.
   */
  private refuseUnlessKeyWorks(vaultId: string): void {
    if (!this.account.mayWrite(vaultId)) throw new VaultKeyNotVerifiedError(vaultId);
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
   * The vaults whose items a screen shows now: every vault {@link vaults} lists, and the account's own personal vault
   * ({@link Account.personalVaultId}, which only the opened account sets) where its key is held, also when the server
   * serves no row for it. Which vault is the person's own never comes from a served row: a shared vault the server
   * serves no row for, or labels "personal", gets nothing from this.
   */
  shownVaultIds(): string[] {
    const ids = this.vaults().map((v) => v.vaultId);
    const own = this.account.personalVaultId;
    if (own && !ids.includes(own) && this.account.hasVault(own) && this.account.keyWorks(own)) ids.push(own);
    return ids;
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
      if (!this.account.keyWorks(v.vaultId)) continue; // a key whose `add` the verified log no longer names: not listed
      const name = this.account.decryptVaultName(v.vaultId, v.metaBlob);
      const personal = v.vaultId === this.account.personalVaultId;
      out.push({
        vaultId: v.vaultId,
        type: personal ? "personal" : "shared",
        name: name && name !== "(vault)" ? name : personal ? "Personal" : "Shared",
        role: this.account.roleFor(v.vaultId),
        createdAt: v.createdAt,
      });
    }
    // Two vaults of one name sit side by side, the older first.
    return out.sort((a, b) =>
      a.type === b.type ? a.name.localeCompare(b.name) || (a.createdAt ?? 0) - (b.createdAt ?? 0) : a.type === "personal" ? -1 : 1,
    );
  }

  private syncInFlight: Promise<void> | null = null;

  private lastQuota: QuotaUse | null = null;

  /** The account's own meters from the newest sync answer (spec 03 §14.4), or null when it gave none that reads. */
  quota(): QuotaUse | null {
    return this.lastQuota;
  }

  /**
   * One signed log action (design §3.7). Returns when the entry was appended or is held in the pending-append record
   * (re-posted byte for byte later); throws {@link LogActionError} for every other outcome, never swallowing one.
   */
  private async logAction(vaultId: string | null, action: LogAction, opts: AppendOpts = {}): Promise<Extract<AppendOutcome, { kind: "appended" } | { kind: "pending" }>> {
    this.assertWritable();
    // Design §3.13 as decided on 2026-11-17: while a move's deletion of [vaultId] waits, nothing else is signed on its
    // log; only the move itself re-posts that deletion, through the log's own held-frame call.
    if (opts.forMove !== true || action.kind !== "delete") this.refuseIfMoveWaiting(vaultId);
    const out = await this.shared!.logs.append(vaultId, action, opts);
    // Only a change of the vault's members, outside a move: the move reads and re-posts what it holds by its own steps.
    if (out.kind === "pending" && out.known === "unknown" && opts.forMove !== true && (action.kind === "add" || action.kind === "remove" || action.kind === "role")) {
      // "Cannot tell" sends the person to the vault's members: they are read from the server first (nothing is posted).
      // The change may turn out made, or its place taken; otherwise the line says whether that read could be made.
      const look = await this.shared!.logs.readAfterUnknown(out.vaultId);
      if (look.outcome !== null && look.outcome.kind === "appended") return look.outcome;
      // The read found the server contradicting its own word: the vault froze, and the change went with it.
      if (look.outcome?.kind === "read_only") throw new LogActionError(look.outcome);
      if (look.outcome === null && !this.shared!.logs.holds(out.vaultId)) throw new LogActionError({ kind: "head_moved", vaultId: out.vaultId });
      return look.read ? out : { ...out, listRead: false };
    }
    if (out.kind === "appended" || out.kind === "pending") return out;
    throw new LogActionError(out);
  }

  /**
   * One signed log action that counts as done only when the server stored it. An answer that never came (the frame is
   * held for re-posting) throws {@link ChangeNotStoredError}: every action a screen shows as made goes through here, so
   * none is shown as made on a held frame.
   */
  private async storedLogAction(vaultId: string | null, action: LogAction, opts: AppendOpts = {}): Promise<Extract<AppendOutcome, { kind: "appended" }>> {
    const out = await this.logAction(vaultId, action, opts);
    if (out.kind === "pending") throw new ChangeNotStoredError(out.vaultId, action.kind, out.known, out.listRead !== false);
    return out;
  }

  /** A leave or delete this browser made: the reconcile pull drops the vault without a banner. */
  private async dropAfterOwnLogAction(vaultId: string): Promise<void> {
    this.suppressDrop.add(vaultId);
    try {
      await this.reconcileAfterLogAction();
    } finally {
      this.suppressDrop.delete(vaultId);
    }
  }

  /** The pull after a log action; a failed pull leaves the change committed (a later sync trues up). */
  private async reconcileAfterLogAction(): Promise<void> {
    try {
      await this.sync();
    } catch (e) {
      console.warn("log action committed; reconcile pull failed — a later sync trues up", e);
    }
  }

  /** Changes a member's role in a log-governed vault (owner only, by the verified log). */
  async setMemberRole(vaultId: string, userId: string, role: "writer" | "reader"): Promise<void> {
    if (!this.logGoverns(vaultId)) throw new LogActionError({ kind: "not_allowed", reason: "not_log_governed" });
    await this.storedLogAction(vaultId, { kind: "role", member: userId, role });
    await this.reconcileAfterLogAction();
  }

  /**
   * Puts the shared vaults on the signed vault logs (design §3.6, §3.9, §3.11). From then on a pull hands every
   * shared grant row, vault row and removal to [shared]; the account's key ring for those vaults is the log
   * store's, and their roles are the verified log's. Called once, before the first pull.
   */
  attachSharedLogs(shared: SharedLogSession): void {
    this.shared = shared;
    // The question to join a vault again says how many changes made before its removal wait here: the ones its held
    // copy keeps, which a yes sends again (the reinstate re-queues them).
    shared.attachWaitingCount((vaultId) => this.holding.get(vaultId)?.parked.length ?? 0);
    this.account.attachLogRoles(
      (vaultId) => shared.logs.roleOf(vaultId),
      // A vault whose move's deletion waits is read-only here (design §3.13 as decided on 2026-11-17): nothing is sealed
      // under its key, so no item is written into it by any road.
      (vaultId) => shared.logs.writeAllowed(vaultId) && !shared.logs.holdsMoveDelete(vaultId),
    );
    this.account.attachLogHeads((vaultId) => {
      const st = shared.logs.status(vaultId);
      return st.kind === "verified" ? { seq: st.state.head.seq, hash: st.state.head.hash } : null;
    });
    // The backstop at the point of use: a key works only while the log names the account through the `add` it was
    // adopted under (Account.keyWorks); asked of the log as stored now, which every tab of the profile writes.
    this.account.attachLogMember((vaultId) => this.memberAddNow(vaultId));
    // The one place of the log's appends asks the same question as every other change (Account.mayWrite).
    shared.logs.attachWriteGate((vaultId) => this.account.mayWrite(vaultId));
  }

  /**
   * The `add` through which [vaultId]'s log, as this browser holds it verified now, names this account; null where it
   * does not name it: nothing verified, removed (or its own leave), purged, or deleted. A log frozen, withheld or failed
   * here answers from its last verified state, as its vault is shown from it.
   */
  private memberAddNow(vaultId: string): number | null | undefined {
    const st = this.shared?.logs.status(vaultId);
    if (st === undefined || st.kind === "unknown" || st.kind === "removed" || st.kind === "purged" || st.state === null || st.state.deleteId !== null) return null;
    const m = st.state.members[this.account.userId];
    // The creator never added is named through the genesis (0), as the log store numbers its key (memberAddOf).
    if (m === undefined) return null;
    return m.addSeq === undefined ? undefined : (m.addSeq ?? 0);
  }

  /**
   * The names of the vaults listed, and of every other vault whose key this session holds, for the notices about the
   * person's own changes: a vault that is no longer listed because a read of its log just moved on (its own deletion
   * found stored, a removal not carried out yet) is still named in what is said about it.
   */
  private heldNames(): Map<string, string> {
    const names = new Map(this.vaults().map((v) => [v.vaultId, v.name] as const));
    for (const vaultId of this.vaultsById.keys()) {
      const n = names.has(vaultId) ? undefined : this.nameWhileKeyHeld(vaultId);
      if (n !== undefined && n !== "(vault)") names.set(vaultId, n);
    }
    return names;
  }

  /** [vaultId]'s name under the key this session holds for it, or undefined. */
  private nameWhileKeyHeld(vaultId: string): string | undefined {
    const row = this.vaultsById.get(vaultId);
    return row === undefined || !this.account.hasVault(vaultId) ? undefined : this.account.decryptVaultName(vaultId, row.metaBlob);
  }

  /**
   * The record the removal's rule asks for [vaultId]: the `add` beside its key in this session's ring where a key is
   * held, else the record kept with the offline copy. Undefined where this browser never adopted the vault.
   */
  private recordFor(vaultId: string): { readonly addSeq: number; readonly carried: boolean } | undefined {
    const inRing = this.account.logKeyRing().addOf(vaultId);
    if (inRing !== undefined && !Number.isNaN(inRing)) return { addSeq: inRing, carried: false };
    return this.logRecords.get(vaultId);
  }

  /** Inside a pull: [vaultId]'s record changed in memory and in the pull's commit (null: removed with the last of the vault's rows). */
  private putLogRecord(vaultId: string, rec: { readonly addSeq: number; readonly carried: boolean } | null): void {
    if (!this.logGoverns(vaultId)) return;
    const cur = this.logRecords.get(vaultId);
    if (rec === null) {
      // Recorded whether or not memory still held one: rows dropped outside a pull keep their record on disk with them,
      // and the pull that drops them on disk drops the record in the same commit.
      this.logRecords.delete(vaultId);
      this.recordPullOp((b) => b.removeLogRecord(vaultId));
      return;
    }
    if (cur !== undefined && cur.addSeq === rec.addSeq && cur.carried === rec.carried) return;
    this.logRecords.set(vaultId, rec);
    this.recordPullOp((b) => b.setLogRecord({ vaultId, addSeq: rec.addSeq, carried: rec.carried }));
  }

  /**
   * Design §3.9 (FS-R4): the log heads the items of one pull carried are hints to fetch, never verdicts. For each
   * log-governed vault the three highest distinct heads go to the log store, which fetches only for one that mentions
   * more than it verified, and backs off after a chase that brought nothing. Never throws.
   */
  private async chaseItemHeads(items: readonly WireItem[]): Promise<void> {
    await this.chaseHeads(
      this.itemHeadsOf(items, (w) => {
        const it = this.itemsById.get(w.itemId);
        return it === undefined || it.vaultId !== w.vaultId || it.rev !== w.rev ? undefined : it.doc;
      }),
    );
  }

  /** The distinct log heads [items] name, by log-governed vault; [docOf]: the item's opened document, where it is open. */
  private itemHeadsOf(items: readonly WireItem[], docOf: (w: WireItem) => ItemDoc | undefined): Map<string, Map<number, string>> {
    const byVault = new Map<string, Map<number, string>>();
    for (const w of items) {
      if (w.deleted || !this.logGoverns(w.vaultId)) continue;
      const doc = docOf(w);
      if (doc === undefined) continue;
      const h = itemLogHead(doc);
      if (h === null) continue;
      const heads = byVault.get(w.vaultId) ?? new Map<number, string>();
      if (!heads.has(h.seq)) heads.set(h.seq, h.hash);
      byVault.set(w.vaultId, heads);
    }
    return byVault;
  }

  /** Each vault's three highest distinct heads of [byVault] to the log store, which fetches only for one that mentions more. Never throws. */
  private async chaseHeads(byVault: ReadonlyMap<string, ReadonlyMap<number, string>>): Promise<void> {
    const shared = this.shared;
    if (shared === null) return;
    for (const [vaultId, heads] of byVault) {
      for (const [seq, hash] of [...heads.entries()].sort((a, b) => b[0] - a[0]).slice(0, 3)) {
        try {
          await shared.logs.noteItemHead(vaultId, seq, hash);
        } catch {
          /* the log keeps its last verified state */
        }
      }
    }
  }

  /** The shared-vault layer of this session, or null on a session without one. */
  sharedLogs(): SharedLogSession | null {
    return this.shared;
  }

  /** Whether a vault is a shared vault this session decides on through its log (not the personal vault). */
  private logGoverns(vaultId: string): boolean {
    return this.shared !== null && vaultId !== this.account.personalVaultId;
  }

  /**
   * One removal a pull listed for a log-governed vault. The served reason is a hint: the log is fetched afresh and
   * the outcome read from the verified state alone. A log that still lists this account keeps the vault: true then.
   * [unfinished]: a removal that stands although this browser did not carry it out (see logDecides), also where the log
   * now names the account again; [byOwner] says whose it was. It is carried out whatever the log now says of the
   * account, unless the log shows the vault deleted.
   */
  private async handleLogRemoval(
    vaultId: string,
    info: RemovedGrantInfo | undefined,
    cachedName: string | undefined,
    since: number,
    resyncing: boolean,
    unfinished?: { readonly byOwner: boolean },
  ): Promise<boolean> {
    const shared = this.shared!;
    const suppressed = this.suppressDrop.delete(vaultId);
    // A vault this session holds unopened, whose removal is known here: while the mark of this account's own leave
    // stood, a frozen vault was not listed again, so a tab opened since holds it unopened; a vault whose verified log no
    // longer names the account is not opened again (a page closed after the removal was read, before its copy was
    // written); and the account's record may no longer let the key be adopted (another device of the account read the
    // removal first). Its key is opened now through this account's own wrap, before the removal forgets the grant row,
    // but it is NOT put in the key ring: it is only used below, after the removal is confirmed, to seal the held copy, and
    // leaves the ring again before anything else runs.
    const before = shared.logs.status(vaultId);
    const holdable = unfinished !== undefined || (before.kind === "frozen" && shared.logs.ownFrozenLeaveTaken(vaultId)) || logNoLongerNames(before);
    const sealKey = cachedName === undefined && since > 0 && !resyncing && !this.account.hasVault(vaultId) && this.vaultsById.has(vaultId) && holdable ? await shared.keyForHolding(vaultId) : null;
    try {
      return await this.carryOutLogRemoval(vaultId, info, cachedName, since, resyncing, unfinished, suppressed, sealKey);
    } finally {
      // The key taken to seal the held copy leaves the ring whatever happened, also when the seal threw, and its bytes
      // are wiped; a working key of the vault (none was held when this key was taken) is never touched here.
      if (sealKey !== null) {
        if (this.account.logKeyRing().get(vaultId) === sealKey) this.account.logKeyRing().delete(vaultId);
        sealKey.fill(0);
      }
    }
  }

  /** An item held sealed under a key this session did not hold, opened with [vk] only to go into the held copy made next. */
  private openForHeldCopy(w: WireItem, vk: Uint8Array): void {
    try {
      const doc = this.account.decryptHeldItem(w, vk);
      this.missingVkById.delete(w.itemId);
      this.missingVkWire.delete(w.itemId);
      this.itemsById.set(w.itemId, { itemId: w.itemId, vaultId: w.vaultId, rev: w.rev, updatedAt: w.updatedAt, formatVersion: w.formatVersion, doc });
    } catch {
      /* it stays sealed as it was held; the held copy is made without it, as an item that cannot be read is */
    }
  }

  /** {@link handleLogRemoval} once the key to seal its held copy, if one was needed, is taken ([sealKey]). */
  private async carryOutLogRemoval(
    vaultId: string,
    info: RemovedGrantInfo | undefined,
    cachedName: string | undefined,
    since: number,
    resyncing: boolean,
    unfinished: { readonly byOwner: boolean } | undefined,
    suppressed: boolean,
    sealKey: Uint8Array | null,
  ): Promise<boolean> {
    const shared = this.shared!;
    const st = await shared.onRemoved(vaultId);
    // Nothing is awaited from here to the end of this removal, so no other code runs while a key taken to seal the held
    // copy is in the ring: it lists no vault, opens no item for show and allows no write.
    // A frozen vault's log cannot show which removal this is, so it is never quiet, also after the person's own leave
    // (decided on 2026-11-21): the notice and the held copy stay. Where this account's own leave of it was answered by
    // the server naming it, the notice says that the person left it here and that nothing since can be checked. The
    // mark is used up by this removal, whatever it turns out to be.
    const ownFrozenLeave = st.kind === "frozen" && shared.logs.ownFrozenLeaveTaken(vaultId);
    shared.logs.forgetOwnFrozenLeave(vaultId);
    if (st.kind === "verified" && st.state.deleteId === null && unfinished === undefined) {
      sealKey?.fill(0);
      return true;
    }
    if (sealKey !== null && this.account.hasVault(vaultId)) sealKey.fill(0);
    else if (sealKey !== null) {
      // In the ring with no `add` of the log beside it (NaN equals none), so even inside this synchronous stretch it
      // works for nothing (Account.keyWorks): it is there only for the held copy's re-seal. The items it was missing for
      // are opened with it directly, as a held copy's are.
      this.account.logKeyRing().set(vaultId, sealKey, Number.NaN);
      for (const w of [...this.missingVkWire.values()]) if (w.vaultId === vaultId && this.missingVkById.has(w.itemId)) this.openForHeldCopy(w, sealKey);
      const row = this.vaultsById.get(vaultId);
      try {
        cachedName = row === undefined ? undefined : this.account.decryptVaultName(vaultId, row.metaBlob);
      } catch {
        cachedName = undefined;
      }
    }
    const selfInitiated = suppressed;
    const dropKey = (): void => this.account.logKeyRing().delete(vaultId);
    // The person removed this browser's held copy of this vault since it was last listed (in another tab, which learned
    // this same removal first and told it): no copy is written again and nothing is told again.
    if (!this.holding.has(vaultId) && this.dropWithoutHeldCopy(vaultId, "held-copy-removed-by-person")) {
      dropKey();
      return false;
    }
    // A verified deletion: the log's `delete` in force (in its grace), or its purge verified through the tombstone.
    const deletedState = st.kind === "purged" || (st.kind === "verified" && st.state.deleteId !== null) ? st.state : null;
    const deletion = deletedState !== null;
    // Only the owner signs a `delete` (§3.11): a verified deletion of a vault this account owns is this account's own,
    // also one held for re-posting whose answer never came and that the server applied later. It is never shown to
    // the person as "deleted by its owner", and it is restored from Recently deleted.
    const ownDelete = deletedState !== null && (deletedState.owner ?? shared.logs.verifiedState(vaultId)?.owner) === this.account.userId;
    // Design §3.8: a purge verified for a vault whose copy is already held (its delete was verified in its grace) keeps
    // the copy 30 days from this verification, never fewer than it had.
    const held = this.holding.get(vaultId);
    if (held !== undefined && st.kind === "purged") {
      const record: HeldVault = { ...held, expungeAt: Math.max(held.expungeAt, Date.now() + HOLDING_MS) };
      this.holding.set(vaultId, record);
      this.recordPullOp((b) => b.putHeld(record));
    }
    // A leave this browser made drops the vault at once. A deletion does not, whoever signed it: design §3.8 (T2-R-h)
    // has no exception for the owner, who is the one whose later restore a server could withhold.
    if (selfInitiated && !deletion) {
      this.dropWithoutHeldCopy(vaultId, "own-leave");
      dropKey();
      return false;
    }
    if (cachedName === undefined || since === 0 || resyncing) {
      // No name to hold a copy under. Only a vault nothing of which was opened here leaves without one; anything else
      // stays as it is held, unopened, until a later answer lets the removal be carried out with its held copy. A log
      // never verified here decides nothing and drops nothing either.
      if (st.kind !== "unknown" && st.state !== null && this.dropWithoutHeldCopy(vaultId, "nothing-opened")) {
        dropKey();
        return false;
      }
      return true;
    }
    const base = { id: crypto.randomUUID(), vaultId, vaultName: cachedName };
    // §3.8, §3.12: items can still be copied out of the holding area, so the held copy keeps this account's own wrap
    // of the key, taken before the key leaves the ring.
    const wrap = shared.logs.wrapForHolding(vaultId) ?? undefined;
    if (deletion && (ownDelete || selfInitiated)) {
      // This account's own deletion: into the holding area, 30 days from this verification, without the notice a
      // deletion by someone else gets. A move's delete stored outside the move's own run is never quiet (design §3.13).
      const late = this.moveStoredOutside(vaultId);
      this.moveToHolding(vaultId, "deleted", info, true, cachedName, wrap, true);
      dropKey();
      if (late !== null) this.pushNotice({ ...base, kind: "move-stored", ...late });
      return false;
    }
    // The verified log shows the owner's `remove` (or this account's `leave`): an attributed removal (§3.12). So does a
    // removal this browser verified earlier and did not carry out, whatever the log shows of the account since.
    const removal = st.kind === "removed" ? { byOwner: st.byOwner } : deletion ? null : (unfinished ?? null);
    if (removal !== null) {
      this.moveToHolding(vaultId, removal.byOwner ? "removed" : "left", undefined, true, cachedName, wrap);
      dropKey();
      this.pushNotice({ ...base, kind: removal.byOwner ? "removed" : "left" });
      return false;
    }
    if (st.kind === "purged" || st.kind === "verified") {
      // A verified `delete` (§3.11): the served purge time is only shown, the log answer's grace end first (spec 03 §10.6).
      const parked = this.moveToHolding(vaultId, "deleted", info, true, cachedName, wrap);
      dropKey();
      this.pushNotice({ ...base, kind: "deleted", purgeAt: shared.logs.serverGraceEnd(vaultId)?.purgeAt ?? info?.purgeAt ?? undefined, keptUntil: this.holding.get(vaultId)?.expungeAt, parkedCount: parked || undefined });
      return false;
    }
    // failed, withheld, frozen or unknown: the log does not explain the removal. Writes stopped already.
    this.moveToHolding(vaultId, "removed", undefined, false, cachedName, wrap);
    dropKey();
    this.pushNotice({ ...base, kind: ownFrozenLeave ? "left-frozen" : "anomaly" });
    return false;
  }

  /**
   * Before a 410 resync replaces the working set: every item this browser holds, opened or sealed under a key it does
   * not hold yet, except one with a change of this browser waiting to be sent (the server has not had it yet, so a list
   * cannot leave it out).
   */
  private itemsHeldBeforeResync(): Map<string, { readonly vaultId: string; readonly item?: VaultItem; readonly wire?: WireItem }> {
    const out = new Map<string, { readonly vaultId: string; readonly item?: VaultItem; readonly wire?: WireItem }>();
    for (const it of this.itemsById.values()) if (!this.pendingSyncItemIds.has(it.itemId)) out.set(it.itemId, { vaultId: it.vaultId, item: it });
    for (const it of this.missingVkById.values()) {
      const w = this.missingVkWire.get(it.itemId);
      if (w !== undefined && !this.pendingSyncItemIds.has(it.itemId)) out.set(it.itemId, { vaultId: it.vaultId, wire: w });
    }
    return out;
  }

  /**
   * After a full list applied (a 410 resync), the other half of the removal's promise: nothing this browser held
   * vanishes without a trace where it cannot tell why. Each item held before the list ([before]) of the personal vault,
   * or of a shared vault still listed (frozen or not; not [gone], whose items the removal's road keeps), that the list
   * neither carried nor marked as deleted ([served]) and that is not in the working set again, is set aside: sealed as a
   * held copy is, for 30 days, with one notice per vault. An item the list marks as deleted is dropped, as on the
   * ordinary road. [names]: the vaults' names as this browser read them before the list.
   */
  private setAsideLeftOut(
    before: ReadonlyMap<string, { readonly vaultId: string; readonly item?: VaultItem; readonly wire?: WireItem }>,
    served: ReadonlySet<string>,
    gone: ReadonlySet<string>,
    names: ReadonlyMap<string, string>,
  ): void {
    const personal = this.account.personalVaultId;
    const byVault = new Map<string, WireItem[]>();
    for (const [itemId, h] of before) {
      if (served.has(itemId) || this.itemsById.has(itemId) || this.missingVkById.has(itemId)) continue;
      const vaultId = h.vaultId;
      if (vaultId !== personal && (!this.logGoverns(vaultId) || gone.has(vaultId))) continue;
      let wire: WireItem;
      if (h.wire !== undefined) {
        wire = h.wire;
      } else {
        const it = h.item!;
        try {
          const upload = this.account.resealForHolding(vaultId, itemId, it.doc); // local, never pushed
          wire = { itemId, vaultId, rev: it.rev, createdAt: 0, updatedAt: it.updatedAt, deleted: false, conflict: false, formatVersion: upload.formatVersion, attachmentIds: it.doc.attachments?.map((a) => a.id) ?? [], blob: upload.blob };
        } catch (e) {
          console.warn(`an item the full list left out was not set aside: its vault's key is gone (${itemId})`, e);
          continue;
        }
      }
      const list = byVault.get(vaultId) ?? [];
      list.push(wire);
      byVault.set(vaultId, list);
    }
    for (const [vaultId, items] of byVault) {
      const prev = this.setAside.get(vaultId);
      // A copy set aside is never replaced (decided on 2026-11-21): an item left out again with other content than a
      // copy kept of it is kept BESIDE that copy (the record holds more than one copy of an id; copying out gives each
      // its own new item), so what the person was told of the kept copy stays true. One with the same content as a copy
      // kept is that copy, kept once.
      const kept = [...(prev?.items ?? [])];
      const added: WireItem[] = [];
      for (const w of items) {
        if (kept.some((k) => k.itemId === w.itemId && this.setAsideVerdict(k, w) === "back")) continue;
        kept.push(w);
        added.push(w);
      }
      if (added.length === 0) continue;
      const expungeAt = Math.max(Date.now() + HOLDING_MS, prev?.expungeAt ?? 0);
      // A shared vault's items can be copied out after the vault is gone too: the record keeps this account's own wrap.
      const ownWrap = (this.logGoverns(vaultId) ? this.shared!.logs.wrapForHolding(vaultId) : null) ?? prev?.ownWrap;
      const name = names.get(vaultId);
      const record: HeldVault = {
        vault: this.vaultsById.get(vaultId) ?? prev?.vault ?? { vaultId, type: vaultId === personal ? "personal" : "shared", rev: 0, metaBlob: "", createdAt: 0 },
        grant: null,
        items: kept,
        reason: "removed",
        verified: false,
        cachedName: name !== undefined && name !== "(vault)" ? name : (prev?.cachedName ?? ""),
        parked: [],
        expungeAt,
        ...(ownWrap !== undefined ? { ownWrap } : {}),
        // What the person was told once stays told: the items already said to have come back with other content.
        ...(prev?.otherContentTold !== undefined ? { otherContentTold: prev.otherContentTold } : {}),
        setAside: true,
      };
      this.setAside.set(vaultId, record);
      this.recordPullOp((b) => b.putHeld(record));
      const frozen = this.logGoverns(vaultId) && this.shared!.logs.status(vaultId).kind === "frozen";
      this.pushNotice({
        id: crypto.randomUUID(),
        vaultId,
        vaultName: record.cachedName,
        kind: "items-set-aside",
        parkedCount: added.length,
        keptUntil: expungeAt,
        ...(vaultId === personal ? { personal: true as const } : {}),
        ...(frozen ? { frozen: true as const } : {}),
      });
    }
  }

  /**
   * Whether an item set aside is back in its vault: the ONE answer to that question, asked by a pull and by a reload
   * alike. [kept]: the copy set aside here; [served]: a row of the same id, as an answer serves it (or, at a reload, as
   * the offline copy holds it).
   *  - "back": the row is in the item's own vault and opens to the same content as the copy kept (or is the very sealed
   *    row kept): the item is in its vault again and leaves the set, so it is never there twice;
   *  - "other": the row is in its own vault and opens, to other content than the copy kept, which opens too: the copy
   *    stays set aside, and the person is told once;
   *  - "not": anything else (a marker that it is deleted, a row under another vault, a row that cannot be read, or a copy
   *    kept that cannot be opened any more): nothing is known of its content, and the copy stays set aside.
   */
  private setAsideVerdict(kept: WireItem, served: WireItem): "back" | "other" | "not" {
    if (served.deleted || served.itemId !== kept.itemId || served.vaultId !== kept.vaultId) return "not";
    if (served.blob === kept.blob && served.formatVersion === kept.formatVersion) return "back";
    let keptDoc: unknown;
    let servedDoc: unknown;
    try {
      keptDoc = this.account.decryptItem(kept);
      servedDoc = this.account.decryptItem(served);
    } catch {
      return "not";
    }
    return canonicalJson(keptDoc) === canonicalJson(servedDoc) ? "back" : "other";
  }

  /**
   * The items set aside of one record checked against [rowOf] (the row of an id served now, or none), by
   * {@link setAsideVerdict}: the record without the items that are back, and the ids newly found to have other content
   * (each is told once: the record's otherContentTold keeps them).
   */
  private settleSetAsideRecord(rec: HeldVault, rowOf: (itemId: string) => WireItem | undefined): { record: HeldVault; changed: boolean; newlyOther: string[] } {
    const toldBefore = rec.otherContentTold ?? [];
    const items: WireItem[] = [];
    const newlyOther: string[] = [];
    for (const w of rec.items) {
      const row = rowOf(w.itemId);
      const verdict = row === undefined ? "not" : this.setAsideVerdict(w, row);
      if (verdict === "back") continue;
      items.push(w);
      if (verdict === "other" && !toldBefore.includes(w.itemId)) newlyOther.push(w.itemId);
    }
    const kept = new Set(items.map((w) => w.itemId));
    const told = [...toldBefore.filter((id) => kept.has(id)), ...newlyOther];
    const { otherContentTold: _old, ...rest } = rec;
    const record: HeldVault = { ...rest, items, ...(told.length > 0 ? { otherContentTold: told } : {}) };
    return { record, changed: items.length !== rec.items.length || newlyOther.length > 0, newlyOther };
  }

  /** The notice that [count] items set aside of [vaultId] were sent again with other content than the copy kept here. */
  private tellSetAsideOther(vaultId: string, rec: HeldVault, count: number): void {
    const personal = vaultId === this.account.personalVaultId;
    let name = rec.cachedName;
    const row = this.vaultsById.get(vaultId);
    if (!personal && row !== undefined && this.account.hasVault(vaultId)) {
      try {
        name = this.account.decryptVaultName(vaultId, row.metaBlob);
      } catch {
        /* the name kept when they were set aside */
      }
    }
    this.pushNotice({ id: crypto.randomUUID(), vaultId, vaultName: name, kind: "items-set-aside-other", parkedCount: count, ...(personal ? { personal: true as const } : {}) });
  }

  /** Items set aside that a pull served again ([served]: rows applied in their own vault), each checked by {@link setAsideVerdict}. */
  private settleSetAsideServed(served: readonly WireItem[]): void {
    const byVault = new Map<string, Map<string, WireItem>>();
    for (const w of served) {
      if (!this.setAside.has(w.vaultId)) continue;
      const rows = byVault.get(w.vaultId) ?? new Map<string, WireItem>();
      rows.set(w.itemId, w);
      byVault.set(w.vaultId, rows);
    }
    for (const [vaultId, rows] of byVault) {
      const rec = this.setAside.get(vaultId)!;
      const { record, changed, newlyOther } = this.settleSetAsideRecord(rec, (id) => rows.get(id));
      if (!changed) continue;
      this.putSetAside(vaultId, record);
      if (newlyOther.length > 0) this.tellSetAsideOther(vaultId, record, newlyOther.length);
    }
  }

  /** Inside a pull: a set-aside record replaced (or, with no item left, removed), in memory and in the pull's commit. */
  private putSetAside(vaultId: string, record: HeldVault): void {
    if (record.items.length === 0) {
      this.setAside.delete(vaultId);
      this.recordPullOp((b) => b.removeHeld(heldRowKey(vaultId, true)));
      return;
    }
    this.setAside.set(vaultId, record);
    this.recordPullOp((b) => b.putHeld(record));
  }

  /** The shared vaults whose rows this browser holds in its working set (opened or not). */
  private heldSharedVaults(): Set<string> {
    return new Set([...this.vaultsById.keys()].filter((id) => this.logGoverns(id)));
  }

  /**
   * The verified log decides (decided on 2026-11-21). A shared vault's log of who is in it is signed by its members and
   * checked here; what the server serves beside it is not. This is the ONE place where a pull, a 410 resync and an
   * ordinary delta alike, reads that log before anything the answer serves is applied:
   *  - first each shared vault row the answer serves has its log brought up to the served head (a hint; the account
   *    state is read before, where the answer's counter moved), and so has the log of every shared vault this browser
   *    holds (in [held], or as a held copy) for which the answer serves anything else: a grant row (the key), an item,
   *    a marker that an item is deleted, or a removal;
   *  - [gone]: [notListed] (a resync's held vaults that its fresh list does not list), and every vault in [held] (what
   *    this browser held before the answer) whose verified log no longer names this account: removed (or its own
   *    leave), purged, or the vault deleted. Each takes the removal's road from what was held, whatever the answer
   *    serves for it: the held copy, then the notice; it is not listed as the person's any more;
   *  - [unfinished]: every vault in [held] whose removal is owed ({@link removalsOwed}): its verified log names this
   *    account through another `add` than the one this browser adopted it under, or not at all, by the record of the
   *    session's key or, without a key, the record kept with the offline copy. Never by the log as stored before this
   *    answer, which the refresh itself, another tab or a chase of an item's head moves on before the removal's effects
   *    land. [byOwner]: the removal was the owner's, not the person's own leave. Of these, [again] are the ones
   *    whose log now names the account again: their removal is carried out before anything of the answer is applied,
   *    and the answer then applies to them as to any vault whose copy is held (a re-added member is asked again). The
   *    others are in [gone];
   *  - [refused]: [gone], and every other shared vault this answer serves anything for whose verified log no longer
   *    names this account. Nothing the answer serves for a refused vault (grant row, vault row, item) is applied.
   * A log the server does not serve in full at this moment (frozen, withheld, failed) is decided against its last
   * verified state, which does not delay a removal that state already shows; a flag one answer set is read again at
   * every pull until a full read clears it ([readInFull]: the held copies whose log was read in full again here, so a
   * person their log names again is asked). A log never verified here decides nothing. Never throws for a log that
   * cannot be read.
   */
  private async logDecides(
    resp: SyncResponse,
    held: ReadonlySet<string>,
    notListed: ReadonlySet<string>,
  ): Promise<{ gone: Set<string>; refused: Set<string>; unfinished: Map<string, { readonly byOwner: boolean }>; again: Set<string>; readInFull: Set<string> }> {
    const gone = new Set(notListed);
    const unfinished = new Map<string, { readonly byOwner: boolean }>();
    const again = new Set<string>();
    const readInFull = new Set<string>();
    const shared = this.shared;
    if (shared === null) return { gone, refused: new Set(gone), unfinished, again, readInFull };
    // A flag one answer set does not outlive the next full read: every held vault and held copy whose log was withheld
    // or did not verify is read again at each pull, whatever this answer serves for it.
    const flaggedNow = (vaultId: string): boolean => {
      const k = shared.logs.status(vaultId).kind;
      return k === "withheld" || k === "failed";
    };
    for (const vaultId of new Set([...held, ...this.holding.keys()])) {
      if (!this.logGoverns(vaultId) || notListed.has(vaultId) || !flaggedNow(vaultId)) continue;
      await shared.refreshLog(vaultId, null);
      if (shared.logs.status(vaultId).kind === "verified") readInFull.add(vaultId);
    }
    // Spec 03 §4: the pull's counter of the account state; it is read only when the counter moved (or there is none).
    if (resp.vaults.some((v) => this.logGoverns(v.vaultId)) || resp.removedGrants.some((id) => this.logGoverns(id))) await shared.refreshState(resp.accountStateSeq ?? null);
    for (const v of resp.vaults) if (this.logGoverns(v.vaultId) && !notListed.has(v.vaultId)) await shared.refreshLog(v.vaultId, logHeadOf(v));
    const rowServed = new Set(resp.vaults.map((v) => v.vaultId));
    const servedFor = new Set([...resp.grants.map((g) => g.vaultId), ...resp.items.map((i) => i.vaultId), ...resp.removedGrants]);
    for (const vaultId of servedFor) {
      if (rowServed.has(vaultId) || notListed.has(vaultId) || !this.logGoverns(vaultId) || !(held.has(vaultId) || this.holding.has(vaultId))) continue;
      await shared.refreshLog(vaultId, null);
    }
    // The heads the served items name are hints the log is chased to, and they are chased HERE, before the rule, for the
    // vaults whose key works in this session: an item written after a removal and a re-add names a head beyond the one
    // its vault's row was served with, and what the answer serves is decided on that log, before any of it is applied.
    await this.chaseHeads(this.itemHeadsOf(resp.items.filter((i) => held.has(i.vaultId) && !notListed.has(i.vaultId)), (w) => this.peekItem(w)));
    const noLongerNamed = (vaultId: string): boolean => this.logGoverns(vaultId) && logNoLongerNames(shared.logs.status(vaultId));
    for (const [vaultId, owed] of this.removalsOwed(held)) {
      unfinished.set(vaultId, { byOwner: owed.byOwner });
      if (owed.namedAgain) again.add(vaultId);
      else gone.add(vaultId);
    }
    for (const vaultId of held) if (!unfinished.has(vaultId) && noLongerNamed(vaultId)) gone.add(vaultId);
    for (const vaultId of again) gone.delete(vaultId);
    const refused = new Set(gone);
    for (const vaultId of [...rowServed, ...servedFor]) {
      if (!refused.has(vaultId) && !again.has(vaultId) && noLongerNamed(vaultId)) refused.add(vaultId);
    }
    return { gone, refused, unfinished, again, readInFull };
  }

  /**
   * The rule (decided on 2026-11-21): for each shared vault in [held] that this browser adopted and has not carried a
   * removal of out, whether its verified log now names this account through another `add` than the record's (the
   * `add` beside the session's key, else the one kept with the offline copy), or does not name it. Such a removal is
   * owed: the held copy and the notice, and where the log names the account again ([namedAgain]) the question to join
   * again, before anything of the vault is shown or can be written. A log the server does not serve in full at this
   * moment is decided against its last verified state; a log never verified here decides nothing.
   */
  private removalsOwed(held: Iterable<string>): Map<string, { readonly byOwner: boolean; readonly namedAgain: boolean }> {
    const out = new Map<string, { readonly byOwner: boolean; readonly namedAgain: boolean }>();
    const shared = this.shared;
    if (shared === null) return out;
    for (const vaultId of held) {
      if (!this.logGoverns(vaultId)) continue;
      const rec = this.recordFor(vaultId);
      if (rec === undefined || rec.carried) continue;
      // Decided against the log's last VERIFIED state, whatever its flag says now (withheld, failed, frozen): the entries
      // a server holds back are newer than that state, so a removal it shows is owed now. Where nothing is verified,
      // nothing is decided.
      const st = shared.logs.status(vaultId);
      if (st.kind === "unknown" || st.state === null) continue;
      const now = this.memberAddNow(vaultId);
      if (now === rec.addSeq) continue;
      out.set(vaultId, { byOwner: st.kind === "removed" ? st.byOwner : shared.logs.lastRemovalByOwner(vaultId), namedAgain: typeof now === "number" });
    }
    return out;
  }

  /** A served row of a vault whose key works here, opened only to read the log head it names; undefined where it does not open. */
  private peekItem(w: WireItem): ItemDoc | undefined {
    if (w.deleted || !this.logGoverns(w.vaultId) || !this.account.hasVault(w.vaultId)) return undefined;
    try {
      return this.account.decryptItem(w);
    } catch {
      return undefined;
    }
  }

  /**
   * Before a 410 resync replaces the working set: what this browser holds of every shared vault (the vault row and its
   * items of every kind), so that a vault the fresh list no longer grants is handled from what was held here.
   */
  private takeSharedVaults(): Map<string, TakenVault> {
    const taken = new Map<string, TakenVault>();
    for (const [vaultId, vault] of this.vaultsById) {
      if (this.logGoverns(vaultId)) taken.set(vaultId, { vault, items: [], undecryptable: [], missing: [], missingWire: [] });
    }
    for (const it of this.itemsById.values()) taken.get(it.vaultId)?.items.push(it);
    for (const it of this.undecryptableById.values()) taken.get(it.vaultId)?.undecryptable.push(it);
    for (const it of this.missingVkById.values()) {
      const t = taken.get(it.vaultId);
      if (t === undefined) continue;
      t.missing.push(it);
      const w = this.missingVkWire.get(it.itemId);
      if (w !== undefined) t.missingWire.push(w);
    }
    return taken;
  }

  /**
   * A resync's removal whose road threw part-way: what is still held of the vault is not dropped. Where it is still in
   * the working set and its name is known it is held with the notice of a removal the browser cannot explain; where that
   * fails too, its rows stay on disk as they were. Where it cannot be held here (a held copy of it is already in memory,
   * or its row is no longer in the working set), its rows stay on disk as they were too: nothing of it is dropped.
   */
  private keepAfterFailedRemoval(vaultId: string, cachedName: string | undefined, keepOnDisk: Set<string>): void {
    if (this.holding.has(vaultId) || !this.vaultsById.has(vaultId)) {
      keepOnDisk.add(vaultId);
      return;
    }
    try {
      if (cachedName === undefined) throw new Error("no name");
      this.moveToHolding(vaultId, "removed", undefined, false, cachedName, this.shared?.logs.wrapForHolding(vaultId) ?? undefined);
      this.account.logKeyRing().delete(vaultId);
      this.pushNotice({ id: crypto.randomUUID(), vaultId, vaultName: cachedName, kind: "anomaly" });
    } catch {
      keepOnDisk.add(vaultId);
    }
  }

  /** A taken vault back in the working set exactly as it was held, for the removal that follows to handle it. */
  private putBackTaken(t: TakenVault): void {
    this.vaultsById.set(t.vault.vaultId, t.vault);
    for (const it of t.items) this.itemsById.set(it.itemId, it);
    for (const it of t.undecryptable) this.undecryptableById.set(it.itemId, it);
    for (const it of t.missing) this.missingVkById.set(it.itemId, it);
    for (const w of t.missingWire) this.missingVkWire.set(w.itemId, w);
  }

  /**
   * After a full list (the first pull after a sign-in, a reload with no offline copy, or a 410 resync): a shared vault
   * that this browser holds nothing of any more and cannot name, which this account's records here hold as frozen on
   * this browser, or as left by the person here, and which the fresh list no longer grants, is told in one notice
   * without its name. The mark of the person's own leave is used up by that notice. It is told again at each such pull
   * until the person dismisses it ({@link dismissNotice}) or the vault is granted again.
   */
  private tellUncheckedGone(granted: ReadonlySet<string>, handled: ReadonlySet<string>, removed: readonly string[]): void {
    const shared = this.shared;
    if (shared === null) return;
    const doc = shared.accountState.local();
    const ids = new Set([...doc.vaults.keys(), ...removed]);
    for (const vaultId of ids) {
      if (!this.logGoverns(vaultId) || granted.has(vaultId) || handled.has(vaultId) || this.holding.has(vaultId)) continue;
      if (doc.accepted.get(vaultId)?.decision === "decline") continue; // declined by the person: never theirs to lose
      if (shared.logs.status(vaultId).kind !== "frozen" && !shared.logs.ownFrozenLeaveTaken(vaultId)) continue;
      if (shared.logs.goneTold(vaultId)) continue;
      shared.logs.forgetOwnFrozenLeave(vaultId);
      this.pushNotice({ id: crypto.randomUUID(), vaultId, vaultName: "", kind: "unchecked-gone" });
    }
  }

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
    if (this.closed) return; // A locked or signed-out session syncs nothing
    if (this.readOnlyCopy) return; // §4.4: nothing is sent to a forked origin, and nothing from it is accepted
    await this.pinChecked();
    if (this.readOnlyCopy) return; // the refresh found a fork: nothing queued is sent
    await this.flushQueue();
    await this.pull();
    // H38 (audit 2026-09-13): a bell that rang DURING that pull joined it and got a snapshot
    // fetched before the bell's commit. If the bell's rev is still ahead of the cursor the
    // change is not here yet — pull once more (a fresh single-flight cycle, since the joined
    // one has settled). Bounded: one extra pull per sync; a bell landing during THIS pull is
    // caught by its own syncNow's comparison after it joins.
    if (this.bellRev > this.cursor) await this.pull();
    // A held change of the vault's log that a re-send before this pull left unsent, because the vault's key did not
    // work yet (nothing adopted at the unlock, or a removal's rule not run): the rule has run now, so it is re-sent once.
    if (this.shared?.logs.takeHeldByGate() === true) await this.resendHeldChanges().catch((e: unknown) => console.warn("a held change was not re-sent after the pull (re-sent at the next unlock)", e));
    // A change that waits for a vault whose log this pull moved is settled by a look at that log (nothing is sent): the
    // member panel no longer says "waiting" beside a member list that already shows it.
    for (const vaultId of this.shared?.logs.settleHeldFromLog() ?? []) {
      this.deleteAsks = this.deleteAsks.filter((v) => v !== vaultId);
      this.noticeList = this.noticeList.filter((n) => !(n.kind === "held-delete-ask" && n.vaultId === vaultId));
    }
    // The vault list is the server's now: a notice of a held change that did not happen names its vault.
    this.pulledOnce = true;
    this.surfaceSettled();
    this.surfaceDeleteAsks();
    // A change withdrawn or given up without knowing whether it was made: what the log says of it now.
    await this.surfaceWatched().catch((e: unknown) => console.warn("the changes this browser withdrew or gave up were not looked for (looked for again at the next sync)", e));
    await this.dropExpiredHeld();
    // The old account-state sync is gone. Ownership, offers and handovers are the verified logs' (design
    // §3.3), and the account state is the session's AccountStateStore (§5.4), read where the shared layer decides.
    try {
      await this.surfaceStagedDenials();
    } finally {
      // L2: even when surface re-throws a genuine denial, sweep C2 snapshots whose queue
      // row a SIBLING tab already settled (their results never reach this tab's maps).
      await this.prunePreEditSnapshots();
    }
    await this.discardDueHalfMade();
  }

  /**
   * Design §3.8, §3.12; core SyncEngine and ItemEngine: a held copy is kept until its date
   * (`expungeAt`, the "kept until" the screen shows) and no longer. At hydrate and after each sync, every held record
   * past its date goes, from memory and from IndexedDB: its re-sealed items, its parked changes, the retained grant and
   * the kept wrap of its key are all in the record. A failed removal from IndexedDB is tried again at the next sync.
   */
  private async dropExpiredHeld(now: number = Date.now()): Promise<void> {
    for (const [vaultId, h] of [...this.holding]) {
      if (h.expungeAt > now) continue;
      this.holding.delete(vaultId);
      for (const k of [...this.heldGestures.keys()]) if (k.startsWith(`${vaultId}|`)) this.heldGestures.delete(k);
      try {
        await this.cache.removeHeld(vaultId);
        this.forgetLateMove(vaultId);
      } catch {
        this.holding.set(vaultId, h); // still on disk: kept in view until the removal goes through
      }
    }
    for (const [vaultId, h] of [...this.setAside]) {
      if (h.expungeAt > now) continue;
      try {
        await this.cache.removeHeld(heldRowKey(vaultId, true));
        if (this.setAside.get(vaultId) === h) this.setAside.delete(vaultId);
      } catch (e) {
        console.warn(`the items set aside from ${vaultId} were not removed from this device at their date (tried again at the next sync)`, e);
      }
    }
  }

  /** A held copy that went also takes the record of a move whose late items could have been copied from it. */
  private forgetLateMove(vaultId: string): void {
    const logs = this.shared?.logs;
    // A stopped run's record is not a late move's: it stays, so the next move finds its half-made vault.
    if (logs !== undefined && !logs.holdsMoveDelete(vaultId) && logs.moveRecord(vaultId)?.stopped !== true) logs.saveMoveRecord(vaultId, null);
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
      resp = await this.wire.sync(since);
    } catch (e) {
      if (e instanceof ApiError && e.status === 410) {
        // Fetch the replacement snapshot FIRST (core SyncEngine parity): the working
        // set is wiped only once the full response is in hand, so a failed or
        // rejected refetch never leaves an emptied store behind.
        resyncing = true;
        resp = await this.wire.sync(0);
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
    // Spec 03 §14.4: the account's own use and limits, the newest answer's (an answer without them is unknown, never
    // the value before it, as the shared code keeps it).
    this.lastQuota = (resp as { quota?: QuotaUse | null }).quota ?? null;

    // A 410 resync replaces the working set with the fresh list. Before anything is replaced, what this browser holds of
    // every shared vault is taken. A vault counts as still listed only where the answer carries BOTH this account's grant
    // row and the vault's own row (a grant row alone lists nothing: no vault, no item). Each taken vault the fresh list
    // does not list, or names as removed, takes the ordinary road of a removal learned at a sync (below), from what was
    // taken: never from anything the server serves of it now, which is not applied. That road is the only way out for
    // what this browser held of a shared vault here. The disk's clear, the fresh rows and the held copies land in ONE
    // commit, so a resync cut before it lands leaves the offline copy as it was, and the next start answers the same 410.
    // The queued changes of each shared vault, read before anything is decided: a removal this pull carries out parks
    // them with its held copy (moveToHolding), since none of them is sent once the vault's key is gone.
    this.unsentByVault = new Map();
    for (const m of await this.cache.pending()) {
      if (!this.logGoverns(m.vaultId)) continue;
      const rows = this.unsentByVault.get(m.vaultId) ?? [];
      rows.push(m);
      this.unsentByVault.set(m.vaultId, rows);
    }
    const taken = resyncing ? this.takeSharedVaults() : new Map<string, TakenVault>();
    const ownRows = new Set(resp.grants.filter((g) => g.userId === this.account.userId).map((g) => g.vaultId));
    const servedListed = new Set(resp.vaults.map((v) => v.vaultId).filter((id) => ownRows.has(id) && !resp.removedGrants.includes(id)));
    const goneAtResync = new Set([...taken.keys()].filter((id) => !servedListed.has(id)));
    // The verified log decides, on both roads and before anything this answer serves is applied (see logDecides):
    // [gone] takes the removal's road from what this browser held before the answer; nothing served for a vault in
    // [refused] (gone, or any other whose verified log no longer names the account) is applied below.
    const { gone, refused, unfinished, again, readInFull } = await this.logDecides(resp, resyncing ? new Set(taken.keys()) : this.heldSharedVaults(), goneAtResync);
    const listedNow = new Set([...servedListed].filter((id) => !refused.has(id)));
    // A vault listed again: a later loss of it is told again, and a held copy of it may be made again.
    if (this.shared !== null) for (const id of listedNow) if (this.logGoverns(id)) this.shared.logs.forgetLossTold(id);
    /** Vaults whose rows the full list's clear keeps on disk: a gone vault whose verified log still names this account. */
    const keepOnDisk = new Set<string>();

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
    this.heldNotedInPull.clear();
    // A1b: homes recorded outside a pull (hydrate of an upgraded cache, a save's first seal) land in this tx.
    for (const itemId of this.homesUnpersisted) {
      const vaultId = this.homes.get(itemId);
      if (vaultId) ops.push((b) => b.setItemHome(itemId, vaultId));
    }
    this.homesUnpersisted.clear();
    for (const vaultId of this.recordsUnpersisted) {
      const rec = this.logRecords.get(vaultId);
      if (rec !== undefined) ops.push((b) => b.setLogRecord({ vaultId, addSeq: rec.addSeq, carried: rec.carried }));
    }
    this.recordsUnpersisted.clear();

    // A removal that stands although this browser did not carry it out, of a vault whose log now names the account again
    // (see logDecides): the removal is carried out first, from what this browser holds, as it would have been at the
    // answer that brought it; this answer then applies to the vault as to any vault whose copy is held, so a re-added
    // member is asked again before anything of it is shown or can be written.
    for (const vaultId of again) {
      try {
        await this.handleLogRemoval(vaultId, resp.removedGrantsInfo?.find((i) => i.vaultId === vaultId), prePullNames.get(vaultId), since, false, unfinished.get(vaultId));      } catch (e) {
        console.warn(`the removal of ${vaultId} that this browser had not carried out was not handled in full (non-fatal; pull continues)`, e);
        this.keepAfterFailedRemoval(vaultId, prePullNames.get(vaultId), keepOnDisk);
      }
      taken.delete(vaultId);
    }

    // Every item this browser holds before a resync replaces the working set: one the fresh list neither carries nor
    // marks as deleted is set aside below, never dropped without a trace.
    const heldBeforeResync = resyncing ? this.itemsHeldBeforeResync() : null;
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
    if (resp.full) ops.push((b) => b.clear(keepOnDisk));

    // Only the personal vault's grant goes through addGrant (its UVK-wrapped key); a shared
    // vault's key and role are the verified log's (design §3.6).
    // A LIVE grant re-arriving for a vault in the holding area is a reinstate signal
    // (restore / re-add) — collected here, acted on after items apply.
    const reinstated = new Set<string>();
    const newlyAdded = new Set<string>(); // F20: grants for vaults not held before this pull
    for (const grant of resp.grants) {
      if (refused.has(grant.vaultId)) continue; // the log decided: never applied
      // §D.1: persist EVERY delivered grant row (wire/ciphertext — native parity), even one
      // this device can't open: it must survive restarts so hydrate re-attempts the open and
      // the F20 warning recomputes (§D.4) instead of the vault silently vanishing from disk.
      ops.push((b) => b.upsertGrant(grant));
      const heldBefore = this.account.hasVault(grant.vaultId); // BEFORE addGrant opens the key
      if (grant.vaultId !== this.account.personalVaultId) {
        // Design §3.6: a shared vault's key is adopted only through its verified log (below, with the vault rows); a
        // store with no log layer adopts none.
        if (this.shared !== null && grant.userId === this.account.userId) this.shared.noteGrantRow(grant.vaultId, { wrappedVk: grant.wrappedVk, signedGrant: grant.signedGrant ?? null, rev: grant.rev });
        if (!heldBefore && since > 0 && !resyncing && !this.holding.has(grant.vaultId)) newlyAdded.add(grant.vaultId);
        if (this.holding.has(grant.vaultId)) reinstated.add(grant.vaultId);
        continue;
      }
      try {
        this.account.addGrant(grant);
        this.grantWireByVault.set(grant.vaultId, grant); // retain the grant blob (§6, normative)
        this.undecryptableGrants.delete(grant.vaultId); // opened now → clear any stale F20 warning
        if (this.holding.has(grant.vaultId)) reinstated.add(grant.vaultId);
        else if (!heldBefore && since > 0 && !resyncing) newlyAdded.add(grant.vaultId); // a genuine add
      } catch {
        // F20: the row was refused (Account.addGrant applies only this account's own row for a personal key it
        // holds). Retain the id so the UI shows a PERSISTENT "can't open" warning until a later pull opens it.
        // Guarded on !heldBefore so a re-delivered row for a vault we ALREADY hold never fabricates one.
        if (!heldBefore) this.undecryptableGrants.add(grant.vaultId);
      }
    }
    if (this.shared !== null) {
      // Design §3.8: each shared vault row's log head is a hint to fetch (fetched already, in logDecides); §3.6 then
      // decides on the key. Runs before the vault rows and items apply, so a vault adopted now decrypts in this same pull.
      for (const v of resp.vaults) {
        if (!this.logGoverns(v.vaultId) || refused.has(v.vaultId)) continue;
        this.shared.noteVaultMeta(v.vaultId, v.metaBlob);
        await this.shared.onSharedVault(v.vaultId, logHeadOf(v), true);
      }
      // A share left undecided can change without a new vault row (its sender became current on this browser).
      const delivered = new Set(resp.vaults.map((v) => v.vaultId));
      for (const id of this.shared.undecided()) if (!delivered.has(id) && !resp.removedGrants.includes(id) && !refused.has(id)) await this.shared.onSharedVault(id, null);
      // A held copy whose log is read in full again only now (a removal carried out while the server held entries back):
      // a person that log names again is asked now, as an honest answer would have asked them.
      for (const id of readInFull) if (this.holding.has(id) && !this.account.hasVault(id) && !delivered.has(id) && !refused.has(id) && !this.shared.undecided().includes(id)) await this.shared.onSharedVault(id, null, true);
      // A vault whose key this answer adopted: the heads its served items name are chased NOW, before any of its items
      // is applied or listed (a server could serve the vault's row and log as they were at an older `add`). Where the
      // log then names the account through another `add`, the key adopted a moment ago works for nothing; nothing of
      // the vault was opened here since its last held copy (or ever), so the key goes, nothing is held or told, and the
      // adoption is decided again on the log as it is now (the person is asked where it names them again).
      const adoptedNow = [...new Set(resp.vaults.map((v) => v.vaultId))].filter((id) => this.logGoverns(id) && !refused.has(id) && !prePullNames.has(id) && this.account.hasVault(id));
      if (adoptedNow.length > 0) {
        await this.chaseHeads(this.itemHeadsOf(resp.items.filter((i) => adoptedNow.includes(i.vaultId)), (w) => this.peekItem(w)));
        for (const id of adoptedNow) {
          if (this.account.keyWorks(id) || !this.nothingOpenedSinceRecord(id)) continue;
          this.account.logKeyRing().delete(id);
          await this.shared.onSharedVault(id, null, true);
        }
      }
      // A key adopted after its vault's items arrived (an answered ask, a sender who became current): a delta never
      // re-sends those rows, so the retained ones apply now. A newer row in this pull still applies after them.
      for (const w of [...this.missingVkWire.values()]) if (this.missingVkById.has(w.itemId) && this.account.hasVault(w.vaultId) && !refused.has(w.vaultId)) this.applyWireItem(w);
    }
    for (const delivered of resp.vaults) {
      if (refused.has(delivered.vaultId)) continue; // the log decided: never applied
      // spec 02 §4 warn-and-keep-newer: a delivered metaBlob whose metaV regressed keeps
      // the newer local blob (rev/lifecycle fields still apply).
      const vault = this.keepNewerMeta(delivered);
      this.vaultsById.set(vault.vaultId, vault);
      ops.push((b) => b.upsertVault(vault)); // the merged keepNewerMeta row — disk mirrors memory
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
      // Security review 2026-10, branch A11 (q56): decided by KEY PROVENANCE, never the served row's `role` label
      // (the server chooses it, and "owner" used to make a verified adoption silent): quiet only when the key opened
      // from our own UVK wrap and did not arrive by a member grant (no signed grant, no seal).
      if (this.logGoverns(vaultId) ? this.shared!.logs.roleOf(vaultId) === "owner" : this.isOwnCreatedKey(vaultId)) continue;
      this.addedNoticed.add(vaultId);
      this.pushNotice({ id: crypto.randomUUID(), vaultId, vaultName: this.account.decryptVaultName(vaultId, v.metaBlob), kind: "added" });
    }

    const conflictsToMaterialize: WireItem[] = [];
    /** The items this answer carries in their own vault (a row refused for its vault carries nothing). */
    const carried = new Set<string>();
    /** What was opened of each shared vault before this answer's items apply: a held copy made later in this answer holds that, never what the answer brought. */
    const openedBefore = new Map([...this.itemsById].filter(([, it]) => this.logGoverns(it.vaultId)));
    for (const item of resp.items) {
      if (refused.has(item.vaultId)) continue; // the log decided: never applied
      // INV-HOME first (A1b): a row under another vault than this item's home is not applied at all (not even a
      // tombstone) and never reaches the cache, the working set, search, export or autofill.
      if (!this.admitHome(item)) continue;
      carried.add(item.itemId);
      // §D.1 disk twin first: tombstone ⇒ delete, else the WIRE row — persisted even when
      // the VK is missing or the decrypt fails (everything at rest is ciphertext; hydrate
      // re-runs the same tri-state below, retrying undecryptables — §D.4).
      if (item.deleted) ops.push((b) => b.deleteItem(item.itemId));
      else ops.push((b) => b.upsertItem(item));
      this.applyWireItem(item, conflictsToMaterialize);
    }
    await this.chaseItemHeads(resp.items.filter((i) => !refused.has(i.vaultId)));
    // The rule asked again after the chase, which can move a log on (heads first read only now, of a vault adopted in
    // this answer): a removal now owed is carried out before this answer is committed, and where the log names the
    // account again the question is asked. Until then the vault's key works for nothing (Account.keyWorks).
    for (const [vaultId, owed] of this.removalsOwed([...this.vaultsById.keys()].filter((id) => this.account.hasVault(id) && !gone.has(id) && !again.has(id)))) {
      try {
        // An item this very answer brought is not what the person held: the held copy gets what was opened before.
        for (const id of carried) {
          if (this.itemsById.get(id)?.vaultId !== vaultId) continue;
          const was = openedBefore.get(id);
          if (was !== undefined) this.itemsById.set(id, was);
          else this.itemsById.delete(id);
        }
        await this.handleLogRemoval(vaultId, undefined, prePullNames.get(vaultId) ?? this.nameWhileKeyHeld(vaultId), since, false, { byOwner: owed.byOwner });
        if (owed.namedAgain) await this.shared?.onSharedVault(vaultId, null, true);
      } catch (e) {
        console.warn(`the removal of ${vaultId} found after an item's head was chased was not handled in full (non-fatal; pull continues)`, e);
        this.keepAfterFailedRemoval(vaultId, prePullNames.get(vaultId), keepOnDisk);
      }
    }
    // An item set aside that this answer serves again in its vault, with the same content, is in its vault again: it
    // leaves the set, so it is never twice. Served with other content, the copy stays set aside and the person is told.
    this.settleSetAsideServed(resp.items.filter((i) => !refused.has(i.vaultId) && carried.has(i.itemId)));

    this.cursor = resp.rev;

    // Reinstate (spec 03 §11): a live grant re-arrived for a held vault (restore / re-add) —
    // the vault + its items are back in the live set via the ordinary backfill above; here we
    // clear the holding record, re-enqueue parked mutations for replay, mark the deleteId
    // consumed, and notice it. Runs AFTER items apply so replay sees current state.
    const replayMutations: Mutation[] = [];
    // A held log-governed vault whose key the log adopted again (an answered re-add) is back, whether or not this pull
    // re-delivered its grant row.
    for (const id of this.holding.keys()) if (this.logGoverns(id) && this.account.hasVault(id)) reinstated.add(id);
    for (const vaultId of reinstated) {
      const held = this.holding.get(vaultId);
      if (!held) continue;
      // Design §3.6: a re-added member is asked again, and a log-governed vault's key comes back only through the log's
      // adoption above. Until then the grant row alone is no restore: the copy stays held and nothing is replayed.
      if (this.logGoverns(vaultId) && !this.account.hasVault(vaultId)) continue;
      this.holding.delete(vaultId);
      ops.push((b) => b.removeHeld(vaultId)); // §D.1 holding-area move, disk twin
      if (held.deleteId) {
        const consumed = held.deleteId;
        this.consumedDeleteIds.add(consumed);
        ops.push((b) => b.addConsumedDeleteId(consumed));
      }
      // The held copy's items are put back as live, in memory and at rest, except an item this browser already has a row
      // of (listed, in this vault or another, or kept as one it cannot read), an item whose deletion a pull applied (in
      // this session, or recorded with the copy while it was held), and an item whose recorded home is another vault.
      for (const wi of held.items) {
        if (this.itemsById.has(wi.itemId) || this.undecryptableById.has(wi.itemId) || this.serverTombstoned.has(wi.itemId) || deletedServedOf(held).includes(wi.itemId) || !this.admitHome(wi)) continue;
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
      // A copy held since this account's own deletion comes back by the owner's own restore (only the owner signs one):
      // no notice, as its deletion had none.
      if (held.byMe !== true) this.pushNotice({ id: crypto.randomUUID(), vaultId, vaultName: held.cachedName, kind: "restored" });
    }

    // Revoked memberships (spec 03 §11 tri-state). F21: this MUST NOT throw — a denied
    // mutation or a bad proof can never abort the pull that delivers removedGrants.
    const infoByVault = new Map<string, RemovedGrantInfo>();
    for (const info of resp.removedGrantsInfo ?? []) infoByVault.set(info.vaultId, info);
    // Each vault logDecides sent the removal's road, on either road: on a 410 resync, each shared vault this browser held
    // that the fresh list no longer grants, whether or not the answer names it as removed; on both, each one held whose
    // verified log no longer names the account. It takes the road of a removal learned at a delta sync, from what was
    // held before this answer (on a resync, what was taken before the working set was replaced).
    for (const vaultId of gone) {
      const t = taken.get(vaultId);
      if (t !== undefined) this.putBackTaken(t);
      try {
        if (await this.handleLogRemoval(vaultId, infoByVault.get(vaultId), prePullNames.get(vaultId), since, false, unfinished.get(vaultId))) keepOnDisk.add(vaultId);
      } catch (e) {
        console.warn(`the removal of ${vaultId} found at a resync was not handled in full (non-fatal; pull continues)`, e);
        this.keepAfterFailedRemoval(vaultId, prePullNames.get(vaultId), keepOnDisk);
      }
    }
    if (heldBeforeResync !== null) this.setAsideLeftOut(heldBeforeResync, carried, gone, prePullNames);
    if (resp.full) this.tellUncheckedGone(listedNow, gone, resp.removedGrants);
    for (const vaultId of resp.removedGrants) {
      if (gone.has(vaultId)) continue; // handled above

      // A personal vault has no members (design §3.10), so no removal of it can be genuine, and a server
      // must not be able to take a person's saved passwords away from their device (§4.4). An answer that names it
      // raises the anomaly notice and changes nothing: the items stay listed, the key stays, the offline copy's rows
      // stay, and saves go on.
      if (vaultId === this.account.personalVaultId) {
        this.pushNotice({ id: crypto.randomUUID(), vaultId, vaultName: prePullNames.get(vaultId) ?? "", kind: "personal-kept" });
        continue;
      }
      try {
        if (this.logGoverns(vaultId)) {
          await this.handleLogRemoval(vaultId, infoByVault.get(vaultId), prePullNames.get(vaultId), since, resyncing);
          continue;
        }
        await this.handleRemovedGrant(vaultId, infoByVault.get(vaultId), prePullNames.get(vaultId), since, resyncing);
      } catch (e) {
        console.warn(`removedGrant handling failed for ${vaultId} (non-fatal; pull continues)`, e);
        // A shared vault is never dropped in silence because its road threw: it is held with the notice of a removal the
        // browser cannot explain, or its rows stay as they are. Only a vault no log decides leaves the live view here.
        if (this.logGoverns(vaultId)) this.keepAfterFailedRemoval(vaultId, prePullNames.get(vaultId), keepOnDisk);
        else this.dropWithoutHeldCopy(vaultId, "not-log-governed");
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
    // The record at rest of every shared vault whose key works in this session: the `add` it was adopted under, in this
    // same commit as the vault's rows (a vault adopted in this answer, or after an answered question).
    for (const vaultId of this.vaultsById.keys()) {
      const add = this.account.logKeyRing().addOf(vaultId);
      if (this.logGoverns(vaultId) && add !== undefined && !Number.isNaN(add) && this.account.keyWorks(vaultId)) this.putLogRecord(vaultId, { addSeq: add, carried: false });
    }
    // Each held record whose served deletions this answer changed, once, as it stands now, in the commit that also deletes
    // or writes the rows. A copy put back above is gone from the holding area, and its removal at rest is in this commit
    // already: nothing is written for it.
    for (const vaultId of this.heldNotedInPull) {
      const record = this.holding.get(vaultId);
      if (record !== undefined) ops.push((b) => b.putHeld(record));
    }
    this.heldNotedInPull.clear();
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
    // From here the removal's rule has run in this session on what the server served now (see pulledInThisSession).
    this.pulledThisSession = true;

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
    if (this.copyBeingRemoved()) return Promise.resolve();
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
      // A queued change of a vault this browser may not write to now stays queued, unsent: until the removal's rule has
      // run (it then goes with the vault's held copy, as a removed person's unsent changes do, moveToHolding), or until
      // a withheld vault's log has been read through. A frozen vault's change is never sent.
      const chunk = (await this.cache.pending()).filter((m) => this.mayWrite(m.vaultId)).slice(0, VaultStore.SERVER_BATCH_MAX);
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
  private async flushChunk(given: Mutation[], displaced: Displaced[]): Promise<boolean> {
    // Nothing of a vault this browser may not write to now is sent in this run; those rows stay where they are.
    const chunk = given.filter((m) => this.mayWrite(m.vaultId));
    if (chunk.length === 0) return false;
    let resp: PushResponse;
    try {
      resp = await this.sendItemChanges(chunk); // rejects offline → propagates; rows stay queued
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
        if (r.status === "conflict" && m.op === "put" && r.serverItem?.deleted === true) {
          this.noteBroughtBack(m, r.newItemRev);
        } else if (r.status === "conflict" && m.op === "put" && r.serverItem && r.newItemRev != null) {
          displaced.push({ item: r.serverItem, winnerRev: r.newItemRev, pushedVaultId: m.vaultId });
        } else if (r.status === "conflict" && m.op === "put" && r.serverItemOmitted === true && r.newItemRev != null) {
          const d = await this.displacedFromHistory(m.itemId, m.vaultId, r.newItemRev);
          if (d !== null) displaced.push(d);
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
    this.noteServedOnHeld(item);
    // A key that does not work now (its log moved past the `add` it was adopted under, and the removal's rule has not
    // run yet) opens nothing: the row is kept sealed as for a key not held, and applied once a key works again.
    if (!this.account.hasVault(item.vaultId) || !this.account.keyWorks(item.vaultId)) {
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
   * A row applied of an item that a held copy of the same vault holds: a deletion is recorded with that copy, and a live
   * row takes the record out again. The record changes in memory here; in a pull, the vault is noted, and the pull writes
   * the held record once, as it stands at its end, in its commit (the one that also deletes or writes the row at rest),
   * so that it outlives the page. The copy itself keeps every item until the vault is put back or its days end: a
   * deletion row carries no signature, and a person who has not accepted, or declines, keeps the whole copy.
   */
  private noteServedOnHeld(item: WireItem): void {
    const held = this.holding.get(item.vaultId);
    if (held === undefined || !held.items.some((w) => w.itemId === item.itemId)) return;
    const was = deletedServedOf(held);
    if (was.includes(item.itemId) === item.deleted) return;
    const now = item.deleted ? [...was, item.itemId] : was.filter((id) => id !== item.itemId);
    const { deletedServed: _was, ...rest } = held;
    const record: HeldVault = now.length > 0 ? { ...rest, deletedServed: now } : rest;
    this.holding.set(item.vaultId, record);
    if (this.pullOps !== null) this.heldNotedInPull.add(item.vaultId);
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
  /** A11 (c12): remove the cached rows the wire grammar refused (everything NOT in `kept`). A vault id that is not an
   *  id drops its whole cached vault (grant, row, items); an item row with a bad id is deleted on its own. */
  private async purgeMalformedCachedRows(kept: { vaults: WireVault[]; grants: WireGrant[]; items: WireItem[] }): Promise<void> {
    const keptVaults = new Set(kept.vaults.map((v) => v.vaultId));
    const keptGrants = new Set(kept.grants.map((g) => `${g.vaultId}\u0000${g.userId}`));
    const keptItems = new Set(kept.items.map((i) => `${i.itemId}\u0000${i.vaultId}`));
    const badVaults = new Set<string>();
    for (const v of await this.cache.vaults()) if (!keptVaults.has(v.vaultId)) badVaults.add(v.vaultId);
    for (const g of await this.cache.grants()) if (!keptGrants.has(`${g.vaultId}\u0000${g.userId}`)) badVaults.add(g.vaultId);
    for (const id of badVaults) await this.cache.dropVault(id);
    for (const i of await this.cache.envelopes()) if (!keptItems.has(`${i.itemId}\u0000${i.vaultId}`)) await this.cache.deleteItem(i.itemId);
  }

  async hydrate(): Promise<void> {
    // Security review 2026-10, branch A11 (c12): the cached rows run the SAME wire id grammar a live /sync answer does
    // (api/wireids.ts). A row a pre-A10 server planted with a malformed id would otherwise reach the throwing
    // trust-record encoders and abort this hydrate and every later sync until sign-out. Such a row is dropped here,
    // removed from the cache (best effort), and reported once as the `bad-id` notice; nothing aborts.
    const cachedRows = sanitizeSync({
      rev: 0, full: true, vaults: await this.cache.vaults(), grants: await this.cache.grants(), items: await this.cache.envelopes(), removedGrants: [],
    });
    if (cachedRows.refused.length > 0) {
      this.pushNotice({ id: this.account.newItemId(), vaultId: "", vaultName: "", kind: "bad-id", parkedCount: cachedRows.refused.length, reason: "cache" });
      await this.purgeMalformedCachedRows(cachedRows.value).catch(() => {});
    }
    // Grants first: keys must open before vault names or items can decrypt.
    for (const grant of cachedRows.value.grants) {
      if (grant.vaultId !== this.account.personalVaultId) {
        // Keys of shared vaults are adopted through their logs (design §3.6, below), never from a cached row; a store
        // with no log layer adopts none.
        if (this.shared !== null && grant.userId === this.account.userId) this.shared.noteGrantRow(grant.vaultId, { wrappedVk: grant.wrappedVk, signedGrant: grant.signedGrant ?? null, rev: grant.rev });
        continue;
      }
      try {
        this.account.addGrant(grant);
        this.grantWireByVault.set(grant.vaultId, grant);
        this.undecryptableGrants.delete(grant.vaultId);
      } catch {
        // F20 recompute: the same persistent "can't open" warning a pull maintains; cleared when a later pull
        // delivers a row that applies.
        this.undecryptableGrants.add(grant.vaultId);
      }
    }
    for (const vault of cachedRows.value.vaults) {
      this.vaultsById.set(vault.vaultId, vault);
    }
    // Design §3.13: half-made vaults whose deletion was due when this browser last held the session; the next sync deletes
    // them ({@link discardDueHalfMade}). Their names are read when needed, from their own sealed meta.
    for (const d of await this.cache.halfMadeDue()) if (!this.halfMadeDue.has(d.vaultId)) this.halfMadeDue.set(d.vaultId, { name: "", copies: d.copies === null ? null : new Map(d.copies) });
    if (this.shared !== null) {
      for (const r of await this.cache.logRecords()) this.logRecords.set(r.vaultId, { addSeq: r.addSeq, carried: r.carried });
      // Design §3.6 across a reload: the key of each cached shared vault is decided again from its log's last verified
      // state (nothing is fetched), before the items apply. The next pull is a delta that re-sends no unchanged vault
      // row, so without this the shared items of a reloaded or offline copy stayed unreadable.
      for (const vault of cachedRows.value.vaults) {
        if (!this.logGoverns(vault.vaultId)) continue;
        this.shared.noteVaultMeta(vault.vaultId, vault.metaBlob);
        const now = this.memberAddNow(vault.vaultId);
        let rec = this.logRecords.get(vault.vaultId);
        if (rec === undefined) {
          // An offline copy from before the record was kept: the vault counts as adopted under the `add` its log as
          // stored names now, or, where that log no longer names the account, under none, so a removal it shows is
          // carried out at the next pull, as before. The record is written with that pull's commit.
          // The `add` is the account's own accepted entry for the vault where it has one: that entry is synced and sealed,
          // and it is what the adoption itself used, so a log at rest that moved on before any record was written (a page
          // closed after the log was read) cannot stand in for it.
          const st = this.shared.logs.status(vault.vaultId);
          const accepted = this.shared.accountState.local().accepted.get(vault.vaultId);
          if (accepted !== undefined) {
            rec = { addSeq: accepted.addSeq, carried: false };
            this.logRecords.set(vault.vaultId, rec);
            this.recordsUnpersisted.add(vault.vaultId);
          } else if (st.kind !== "unknown" && st.state !== null && now !== undefined) {
            rec = { addSeq: now ?? -1, carried: false };
            this.logRecords.set(vault.vaultId, rec);
            this.recordsUnpersisted.add(vault.vaultId);
          }
        }
        // The rule at a new start: where the log names the account through another `add` than the one this browser
        // adopted the vault under (or not at all), a removal is owed. The key is not taken up: the vault stays held
        // unopened, shows nothing and asks nothing, until the next pull carries the removal out (the held copy, the
        // notice) and only then asks again where the log names the account again.
        if (rec !== undefined && !rec.carried && rec.addSeq !== now) continue;
        await this.shared.onCachedVault(vault.vaultId);
      }
    }
    // A1b INV-HOME: the recorded homes first, then every cached row is admitted against them (an upgraded cache records
    // its homes here, persisted by the next pull); a cached row contradicting a home is quarantined, never applied.
    for (const h of await this.cache.itemHomes()) this.homes.set(h.itemId, h.vaultId);
    for (const q of await this.cache.quarantined()) this.quarantinedRows.set(q.itemId, q);
    const atRest = new Map<string, WireItem>();
    for (const item of cachedRows.value.items) {
      if (!this.admitHome(item)) continue;
      atRest.set(item.itemId, item);
      this.applyWireItem(item);
    }
    // A held vault's key went with its removal and the persisted record has no plaintext name (A2), so a reload shows
    // the placeholder; no retained grant row is opened to re-derive it.
    for (const rec of await this.cache.heldVaults()) {
      if (rec.setAside === true) {
        // Items set aside from a vault this browser still has: named from the vault's row where its key is held. Each is
        // asked the same question as at a pull ({@link setAsideVerdict}) against the row the offline copy holds of it: one
        // that is back (served again by an answer whose commit was skipped) leaves the set here, so it is never twice; one
        // held there with other content stays set aside, and is told once.
        const settled = this.settleSetAsideRecord({ ...rec, cachedName: "" }, (id) => atRest.get(id));
        const record = settled.record;
        if (settled.newlyOther.length > 0) this.tellSetAsideOther(rec.vault.vaultId, record, settled.newlyOther.length);
        if (settled.changed) {
          try {
            if (record.items.length === 0) await this.cache.removeHeld(heldRowKey(rec.vault.vaultId, true));
            else await this.cache.putHeld(record);
          } catch (err) {
            console.warn(`hydrate: the items set aside from ${rec.vault.vaultId} were not brought up to date on disk (kept in memory)`, err);
          }
        }
        if (record.items.length > 0) this.setAside.set(rec.vault.vaultId, record);
        continue;
      }
      let held: HeldVault = { ...rec, cachedName: "(vault)" };
      // A record made by the earlier rule (a verified delete's copy kept only until the vault's purge time, the mark
      // being expungeAt === purgeAt) cannot say when it was verified: it is kept 30 days from now, never fewer.
      if (rec.reason === "deleted" && rec.verified && rec.purgeAt !== undefined && rec.expungeAt === rec.purgeAt) {
        held = { ...held, expungeAt: Math.max(rec.expungeAt, Date.now() + HOLDING_MS) };
        try {
          await this.cache.putHeld(held);
        } catch (err) {
          // Kept in memory; the record keeps its mark on disk, so the next hydrate extends it again.
          console.warn(`hydrate: extending the held copy of ${rec.vault.vaultId} on disk failed (kept in memory)`, err);
        }
      }
      this.holding.set(rec.vault.vaultId, held);
    }
    await this.dropExpiredHeld();
    for (const id of await this.cache.consumedDeleteIds()) this.consumedDeleteIds.add(id);
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
    // A row this browser's own put brought back from a deletion (noteBroughtBack) displaced no version: its mark (an
    // older server's, or a replay journaled before the server stopped storing it) is only cleared, and nothing copied.
    if (!this.itemsById.has(copyId) && !this.broughtBack.has(`${item.itemId}|${item.rev}`)) {
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
  /**
   * Spec 03 §5: a conflicting put's answer omitted the displaced item. The server archived it in the
   * item's history when ours replaced it, so it is the newest archived version below the winner's rev; it is fetched
   * and goes through the same INV-CONFLICT and decryption checks as a served one (its vault is the one we pushed to,
   * which the item's AD then binds). Its attachment references are not in the history, so the copy carries none. A
   * failed fetch leaves the copy to the reconcile pull's flagged-item fallback, which every push path runs.
   */
  private async displacedFromHistory(itemId: string, pushedVaultId: string, winnerRev: number): Promise<Displaced | null> {
    let versions: ItemVersion[];
    try {
      versions = (await this.wire.itemVersions(itemId)).versions;
    } catch (e) {
      console.warn(`displaced version of ${itemId} could not be fetched; the reconcile pull keeps the flagged value`, e);
      return null;
    }
    let best: ItemVersion | null = null;
    for (const v of versions) if (v.rev < winnerRev && (best === null || v.rev > best.rev)) best = v;
    if (best === null) return null;
    const item: WireItem = {
      itemId,
      vaultId: pushedVaultId,
      rev: best.rev,
      createdAt: best.archivedAt,
      updatedAt: best.archivedAt,
      deleted: false,
      conflict: false,
      formatVersion: best.formatVersion,
      attachmentIds: [],
      blob: best.blob,
    };
    return { item, winnerRev, pushedVaultId };
  }

  /** `itemId|rev` of each item this browser's own put brought back from a deletion ({@link noteBroughtBack}). */
  private readonly broughtBack = new Set<string>();

  /**
   * Spec 03 §5: [m], a put, was answered `conflict` with the deletion's mark (`serverItem` deleted): the item had been
   * deleted elsewhere and this change brought it back. There is no displaced version, so no copy is made; the person is
   * told, once per change (a replay of the same answer says nothing more), in one notice per vault that counts them.
   */
  private noteBroughtBack(m: Mutation, newItemRev: number | null | undefined): void {
    const key = `${m.itemId}|${newItemRev ?? "?"}`;
    if (this.broughtBack.has(key)) return;
    this.broughtBack.add(key);
    const prior = this.noticeList.find((x) => x.vaultId === m.vaultId && x.kind === "item-brought-back");
    const count = (prior?.parkedCount ?? 0) + 1;
    const itemName = count === 1 ? this.itemsById.get(m.itemId)?.doc.name : undefined;
    this.pushNotice({
      id: crypto.randomUUID(),
      vaultId: m.vaultId,
      vaultName: this.liveVaultName(m.vaultId),
      kind: "item-brought-back",
      parkedCount: count,
      ...(itemName !== undefined ? { itemName } : {}),
    });
  }

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
      this.dropWithoutHeldCopy(vaultId, "not-log-governed");
      return;
    }

    // This device initiated the delete/leave — drop cleanly, no banner (§4 / §13).
    if (selfInitiated) {
      this.dropWithoutHeldCopy(vaultId, "not-log-governed");
      return;
    }

    const reason: RemovedReason = info?.reason ?? "removed";
    if (reason === "removed" || reason === "left") {
      await this.handleRemovalOrLeave(vaultId, reason, info, cachedName);
      return;
    }
    // A deletion of a held vault that no verified log governs is never "valid": design §15 removed the delete proof, and
    // a log-governed vault's delete is read from its verified log (handleLogRemoval). Snapshot ciphertext + move to
    // holding BEFORE forgetting the VK.
    this.moveToHolding(vaultId, reason, info, false, cachedName);
    this.pushNotice({ id: crypto.randomUUID(), vaultId, vaultName: cachedName, kind: "anomaly" });
  }

  /**
   * `removed` / `left` on a held vault that no verified log governs, not self-initiated. Design §15 removed every
   * lifecycle proof, so nothing the server relays can show the removal was a member's act: the vault goes to the
   * holding area (30 days) with the anomaly notice, whatever proof fields the row carries.
   */
  private async handleRemovalOrLeave(vaultId: string, reason: "removed" | "left", info: RemovedGrantInfo | undefined, cachedName: string): Promise<void> {
    this.moveToHolding(vaultId, reason, info, false, cachedName);
    this.pushNotice({ id: crypto.randomUUID(), vaultId, vaultName: cachedName, kind: "anomaly" });
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
    ownWrap?: string,
    byMe = false,
  ): number {
    // The `add` this removal ends: the session's key's, else the record kept with the offline copy (read before the
    // live rows and the key go below).
    const ended = this.recordFor(vaultId);
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
    // The person's changes of this vault that were queued and never sent because its key stopped working (flushChunk)
    // go with the held copy as the denied ones do: parked, and dequeued in the same commit.
    const unsent = (this.unsentByVault.get(vaultId) ?? []).filter((m) => !stagedEntries.some((s) => s.mutation.mutationId === m.mutationId));
    this.unsentByVault.delete(vaultId);
    for (const m of unsent) {
      this.pendingSyncItemIds.delete(m.itemId);
      this.preEditByMutation.delete(m.mutationId);
    }
    const staged = [...stagedEntries.map((s) => s.mutation), ...unsent];
    for (const s of stagedEntries) this.preEditByMutation.delete(s.mutation.mutationId); // parked — replay owns them
    const parked = [...(this.holding.get(vaultId)?.parked ?? []), ...staged];
    // Design §3.8, §3.12: 30 days from this moment, for every reason; a verified delete or purge too, whatever the
    // vault's own dates say (a purge seen late still gets its full 30 days). A copy held already never loses days.
    const expungeAt = Math.max(Date.now() + HOLDING_MS, this.holding.get(vaultId)?.expungeAt ?? 0);
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
      ...((ownWrap ?? this.holding.get(vaultId)?.ownWrap) !== undefined ? { ownWrap: ownWrap ?? this.holding.get(vaultId)?.ownWrap } : {}),
      ...(byMe || this.holding.get(vaultId)?.byMe === true ? { byMe: true as const } : {}),
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
    this.dropWithoutHeldCopy(vaultId, "held-copy-made");
    // The record says the removal of that `add` is carried out, in the same commit as the held copy (and the notice the
    // caller tells with it): a page closed before that commit comes back with the old rows and the old record, and the
    // rule decides again; one closed after it never carries the same removal out twice.
    this.putLogRecord(vaultId, { addSeq: ended?.addSeq ?? -1, carried: true });
    return parked.length;
  }

  /**
   * THE one function that drops a vault's rows from this browser without making a held copy, for a reason from the
   * closed list {@link DROP_REASONS}. Where a reason can be checked here it is, and a reason that does not hold drops
   * nothing (false): the caller then makes the held copy, or keeps the rows unopened.
   *  - "held-copy-made": the held copy was made in this same commit (moveToHolding);
   *  - "held-copy-removed-by-person": the person removed this browser's held copy of the vault (the mark only this
   *    profile's own gesture writes);
   *  - "own-leave": the person's own leave from this browser, which the server stored;
   *  - "nothing-opened": no key of the vault is held in this session and no record says this browser adopted it since
   *    its last held copy (or ever), so nothing of it was ever opened here;
   *  - "not-log-governed": a vault no shared log decides (no log layer attached, or the personal vault's road).
   * Each reason is true whatever a server serves, withholds, cuts or repeats: none of them is read from an answer.
   */
  private dropWithoutHeldCopy(vaultId: string, reason: DropReason): boolean {
    const holds =
      reason === "held-copy-made"
        ? this.holding.has(vaultId)
        : reason === "held-copy-removed-by-person"
          ? this.shared?.logs.heldRemoved(vaultId) === true
          : reason === "nothing-opened"
            ? this.nothingOpened(vaultId)
            : reason === "not-log-governed"
              ? !this.logGoverns(vaultId)
              : true;
    if (!holds) return false;
    this.hardDropLocal(vaultId);
    return true;
  }

  /** No key of [vaultId] in this session, and no record of an adoption here that a held copy has not ended. */
  private nothingOpened(vaultId: string): boolean {
    return !this.account.hasVault(vaultId) && this.nothingOpenedSinceRecord(vaultId);
  }

  /** No record at rest of an adoption of [vaultId] here that a held copy has not ended (and no row of it opened). */
  private nothingOpenedSinceRecord(vaultId: string): boolean {
    const rec = this.logRecords.get(vaultId);
    if (rec !== undefined && !rec.carried) return false;
    for (const it of this.itemsById.values()) if (it.vaultId === vaultId) return false;
    return true;
  }

  /** Drop a vault from the LIVE view: its items, undecryptables, vault row, wire grant, key,
   *  AND its queued mutations. Called only by {@link dropWithoutHeldCopy}. */
  private hardDropLocal(vaultId: string): void {
    for (const it of [...this.itemsById.values()]) if (it.vaultId === vaultId) this.itemsById.delete(it.itemId);
    for (const it of [...this.undecryptableById.values()]) if (it.vaultId === vaultId) this.undecryptableById.delete(it.itemId);
    for (const it of [...this.missingVkById.values()]) if (it.vaultId === vaultId) this.missingVkById.delete(it.itemId);
    this.vaultsById.delete(vaultId);
    this.grantWireByVault.delete(vaultId);
    this.incomingByVault.delete(vaultId);
    this.undecryptableGrants.delete(vaultId); // F20: access gone → the "can't open" warning is moot
    this.account.removeVault(vaultId);
    // Nothing of the vault is held here any more: its record goes in the same commit as its rows (a held copy made by
    // moveToHolding writes its own record right after).
    this.putLogRecord(vaultId, null);
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

  // The offers this account made, and the handovers held back for its record of them, were the old
  // account-state sync's. An owner's offers, a refusal and a handover are entries of the vault's verified log now
  // (design §3.3): pendingTransferFor, incomingTransfers, logs.refusedOffer.

  /**
   * Transfer state for one vault row that no verified log governs (the personal vault, or a share the log has not
   * decided). Offers and handovers are read from the verified log alone (incomingTransfers, design §3.7); the served
   * row's offer and completion fields carry no proof this client checks any more (design §15: every lifecycle proof
   * went), so an offer to us is never shown, and a completion the server reports on a held vault is a warning
   * (retain-and-warn), never an ownership change.
   */
  private async applyTransferState(vault: WireVault, noticeable: boolean): Promise<void> {
    const vaultId = vault.vaultId;
    if (!this.account.hasVault(vaultId)) return;
    if (this.logGoverns(vaultId)) return; // offers and handovers are read from the verified log (incomingTransfers)
    this.incomingByVault.delete(vaultId);
    const lt = vault.lastTransfer;
    const seenSeq = this.lastTransferSeqSeen.get(vaultId) ?? 0;
    if (lt && lt.seq > seenSeq) {
      if (noticeable) {
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
   * `SyncEngine.surfaceKeyAnomalies` twin): Account.addGrant kept the personal key when the personal row's own wrap
   * opened to another one; this raises the house "server may be misbehaving" notice ONCE per vault per session.
   * Rebuilt from the cached rows on every hydrate, so a server that keeps serving the bad row is reported again.
   */
  private surfaceKeyAnomalies(): void {
    for (const vaultId of this.account.vkMismatchVaultIds()) {
      if (this.keyAnomaliesShown.has(`vk-mismatch|${vaultId}`)) continue;
      this.keyAnomaliesShown.add(`vk-mismatch|${vaultId}`);
      const v = this.vaultsById.get(vaultId);
      const vaultName = v ? this.account.decryptVaultName(vaultId, v.metaBlob) : "(vault)";
      this.pushNotice({ id: crypto.randomUUID(), vaultId, vaultName, kind: "vk-mismatch" });
    }
  }

  private pushNotice(n: LifecycleNotice): void {
    // Collapse a repeat notice for the same vault+kind (idempotent re-pulls). Two held changes that did not happen are two
    // notices (each goes with its own settled record).
    this.noticeList = this.noticeList.filter((x) => !(x.vaultId === n.vaultId && x.kind === n.kind && x.settledId === n.settledId && x.watchId === n.watchId));
    this.noticeList.push(n);
  }

  /**
   * H37 (audit 2026-09-13, spec 03 §5 "Queue coalescing"; core SyncEngine.queuedPutsToFold / dequeueFolded
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
    this.assertWritable();
    this.refuseWhileCopyIsRemoved();
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
    this.refuseIfMoveWaiting(targetVaultId);
    // Asked before anything is uploaded or queued; the seal asks the same again (Account.canSealUnder).
    this.refuseUnlessMayWrite(targetVaultId);
    // The personal vault named but its key not held (after an anomaly) is refused here, as such, instead
    // of failing inside the seal as a crypto error.
    if (targetVaultId === this.account.personalVaultId && !this.account.hasVault(targetVaultId)) throw new VaultNotOpenError(targetVaultId);
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
      try {
        await this.uploadInto(targetVaultId, file.id, id, concat(enc.header, enc.ciphertext));
      } catch (e) {
        // A file goes up only while the server answers; nothing was saved (the item is written after its files). That
        // includes an upload whose answer a limit ended after its head came: the item is not written either.
        if (e instanceof TypeError || answerLimitOf(e) !== null) throw new OfflineNotSavedError("attachments", e);
        throw e;
      }
      onUploadProgress?.(++done, newFiles.length);
    }

    // H37: fold this item's own unsent queued puts into THIS one first — the folded base rev
    // (and the folded pre-edit truth) then ride the mutation below. See coalesceQueuedPuts.
    const folded = await this.coalesceQueuedPuts(id);
    // A13 (q54): the fold has DURABLY dequeued this item's backlog, and the seal below is the step that can still
    // refuse (sealDecision, INV-WRITE-KEY, or a removal/hold that landed during the fold's awaits). A refusal must put
    // the backlog back — the R32 restore — before it propagates, or the member's offline edits vanish here while the
    // optimistic envelope still shows them.
    let m: Mutation;
    try {
      m = this.putMutation(provenance, id, doc, folded ? folded.baseItemRev : (existing?.rev ?? 0));
    } catch (e) {
      if (folded) await this.restoreFoldedPuts(folded);
      throw e;
    }
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
      // The server could not be reached (a fetch that never got an answer) and the change could not wait here: say why.
      if (e instanceof TypeError) throw new OfflineNotSavedError(!this.cache.durable ? "no_offline_copy" : "not_persistent", e);
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
    const resp = await this.wire.itemVersions(itemId);
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
   * by identity, just unnamed. Restore a chosen one with restoreDeleted. A row of a vault this account holds no key for
   * (another account's row, or a vault shared a moment ago that this browser has not adopted) is left out (spec 03 §5.1):
   * never shown, restored or purged, and nothing is fetched for it.
   */
  async deletedItems(): Promise<{ itemId: string; vaultId: string; deletedAt: number; doc: ItemDoc | null }[]> {
    const resp = await this.wire.deletedItems();
    const out: { itemId: string; vaultId: string; deletedAt: number; doc: ItemDoc | null }[] = [];
    for (const d of resp.items) {
      if (!this.account.hasVault(d.vaultId)) continue;
      let doc: ItemDoc | null = null;
      try {
        const newest = (await this.wire.itemVersions(d.itemId)).versions[0]; // newest first
        if (newest) doc = this.account.decryptItemVersion(d.vaultId, d.itemId, newest);
      } catch {
        /* no archive / undecryptable — surface as an unnamed deleted item */
      }
      out.push({ itemId: d.itemId, vaultId: d.vaultId, deletedAt: d.deletedAt, doc });
      this.trashVaults.set(d.itemId, d.vaultId);
    }
    return out;
  }

  /**
   * Item undelete (feature): restore a tombstoned item by re-encrypting the chosen doc under the
   * current VK and POSTing to the dedicated restore route (the server un-tombstones cleanly — no
   * conflict, no spurious copy). Then sync so the item reappears live.
   */
  async restoreDeleted(itemId: string, vaultId: string, doc: ItemDoc): Promise<void> {
    this.assertWritable();
    this.refuseIfMoveWaiting(vaultId);
    // A deleted item's attachment BLOBS were hard-unlinked at tombstone (applyDelete) — only the
    // item ciphertext is archived, never attachment blobs. So a restore MUST drop the old
    // attachment refs; carrying them back would leave dangling/broken download links. The passwords,
    // notes, and other fields come back; attachments do not (design doc: undelete limitation).
    const restored: ItemDoc = { ...doc, attachments: undefined };
    // INV-SEAL (a): the doc was decrypted from this item's archived envelope under `vaultId`; INV-HOME: only at home.
    const upload = this.sealFor(envelopeProvenance(vaultId), itemId, restored);
    this.refuseUnlessMayWrite(vaultId);
    await this.wire.restoreItem(itemId, {
      formatVersion: upload.formatVersion,
      attachmentIds: [],
      blob: upload.blob,
    });
    await this.sync();
  }

  /** Item undelete (F49): "Delete forever" — hard-delete a tombstoned item (+ its versions). */
  async purgeDeleted(itemId: string, vaultId: string): Promise<void> {
    this.assertWritable();
    // Design §3.13 as decided on 2026-11-17 (core WriteClosed's "delete for good"): nothing is changed in a vault whose
    // move's deletion waits. The vault is the one the trash listed the item in, or the one the caller names.
    this.refuseIfMoveWaiting(vaultId);
    this.refuseIfMoveWaiting(this.trashVaults.get(itemId));
    this.refuseUnlessMayWrite(vaultId);
    this.refuseUnlessMayWrite(this.trashVaults.get(itemId));
    await this.wire.purgeItem(itemId);
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
    this.refuseUnlessMayWrite(target);
    for (const it of this.openedItems()) {
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
    this.assertWritable();
    const vaultId = destinationVaultId ?? this.personalVaultOrRefuse();
    this.refuseIfMoveWaiting(vaultId);
    this.refuseUnlessMayWrite(vaultId);
    const total = items.length;
    let done = 0;
    // Spec 03 §14.4, the check before a large copy: a fresh sync, then the blobs exactly as sealed. Only a vault this
    // account owns is counted against its own meters (another owner's are not served to it); on a retry of the same
    // plan, an item the server already holds adds nothing. Short: nothing is sent.
    await this.sync();
    const mutations: Mutation[] = items.map(({ itemId, doc }): Mutation => {
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
    if (this.ownsVault(vaultId)) {
      const fresh = mutations.filter((m) => this.openedItem(m.itemId) === undefined);
      const room = quotaRoom(this.lastQuota, copySize(fresh.reduce((sum, m) => sum + (m.item?.blob.length ?? 0), 0), fresh.length));
      if (room.kind === "short") throw new QuotaShortError(room.limits);
    }
    for (let start = 0; start < mutations.length; start += VaultStore.SERVER_BATCH_MAX) {
      const chunk = mutations.slice(start, start + VaultStore.SERVER_BATCH_MAX);
      await this.push(chunk);
      done += chunk.length;
      onProgress?.(done, total);
    }
    await this.sync();
  }

  /** Fetch + decrypt one attachment blob (24-byte secretstream header ‖ chunks). */
  async downloadAttachment(item: VaultItem, ref: AttachmentRef): Promise<Uint8Array> {
    if (!item.doc.attachments?.some((a) => a.id === ref.id)) throw new Error("attachment does not belong to this item");
    // An item a screen kept from before its vault's log moved opens no file. A read: a vault that may not be written now
    // still gives up its files.
    this.refuseUnlessKeyWorks(item.vaultId);
    // ref.size is the item author's claim (a co-member's, in a shared vault — security review
    // 2026-10): the body must be exactly the length it implies, so the backup cap that budgets with
    // it holds what it says, and a lie is refused instead of decrypted. Core twin.
    const expected = wireLength(ref.size);
    if (expected === null) throw new Error("attachment does not match its declared size");
    // Core ItemEngine.fetchAttachment twin: a file key that is no key (all zeros, the wrong length, not base64url) is
    // damaged content, refused before anything is downloaded, never read as a lock.
    const fileKey = fileKeyOf(ref.fileKey);
    if (fileKey === null) throw new DamagedAttachmentError();
    try {
      const bytes = await this.wire.downloadAttachment(ref.id);
      // A lock or a sign-out during the download opens nothing.
      if (this.closed) throw new SessionClosedError();
      // Asked again now that the answer is here, before the file is opened: a removal carried out while the answer was on
      // its way (a sync, another tab) leaves the vault's key working for nothing, and nothing of it is handed out, to any
      // caller (the item view, a backup's attachments, a copy's files).
      this.refuseUnlessKeyWorks(item.vaultId);
      if (bytes.length !== expected) throw new Error("attachment does not match its declared size");
      return decryptAttachment(fileKey, bytes.subarray(0, HEADER_BYTES), bytes.subarray(HEADER_BYTES));
    } finally {
      fileKey.fill(0);
    }
  }

  /**
   * §D.3 durable delete (save()'s twin): enqueue the delete durably, drop the item
   * optimistically, then flush + reconcile. OFFLINE ⇒ success-as-QUEUED while persistence is
   * granted (breaker #1), else push-or-throw; a GENUINE denial (a reader) re-thrown and the
   * item restored; a committed delete whose reconcile pull fails stays removed (the item is
   * gone fleet-wide — the UI must never claim "nothing was removed").
   */
  async remove(itemId: string): Promise<void> {
    this.assertWritable();
    this.refuseWhileCopyIsRemoved();
    // The item is read through the guarded read, and the vault asked before anything is queued: an item a screen kept
    // from before its vault's log moved is refused as a save is, never deleted.
    const kept = this.itemsById.get(itemId);
    if (kept !== undefined) this.refuseUnlessMayWrite(kept.vaultId);
    const existing = this.openedItem(itemId);
    if (!existing) return;
    this.refuseIfMoveWaiting(existing.vaultId);
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
    // A notice that a held change did not happen goes with the change's settled record, which kept it across a reload;
    // one that a change was made after all goes with the remembered change, kept at rest for the same reason.
    for (const n of this.noticeList) {
      if (n.id !== id) continue;
      if (n.settledId !== undefined) this.shared?.logs.dismissSettled(n.vaultId, n.settledId);
      if ((n.kind === "held-found-made" || n.kind === "held-delete-made") && n.watchId !== undefined) this.shared?.logs.dismissWatched(n.vaultId, n.watchId);
      // The loss of a vault the browser cannot check, once seen, is not told again by a later full pull that holds nothing.
      if ((n.kind === "unchecked-gone" || n.kind === "anomaly" || n.kind === "left-frozen") && this.logGoverns(n.vaultId)) this.shared?.logs.noteGoneTold(n.vaultId);
    }
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
   *  "Recently removed" — read-only; recovery is automatic on restore/re-add). `purgeAt` is for display only: the grace
   *  end the log answers carried (spec 03 §10.6) when there was one, else the one the pull's removal hint carried.
   *  `addedAgain`: this browser shows an invitation to the vault that its person can answer, so the copy is closed until
   *  it is answered (decided on 23 November 2026; {@link SharedLogSession.heldClosedByAsk}). `invitationName`: while
   *  closed, the vault's name as that invitation names it (the row's own name is "(vault)" after a reload); else absent. */
  heldVaults(): { vaultId: string; name: string; reason: RemovedReason; verified: boolean; byMe: boolean; purgeAt?: number; expungeAt: number; itemCount: number; canCopyOut: boolean; addedAgain: boolean; invitationName?: string }[] {
    return [...this.holding.entries()].map(([vaultId, h]) => {
      const closed = this.heldClosed(vaultId);
      const asked = closed ? this.shared?.outcome(vaultId) : undefined;
      return {
        vaultId,
        name: h.cachedName,
        reason: h.reason,
        verified: h.verified,
        byMe: h.byMe === true,
        purgeAt: this.shared?.logs.serverGraceEnd(vaultId)?.purgeAt ?? h.purgeAt,
        expungeAt: h.expungeAt,
        itemCount: h.items.length,
        addedAgain: closed,
        invitationName: asked?.kind === "ask" ? asked.vaultName : undefined,
        // §3.8: copy-out needs this account's own wrap of the key, kept since the removal, and a verified history here;
        // none while the copy is closed for an invitation.
        canCopyOut: !closed && h.ownWrap !== undefined && this.shared !== null && this.shared.logs.verifiedState(vaultId) !== null && h.items.length > 0,
      };
    });
  }

  /**
   * Whether the copy this browser kept of [vaultId] is closed because this browser shows an invitation to the vault that
   * its person can answer ({@link SharedLogSession.heldClosedByAsk}), asked of the session layer itself. A store with no
   * session layer closes nothing.
   */
  private heldClosed(vaultId: string): boolean {
    return this.shared?.heldClosedByAsk(vaultId) === true;
  }

  /**
   * "Remove from this device" (spec 02 §10.6): the person drops this browser's copy of a vault in the holding area, at
   * once, whatever its date. A local action that tells the server nothing. The copy leaves the view only once it is
   * gone from IndexedDB too; a failed removal throws and leaves the copy where it was.
   */
  async removeHeldCopy(vaultId: string): Promise<void> {
    if (!this.holding.has(vaultId)) return;
    await this.cache.removeHeld(vaultId);
    this.holding.delete(vaultId);
    // Another tab that still holds the vault from before learns the same removal: it writes no copy again.
    if (this.logGoverns(vaultId)) this.shared!.logs.noteHeldRemoved(vaultId);
    this.forgetLateMove(vaultId);
    for (const k of [...this.heldGestures.keys()]) if (k.startsWith(`${vaultId}|`)) this.heldGestures.delete(k);
  }

  /** Held copy-out gestures by (vault, item): a retry after a stop reuses the same new item id, so nothing is copied twice. */
  private heldGestures = new Map<string, { newItemId: string; gestureId: string }>();

  /**
   * Copy every item of a vault in the holding area into the personal vault (design §3.8: "items can still be copied
   * out"). The key is opened from this account's own wrap kept with the held copy and checked against the log's key
   * commitment; it is used only to read, and wiped after. Each item is written to the personal vault under a fresh id.
   *
   * - **Attachments**: the server no longer serves the files of a vault this account was removed from, so each one is
   *   tried and, when it cannot be fetched, left out of the copy; the count is returned.
   * - **Items that cannot be opened** (a newer format, a damaged blob) are not copied; the count is returned.
   *
   * Copying out writes only under the personal vault's key, so it is allowed whatever the old vault's state (§3.6).
   */
  async copyHeldToPersonal(vaultId: string, onProgress?: (done: number, total: number) => void): Promise<{ copied: number; attachmentsLeftOut: number; unreadable: number }> {
    this.assertWritable();
    const personal = this.personalVaultOrRefuse();
    const held = this.holding.get(vaultId);
    const shared = this.shared;
    if (held === undefined || held.ownWrap === undefined || shared === null) throw new HeldKeyGoneError();
    // Closed while this browser shows an invitation to the vault that can be answered: nothing is opened, written or sent.
    if (this.heldClosed(vaultId)) throw new HeldClosedWhileAskedError(vaultId);
    const vk = await shared.logs.openOwnWrap(vaultId, held.ownWrap);
    if (vk === null) throw new HeldKeyGoneError();
    let out: { copied: number; attachmentsLeftOut: number; unreadable: number };
    try {
      out = await this.copyItemsToPersonal(vaultId, held.items, (w) => this.account.decryptHeldItem(w, vk), personal, onProgress);
    } finally {
      vk.fill(0);
    }
    try {
      await this.sync();
    } catch (e) {
      console.warn("held copy committed; reconcile failed", e);
    }
    return out;
  }

  /**
   * Each of [items] (sealed copies of [vaultId]'s items) opened with [open] and written into the personal vault under a
   * fresh id, the same one again on a retry. Items that cannot be opened are counted, not copied.
   */
  private async copyItemsToPersonal(
    vaultId: string,
    held: readonly WireItem[],
    open: (w: WireItem) => ItemDoc,
    personal: string,
    onProgress?: (done: number, total: number) => void,
  ): Promise<{ copied: number; attachmentsLeftOut: number; unreadable: number }> {
    let copied = 0;
    let attachmentsLeftOut = 0;
    let unreadable = 0;
    const items = [...held].sort((a, b) => (a.itemId < b.itemId ? -1 : 1));
    onProgress?.(0, items.length);
    for (const w of items) {
      let doc: ItemDoc;
      try {
        doc = open(w);
      } catch {
        unreadable++;
        onProgress?.(copied + unreadable, items.length);
        continue;
      }
      const gKey = `${vaultId}|${w.itemId}|${w.rev}|${personal}`;
      const g = this.heldGestures.get(gKey) ?? { newItemId: crypto.randomUUID(), gestureId: crypto.randomUUID() };
      this.heldGestures.set(gKey, g);
      attachmentsLeftOut += await this.putHeldCopy(doc, g, personal, 0);
      copied++;
      onProgress?.(copied + unreadable, items.length);
    }
    return { copied, attachmentsLeftOut, unreadable };
  }

  /**
   * The items set aside, one entry per vault ({@link setAside}): items of the personal vault, or of a shared vault still
   * listed, that a full list neither carried nor marked as deleted. [name]: the vault's name as this browser reads it
   * now, else as it read it when they were set aside ("" when it cannot); [personal]: the personal vault's.
   */
  itemsSetAside(): { vaultId: string; name: string; personal: boolean; itemCount: number; expungeAt: number; canCopyOut: boolean }[] {
    const personal = this.account.personalVaultId;
    return [...this.setAside.entries()].map(([vaultId, h]) => {
      const row = this.vaultsById.get(vaultId);
      let name = h.cachedName;
      if (row !== undefined && this.account.hasVault(vaultId)) {
        try {
          const n = this.account.decryptVaultName(vaultId, row.metaBlob);
          if (n && n !== "(vault)") name = n;
        } catch {
          /* the name kept when they were set aside */
        }
      }
      return {
        vaultId,
        name,
        personal: vaultId === personal,
        itemCount: h.items.length,
        expungeAt: h.expungeAt,
        canCopyOut: h.items.length > 0 && (this.account.hasVault(vaultId) || (h.ownWrap !== undefined && this.shared !== null && this.shared.logs.verifiedState(vaultId) !== null)),
      };
    });
  }

  /**
   * Copy the items set aside from [vaultId] into the personal vault, each under a fresh id, as from a held copy. The key
   * is the vault's own while this browser holds it, else this account's own wrap kept with them. They stay set aside
   * until their date or until the person removes them: copying sends nothing else and removes nothing.
   */
  async copySetAsideToPersonal(vaultId: string, onProgress?: (done: number, total: number) => void): Promise<{ copied: number; attachmentsLeftOut: number; unreadable: number }> {
    this.assertWritable();
    const personal = this.personalVaultOrRefuse();
    const rec = this.setAside.get(vaultId);
    if (rec === undefined) throw new HeldKeyGoneError();
    let vk: Uint8Array | null = null;
    if (!this.account.hasVault(vaultId)) {
      if (rec.ownWrap === undefined || this.shared === null) throw new HeldKeyGoneError();
      vk = await this.shared.logs.openOwnWrap(vaultId, rec.ownWrap);
      if (vk === null) throw new HeldKeyGoneError();
    }
    const key = vk;
    let out: { copied: number; attachmentsLeftOut: number; unreadable: number };
    try {
      out = await this.copyItemsToPersonal(vaultId, rec.items, (w) => (key === null ? this.account.decryptItem(w) : this.account.decryptHeldItem(w, key)), personal, onProgress);
    } finally {
      key?.fill(0);
    }
    try {
      await this.sync();
    } catch (e) {
      console.warn("items set aside copied; reconcile failed", e);
    }
    return out;
  }

  /**
   * "Remove from this device" for the items set aside from [vaultId]: gone at once, from IndexedDB first, whatever their
   * date. Tells the server nothing. A failed removal throws and leaves them where they were.
   */
  async removeSetAside(vaultId: string): Promise<void> {
    if (!this.setAside.has(vaultId)) return;
    await this.cache.removeHeld(heldRowKey(vaultId, true));
    this.setAside.delete(vaultId);
  }

  /**
   * One item of a held copy, written into [target] as the item [g.newItemId] (a new one at [baseItemRev] 0, or over an
   * earlier copy at its revision). Each attachment is fetched, re-sealed under a fresh key and uploaded; one the server
   * no longer serves is left out, and the count of those is returned. A stop (no connection, no space) throws.
   */
  private async putHeldCopy(doc: ItemDoc, g: { newItemId: string; gestureId: string }, target: string, baseItemRev: number): Promise<number> {
    let leftOut = 0;
    const newDoc: ItemDoc = structuredClone(doc);
    const refs: AttachmentRef[] = [];
    for (const ref of doc.attachments ?? []) {
      try {
        const expected = wireLength(ref.size);
        // A file key that is no key is a file that cannot be copied: left out and counted, with nothing downloaded.
        const heldKey = fileKeyOf(ref.fileKey);
        if (heldKey === null) throw new DamagedAttachmentError();
        const bytes = await this.wire.downloadAttachment(ref.id);
        if (this.closed) throw new SessionClosedError();
        if (expected === null || bytes.length !== expected) throw new Error("attachment does not match its declared size");
        const plain = decryptAttachment(heldKey, bytes.subarray(0, HEADER_BYTES), bytes.subarray(HEADER_BYTES));
        heldKey.fill(0);
        const fileKey = toB64(randomBytes(32));
        const enc = encryptAttachment(fromB64(fileKey), plain);
        const newId = await uuidFromLabel(`held|${g.gestureId}|${ref.id}`);
        await this.uploadInto(target, newId, g.newItemId, concat(enc.header, enc.ciphertext));
        refs.push({ id: newId, name: ref.name, size: ref.size, fileKey });
      } catch (e) {
        if (e instanceof ApiError && (e.status === 0 || e.code === "quota_exceeded")) throw e; // a stop, not a missing file
        if (e instanceof SessionClosedError) throw e; // a lock, not a missing file
        leftOut++;
      }
    }
    if (doc.attachments !== undefined) newDoc.attachments = refs;
    const upload = this.sealFor(chosenProvenance(target), g.newItemId, newDoc);
    const resp = await this.sendItemChanges([
      {
        mutationId: await this.gestureMutationId(g.gestureId, "copy"),
        op: "put",
        itemId: g.newItemId,
        vaultId: target,
        baseItemRev,
        item: { formatVersion: upload.formatVersion, attachmentIds: refs.map((a) => a.id), blob: upload.blob },
      },
    ]);
    const r = resp.results[0];
    if (r?.status === "denied") throw new CopyDeniedError();
    if (r?.status === "rejected") throw new ApiError(r.reason === "quota_exceeded" ? 413 : 400, r.reason ?? "rejected", `the server refused the copy: ${r.reason ?? "rejected"}`);
    if (r?.status !== "applied" && r?.status !== "conflict") throw new ApiError(0, "copy_unconfirmed", "The copy could not be confirmed. Try again.");
    return leftOut;
  }

  /** Verified incoming ownership offers TO us — the accept consent screen renders per entry. */
  incomingTransfers(): IncomingTransfer[] {
    const out = [...this.incomingByVault.values()].filter((t) => !this.logGoverns(t.vaultId));
    // A log-governed vault's offer is the verified log's pending `offer` to this account (design §3.5), never a row field.
    for (const [vaultId, vault] of this.vaultsById) {
      if (!this.logGoverns(vaultId)) continue;
      const st = this.shared!.logs.verifiedState(vaultId);
      const p = st?.pending ?? null;
      if (st === null || p === null || p.to !== this.account.userId || p.expiresAt <= Date.now()) continue;
      let vaultName = "(vault)";
      try {
        vaultName = this.account.decryptVaultName(vaultId, vault.metaBlob);
      } catch {
        /* the name stays a placeholder; the offer itself is the log's */
      }
      out.push({ vaultId, vaultName, offerId: p.offerId, seq: st.head.seq, expiresAt: p.expiresAt });
    }
    return out;
  }

  /** The pending offer on an owned vault (for the owner's "Ownership offer to …" chip), or null. */
  pendingTransferFor(vaultId: string): PendingTransfer | null {
    if (this.logGoverns(vaultId)) {
      const p = this.shared!.logs.verifiedState(vaultId)?.pending ?? null;
      // `proof` and `seq` belong to the old proof scheme; the log's offer carries neither (the chip shows who and when).
      return p === null ? null : { toUserId: p.to, offerId: p.offerId, proof: "", expiresAt: p.expiresAt, seq: 0 };
    }
    return this.vaultsById.get(vaultId)?.pendingTransfer ?? null;
  }

  /** Whether [vaultId] is a shared vault this session decides on through its signed log. */
  isLogGoverned(vaultId: string): boolean {
    return this.logGoverns(vaultId);
  }

  // ==== vault lifecycle: actions (spec 03 §11) ====

  /** DELETE (soft, 7d grace). Mints a fresh deleteId + delete proof under the held VK.
   *  This device initiated it, so the reconcile pull drops the vault cleanly (no banner);
   *  the owner restores it from the Sharing trash icon. Returns the server-erase deadline. */
  async deleteSharedVault(vaultId: string): Promise<{ purgeAt: number | null }> {
    if (this.logGoverns(vaultId)) {
      // Deleted only when the server stored it: a delete whose answer never came throws ChangeNotStoredError, and the
      // vault stays listed (its held frame is re-posted later, byte for byte).
      const out = await this.storedLogAction(vaultId, { kind: "delete" });
      return this.afterOwnDelete(vaultId);
    }
    throw NOT_LOG_GOVERNED();
  }

  /**
   * {@link deleteSharedVault} of a stopped move's half-made vault, after the read that showed it holds nothing but
   * [copies]: the delete is held marked as such, so that it is never sent again unread ({@link resendHeldChanges}).
   */
  private async deleteHalfMadeVault(vaultId: string, copies: ReadonlyMap<string, number | null> | null, itemsAtMost: number): Promise<{ purgeAt: number | null }> {
    if (!this.logGoverns(vaultId)) throw NOT_LOG_GOVERNED();
    const out = await this.storedLogAction(vaultId, { kind: "delete" }, { halfMade: { copies }, itemsAtMost });
    return this.afterOwnDelete(vaultId);
  }

  /**
   * After this account's `delete` of [vaultId] was stored: the vault drops without a banner, and the deadline shown is
   * the grace end the server stored and sent on the append's answer or the refetch (spec 03 §10.3, §10.6). Where the
   * server sent none (an older server), it is null: no day is computed here, and the line names none and points to the
   * list of deleted vaults, which shows the server's own. Display only.
   */
  private async afterOwnDelete(vaultId: string): Promise<{ purgeAt: number | null }> {
    const served = this.shared!.logs.serverGraceEnd(vaultId);
    await this.dropAfterOwnLogAction(vaultId);
    return { purgeAt: served?.purgeAt ?? null };
  }

  /** REMOVE a member (design §3.7): a signed `remove`; the removed member's browser decides from the log. */
  async removeVaultMember(vaultId: string, userId: string): Promise<void> {
    if (!this.logGoverns(vaultId)) throw NOT_LOG_GOVERNED();
    await this.storedLogAction(vaultId, { kind: "remove", member: userId });
    await this.reconcileAfterLogAction();
  }

  /**
   * The caller's own in-grace deleted vaults. Each name is read with the key in the owner's own wrap, opened under the
   * verified log's genesis and checked against its key commitment (design §3.6), and wiped at once: listing a deleted
   * vault never puts its key back into use. A vault whose log this browser has not verified is fetched once; one that
   * still does not open is listed as "(vault)", and its restore is refused by the log check in {@link restoreSharedVault}.
   */
  async listDeleted(): Promise<DeletedVaultInfo[]> {
    const raw = await this.api.deletedVaults();
    const shared = this.shared;
    const out: DeletedVaultInfo[] = [];
    for (const d of raw) {
      let name = "(vault)";
      if (shared !== null) {
        if (shared.logs.verifiedState(d.vaultId) === null) await shared.logs.refresh(d.vaultId, null, null, true).catch(() => null);
        const vk = await shared.logs.openOwnWrap(d.vaultId, d.wrappedVk);
        if (vk !== null) {
          name = vaultNameUnder(d.vaultId, vk, d.metaBlob) ?? "(vault)";
          vk.fill(0);
        }
      }
      out.push({ vaultId: d.vaultId, name, deletedAt: d.deletedAt, purgeAt: d.purgeAt, deleteId: d.deleteId });
    }
    return out;
  }

  /** The members of a shared vault from its verified log, with contact labels (design §3.9), or null without one. */
  memberRoster(vaultId: string): Roster | null {
    return this.shared?.roster(vaultId, this.account.userId) ?? null;
  }

  /** RESTORE (within grace). Requires the VK held (listDeleted re-opened it). */
  async restoreSharedVault(vaultId: string, deleteId: string): Promise<void> {
    if (this.logGoverns(vaultId)) {
      // The `restore` names the deleteId in force in the VERIFIED log; the listed one must be that deletion.
      if (this.shared!.logs.verifiedState(vaultId)?.deleteId !== deleteId) throw new LogActionError({ kind: "not_allowed", reason: "not_deleted" });
      await this.storedLogAction(vaultId, { kind: "restore" });
      this.consumedDeleteIds.add(deleteId);
      await this.reconcileAfterLogAction();
      return;
    }
    throw NOT_LOG_GOVERNED();
  }

  /** LEAVE (design §3.11): a signed `leave`. This device initiated it, so the vault drops without a banner here. */
  async leaveSharedVault(vaultId: string): Promise<void> {
    if (!this.logGoverns(vaultId)) throw NOT_LOG_GOVERNED();
    await this.storedLogAction(vaultId, { kind: "leave" });
    await this.dropAfterOwnLogAction(vaultId);
  }

  /** TRANSFER offer (design §3.5): a signed `offer` to a member, for 14 days. */
  async offerTransfer(vaultId: string, toUserId: string): Promise<void> {
    if (!this.logGoverns(vaultId)) throw NOT_LOG_GOVERNED();
    await this.storedLogAction(vaultId, { kind: "offer", to: toUserId, expiresInMs: 14 * 86_400_000 });
    await this.reconcileAfterLogAction();
  }

  /** TRANSFER cancel (owner) or decline (target): the same signed `cancel` of the offer in force. */
  async cancelTransfer(vaultId: string): Promise<void> {
    if (!this.logGoverns(vaultId)) throw NOT_LOG_GOVERNED();
    await this.storedLogAction(vaultId, { kind: "cancel" });
    this.incomingByVault.delete(vaultId);
    await this.reconcileAfterLogAction();
  }

  /** TRANSFER accept: only the offer the verified log holds for THIS account, the one shown, before it expires (§3.5). */
  async acceptTransfer(vaultId: string, offerId: string): Promise<void> {
    if (!this.logGoverns(vaultId)) throw NOT_LOG_GOVERNED();
    const p = this.shared!.logs.verifiedState(vaultId)?.pending ?? null;
    if (p === null || p.to !== this.account.userId || p.offerId !== offerId || p.expiresAt <= Date.now()) {
      throw new LogActionError({ kind: "not_allowed", reason: "no_offer" });
    }
    await this.storedLogAction(vaultId, { kind: "accept" });
    this.incomingByVault.delete(vaultId);
    await this.reconcileAfterLogAction();
  }

  /** RENAME. Read-modify-write metaBlob (name only, unknown fields preserved, metaV bumped),
   *  with the current vault rev as the stale-write guard. A 409 stale_meta (a concurrent change)
   *  auto-resyncs and retries ONCE on top of the fresh row (never a silent last-write-wins). */
  async renameVault(vaultId: string, newName: string, retry = true): Promise<void> {
    this.assertWritable();
    this.refuseIfMoveWaiting(vaultId);
    const vault = this.vaultsById.get(vaultId);
    if (!vault) throw new Error("vault not found");
    const metaBlob = this.account.buildRenameMeta(vaultId, vault.metaBlob, newName);
    try {
      this.refuseUnlessMayWrite(vaultId);
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
    this.refuseUnlessMayWrite(targetVaultId);
    const src = this.openedItem(itemId);
    if (!src) throw new Error("the item to move is no longer here");
    if (del) this.refuseUnlessMayWrite(src.vaultId);
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
  /**
   * Runs [g]. Resolves to the copy's own revision at the server, as the server's answer to the copy leg named it (null
   * when that answer named none): a move records it per copy, so that a half-made vault is later recognised as holding
   * only what the move made, unchanged (design §3.13).
   */
  /**
   * [g]'s source asked again after a wait of its copy leg: its key is still held and works, and for a move (which deletes
   * the source) the source may still be written ({@link mayWrite}); a copy out only reads it, so it is asked the key.
   */
  private refuseUnlessSourceStill(g: MoveGesture): void {
    if (!this.account.hasVault(g.sourceVaultId) || !this.account.keyWorks(g.sourceVaultId) || (g.del && !this.mayWrite(g.sourceVaultId))) throw new VaultKeyNotVerifiedError(g.sourceVaultId);
  }

  async runGesture(g: MoveGesture, onProgress?: (done: number, total: number) => void, finalSync = true): Promise<number | null> {
    this.assertWritable();
    // A gesture a screen kept from before the log moved is asked again: the target, and the source where it is deleted,
    // must be writable now, and the source is read through the guarded read.
    this.refuseUnlessMayWrite(g.targetVaultId);
    if (g.del) this.refuseUnlessMayWrite(g.sourceVaultId);
    const src = this.openedItem(g.sourceItemId);
    if (!src) throw new Error("The item to move is no longer here — it may have changed or been removed.");
    // INV-HOME (A1b; core twin): the gesture was minted for the source in its vault; never run against another's copy.
    if (src.vaultId !== g.sourceVaultId) throw new ItemChangedVaultsError();
    // Nothing is moved into a vault whose move's deletion waits, and nothing is moved out of it (a move deletes the
    // source); a copy out of it is allowed (§3.6, T2-R-k: items may be copied out of a vault in any state).
    this.refuseIfMoveWaiting(g.targetVaultId);
    if (g.del) this.refuseIfMoveWaiting(g.sourceVaultId);

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
        // Asked again after the download's wait, before the file goes to the target: a move out of a vault that closed
        // meanwhile (its log frozen or withheld here, another tab's read or a pull) uploads nothing.
        this.refuseUnlessSourceStill(g);
        const enc = encryptAttachment(fromB64(a.newFileKey), plain);
        await this.uploadInto(g.targetVaultId, a.newId, g.newItemId, concat(enc.header, enc.ciphertext));
        newRefs.push({ id: a.newId, name: a.name, size: a.size, fileKey: a.newFileKey });
        onProgress?.(++done, g.attachments.length);
      }
      newDoc.attachments = newRefs;
    }
    const copyMutationId = await this.gestureMutationId(g.gestureId, "copy");
    // Asked again after the last wait, before the item is put into the target, with nothing awaited between this question
    // and the push: a removal from the SOURCE vault carried out meanwhile (a sync, another tab) puts nothing of it there,
    // and a move out of a source that may no longer be written sends no copy (it would stay beside a source whose
    // deletion is refused). The files already uploaded stay in the target, named by no item.
    this.refuseUnlessSourceStill(g);
    const copyUpload = this.sealFor(chosenProvenance(g.targetVaultId), g.newItemId, newDoc); // INV-SEAL (c): the chosen destination
    const copyResp = await this.sendItemChanges([
      {
        mutationId: copyMutationId,
        op: "put",
        itemId: g.newItemId,
        vaultId: g.targetVaultId,
        baseItemRev: g.replacesRev ?? 0,
        item: {
          formatVersion: copyUpload.formatVersion,
          attachmentIds: newDoc.attachments?.map((a) => a.id) ?? [],
          blob: copyUpload.blob,
        },
      },
    ]);
    const copyResult = copyResp.results[0];
    if (copyResult?.status === "denied") throw new CopyDeniedError(); // ABORT — source untouched
    // A per-row `rejected` carries the server's reason (spec 03 §5): a full account answers `quota_exceeded` (design
    // §7.4), which the caller must be able to tell from an unconfirmed copy. The source is untouched either way.
    if (copyResult?.status === "rejected") {
      const reason = copyResult.reason ?? "rejected";
      throw new ApiError(reason === "quota_exceeded" || reason === "item_attachment_quota" ? 413 : 400, reason, `the server refused the copy: ${reason}`);
    }
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
      const delResp = await this.sendItemChanges([
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
    const copyRev = copyResult?.newItemRev;
    return typeof copyRev === "number" && Number.isSafeInteger(copyRev) ? copyRev : null;
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
  /** The vault each trashed item was listed in by the last read of the trash ({@link deletedItems}). */
  private readonly trashVaults = new Map<string, string>();

  async copyAllToPersonal(vaultId: string, onProgress?: (done: number, total: number) => void): Promise<{ copied: number }> {
    this.assertWritable();
    // A11 (c08): with no personal vault in force there is no "Personal" to copy into: refuse with the §4.3 copy
    // ("Choose a vault for this item.") instead of sealing under vault "" (which surfaced as a crypto error).
    const personal = this.personalVaultOrRefuse();
    // A vault whose key does not work now is refused as a save is; its items are read through the guarded read. A copy
    // out only reads the vault, so one that may not be written now is copied out of all the same.
    this.refuseUnlessKeyWorks(vaultId);
    const items = this.openedItems().filter((it) => it.vaultId === vaultId);
    let copied = 0;
    for (const it of items) {
      const gKey = `${vaultId}|${it.itemId}|${personal}`;
      let g = this.bulkGestures.get(gKey);
      if (!g || g.sourceRev !== it.rev) {
        // New gesture only for a first attempt or when the source content changed since the
        // memoized attempt (a different rev IS different content — copy that instead).
        g = this.newMoveGesture(it.itemId, personal, false);
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

  // ==== "Move everything to a new vault" (design §3.13, T-R6) ====

  /** Moves this session started and has not finished, by the old vault's id: a retry carries on from where it stopped. */
  private readonly moveRuns = new Map<string, MoveRun>();
  /**
   * Old vaults of moves not finished whose removal (the one a move signs first) the server stored in this session, by
   * any run: no later stop of the same move says the old vault "wasn't changed". Ends when the move finishes.
   */
  private readonly moveChangedOld = new Set<string>();

  /**
   * The unfinished move of [vaultId]: this session's, or, after a reload or an unlock, the one kept beside its held
   * `delete` (design §3.13; a move that stopped at any other step is not kept, and a reload starts it again).
   */
  private moveRunFor(vaultId: string, adopt = false): MoveRun | undefined {
    const live = this.moveRuns.get(vaultId);
    if (live !== undefined) return live;
    const logs = this.shared?.logs;
    const rec = logs?.moveRecord(vaultId) ?? null;
    if (logs === undefined || rec === null || !logs.holdsMoveDelete(vaultId)) return undefined;
    const run = this.runOfRecord(rec, true);
    // Only the move's own run adopts it (after its first sync, so the names read); a look from a screen does not.
    if (adopt) this.moveRuns.set(vaultId, run);
    return run;
  }

  /**
   * A run of the move of [vaultId] that stopped in an earlier session with no delete held (kept at rest from the moment
   * it made its new vault, design §3.13 as decided on 2026-11-18). It is never carried on (what was sent and not answered
   * is not known after the session ended): the next run starts a fresh vault and deals with this one as half-made.
   */
  private stoppedRunAtRest(vaultId: string): MoveRun | undefined {
    const rec = this.shared?.logs.moveRecord(vaultId) ?? null;
    if (rec === null || rec.stopped !== true || this.shared!.logs.holdsMoveDelete(vaultId)) return undefined;
    return this.runOfRecord(rec, false);
  }

  private runOfRecord(rec: MoveRecord, deleteHeld: boolean): MoveRun {
    const held = this.heldNames();
    const nameOf = (id: string): string => held.get(id) ?? "";
    return {
      name: nameOf(rec.newVaultId),
      newVaultId: rec.newVaultId,
      copied: new Map(rec.copied.map(([id, rev, copyId, copyRev]) => [id, { rev, copyId, copyRev }])),
      added: new Set(rec.added),
      discard: rec.discard === null ? null : { vaultId: rec.discard, name: nameOf(rec.discard), copies: rec.discardCopies === null ? null : new Map(rec.discardCopies) },
      removed: rec.removed === true,
      deleteHeld,
    };
  }

  /**
   * Keeps [run] at rest, in the log store's storage (beside its held delete, or, with none held, as a stopped run from
   * the moment it made its new vault), or drops the record ([run] null: the move finished, or nothing of it is left).
   */
  private keepMoveRun(vaultId: string, run: MoveRun | null, oldFrozen = false): void {
    const logs = this.shared?.logs;
    if (logs === undefined) return;
    if (run === null) {
      logs.saveMoveRecord(vaultId, null);
      return;
    }
    logs.saveMoveRecord(vaultId, {
      newVaultId: run.newVaultId,
      copied: [...run.copied].map(([id, c]) => [id, c.rev, c.copyId, c.copyRev] as const),
      added: [...run.added],
      discard: run.discard?.vaultId ?? null,
      discardCopies: run.discard?.copies == null ? null : [...run.discard.copies],
      // [oldFrozen]: the old vault froze under the move's held deletion ({@link MoveRecord.oldFrozen}); never a stopped run.
      ...(run.deleteHeld || oldFrozen ? {} : { stopped: true }),
      ...(run.removed ? { removed: true } : {}),
      ...(oldFrozen ? { oldFrozen: true } : {}),
    });
  }

  /**
   * The moves whose old vault's deletion is signed and waiting for the server (design §3.13): the first screen after an
   * unlock says each is unfinished and offers to finish it ({@link finishMove}).
   */
  unfinishedMoves(): UnfinishedMove[] {
    const logs = this.shared?.logs;
    if (logs === undefined) return [];
    const held = this.heldNames();
    const nameOf = (id: string | null): string | null => (id === null ? null : (held.get(id) ?? null));
    const waiting: UnfinishedMove[] = logs.heldMoveDeletes().map((vaultId) => {
      const run = this.moveRunFor(vaultId);
      return { vaultId, name: nameOf(vaultId), newVaultId: run?.newVaultId ?? null, newName: run === undefined ? null : nameOf(run.newVaultId), added: run === undefined ? [] : [...run.added] };
    });
    // A move whose deletion a freeze of the old vault dropped: said as what it is, until the person dismisses it.
    const frozen: UnfinishedMove[] = [];
    for (const vaultId of logs.frozenMoves()) {
      const rec = logs.moveRecord(vaultId);
      if (rec?.oldFrozen === true) frozen.push({ vaultId, name: nameOf(vaultId), newVaultId: rec.newVaultId, newName: nameOf(rec.newVaultId), added: [...rec.added], oldFrozen: true });
    }
    return [...waiting, ...frozen];
  }

  /** The person dismissed the line of a move whose old vault froze ({@link UnfinishedMove.oldFrozen}): its record goes. */
  dismissFrozenMove(vaultId: string): void {
    const logs = this.shared?.logs;
    if (logs?.moveRecord(vaultId)?.oldFrozen !== true) return;
    logs.saveMoveRecord(vaultId, null);
    this.moveRuns.delete(vaultId);
  }

  /**
   * The stop of a move of [vaultId] whose old vault froze while its deletion was held (marked so at the freeze, or a run of
   * this session whose held deletion the freeze dropped), or null. The move's record is kept, marked, for its line; the
   * run is not kept as a stopped one (its new vault holds the items and is never taken for a half-made one).
   */
  private frozenMoveStop(vaultId: string, name: string): MoveStoppedError | null {
    const logs = this.shared?.logs;
    if (logs === undefined) return null;
    const rec = logs.moveRecord(vaultId);
    const live = this.moveRuns.get(vaultId);
    const dropped = live?.deleteHeld === true && !logs.holdsMoveDelete(vaultId) && logs.status(vaultId).kind === "frozen";
    if (rec?.oldFrozen !== true && !dropped) return null;
    const run = live ?? (rec !== null ? this.runOfRecord(rec, false) : undefined);
    if (run !== undefined) {
      run.deleteHeld = false;
      this.keepMoveRun(vaultId, run, true);
    }
    this.moveRuns.delete(vaultId);
    return new MoveStoppedError("delete", run?.copied.size ?? 0, 0, run?.name ?? name, run?.newVaultId ?? null, new OldVaultFrozenError(vaultId), false, this.moveChangedOld.has(vaultId));
  }

  /** The change of [vaultId] that waits to be sent again (signed, held), as its member panel shows it; null when none. */
  heldChangeFor(vaultId: string): HeldChange | null {
    return this.shared?.logs.heldChange(vaultId) ?? null;
  }

  /**
   * Withdraws [vaultId]'s waiting change, where it may be ({@link HeldChange.withdrawable}): it is never sent again. One
   * whose answer was lost may be made already, so the vault's log is read from the server at once (and at each sync
   * until a read reaches it), and the person is told what it found ({@link surfaceWatched}).
   */
  withdrawHeldChange(vaultId: string): boolean {
    return this.withdrawHeldChangeAs(vaultId) !== null;
  }

  /**
   * {@link withdrawHeldChange}, answering what was known of the change at the moment it was withdrawn (null: nothing was
   * withdrawn): the line after "Withdraw" follows that state, not the one the panel drew.
   */
  withdrawHeldChangeAs(vaultId: string): HeldKnown | null {
    const logs = this.shared?.logs;
    const known = logs === undefined ? null : logs.withdrawHeldAs(vaultId);
    if (known === null) return null;
    this.deleteAsks = this.deleteAsks.filter((v) => v !== vaultId);
    this.noticeList = this.noticeList.filter((n) => !(n.kind === "held-delete-ask" && n.vaultId === vaultId));
    void this.surfaceWatched({ vaultId, read: true }).catch((e: unknown) => console.warn("the vault's log was not read after a withdrawal (read again at the next sync)", e));
    return known;
  }

  /**
   * The person's own word on a deletion of [vaultId] that waits ({@link VaultLogStore.heldDeletionsToAsk}): it is sent
   * again now, byte for byte, and counts as done only when the server stored it (else ChangeNotStoredError or
   * LogActionError, as {@link deleteSharedVault}). Returns the server-erase deadline.
   */
  async sendHeldDeletion(vaultId: string): Promise<{ purgeAt: number | null }> {
    this.assertWritable();
    const logs = this.shared?.logs;
    if (logs === undefined || !this.logGoverns(vaultId)) throw NOT_LOG_GOVERNED();
    // A freeze drops the vault's held deletion, which was sent when it was signed: nothing may be said of whether it was
    // made (a read froze the vault between the question and the tap, or the give-up's read below did).
    const frozen = (): LogActionError | null => (logs.status(vaultId).kind === "frozen" ? new LogActionError({ kind: "read_only", vaultId, frozen: "sent" }) : null);
    const held = logs.heldChange(vaultId);
    if (held === null || held.kind !== "delete") throw frozen() ?? new LogActionError({ kind: "not_allowed", reason: "nothing_held" });
    if (!logs.heldDeletionsToAsk().includes(vaultId)) {
      // The day ran out between the question and the tap: the deletion is given up here (the log is read, nothing is
      // sent), and the line says so, with how to delete the vault again. Made after all: done.
      const gave = await logs.giveUpHeldDeletion(vaultId);
      if (gave === null) throw frozen() ?? new LogActionError({ kind: "not_allowed", reason: "nothing_held" });
      if (gave.kind === "appended") return this.afterOwnDelete(vaultId);
      if (gave.kind === "pending") throw new ChangeNotStoredError(vaultId, "delete", gave.known);
      this.deleteAsks = this.deleteAsks.filter((v) => v !== vaultId);
      this.surfaceSettled();
      throw new LogActionError({ kind: "not_allowed", reason: "delete_given_up" });
    }
    this.deleteAsks = this.deleteAsks.filter((v) => v !== vaultId);
    this.noticeList = this.noticeList.filter((n) => !(n.kind === "held-delete-ask" && n.vaultId === vaultId));
    const out = await logs.retryHeld(vaultId);
    if (out === null) throw new LogActionError({ kind: "not_allowed", reason: "nothing_held" });
    if (out.kind === "pending") throw new ChangeNotStoredError(out.vaultId, "delete", out.known);
    if (out.kind !== "appended") throw new LogActionError(out);
    return this.afterOwnDelete(vaultId);
  }

  /** The person's own deletions that wait for their word, found at this session's unlock ({@link resendHeldChanges}). */
  private deleteAsks: string[] = [];
  private readonly deleteAskSurfaced = new Set<string>();

  /** One notice per deletion that waits for the person's word, naming its vault (before the first pull, only once named). */
  private surfaceDeleteAsks(): void {
    const logs = this.shared?.logs;
    if (logs === undefined || this.deleteAsks.length === 0) return;
    const names = this.heldNames();
    for (const vaultId of this.deleteAsks) {
      if (this.deleteAskSurfaced.has(vaultId) || logs.heldChange(vaultId)?.kind !== "delete") continue;
      const vaultName = names.get(vaultId);
      if (vaultName === undefined && !this.pulledOnce) continue;
      this.deleteAskSurfaced.add(vaultId);
      this.pushNotice({ id: crypto.randomUUID(), vaultId, vaultName: vaultName ?? "", kind: "held-delete-ask", heldKind: "delete" });
    }
  }

  /** The watch notices this session has made (by finding and frame hash), so each is made once per session. */
  private readonly watchSurfaced = new Set<string>();
  /** "Not made" findings whose vault is not named yet (before the first pull): made once it is. */
  private watchNotMade: WatchFinding[] = [];

  /**
   * CL.5: what the vault's log says now of the changes this browser withdrew or gave up without knowing whether the
   * server had them ({@link VaultLogStore.checkWatched}), said as a notice each: made after all (with the way to undo
   * it; kept at rest by the log store until the notice is dismissed, so a lock loses nothing), or, after a withdrawal,
   * not made. Before this session's first pull a notice whose vault is not named yet waits for that pull.
   */
  private async surfaceWatched(opts: { readonly vaultId?: string; readonly read?: boolean } = {}): Promise<void> {
    const logs = this.shared?.logs;
    if (logs === undefined) return;
    if (logs.watchedVaults().length > 0) for (const f of await logs.checkWatched(opts)) if (f.found === "not_made" && !this.watchNotMade.some((x) => x.id === f.id)) this.watchNotMade.push(f);
    const found = [...logs.madeWatches(), ...this.watchNotMade].filter((f) => !this.watchSurfaced.has(`${f.found}|${f.id}`));
    if (found.length === 0) return;
    const names = this.heldNames();
    // A vault found deleted after all (a half-made vault's, or the person's own deletion) is no longer listed: its name
    // is read from the deleted vaults (with the owner's own wrap), where it can be restored; a list that cannot be read
    // leaves it unnamed.
    if (this.pulledOnce && found.some((f) => f.found === "made" && (f.why === "half_made" || f.change.kind === "delete") && !names.has(f.change.vaultId))) {
      try {
        for (const d of await this.listDeleted()) if (!names.has(d.vaultId) && d.name !== "(vault)") names.set(d.vaultId, d.name);
      } catch (e) {
        console.warn("the deleted vaults could not be listed for a notice's name", e);
      }
    }
    const unnamed: WatchFinding[] = [];
    for (const f of found) {
      if (!names.has(f.change.vaultId) && !this.pulledOnce) {
        if (f.found === "not_made") unnamed.push(f);
        continue;
      }
      if (this.watchSurfaced.has(`${f.found}|${f.id}`)) continue;
      this.watchSurfaced.add(`${f.found}|${f.id}`);
      const halfMade = f.why === "half_made" && f.found === "made";
      const servedEnd = halfMade ? logs.serverGraceEnd(f.change.vaultId)?.purgeAt : undefined;
      // The person's own deletion, held because its answer was lost, found in the log before they were asked about it.
      if (f.why === "answer_lost") {
        this.pushNotice({
          id: crypto.randomUUID(),
          vaultId: f.change.vaultId,
          vaultName: names.get(f.change.vaultId) ?? "",
          kind: "held-delete-made",
          heldKind: "delete",
          watchId: f.id,
          // Only the server's own day: where it served none, the line names no day.
          ...(f.purgeAt !== undefined ? { purgeAt: f.purgeAt } : {}),
        });
        continue;
      }
      this.pushNotice({
        id: crypto.randomUUID(),
        vaultId: f.change.vaultId,
        vaultName: names.get(f.change.vaultId) ?? "",
        kind: f.found === "made" ? "held-found-made" : "held-found-not-made",
        heldKind: f.change.kind,
        memberName: f.change.memberLabel ?? undefined,
        watchId: f.id,
        // A stopped move's half-made vault deleted after all: when this browser signed it, and the end of its grace.
        // Only the server's own day: where it served none, the line names no day.
        ...(halfMade ? { halfMade: true, signedAt: f.at, ...(servedEnd !== undefined ? { purgeAt: servedEnd } : {}) } : {}),
      });
      // "Not made" counts as told only now that its notice is made (a lock before this loses nothing).
      if (f.found === "not_made") logs.noteWatchTold(f.change.vaultId, f.id);
    }
    this.watchNotMade = unnamed;
  }

  /**
   * Sends again every change kept to be sent (at the unlock), and says every one that did not happen, at that moment,
   * with what it was: a notice per change the server refused, whose place another entry took, that the log does not
   * hold, or that waited too long and was given up. A removal never quietly does not happen. Returns the outcomes.
   */
  async resendHeldChanges(): Promise<ResendOutcome[]> {
    if (this.shared === null) return [];
    const logs = this.shared.logs;
    // A held deletion of a stopped move's half-made vault is never sent from here, unread: it goes to the half-made vaults
    // due, which the sync that follows reads first ({@link discardDueHalfMade}): sent only where the vault holds nothing
    // but the move's copies, dropped (the vault kept, its name said) where it holds anything else, and kept for the next
    // read where it cannot be read. The vaults known to be half-made are passed too, so a plain held deletion of one
    // (signed before the deletion was marked) is left alone as well.
    const halfMade = new Set<string>(this.halfMadeDue.keys());
    for (const run of this.moveRuns.values()) if (run.discard !== null) halfMade.add(run.discard.vaultId);
    for (const old of logs.heldMoveDeletes()) {
      const d = logs.moveRecord(old)?.discard;
      if (d != null) halfMade.add(d);
    }
    let added = false;
    for (const h of logs.heldHalfMadeDeletes()) {
      halfMade.add(h.vaultId);
      // The copies signed with the deletion are the move's own record of what it made there.
      const had = this.halfMadeDue.get(h.vaultId);
      this.halfMadeDue.set(h.vaultId, { name: had?.name ?? "", copies: h.copies });
      if (had === undefined) added = true;
    }
    if (added) await this.keepHalfMadeDue();
    const done = await logs.resendPending(halfMade);
    this.surfaceSettled();
    // The person's own deletion of a vault is not sent again on its own: the unlock asks them, about one that is still
    // held. Each is looked for in the vault's log first (nothing is sent): one the log holds was made (the notice says
    // the vault was deleted, and how to restore it); one whose place another entry took did not happen (said as such).
    this.deleteAsks = await logs.deletionsToAsk(halfMade);
    this.surfaceSettled();
    this.surfaceDeleteAsks();
    // A change withdrawn while its re-send was out, whose answer then said it is stored, is said here.
    await this.surfaceWatched().catch(() => {});
    return done.map((d) => d.outcome);
  }

  /** The settled changes whose notice this session has made (by the change's id), so each is made once per session. */
  private readonly settledSurfaced = new Set<string>();
  /** A pull of this session filled the vault list (so a vault missing from it is not just unread yet). */
  private pulledOnce = false;

  /**
   * One notice per held change that did not happen when it was sent again (kept at rest by the log store until its
   * notice is dismissed: {@link dismissNotice}), naming its vault. Before this session's first pull the vault list may be
   * empty (no offline copy), so a notice whose vault is not named yet waits for that pull ({@link sync} calls this again).
   * A re-post the gate stopped leaves the change held, and says nothing here.
   */
  private surfaceSettled(): void {
    const logs = this.shared?.logs;
    if (logs === undefined) return;
    const names = this.heldNames();
    const settled = logs.settledChanges();
    // A notice whose settled change the log store took back (a freeze over a "its place was taken") is taken back too.
    const kept = new Set(settled.map((s) => s.id));
    this.noticeList = this.noticeList.filter((n) => n.settledId === undefined || kept.has(n.settledId));
    for (const { id, change, outcome } of settled) {
      if (this.settledSurfaced.has(id)) continue;
      const vaultName = names.get(change.vaultId);
      if (vaultName === undefined && !this.pulledOnce) continue;
      this.settledSurfaced.add(id);
      const base = { id: crypto.randomUUID(), vaultId: change.vaultId, vaultName: vaultName ?? "", heldKind: change.kind, memberName: change.memberLabel ?? undefined, settledId: id };
      if (outcome.kind === "given_up" && outcome.made === "unknown") this.pushNotice({ ...base, kind: "held-given-up" });
      else this.pushNotice({ ...base, kind: "held-not-made", reason: outcome.kind === "refused" ? outcome.code : outcome.kind === "not_allowed" ? outcome.reason : outcome.kind });
    }
  }

  /** Whether [vaultId]'s deletion is signed by a move and waiting for the server (its panel says so). */
  moveDeleteWaiting(vaultId: string): boolean {
    return this.shared?.logs.holdsMoveDelete(vaultId) === true;
  }

  /** Design §3.13 as decided on 2026-11-17: a vault whose move's deletion waits takes nothing new and no change. */
  private refuseIfMoveWaiting(vaultId: string | null | undefined): void {
    if (vaultId !== null && vaultId !== undefined && this.moveDeleteWaiting(vaultId)) throw new MoveWaitingError(vaultId);
  }

  /**
   * Design §3.13 as decided on 2026-11-17: the old vault's deletion, signed by a move and held, is seen stored outside a
   * run of the move (a server keeps the signed frame and can store it whenever it likes). Called before the copy goes
   * into the holding area. What this browser holds of the old vault is compared with the move's record of what it copied
   * at which revision: the counts of items added and changed after their copy. The held frame can never be posted again
   * and is forgotten; the move's record stays, so those items can be copied from the held copy into the new vault
   * ({@link copyLateIntoMove}). Null when no move's delete was held for [vaultId].
   */
  private moveStoredOutside(vaultId: string): { newVaultId: string; newVaultName: string; lateAdded: number; lateChanged: number } | null {
    const logs = this.shared?.logs;
    if (logs === undefined || !logs.holdsMoveDelete(vaultId)) return null;
    const rec = logs.moveRecord(vaultId);
    logs.forgetHeldMoveDelete(vaultId);
    // The move is over, so a half-made vault an earlier run of it replaced (only copies) goes now, as it would at the end
    // of the move's own run: after the sync that found the deletion ({@link discardDueHalfMade}).
    const liveHalf = this.moveRuns.get(vaultId)?.discard ?? null;
    const half = liveHalf?.vaultId ?? rec?.discard ?? null;
    if (half !== null) {
      // With the copies the earlier run made in it, so that it is deleted only while it holds nothing else.
      const copies = liveHalf !== null ? liveHalf.copies : rec?.discardCopies == null ? null : new Map(rec.discardCopies);
      this.halfMadeDue.set(half, { name: this.heldNames().get(half) ?? "", copies });
      // Kept in the copy before the move's record can go, so a reload in between still deletes it.
      void this.keepHalfMadeDue();
    }
    this.moveRuns.delete(vaultId);
    const copied = new Map((rec?.copied ?? []).map(([id, rev]) => [id, rev]));
    let lateAdded = 0;
    let lateChanged = 0;
    for (const it of this.itemsById.values()) {
      if (it.vaultId !== vaultId) continue;
      const rev = copied.get(it.itemId);
      if (rev === undefined) lateAdded++;
      else if (rev !== it.rev) lateChanged++;
    }
    const newVaultId = rec?.newVaultId ?? "";
    const newVaultName = newVaultId === "" ? "" : (this.heldNames().get(newVaultId) ?? "");
    if (lateAdded + lateChanged === 0) logs.saveMoveRecord(vaultId, null);
    return { newVaultId, newVaultName, lateAdded, lateChanged };
  }

  /**
   * What a held copy holds that its move never copied, or copied at an older revision ({@link moveStoredOutside}), by
   * the move's record; null when no such record is kept for [vaultId] or its copy is not held.
   */
  moveLate(vaultId: string): { newVaultId: string; added: number; changed: number } | null {
    const rec = this.shared?.logs.moveRecord(vaultId) ?? null;
    const held = this.holding.get(vaultId);
    if (rec === null || rec.stopped === true || held === undefined || this.shared?.logs.holdsMoveDelete(vaultId) === true) return null;
    const copied = new Map(rec.copied.map(([id, rev]) => [id, rev]));
    let added = 0;
    let changed = 0;
    for (const w of held.items) {
      const rev = copied.get(w.itemId);
      if (rev === undefined) added++;
      else if (rev !== w.rev) changed++;
    }
    return { newVaultId: rec.newVaultId, added, changed };
  }

  /**
   * Copies from the held copy of a move's old vault into the move's new vault what the move had not copied: an item it
   * never copied as a new item, and an item changed after its copy over that copy (never a second copy beside it). The
   * key is this account's own wrap kept with the held copy, opened only to read and wiped after. Each copy is recorded
   * as it lands, so a second run copies nothing twice; the record goes once nothing is left.
   */
  async copyLateIntoMove(vaultId: string, onProgress?: (done: number, total: number) => void): Promise<{ copied: number; attachmentsLeftOut: number; unreadable: number }> {
    this.assertWritable();
    const logs = this.shared?.logs;
    const held = this.holding.get(vaultId);
    const rec = logs?.moveRecord(vaultId) ?? null;
    if (logs === undefined || held === undefined || held.ownWrap === undefined || rec === null || rec.stopped === true) throw new HeldKeyGoneError();
    const target = rec.newVaultId;
    if (!this.account.hasVault(target)) throw new LogActionError({ kind: "not_allowed", reason: "move_target_gone" });
    this.refuseUnlessMayWrite(target);
    const copiedMap = new Map(rec.copied.map(([id, rev, copyId, copyRev]) => [id, { rev, copyId, copyRev }]));
    const due = [...held.items].filter((w) => copiedMap.get(w.itemId)?.rev !== w.rev).sort((a, b) => (a.itemId < b.itemId ? -1 : 1));
    const vk = await logs.openOwnWrap(vaultId, held.ownWrap);
    if (vk === null) throw new HeldKeyGoneError();
    let copied = 0;
    let attachmentsLeftOut = 0;
    let unreadable = 0;
    const save = (): void => logs.saveMoveRecord(vaultId, { ...rec, copied: [...copiedMap].map(([id, c]) => [id, c.rev, c.copyId, c.copyRev] as const) });
    try {
      onProgress?.(0, due.length);
      for (const w of due) {
        let doc: ItemDoc;
        try {
          doc = this.account.decryptHeldItem(w, vk);
        } catch {
          unreadable++;
          onProgress?.(copied + unreadable, due.length);
          continue;
        }
        const earlier = copiedMap.get(w.itemId);
        const copyNow = earlier === undefined ? undefined : this.openedItem(earlier.copyId);
        const over = earlier !== undefined && copyNow !== undefined && copyNow.vaultId === target;
        const gKey = `${vaultId}|${w.itemId}|${w.rev}|${target}`;
        const g = this.heldGestures.get(gKey) ?? { newItemId: over ? earlier.copyId : crypto.randomUUID(), gestureId: crypto.randomUUID() };
        this.heldGestures.set(gKey, g);
        attachmentsLeftOut += await this.putHeldCopy(doc, g, target, over && g.newItemId === earlier.copyId ? copyNow.rev : 0);
        copiedMap.set(w.itemId, { rev: w.rev, copyId: g.newItemId, copyRev: null });
        save();
        this.heldGestures.delete(gKey);
        copied++;
        onProgress?.(copied + unreadable, due.length);
      }
    } finally {
      vk.fill(0);
    }
    if (unreadable === 0) logs.saveMoveRecord(vaultId, null);
    try {
      await this.sync();
    } catch (e) {
      console.warn("the copy into the move's new vault committed; reconcile failed", e);
    }
    return { copied, attachmentsLeftOut, unreadable };
  }

  /** Finishes an unfinished move ({@link unfinishedMoves}): the move's next run, with the members it added. */
  finishMove(m: UnfinishedMove, onProgress?: (done: number, total: number) => void): Promise<MoveResult> {
    return this.moveEverything(m.vaultId, { name: m.newName ?? "", add: m.added }, onProgress);
  }

  /**
   * What "Move everything to a new vault" would do with [vaultId] (design §3.13), or null where this browser cannot
   * offer it: no verified history, a state other than verified, frozen or failed, not the owner, or no key held.
   * [removing] is the member the remove dialog is about: not one of the remaining members, so never added again.
   */
  movePlan(vaultId: string, removing: string | null = null): MovePlan | null {
    const shared = this.shared;
    if (shared === null || !this.logGoverns(vaultId) || !this.account.hasVault(vaultId)) return null;
    const st = shared.logs.status(vaultId);
    if ((st.kind !== "verified" && st.kind !== "frozen" && st.kind !== "failed") || st.state === null) return null;
    const s = st.state;
    if (s.members[this.account.userId]?.role !== "owner") return null;
    // §3.13: on a frozen or failed vault the old one stays where it is, and nothing is signed on its log (T2-R-k).
    const sourceStays = st.kind !== "verified";
    const members: MoveMember[] = [];
    for (const [userId, m] of Object.entries(s.members)) {
      if (userId === this.account.userId || userId === removing || m.role === "owner") continue;
      const c = shared.contacts.currentFor(userId, m.key);
      members.push({ userId, role: m.role, label: c?.labelText ?? null, canBeAdded: c !== null && c.record.compared });
    }
    members.sort((a, b) => (a.label ?? "").localeCompare(b.label ?? "") || (a.userId < b.userId ? -1 : 1));
    const stored = this.moveRunFor(vaultId);
    // A stopped run is offered for resuming only when no one holds its new vault's key who is not in this plan.
    const inPlan = new Set([this.account.userId, ...members.map((m) => m.userId)]);
    const holders = stored === undefined ? [] : [...Object.keys(shared.logs.verifiedState(stored.newVaultId)?.members ?? {}), ...stored.added];
    const run = stored !== undefined && holders.every((u) => inPlan.has(u)) ? stored : undefined;
    return {
      vaultId,
      sourceStays,
      members,
      itemCount: this.openedItems().filter((it) => it.vaultId === vaultId).length,
      uncopyable: this.undecryptable().filter((u) => u.vaultId === vaultId).length,
      resume: run === undefined ? null : { name: run.name, newVaultId: run.newVaultId, copied: run.copied.size },
    };
  }

  /**
   * What a move of [vaultId] writes (spec 03 §14.4): B, each item not in [copied] at its blob's length as sealed plus its
   * attachments' stored sizes; N, those items; and, when [newVaultName] is given (a new vault is made), V = 1 and M, the
   * length of the new vault's metaBlob, as it will be sealed: its name and the entry that names [vaultId] as the vault
   * the move takes everything out of ({@link VAULT_META_MOVE_OF}, as `sharedlogs.ts` seals it). The source's plaintext
   * gives the same lengths the copy seals (an estimate only where the log head stamped into a shared vault's item differs
   * in length).
   */
  moveSize(vaultId: string, copied: ReadonlyMap<string, unknown> | null, newVaultName: string | null) {
    let bytes = 0;
    let count = 0;
    for (const it of this.openedItems()) {
      if (it.vaultId !== vaultId || copied?.has(it.itemId) === true) continue;
      count++;
      bytes += sealedBlobLength(utf8(JSON.stringify(it.doc)).length);
      for (const a of it.doc.attachments ?? []) bytes += storedAttachmentSize(a.size);
    }
    return newVaultName === null ? copySize(bytes, count) : copySize(bytes, count, true, sealedBlobLength(utf8(JSON.stringify({ name: newVaultName, [VAULT_META_MOVE_OF]: vaultId })).length));
  }

  /**
   * "Move everything to a new vault" (design §3.13), in the design's order: a new vault (its own key), every item
   * copied into it through the move path's copy leg (fresh item ids and attachment keys; the originals stay where they
   * are), the members in [add] added with the role they hold now (each is asked to accept it, §3.6), and then the old
   * vault deleted, into its grace. Nothing is ever in neither vault: the old one is only deleted once everything else
   * succeeded.
   *
   * - [removing]: the member the remove dialog was opened for. Their `remove` is signed on the old log first, so a
   *   later restore of the old vault does not bring them back.
   * - On a frozen or failed vault the old one stays, untouched, and nothing is signed on its log (T2-R-k, FS-R3).
   * - The old vault is also kept when a remaining member could not be added from this browser, or when some of its
   *   items could not be read here and so were not copied; the result says which.
   *
   * A stop at any step throws {@link MoveStoppedError}, which says exactly where; the next call for the same vault
   * carries on from there (the same new vault, the same copy gestures, members already added skipped).
   */
  async moveEverything(vaultId: string, req: { name: string; add: readonly string[]; removing?: string | null }, onProgress?: (done: number, total: number) => void): Promise<MoveResult> {
    this.assertWritable();
    const removing = req.removing ?? null;
    // Spec 03 §14.4: the check for space reads the quota of a FRESH sync, and the plan is made on what it pulled. A sync
    // that fails is the answer: nothing is checked on an older value, and nothing starts.
    try {
      await this.sync();
    } catch (e) {
      // A removal an earlier run of this move stored changed the old vault: this stop does not say it "wasn't changed".
      throw new MoveStoppedError("create", 0, 0, this.moveRuns.get(vaultId)?.name ?? req.name.trim(), null, e, false, this.moveChangedOld.has(vaultId));
    }
    // Asked after the fresh sync, which runs the removal's rule: a vault whose key does not work now moves nothing. Only
    // the key is asked here: the move writes into the new vault, and the old vault's own log refuses its deletion on
    // its standing, with the move's own line for a frozen one.
    this.refuseUnlessKeyWorks(vaultId);
    // A run whose old vault's delete is signed and held (its answer never came; design §3.13 as decided on 2026-11-16):
    // look at the old vault's log first, posting nothing.
    // - The delete is stored (its answer was lost): the move is finished, and only now is the old vault "deleted".
    // - Another stored change took its place: it can never be stored and the log store dropped it (spec 03 §10.3). The run
    //   goes on as an ordinary one, with the old vault's members read again, and may sign a new delete under §3.13's rules.
    // - Still storable: what is new or changed in the old vault is copied first (a changed item replaces its own copy),
    //   and the held frame is re-posted only then, at step 4.
    // The old vault froze while this move's deletion of it was held: the deletion was dropped and can never be sent. The
    // move stops here with its own line; nothing is signed, copied or opened for writing again.
    const frozenBefore = this.frozenMoveStop(vaultId, req.name.trim());
    if (frozenBefore !== null) throw frozenBefore;
    const heldRun = this.moveRunFor(vaultId, true);
    if (heldRun?.deleteHeld === true && this.shared !== null) {
      const logs = this.shared.logs;
      const look = await logs.lookHeld(vaultId);
      // The look itself found the server contradicting its word about the deletion: frozen, the deletion dropped.
      const frozenAtLook = look?.kind === "read_only" ? this.frozenMoveStop(vaultId, req.name.trim()) : null;
      if (frozenAtLook !== null) throw frozenAtLook;
      const st = logs.verifiedState(vaultId);
      if ((look?.kind === "appended" || look === null) && st !== null && st.deleteId !== null) {
        const deleted = await this.afterOwnDelete(vaultId);
        this.moveRuns.delete(vaultId);
        this.moveChangedOld.delete(vaultId);
        this.keepMoveRun(vaultId, null);
        const discarded = await this.discardAfterMove(heldRun);
        return { newVaultId: heldRun.newVaultId, name: heldRun.name, copied: heldRun.copied.size, oldDeleted: deleted, oldKept: null, notAdded: [], added: heldRun.added.size, uncopyable: 0, changed: 0, discarded };
      }
      if (look === null) {
        heldRun.deleteHeld = false;
        // Kept at rest as a stopped run: its new vault exists whatever this run does next.
        this.keepMoveRun(vaultId, heldRun);
      }
    }
    // The delete is signed and waiting: every stop of this run says so, as it cannot be taken back.
    const waiting = (): boolean => this.moveRuns.get(vaultId)?.deleteHeld === true;
    const plan = this.movePlan(vaultId, removing);
    if (plan === null) throw new LogActionError({ kind: "not_allowed", reason: "move_not_offered" });
    const byId = new Map(plan.members.map((m) => [m.userId, m]));
    const add = req.add.filter((id) => byId.has(id));
    const shared = this.shared!;
    // Who may hold the new vault's key: this account and the people this move adds. A removal from
    // the new vault takes back no key it gave, so a stopped run is carried on only when everyone it gave the key to (its
    // log's members and everyone it added) is among them. Otherwise this move starts a fresh vault with a fresh key, and
    // the half-made one is dealt with before anything is copied (design §3.13 as decided on 2026-11-18, below).
    const allowed = new Set([this.account.userId, ...add]);
    const keyHolders = (r: MoveRun): string[] => [...new Set([...Object.keys(shared.logs.verifiedState(r.newVaultId)?.members ?? {}), ...r.added])];
    const live = this.moveRuns.get(vaultId);
    // A run that stopped in an earlier session (a lock, a reload, a closed tab) is found at rest, and never carried on.
    const atRest = live === undefined ? this.stoppedRunAtRest(vaultId) : undefined;
    const earlier = live ?? atRest;
    // A run whose delete is still held is always carried on: its new vault is the one the held delete was signed for.
    const prior = live !== undefined && (live.deleteHeld || keyHolders(live).every((u) => allowed.has(u))) ? live : undefined;
    const name = prior?.name || req.name.trim() || earlier?.name || "";
    if (name === "" && prior === undefined) throw new LogActionError({ kind: "not_allowed", reason: "no_name" });
    let discard = prior === undefined && earlier !== undefined ? this.halfMadeOf(vaultId, earlier) : (prior?.discard ?? null);
    // With no record of an earlier run here (another device's run, or a record lost), a target an earlier run made is
    // found by its own sealed meta, and dealt with as a half-made vault whose copies are not known: deleted only where
    // it holds nothing at all, else kept and named. More than one: the others are due, read at the next sync.
    const unrecorded = earlier === undefined ? this.unrecordedMoveTargets(vaultId) : [];
    if (unrecorded.length > 0) {
      discard = { vaultId: unrecorded[0]!.vaultId, name: unrecorded[0]!.name, copies: null };
      for (const t of unrecorded.slice(1)) this.halfMadeDue.set(t.vaultId, { name: t.name, copies: null });
      if (unrecorded.length > 1) await this.keepHalfMadeDue();
    }
    // The old vault was changed by a removal this move signed and the server stored (this run's, or an earlier run's,
    // whether this run carries that one on or not, kept at rest too): no stop says that it "wasn't changed".
    let oldChanged = prior?.removed === true || atRest?.removed === true || this.moveChangedOld.has(vaultId);
    // What became of the half-made vault dealt with before this run copied anything: said by every stop and the result.
    let discardedEarly: DiscardOutcome | null = null;
    const stop = (stage: MoveStage, cause: unknown, run: MoveRun | null, total = 0): MoveStoppedError =>
      new MoveStoppedError(stage, run?.copied.size ?? 0, total, name, run?.newVaultId ?? null, cause, waiting(), oldChanged, discardedEarly);

    // Spec 03 §14.4 and design §3.13: the move needs room for a second copy while both vaults exist. Before anything is
    // signed or written: short on any limit, and the move does not start. A run carried on counts only what it has not
    // copied yet, and makes no new vault.
    const room = quotaRoom(this.lastQuota, this.moveSize(vaultId, prior?.copied ?? null, prior === undefined ? name : null));
    if (room.kind === "short") throw new QuotaShortError(room.limits);

    // The remove the dialog was opened for, on a vault in good standing only.
    if (removing !== null && !plan.sourceStays && shared.logs.verifiedState(vaultId)?.members[removing] !== undefined) {
      // Only a remove the server stored counts; one held for re-posting stops the move here.
      let out: Awaited<ReturnType<VaultStore["logAction"]>>;
      try {
        out = await this.logAction(vaultId, { kind: "remove", member: removing });
      } catch (e) {
        throw stop("remove", e, null);
      }
      if (out.kind !== "appended") throw stop("remove", new ChangeNotStoredError(vaultId, "remove", out.known), null);
      oldChanged = true;
      this.moveChangedOld.add(vaultId);
      if (prior !== undefined) prior.removed = true;
    }

    // Design §3.13 as decided on 2026-11-18: a move that leaves out someone who holds a half-made vault's key never leaves
    // them holding copies without saying so. Before this run copies anything, the half-made vault of the earlier run it
    // does not carry on is read and deleted where it holds only that run's copies; otherwise it is named, with who can
    // still open it and the copies in it. One that could not be read stays due (and in this run's record), and is read
    // again at the end of the run and at later syncs.
    if (prior === undefined && (earlier !== undefined || unrecorded.length > 0)) {
      if (earlier !== undefined && earlier.discard !== null && earlier.discard.vaultId !== discard?.vaultId) {
        // The earlier run's own half-made vault, not dealt with yet: due, read at the next sync.
        this.halfMadeDue.set(earlier.discard.vaultId, { name: earlier.discard.name, copies: earlier.discard.copies });
        await this.keepHalfMadeDue();
      }
      if (discard !== null) {
        const half = discard;
        // Of a target found by its meta, the people its own log names are the ones who hold its key.
        const holdersOf = earlier !== undefined ? keyHolders(earlier) : Object.keys(shared.logs.verifiedState(half.vaultId)?.members ?? {});
        const outsiders = holdersOf.filter((u) => !allowed.has(u));
        const r = await this.discardAfterMove({ discard: half });
        if (r !== null && !r.deleted && r.notHeld !== true) {
          const members = shared.logs.verifiedState(half.vaultId)?.members ?? {};
          const holders = outsiders.map((u) => {
            const key = members[u]?.key;
            return key === undefined ? null : (shared.contacts.currentFor(u, key)?.labelText ?? null);
          });
          // Of a target found by its meta (its copies not known, so everything in it counts), the number said is what the
          // read from the server just counted ({@link foreignInHalfMade}): its items, the rows of its trash and what this
          // browser cannot read. Where that read failed there is no number to say.
          if (earlier === undefined) discardedEarly = { ...r, holders, found: true, ...(r.kept === true ? { copies: r.foreign ?? 0 } : {}) };
          else discardedEarly = { ...r, holders, copies: half.copies?.size ?? 0 };
        } else discardedEarly = r;
        if (r?.unread !== true) discard = null;
      }
    }

    // 1. The new vault. A genesis held for re-posting (the connection dropped) is re-posted on the retry, never made twice.
    let run = prior ?? null;
    try {
      if (run === null) {
        // The new vault says in its own sealed meta that it is this move's target (design §3.13 as decided on 2026-11-18).
        const out = await this.logAction(null, { kind: "create", name, moveOf: vaultId });
        run = { name, newVaultId: out.vaultId, copied: new Map(), added: new Set(), discard, removed: oldChanged, deleteHeld: false };
        this.moveRuns.set(vaultId, run);
        // Kept at rest from here on: after a lock, a reload or a closed tab the next move finds this vault.
        this.keepMoveRun(vaultId, run);
      } else if (shared.logs.verifiedState(run.newVaultId) === null) {
        // Only the new vault's own held genesis: a frame held for any other vault (the old one's delete above all) is
        // never re-posted as a side effect of this step.
        const again = await shared.logs.retryHeld(run.newVaultId);
        // The log as read after an answer that named no frame does not hold the genesis: the new vault was not made.
        if (again !== null && again.kind === "not_made") throw new LogActionError(again);
      }
      if (shared.logs.verifiedState(run.newVaultId) === null) {
        // Said as what is known of the held genesis; a genesis no longer held (refused, or never sent) was not made.
        const known = shared.logs.heldKnown(run.newVaultId);
        throw known !== null ? new ChangeNotStoredError(run.newVaultId, "create", known) : new ApiError(0, "network", "the new vault is not confirmed yet");
      }
      await this.reconcileAfterLogAction();
      if (!this.account.hasVault(run.newVaultId)) throw new ApiError(0, "network", "the new vault's key is not in use yet");
    } catch (e) {
      throw stop("create", e, run);
    }
    const target = run.newVaultId;

    // 2. Every item, copied (never moved: the old vault keeps its originals until it is deleted). An item that arrives
    //    while this runs is copied too: the list is read again until nothing is left. With the old vault's delete held,
    //    the old vault was read again (the sync above) and an item changed since its copy is copied again, over its own
    //    copy (the same item id in the new vault): the new vault holds its newest revision once, never two copies.
    const replacing = run.deleteHeld;
    const due = (it: { itemId: string; rev: number }): boolean => {
      const c = run!.copied.get(it.itemId);
      return c === undefined || (replacing && c.rev !== it.rev);
    };
    let total = 0;
    for (let pass = 0; pass < 3; pass++) {
      const items = this.openedItems()
        .filter((it) => it.vaultId === vaultId && due(it))
        .sort((a, b) => (a.itemId < b.itemId ? -1 : 1));
      total = run.copied.size + items.filter((it) => !run!.copied.has(it.itemId)).length;
      onProgress?.(run.copied.size, total);
      if (items.length === 0) break;
      for (const it of items) {
        const gKey = `${vaultId}|${it.itemId}|${target}`;
        let g = this.bulkGestures.get(gKey);
        if (!g || g.sourceRev !== it.rev) {
          g = this.newMoveGesture(it.itemId, target, false);
          const earlierCopy = run.copied.get(it.itemId);
          const copyNow = earlierCopy === undefined ? undefined : this.openedItem(earlierCopy.copyId);
          if (earlierCopy !== undefined && copyNow !== undefined && copyNow.vaultId === target) {
            g.newItemId = earlierCopy.copyId;
            g.replacesRev = copyNow.rev;
          }
          this.bulkGestures.set(gKey, g);
        }
        let copyRev: number | null;
        try {
          copyRev = await this.runGesture(g, undefined, false);
        } catch (e) {
          throw stop("copy", e, run, total);
        }
        run.copied.set(it.itemId, { rev: g.sourceRev, copyId: g.newItemId, copyRev });
        this.keepMoveRun(vaultId, run);
        this.bulkGestures.delete(gKey);
        onProgress?.(run.copied.size, total);
      }
      await this.reconcileAfterLogAction();
    }

    // 3. The remaining members, each with the role they hold now. One that this browser cannot add is named.
    const notAdded: string[] = [];
    const verifiedNow = (): VaultState | null => shared.logs.verifiedState(target);
    // An add held from an earlier run is re-posted first; only what the verified log shows counts as added. Only the
    // new vault's held frame: the old vault's held delete waits for step 4's checks. Only the move's own step: anything
    // else held for the new vault (the person's own deletion of it) waits for their word like any other.
    await shared.logs.retryMoveStep(target).catch(() => null);
    for (const userId of add) {
      if (verifiedNow()?.members[userId] !== undefined) {
        run.added.add(userId);
        this.keepMoveRun(vaultId, run);
        continue;
      }
      const m = byId.get(userId)!;
      if (!m.canBeAdded) {
        notAdded.push(userId);
        continue;
      }
      // Only an add the server stored counts: one whose answer never came (held for re-posting) stops the move at
      // "add", so no member ends up in neither vault.
      let out: Awaited<ReturnType<VaultStore["logAction"]>>;
      try {
        // The move's own step: never withdrawn one by one (its run decides).
        out = await this.logAction(target, { kind: "add", contactUserId: userId, role: m.role, releaseUncompared: false }, { moveStep: true });
      } catch (e) {
        if (e instanceof LogActionError && e.outcome.kind === "not_allowed" && (e.outcome.reason === "not_compared" || e.outcome.reason === "not_a_current_contact")) {
          notAdded.push(userId);
          continue;
        }
        throw stop("add", e, run, total);
      }
      run.added.add(userId); // from here they may hold the new vault's key, stored or not
      this.keepMoveRun(vaultId, run);
      if (out.kind !== "appended") throw stop("add", new ChangeNotStoredError(target, "add", out.known), run, total);
    }
    // On a vault in good standing every remaining member is added again (§3.13); one left out keeps the old vault.
    if (!plan.sourceStays) for (const m of plan.members) if (!add.includes(m.userId) && !notAdded.includes(m.userId)) notAdded.push(m.userId);
    await this.reconcileAfterLogAction();

    // 4. The old vault, deleted into its grace: only on a vault in good standing, and only when nothing is left behind.
    // The old vault is read once more after the adds; an item new in it, or changed since its copy,
    // exists only there, so the old vault is kept ("changed meanwhile"). A read that fails stops before the delete.
    if (!plan.sourceStays) {
      try {
        await this.sync();
      } catch (e) {
        throw stop("delete", e, run, total);
      }
    }
    // The head these checks are made on: the delete is signed over it or not at all (core StoredVaultLogs.append's
    // expectHead, as the app interface calls it for the move's delete). A change stored and read in between (a member's
    // leave, an add) is a log that moved on: nothing is signed, and the old vault is kept, "changed meanwhile".
    const checkedHead = shared.logs.verifiedState(vaultId)?.head ?? null;
    // The sync position of the read these checks rest on: the delete names it at every sending (spec 03 §10.3), and the
    // server refuses it when an item of the old vault changed after it (a member saved there between this read and the
    // delete). Nothing is then stored and nothing is held: the old vault is kept, "changed meanwhile".
    const point = this.cursor;
    let itemsMoved = false;
    const changed = this.openedItems().filter((it) => it.vaultId === vaultId && run!.copied.get(it.itemId)?.rev !== it.rev).length;
    const uncopyable = this.undecryptable().filter((u) => u.vaultId === vaultId).length;
    // Never while someone holds the new vault's key who is not among the people this move adds.
    const membersDiffer = !keyHolders(run).every((u) => allowed.has(u));
    let deleted: { purgeAt: number | null } | null = null;
    // Every check passed but the old vault's log moved on before the delete was signed: nothing was signed.
    let movedOn = false;
    const deleteIsDue = !plan.sourceStays && notAdded.length === 0 && uncopyable === 0 && !membersDiffer && changed === 0;
    if (deleteIsDue) {
      // The old vault counts as deleted only when the server stored its `delete`. A frame held for the old vault (this
      // move's own delete from an earlier run, or another change) is re-posted first, now that the checks above passed;
      // an answer that never comes again stops the move here, with the old vault still there.
      let out: AppendOutcome | null;
      try {
        out = shared.logs.holds(vaultId) ? await shared.logs.retryHeld(vaultId, point) : null;
        if (out !== null && (out.kind === "head_moved" || out.kind === "not_made" || out.kind === "items_moved")) {
          // Another change took the held delete's place between the look and the re-post (or the log read after an answer
          // that named no frame does not hold it): it is dropped (spec 03 §10.3), and the next run is an ordinary one.
          run.deleteHeld = false;
          this.keepMoveRun(vaultId, run);
        }
        if (out?.kind === "items_moved") itemsMoved = true;
        else if (out?.kind === "read_only") {
          // The re-post's read found the server contradicting its word: the old vault froze, and the deletion was dropped.
          const frozenStop = this.frozenMoveStop(vaultId, name);
          if (frozenStop !== null) throw frozenStop;
          throw new LogActionError(out);
        } else if (out !== null && out.kind !== "pending" && out.kind !== "appended") throw new LogActionError(out);
        if (!itemsMoved && (out === null || (out.kind === "appended" && out.state.deleteId === null))) {
          try {
            out = await this.logAction(vaultId, { kind: "delete" }, { forMove: true, itemsAtMost: point, ...(checkedHead !== null ? { expectHead: checkedHead } : {}) });
          } catch (e) {
            if (e instanceof LogActionError && e.outcome.kind === "items_moved") itemsMoved = true;
            else if (!(e instanceof LogActionError && e.outcome.kind === "not_allowed" && e.outcome.reason === "log_moved_on")) throw e;
            else movedOn = true; // nothing was signed: the old vault is kept, and the next run reads it again
          }
        }
      } catch (e) {
        if (e instanceof MoveStoppedError) throw e;
        // The deletion signed just now froze the old vault at its own read (the server answered it stored and its log
        // shows another entry there): dropped with the freeze, and the move says so.
        if (e instanceof LogActionError && e.outcome.kind === "read_only" && shared.logs.status(vaultId).kind === "frozen") {
          run.deleteHeld = true;
          this.moveRuns.set(vaultId, run);
          const frozenStop = this.frozenMoveStop(vaultId, name);
          if (frozenStop !== null) throw frozenStop;
        }
        throw stop("delete", e, run, total);
      }
      if (!movedOn && !itemsMoved) {
        if (out === null || out.kind !== "appended") {
          // Signed and not known to be stored: it cannot be taken back. Only this move re-posts it; the run is kept beside
          // it, so a reload or an unlock offers to finish the move.
          run.deleteHeld = true;
          this.keepMoveRun(vaultId, run);
          throw stop("delete", new ChangeNotStoredError(vaultId, "delete", out?.kind === "pending" ? out.known : (shared.logs.heldKnown(vaultId) ?? "unknown")), run, total);
        }
        run.deleteHeld = false;
        this.keepMoveRun(vaultId, null);
        deleted = await this.afterOwnDelete(vaultId);
      }
    } else if (run.deleteHeld && shared.logs.holds(vaultId)) {
      // This move's delete is signed and held, and something is left that this run could not settle (someone left out, an
      // item this browser cannot read): a signed frame is never withdrawn (spec 03 §10.3), so the move cannot say the old
      // vault is kept. It stops at the delete step, the delete still waiting.
      throw stop("delete", new ChangeNotStoredError(vaultId, "delete", shared.logs.heldKnown(vaultId) ?? "unknown"), run, total);
    }
    this.moveRuns.delete(vaultId);
    this.moveChangedOld.delete(vaultId);
    this.keepMoveRun(vaultId, null);
    // The half-made vault dealt with before the copies, or (one that could not be read then and is still due, or one
    // carried in a run from before that rule) read now.
    const late = run.discard !== null && (discardedEarly === null || this.halfMadeDue.has(run.discard.vaultId)) ? await this.discardAfterMove(run) : null;
    const discarded = late === null ? discardedEarly : late.deleted || discardedEarly === null ? late : { ...late, holders: discardedEarly.holders, copies: discardedEarly.copies, ...(discardedEarly.found === true ? { found: true as const } : {}) };
    const oldKept =
      deleted !== null ? null : plan.sourceStays ? "source_stays" : notAdded.length > 0 ? "not_added" : uncopyable > 0 ? "uncopyable" : membersDiffer ? "members_differ" : movedOn ? "moved_on" : "changed_meanwhile";
    return { newVaultId: target, name, copied: run.copied.size, oldDeleted: deleted, oldKept, notAdded, added: run.added.size, uncopyable, changed, discarded };
  }

  /**
   * The half-made vault of [earlier] (a stopped run of the move of [vaultId] that the next run does not carry on into),
   * with every copy that run made in it: those it recorded, at the revision the server answered, and those whose copy
   * was sent and not answered (their gesture kept for a retry), whose revision is not known.
   */
  /**
   * The vaults this account made as targets of a move out of [oldVaultId] ({@link VAULT_META_MOVE_OF} in their sealed
   * meta), other than those already due as half-made: what an earlier run left where this browser kept no record of it.
   */
  private unrecordedMoveTargets(oldVaultId: string): { vaultId: string; name: string }[] {
    const out: { vaultId: string; name: string }[] = [];
    for (const v of this.vaults()) {
      if (v.vaultId === oldVaultId || this.halfMadeDue.has(v.vaultId) || !this.logGoverns(v.vaultId)) continue;
      if (this.shared?.logs.verifiedState(v.vaultId)?.creator !== this.account.userId) continue;
      const blob = this.vaultsById.get(v.vaultId)?.metaBlob;
      if (blob === undefined) continue;
      let moveOf: unknown;
      try {
        moveOf = this.account.decryptVaultMeta(v.vaultId, blob)[VAULT_META_MOVE_OF];
      } catch {
        continue;
      }
      if (moveOf === oldVaultId) out.push({ vaultId: v.vaultId, name: v.name });
    }
    return out;
  }

  private halfMadeOf(vaultId: string, earlier: MoveRun): HalfMade {
    const copies = new Map<string, number | null>();
    for (const c of earlier.copied.values()) copies.set(c.copyId, c.copyRev);
    for (const [k, g] of this.bulkGestures) if (k.startsWith(`${vaultId}|`) && g.targetVaultId === earlier.newVaultId && !copies.has(g.newItemId)) copies.set(g.newItemId, null);
    return { vaultId: earlier.newVaultId, name: earlier.name, copies };
  }

  /**
   * {@link discardHalfMade} at the end of a move's run. A half-made vault that could not be read stays due: the next
   * sync reads it again and decides ({@link discardDueHalfMade}), so the line can say that it is checked again later.
   */
  private async discardAfterMove(run: { readonly discard: HalfMade | null }): Promise<DiscardOutcome | null> {
    const r = await this.discardHalfMade(run);
    if (r?.unread === true && run.discard !== null && this.account.hasVault(run.discard.vaultId)) {
      this.halfMadeDue.set(run.discard.vaultId, { name: run.discard.name, copies: run.discard.copies });
      await this.keepHalfMadeDue();
    }
    return r;
  }

  /**
   * The items of [half] (as this browser holds them from the server's last answer) that are not a copy the move made at
   * the revision it made it: an item someone saved there, a copy changed since, an item this browser cannot read, and,
   * where no record of the copies is kept or a copy's revision is not known, any item at all; and each row of its trash
   * ([trashed], as the server's trash lists it) that is not one of the move's copies.
   */
  private foreignInHalfMade(half: HalfMade, trashed: readonly string[]): number {
    let n = 0;
    for (const it of this.itemsById.values()) {
      if (it.vaultId !== half.vaultId) continue;
      const rev = half.copies?.get(it.itemId);
      if (rev === undefined || rev === null || rev !== it.rev) n++;
    }
    // Its trash, as read from the server: a row there that is not one of the move's copies counts like a live one (a
    // member's own item they put in the trash would go with the vault). A copy in the trash is the move's own.
    for (const itemId of trashed) if (half.copies?.has(itemId) !== true) n++;
    return n + this.undecryptable().filter((u) => u.vaultId === half.vaultId).length;
  }

  /**
   * Design §3.13 as decided on 2026-11-18: the half-made vault of the run [run] replaced, once that run finished.
   * Its own held frame (an add whose answer never came) is re-posted first. Then it is READ from the server (a pull):
   * only where it holds nothing but the copies the earlier run made, each at the revision it made it, is it deleted, and
   * it counts as deleted only when the server stored the delete. Where anything else is in it (a member that run added
   * may have saved items there), it is not deleted: it stays a vault of its own (`kept`). Where it cannot be read, it is
   * not deleted either (`unread`), and nothing is said of what it holds.
   */
  private async discardHalfMade(run: { readonly discard: HalfMade | null }): Promise<DiscardOutcome | null> {
    if (run.discard === null) return null;
    const half = run.discard;
    // The deletion names the point up to which the read that decided it saw the vault's items (spec 03 §10.3), and the
    // server refuses it when an item of the vault changed after that point (another member saved there between the read
    // and the deletion). Nothing is then stored and nothing is held: the vault is read again and judged by the same rule.
    for (let round = 0; round < HALF_MADE_READS_MAX; round++) {
      const r = await this.judgeHalfMade(half);
      if (r !== "items_moved") return r;
    }
    // Its items changed after every read: nothing was deleted, and it is read again later, as a vault not read.
    return { vaultId: half.vaultId, name: half.name, deleted: false, unread: true };
  }

  /** One read of [half] and the decision on it ({@link discardHalfMade}); `items_moved` where the server refused the deletion. */
  private async judgeHalfMade(half: HalfMade): Promise<DiscardOutcome | "items_moved"> {
    const named = { vaultId: half.vaultId, name: half.name };
    let gone = false;
    let waiting = false;
    const logs = this.shared!.logs;
    // Read first, posting nothing: a held frame of this vault (an add of the earlier run, or this deletion signed by an
    // earlier attempt) is sent again only once the read showed nothing but the copies.
    let trashed: string[];
    let point: number;
    try {
      await this.pull();
      // The read that decides is never older than what this browser was told: a newer change a bell announced while
      // that pull was in flight (one fetched before the change) is read as well before anything is decided, as sync() does.
      if (this.bellRev > this.cursor) await this.pull();
      // The sync position of that read: the deletion names it.
      point = this.cursor;
      // The vault's trash is part of what it holds: a trash that cannot be read is a vault not read.
      trashed = (await this.wire.deletedItems()).items.filter((d) => d.vaultId === half.vaultId).map((d) => d.itemId);
    } catch (e) {
      console.warn("the half-made vault of a stopped move could not be read, so it was not deleted", e);
      return { ...named, deleted: false, unread: true };
    }
    // A deletion of it held from an earlier attempt is looked for in the log first (nothing is posted): stored after all,
    // and the vault is gone already.
    if (logs.heldChange(half.vaultId)?.kind === "delete") {
      const look = await logs.lookHeld(half.vaultId).catch(() => null);
      if (look?.kind === "appended" && look.state.deleteId !== null) return { ...named, deleted: true };
    }
    // No longer among this account's vaults as read just now: nothing is deleted on what it cannot see, and nothing is
    // checked again later (it is not due), so it is not said as "not read".
    if (!this.account.hasVault(half.vaultId)) return { ...named, deleted: false, notHeld: true };
    const foreign = this.foreignInHalfMade(half, trashed);
    if (foreign > 0) {
      // It stays a vault of its own: a deletion of it held from an earlier attempt is dropped and never sent.
      logs.dropHeldHalfMadeDelete(half.vaultId);
      return { ...named, deleted: false, kept: true, foreign };
    }
    try {
      // A held deletion is sent with the point of the read just made, not the one it kept.
      const again = logs.holds(half.vaultId) ? await logs.retryHeld(half.vaultId, point) : null;
      if (again?.kind === "items_moved") return "items_moved";
      // The held frame was this very deletion (an earlier attempt's), and the server has it now.
      if (again?.kind === "appended" && again.state.deleteId !== null) gone = true;
      // It was, and its answer is lost again: still held, sent again only after the next read.
      else if (again?.kind === "pending" && logs.heldChange(half.vaultId)?.kind === "delete") throw new ChangeNotStoredError(half.vaultId, "delete", again.known);
      else await this.deleteHalfMadeVault(half.vaultId, half.copies, point);
      gone = true;
    } catch (e) {
      if (e instanceof LogActionError && e.outcome.kind === "items_moved") return "items_moved";
      // Said from what is known of the delete: stored by the server's own answer (deleted, not read back yet), or held
      // and sent again after the next read of the vault (waiting), or not made (refused, not sent, or not signed at all).
      if (e instanceof ChangeNotStoredError && e.action === "delete") {
        if (e.known === "stored") gone = true;
        else waiting = true;
      } else {
        console.warn("the half-made vault of a stopped move was not deleted", e);
      }
    }
    return { ...named, deleted: gone, ...(waiting ? { waiting: true } : {}) };
  }

  /**
   * Half-made vaults of moves whose old vault's deletion was seen stored outside a run of the move ({@link moveStoredOutside}).
   * Kept in this browser's copy too ({@link keepHalfMadeDue}, read again at {@link hydrate}), so a reload before the
   * deletion lands does not forget them; with no copy, the session's memory only.
   */
  private readonly halfMadeDue = new Map<string, { name: string; copies: ReadonlyMap<string, number | null> | null }>();
  private discardingHalfMade = false;

  /** Writes {@link halfMadeDue} (each id with the copies) to the copy. A failed write is said in the console and kept in memory. */
  private async keepHalfMadeDue(): Promise<void> {
    if (!this.cache.durable) return;
    try {
      const rows = [...this.halfMadeDue].map(([vaultId, d]) => ({ vaultId, copies: d.copies === null ? null : [...d.copies] }));
      if (!(await this.cache.setHalfMadeDue(rows))) console.warn("the half-made vaults waiting for deletion were not kept in the copy (kept in memory)");
    } catch (e) {
      console.warn("the half-made vaults waiting for deletion were not kept in the copy (kept in memory)", e);
    }
  }

  /**
   * Deletes each half-made vault in {@link halfMadeDue}, once per sync, after the pull that found its move over, under
   * {@link discardHalfMade}'s rule (read first; deleted only while it holds nothing but the move's copies). One that
   * is not deleted (not read, no answer, the server refused) is tried again at the next sync while this session lasts.
   * One that holds something the move did not make is not deleted and no longer due: it stays a vault of its own, and a
   * notice says so with its name (`half-made-kept`).
   */
  private async discardDueHalfMade(): Promise<void> {
    if (this.discardingHalfMade || this.halfMadeDue.size === 0 || this.closed || this.readOnlyCopy) return;
    this.discardingHalfMade = true;
    try {
      const before = this.halfMadeDue.size;
      for (const [vaultId, due] of [...this.halfMadeDue]) {
        this.halfMadeDue.delete(vaultId);
        if (!this.account.hasVault(vaultId)) {
          // Gone from this account (its deletion stored, by this browser or another): a deletion of it still held is
          // looked for in its log (nothing is posted), so that the record goes once the log shows it.
          if (this.shared?.logs.heldChange(vaultId)?.kind === "delete") await this.shared.logs.lookHeld(vaultId).catch(() => null);
          continue;
        }
        const name = due.name || (this.heldNames().get(vaultId) ?? "");
        const r = await this.discardHalfMade({ discard: { vaultId, name, copies: due.copies } });
        if (r?.kept === true) {
          this.pushNotice({ id: crypto.randomUUID(), vaultId, vaultName: name, kind: "half-made-kept", parkedCount: r.foreign ?? 0 });
          continue;
        }
        if (r !== null && !r.deleted && this.account.hasVault(vaultId)) this.halfMadeDue.set(vaultId, { name, copies: due.copies });
      }
      if (this.halfMadeDue.size !== before) await this.keepHalfMadeDue();
    } finally {
      this.discardingHalfMade = false;
    }
  }

  /**
   * The store's one place where changes to items leave this browser: every push of the store goes through here. (The
   * only other is the one attempt before a policy's wipe, vault/policywipe.ts, which asks the same question; the closed
   * list of every send is api/sends.ts.) A change of a vault this browser may not write to now ({@link mayWrite}) is
   * never sent, whatever its kind (a put, a delete, a step of a move): the queue's drain leaves such rows queued
   * ({@link flushChunk}), and any other caller is refused here.
   */
  private async sendItemChanges(mutations: Mutation[]): Promise<PushResponse> {
    for (const m of mutations) this.refuseUnlessMayWrite(m.vaultId);
    return this.wire.pushMutations(mutations);
  }

  /** An attachment's upload into [vaultId]: asked {@link mayWrite} like every change. */
  private async uploadInto(vaultId: string, id: string, itemId: string, body: Uint8Array): Promise<AttachmentMeta> {
    this.refuseUnlessMayWrite(vaultId);
    return this.wire.uploadAttachment(id, itemId, vaultId, body);
  }

  private async push(mutations: Mutation[]): Promise<PushResponse> {
    const resp = await this.sendItemChanges(mutations);
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
      if (r.status === "conflict" && m?.op === "put" && r.serverItem?.deleted === true) {
        this.noteBroughtBack(m, r.newItemRev);
      } else if (r.status === "conflict" && m?.op === "put" && r.serverItem && r.newItemRev != null) {
        displaced.push({ item: r.serverItem, winnerRev: r.newItemRev, pushedVaultId: m.vaultId });
      } else if (r.status === "conflict" && m?.op === "put" && r.serverItemOmitted === true && r.newItemRev != null) {
        const d = await this.displacedFromHistory(m.itemId, m.vaultId, r.newItemRev);
        if (d !== null) displaced.push(d);
      }
    }
    for (const d of displaced) await this.materializeConflictFromServerItem(d);
    return resp;
  }
}
