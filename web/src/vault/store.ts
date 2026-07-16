import type { ApiClient } from "../api/client";
import { ApiError } from "../api/client";
import type {
  AttachmentRef,
  ItemDoc,
  Mutation,
  PendingTransfer,
  PushResponse,
  RemovedGrantInfo,
  WireGrant,
  WireItem,
  WireVault,
} from "../api/types";
import { HEADER_BYTES, decryptAttachment, encryptAttachment } from "../crypto/attachments";
import { concat, fromB64, toB64, toHexLower, utf8 } from "../crypto/bytes";
import {
  acceptProof,
  acceptProofFromHash,
  deleteProof,
  offerProof,
  removeProof,
  restoreProof,
  verifyProof,
} from "../crypto/lifecycleproof";
import { randomBytes, sha256 } from "../crypto/provider";
import type { ImportProjections } from "../import/csv";
import { ITEM_FORMAT_VERSION, type Account } from "./account";
import { type HeldVaultRecord, NullCache, type PullBatch, type QueuedPreEdit, type VaultCache } from "./idbcache";

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
    | "meta-regression";
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
  /** transfer-complete: who now owns the vault, and whether that is us. */
  newOwnerUserId?: string;
  becameMine?: boolean;
}

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
  private _lastSyncAt: number | null = null;

  // ---- vault lifecycle state (spec 03 §11) ----
  /** Soft-hidden removed vaults (ciphertext-only), keyed by vaultId — the holding area. */
  private holding = new Map<string, HeldVault>();
  /** deleteIds we have seen consumed by a restore — a later tombstone bearing one is stale. */
  private consumedDeleteIds = new Set<string>();
  /** Notices awaiting the UI banner. */
  private noticeList: LifecycleNotice[] = [];
  /** Vaults this device just deleted/left — drop them cleanly on the reconcile pull (no banner). */
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
  /** F20: shared vaults whose grant this device can't open (sealed to a key we don't hold, or a
   *  newer grant format). A PERSISTENT, non-dismissable warning — distinct from the dismissable
   *  lifecycle notices; cleared automatically when a later pull opens the grant, the grant is
   *  revoked, or a resync no longer re-delivers it. */
  private undecryptableGrants = new Set<string>();

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
   *  destroy — App.signOut BLOCKS on a confirm carrying this count before a user sign-out,
   *  and surfaces it on a definitive-401 wipe it cannot block. */
  async queuedMutationCount(): Promise<number> {
    const [pending, staged] = await Promise.all([this.cache.pending(), this.cache.stagedDenied()]);
    return pending.length + staged.length;
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
  ) {
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

  /** Vaults whose key we hold, personal first then shared by name. */
  vaults(): VaultInfo[] {
    const out: VaultInfo[] = [];
    for (const v of this.vaultsById.values()) {
      if (!this.account.hasVault(v.vaultId)) continue; // no key → nothing usable
      const name = this.account.decryptVaultName(v.vaultId, v.metaBlob);
      out.push({
        vaultId: v.vaultId,
        type: v.type,
        name: name && name !== "(vault)" ? name : v.type === "personal" ? "Personal" : "Shared",
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
    this.syncInFlight ??= this.pullOnce().finally(() => {
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
        if (!heldBefore) this.undecryptableGrants.add(grant.vaultId);
      }
    }
    for (const delivered of resp.vaults) {
      // spec 02 §4 warn-and-keep-newer: a delivered metaBlob whose metaV regressed keeps
      // the newer local blob (rev/lifecycle fields still apply).
      const vault = this.keepNewerMeta(delivered);
      this.vaultsById.set(vault.vaultId, vault);
      ops.push((b) => b.upsertVault(vault)); // the merged keepNewerMeta row — disk mirrors memory
      // Discover the personal vault so save()/encrypt default to it.
      if (vault.type === "personal" && this.account.hasVault(vault.vaultId)) {
        this.account.setPersonalVault(vault.vaultId);
      }
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
      if (!v || v.type === "personal" || !this.account.hasVault(vaultId)) continue;
      // An owner grant is our OWN wrappedVk (opened under the UVK), so a second active device sees
      // a vault THIS account just created as a brand-new grant. "You were added to X" would be a
      // lie there. Ownership handed TO us arrives on a vault we already held (promotion), so it is
      // already excluded by heldBefore — and it emits its own transfer-complete notice regardless.
      if (this.account.roleFor(vaultId) === "owner") continue;
      this.addedNoticed.add(vaultId);
      this.pushNotice({ id: crypto.randomUUID(), vaultId, vaultName: this.account.decryptVaultName(vaultId, v.metaBlob), kind: "added" });
    }

    const conflictsToMaterialize: WireItem[] = [];
    for (const item of resp.items) {
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
        if (this.itemsById.has(wi.itemId)) continue;
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
          const displaced: { item: WireItem; winnerRev: number }[] = [];
          for (let i = 0; i < replayMutations.length; i += VaultStore.SERVER_BATCH_MAX) {
            await this.flushChunk(replayMutations.slice(i, i + VaultStore.SERVER_BATCH_MAX), displaced);
          }
          for (const d of displaced) await this.materializeConflictFromServerItem(d.item, d.winnerRev);
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
    const displaced: { item: WireItem; winnerRev: number }[] = []; // PDD-1: (losing serverItem, winner rev)
    for (;;) {
      const chunk = (await this.cache.pending()).slice(0, VaultStore.SERVER_BATCH_MAX);
      if (chunk.length === 0) break;
      const progressed = await this.flushChunk(chunk, displaced); // rejects offline → propagates
      if (!progressed) break; // defensive: the server returns one result per mutation
    }
    for (const d of displaced) await this.materializeConflictFromServerItem(d.item, d.winnerRev);
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
  private async flushChunk(chunk: Mutation[], displaced: { item: WireItem; winnerRev: number }[]): Promise<boolean> {
    const resp = await this.api.push(chunk); // rejects offline → propagates; rows stay queued
    const byId = new Map(resp.results.map((r) => [r.mutationId, r]));
    let progressed = false;
    for (const m of chunk) {
      const r = byId.get(m.mutationId);
      if (!r) continue;
      // C1: settled either way — a reinstate-replayed row's denial gets the calm-notice tag
      // (core flushQueue's `replayedMutationIds.remove` shape).
      const wasReplay = this.replayedMutationIds.delete(m.mutationId);
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
          displaced.push({ item: r.serverItem, winnerRev: r.newItemRev });
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
      if (item.deleted) this.missingVkById.delete(item.itemId);
      else this.missingVkById.set(item.itemId, { itemId: item.itemId, vaultId: item.vaultId, formatVersion: item.formatVersion });
      return;
    }
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
        // pull maintains; cleared when a later pull delivers an openable grant.
        this.undecryptableGrants.add(grant.vaultId);
      }
    }
    for (const vault of await this.cache.vaults()) {
      this.vaultsById.set(vault.vaultId, vault);
      // Discover the personal vault so save()/encrypt default to it (pull parity).
      if (vault.type === "personal" && this.account.hasVault(vault.vaultId)) {
        this.account.setPersonalVault(vault.vaultId);
      }
    }
    for (const item of await this.cache.envelopes()) this.applyWireItem(item);
    for (const rec of await this.cache.heldVaults()) {
      this.holding.set(rec.vault.vaultId, { ...rec, cachedName: this.peekHeldName(rec) });
    }
    for (const id of await this.cache.consumedDeleteIds()) this.consumedDeleteIds.add(id);
    for (const t of await this.cache.transferSeqs()) this.lastTransferSeqSeen.set(t.vaultId, t.seq);
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

  /** The row's plaintext `metaV` (spec 02 §4): it counts ONLY when it is an integral,
   *  non-negative JSON number, else 0 — a string-encoded/fractional/negative value must
   *  read identically on every client (the same read buildRenameMeta uses), or one impl
   *  pins while another applies, forking the fleet in exactly the adversarial anti-replay
   *  path this guard exists for. Core twin: SyncEngine.metaV. */
  private metaVOf(vaultId: string, metaBlob: string): number {
    const meta = this.account.decryptVaultMeta(vaultId, metaBlob);
    const v = meta.metaV;
    return typeof v === "number" && Number.isInteger(v) && v >= 0 ? v : 0;
  }

  private async materializeConflict(item: WireItem): Promise<void> {
    const winner = this.itemsById.get(item.itemId);
    if (!winner) return;
    // PDD-1: the CORRECT conflict copy is built from the DISPLACED (losing) version, which
    // only the pushing client receives (materializeConflictFromServerItem, below). On a plain
    // pull we hold only the winner, so this path is a FALLBACK plus the flag-clearer: if the
    // push side already materialized the copy (deterministic id over (itemId, rev), spec 03
    // §5), skip re-creating it and just clear the flag with the live winner; otherwise (the
    // conflict was caused by a client that didn't materialize) preserve at least the winner so
    // clearing the flag doesn't erase the only trace.
    const copyId = await conflictCopyId(item.itemId, item.rev);
    const mutations: Mutation[] = [];
    if (!this.itemsById.has(copyId)) {
      const stamp = new Date(item.updatedAt).toISOString().slice(0, 10);
      const copyDoc: ItemDoc = { ...winner.doc, name: `${winner.doc.name} (conflict ${stamp})` };
      mutations.push(this.putMutation(copyId, item.vaultId, copyDoc, 0));
    }
    mutations.push(this.putMutation(item.itemId, item.vaultId, winner.doc, winner.rev)); // clears conflict flag
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
  private async materializeConflictFromServerItem(losing: WireItem, winnerRev: number): Promise<void> {
    if (this.account.roleFor(losing.vaultId) === "reader") return; // a reader's push would be denied
    let losingDoc: ItemDoc;
    try {
      losingDoc = this.account.decryptItem(losing);
    } catch {
      return; // losing version under a held key (formatVersion too new) — nothing safe to copy
    }
    const copyId = await conflictCopyId(losing.itemId, winnerRev);
    if (this.itemsById.has(copyId)) return; // already materialized
    const stamp = new Date(losing.updatedAt).toISOString().slice(0, 10);
    const copyDoc: ItemDoc = { ...losingDoc, name: `${losingDoc.name} (conflict ${stamp})` };
    await this.push([this.putMutation(copyId, losing.vaultId, copyDoc, 0)]);
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
    // A stale/replayed tombstone of an already-restored vault: keep it live, do not re-warn.
    if (info?.reason === "deleted" && info.deleteId && this.consumedDeleteIds.has(info.deleteId)) return;

    // Unverifiable: the VK was not held before this pull (fresh device, F20-hidden grant, or a
    // since=0 / resync pull) → silent no-op. Drop any stray unusable row.
    if (cachedName === undefined || since === 0 || resyncing) {
      this.hardDropLocal(vaultId);
      return;
    }

    // This device initiated the delete/leave — drop cleanly, no banner (§4 / §13).
    if (this.suppressDrop.delete(vaultId)) {
      this.hardDropLocal(vaultId);
      return;
    }

    const reason: RemovedReason = info?.reason ?? "removed";
    const verdict: "valid" | "anomaly" | "left" =
      reason === "left" ? "left" : (await this.verifyRemoval(vaultId, reason, info)) ? "valid" : "anomaly";

    // Snapshot ciphertext + move to holding BEFORE forgetting the VK.
    const parkedCount = this.moveToHolding(vaultId, reason, info, verdict === "valid", cachedName);

    if (verdict === "left") {
      this.pushNotice({ id: crypto.randomUUID(), vaultId, vaultName: cachedName, kind: "left" });
    } else if (verdict === "anomaly") {
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

  /** Verify the relayed removal/delete proof under the still-held VK (spec 03 §11). */
  private async verifyRemoval(vaultId: string, reason: RemovedReason, info: RemovedGrantInfo | undefined): Promise<boolean> {
    if (!info) return false; // a bare revocation of a held vault is never "valid"
    try {
      const key = await this.account.lifecycleKeyFor(vaultId);
      if (reason === "deleted") {
        if (!info.deleteProof || !info.deleteId) return false;
        return verifyProof(info.deleteProof, await deleteProof(key, vaultId, info.deleteId));
      }
      // 'removed' / 'transferred': verify the optional removal proof over (vaultId, me, nonce).
      if (!info.removeProof || !info.removeNonce) return false;
      return verifyProof(info.removeProof, await removeProof(key, vaultId, this.account.userId, info.removeNonce));
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
      const upload = this.account.encryptItem(vaultId, it.itemId, it.doc);
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
   *  AND its queued mutations. */
  private hardDropLocal(vaultId: string): void {
    for (const it of [...this.itemsById.values()]) if (it.vaultId === vaultId) this.itemsById.delete(it.itemId);
    for (const it of [...this.undecryptableById.values()]) if (it.vaultId === vaultId) this.undecryptableById.delete(it.itemId);
    for (const it of [...this.missingVkById.values()]) if (it.vaultId === vaultId) this.missingVkById.delete(it.itemId);
    this.vaultsById.delete(vaultId);
    this.grantWireByVault.delete(vaultId);
    this.incomingByVault.delete(vaultId);
    this.undecryptableGrants.delete(vaultId); // F20: access gone → the "can't open" warning is moot
    this.account.removeVault(vaultId);
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

  private pushNotice(n: LifecycleNotice): void {
    // Collapse a repeat notice for the same vault+kind (idempotent re-pulls).
    this.noticeList = this.noticeList.filter((x) => !(x.vaultId === n.vaultId && x.kind === n.kind));
    this.noticeList.push(n);
  }

  putMutation(itemId: string, vaultId: string, doc: ItemDoc, baseItemRev: number): Mutation {
    // The wire fv is read back from the upload — ONE encryptItem computes it (per-doc floor,
    // monotonic reseal) and binds it into the AD, so the two can never diverge.
    const upload = this.account.encryptItem(vaultId, itemId, doc);
    return {
      mutationId: crypto.randomUUID(),
      op: "put",
      itemId,
      vaultId,
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
      const up = this.account.encryptItem(pre.vaultId, pre.itemId, pre.doc);
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
        const up = this.account.encryptItem(existing.vaultId, id, existing.doc); // re-seal the pre-edit value
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
   * An EXISTING item always stays in its own vault (the server enforces `vault_mismatch`);
   * a new item goes to [vaultId] when given, else the personal vault.
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
    const targetVaultId = existing?.vaultId ?? vaultId ?? this.account.personalVaultId;
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

    const m = this.putMutation(id, targetVaultId, doc, existing?.rev ?? 0);
    let mayQueue = newFiles.length === 0 && (await this.offlineQueueAllowed());

    const committedAt = Date.now();
    const optimisticRev = (existing?.rev ?? 0) + 1; // the reconcile pull trues the rev up
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
    const enqueued = await this.cache.enqueue(m, this.durablePreEdit(existing ?? null, "put", optimisticRev, committedAt));
    if (!enqueued) {
      this.demoteCache(); // no-op if already cache-less; else sever the dead handle
      mayQueue = false; // this write can't be durably queued — do the real send or refuse
    }
    // Optimistic apply — memory AND disk — so the item renders immediately with a "pending
    // sync" mark and survives a restart (the queue row carries the mutation, not the envelope).
    // C2 (a): the pre-edit truth, keyed by mutationId — if this write is later classified a
    // GENUINE denial, surfaceStagedDenials restores exactly this (memory + disk) so the
    // refused value cannot outlive its refusal.
    this.preEditByMutation.set(m.mutationId, { pre: existing ?? null, op: "put", optimisticRev, optimisticUpdatedAt: committedAt });
    this.itemsById.set(id, { itemId: id, vaultId: targetVaultId, rev: optimisticRev, updatedAt: committedAt, formatVersion: m.item!.formatVersion, doc });
    this.undecryptableById.delete(id); // it decrypts by construction — we wrote it
    this.pendingSyncItemIds.add(id);
    await this.persistEnvelope(id, targetVaultId, committedAt, optimisticRev, m);

    // SEND m (breaker #3 ONE denial path; C3 FIFO): on a DURABLE cache the send goes through
    // flushQueue itself — the drain is FIFO over the WHOLE queue (older offline edits of the
    // same item flush BEFORE m, so LWW can never enthrone a stale draft and demote this
    // newest edit to a conflict copy), single-flighted, and §D.5 lock-wrapped. Only the
    // NullCache path (enqueue is a no-op) sends m directly via flushChunk. Either way a
    // `denied` result is STAGED (not thrown) and an OFFLINE reject propagates.
    const displaced: { item: WireItem; winnerRev: number }[] = [];
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
      await this.cache.dequeue(m.mutationId);
      this.preEditByMutation.delete(m.mutationId);
      await this.revertOptimisticSave(id, existing);
      throw e;
    }
    for (const d of displaced) await this.materializeConflictFromServerItem(d.item, d.winnerRev);

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
    const upload = this.account.encryptItem(vaultId, itemId, restored);
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
    const target = vaultId ?? this.account.personalVaultId;
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
    const vaultId = destinationVaultId ?? this.account.personalVaultId;
    const total = items.length;
    let done = 0;
    for (let start = 0; start < items.length; start += VaultStore.SERVER_BATCH_MAX) {
      const chunk = items.slice(start, start + VaultStore.SERVER_BATCH_MAX);
      const mutations: Mutation[] = chunk.map(({ itemId, doc }): Mutation => {
        const upload = this.account.encryptItem(vaultId, itemId, doc);
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
    const bytes = await this.api.downloadAttachment(ref.id);
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
    const displaced: { item: WireItem; winnerRev: number }[] = [];
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
    for (const d of displaced) await this.materializeConflictFromServerItem(d.item, d.winnerRev);
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
      const up = this.account.encryptItem(existing.vaultId, itemId, existing.doc);
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
      await this.sync();
    } catch {
      this.hardDropLocal(vaultId);
    }
    return { purgeAt: resp.purgeAt };
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

  /** LEAVE (self-removal). This device initiated it → drop cleanly (no "you left" banner here). */
  async leaveSharedVault(vaultId: string): Promise<void> {
    await this.api.leaveVault(vaultId);
    this.suppressDrop.add(vaultId);
    try {
      await this.sync();
    } catch {
      this.hardDropLocal(vaultId);
    }
  }

  /** TRANSFER offer. seq = transferSeq+1 (= the vault's lastTransfer.seq + 1). */
  async offerTransfer(vaultId: string, toUserId: string): Promise<void> {
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
    const copyUpload = this.account.encryptItem(g.targetVaultId, g.newItemId, newDoc);
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
    const opById = new Map(mutations.map((m) => [m.mutationId, m.op]));
    const displaced: { item: WireItem; winnerRev: number }[] = [];
    for (const r of resp.results) {
      if (r.status === "denied") throw new ApiError(403, "denied", "write denied");
      if (r.status === "conflict" && opById.get(r.mutationId) === "put" && r.serverItem && r.newItemRev != null) {
        displaced.push({ item: r.serverItem, winnerRev: r.newItemRev });
      }
    }
    for (const d of displaced) await this.materializeConflictFromServerItem(d.item, d.winnerRev);
    return resp;
  }
}
