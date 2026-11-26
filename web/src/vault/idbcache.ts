import type { AccountKeys, Mutation, WireGrant, WireItem, WireVault } from "../api/types";
import type { AccountKeysV2 } from "../api/wire";
import { assertServerKdfParams } from "../crypto/keys";

/**
 * Durable web offline cache — the IndexedDB twin of core `VaultCache` /
 * `SqliteVaultCache` (design: docs/design/2026-07-13-web-offline-cache.md §B;
 * native contract: spec 02 §8). At rest it holds item ENVELOPES, grant/vault
 * rows, the sync cursor, the outbound queue, the lifecycle holding area +
 * replay floors, and the web-only cached `accountKeys` — every persisted value
 * is ciphertext or server-visible wire metadata (⊆ the spec 02 §5 table). The
 * decrypted working set stays in memory in `VaultStore`, so `upsertItem` takes
 * the WIRE row only (no decrypted twin at rest — the one deliberate signature
 * divergence from native, §B.3). IndexedDB is async, so the interface is the
 * Promise-returning twin of the sync Kotlin one, not a 1:1 copy.
 *
 * Contract anchors (MUST points from the design, tested in idbcache.test.ts):
 *  - §B.1/§B.2 — one DB per account (`andvari-vault-<userId>`), DB_VERSION=1,
 *    ALL stores created in version 1 (queue/held/etc. included even though S4
 *    lands later — no onupgradeneeded dance mid-rollout).
 *  - §B.4 open-time coherence — (i) kv.userId exists and equals the session
 *    userId, else wipe EVERYTHING including the queue (`SqliteVaultCache.init`
 *    parity); (ii) every expected store exists, else wipe + recreate fresh;
 *    (iii) ANY open/quota/corruption error ⇒ deleteDatabase + signal
 *    cache-less (`openVaultCache` returns `NullCache`). Doubt ⇒ discard ⇒
 *    since=0 resync — never partial trust (invariant A1).
 *  - §D.1 clear() — the ENUMERATED 410-resync contract (breaker #2): deletes
 *    items/grants/vaults and resets `kv:cursor` ONLY. It MUST NOT touch
 *    queue/held/consumedDeleteIds/transferSeq (spec 03 §4 safety state) NOR
 *    kv:accountKeys/userId/policy/lastSyncAt — web co-locates accountKeys in
 *    this DB (design §A D5), so a naive kv.clear() would break offline unlock
 *    after any resync-then-lock.
 *  - §D.1 applyPull(fn) — the one-tx commit seam: `fn` synchronously BUFFERS
 *    ops, then everything commits in ONE IndexedDB transaction spanning all
 *    stores. A failed commit leaves the OLD cursor+rows intact (coherent, A1):
 *    memory then runs ahead of disk, and because pulls are driven by the memory
 *    cursor the strict-delta server never re-sends that delta within the
 *    session — so the heal is two-part (S2/S4 as-built): store.ts's CONTIGUITY
 *    GUARD refuses any later delta whose base is ahead of the disk cursor (disk
 *    stays coherent-stale, never stamping a cursor over a gap the server won't
 *    re-send), and hydrate resumes from the DISK cursor so the next session's
 *    first pull re-fetches the whole gap (the server re-delivers every change
 *    with rev > since). Each failed commit counts one stuck-cache strike
 *    (breaker #6); `consecutiveCommitFailures()` exposes
 *    the count. After 3, S2 treats it as a §B.4 coherence failure (attempt
 *    `wipe()`, demote to NullCache for the session) — the ORCHESTRATION is
 *    S2's; S1 exposes the counter + wipe(). The counter is scoped to applyPull
 *    commits (a small standalone write succeeding under quota pressure must
 *    not mask a persistently failing pull commit).
 *  - §D.2a guarded writes — once close()/versionchange has begun, a pending
 *    read/write resolves as a caught no-op (reads fall back to empty), never
 *    an uncaught rejection: a post-push envelope persist may race a sibling
 *    tab's sign-out wipe(); losing that race is harmless (server-committed
 *    rows re-sync at next login).
 *  - §D.2c setAccountKeys keep-old-on-bad-write (breaker #5) — a payload that
 *    LACKS or FAILS the H1 kdfParams floor (`assertServerKdfParams`) never
 *    overwrites a good cached one; the FIRST write is allowed regardless (C3's
 *    read-time assert in the unlock path is the belt; this is the suspenders).
 *  - §E.4 wipe() = deleteDatabase — the ONLY operation that removes cached
 *    accountKeys (sign-out / revoked / definitive-401 / policy-off /
 *    opt-out / coherence-failure rows of the wipe table). Lock RETAINS the
 *    cache (spec 05 T3) — locking is a key-drop, not a data event.
 *  - A2 — putHeld persists the HeldVaultRecord shape WITHOUT `cachedName`
 *    (the one plaintext field of store.ts's in-memory HeldVault; native
 *    `HeldVaultRecord` parity — the name is re-derived from the retained
 *    grant on rehydrate, as core `peekVaultName` does).
 */

export const DB_VERSION = 1;

/** §B.1: one DB per account — `vault-<userId>.db` native parity. */
export const vaultDbName = (userId: string): string => `andvari-vault-${userId}`;

const STORE_KV = "kv";
const STORE_ITEMS = "items";
const STORE_GRANTS = "grants";
const STORE_VAULTS = "vaults";
const STORE_QUEUE = "queue";
const STORE_HELD = "held";
const STORE_CONSUMED = "consumedDeleteIds";
const STORE_TRANSFER = "transferSeq";
/** Root cause A §5.1 INV-HOME (branch A1b): kv-row prefixes, again no new object store. Both survive the §D.1 clear
 *  (a server-triggered 410 wipes the row stores, never the homes) and die with wipe(). */
const KV_ITEM_HOME = "itemHome:";
const KV_QUARANTINE = "quarantine:";
const KV_LOG_RECORD = "logRecord:";

/** Every §B.2 store — all created in version 1, all spanned by the pull tx. */
const ALL_STORES = [
  STORE_KV,
  STORE_ITEMS,
  STORE_GRANTS,
  STORE_VAULTS,
  STORE_QUEUE,
  STORE_HELD,
  STORE_CONSUMED,
  STORE_TRANSFER,
] as const;

/** Why a held vault left the live set — structurally store.ts's RemovedReason
 *  (declared locally so idbcache stays import-cycle-free of store.ts). */
export type HeldReason = "removed" | "left" | "deleted" | "transferred";

/**
 * The persisted holding-area record — core `HeldVaultRecord` twin: the vault
 * row, the retained grant blob (normative — held ciphertext is dead bytes
 * without it), the re-sealed ciphertext item snapshot, and the parked
 * mutations replayed on restore (F21). Ciphertext/wire material ONLY — the
 * in-memory `HeldVault.cachedName` is deliberately NOT part of this record
 * (invariant A2); putHeld strips it.
 */
export interface HeldVaultRecord {
  vault: WireVault;
  grant: WireGrant | null;
  items: WireItem[];
  reason: HeldReason;
  verified: boolean;
  purgeAt?: number;
  deleteId?: string;
  parked: Mutation[];
  expungeAt: number;
  /**
   * Design §3.8, §3.12: this account's own wrap of the vault's key under its UVK (the self-wrap's form, bound to the
   * log's genesis), so items can still be copied out of the held copy. Absent on records made before it was kept.
   */
  ownWrap?: string;
  /** This account deleted the vault itself (its copy is held all the same, design §3.8). Absent on older records. */
  byMe?: true;
  /**
   * Not a removed vault's copy: the items of a vault this browser still has (the personal vault, or a shared vault still
   * listed) that a full list neither carried nor marked as deleted, set aside here. Kept under its own key
   * ({@link heldRowKey}), beside any held copy of the same vault. Absent on every other record.
   */
  setAside?: true;
  /**
   * Items set aside only: the ids of those the server has sent again since, in their own vault, with other content than
   * the copy kept here; the person was told of each once. Absent where there is none.
   */
  otherContentTold?: string[];
  /**
   * A removed vault's copy only: the ids of items it holds whose deletion a pull applied while it was held, each taken
   * out again when a live row of the item is applied. The items stay in the copy; putting the vault back leaves them
   * out. Absent where there is none, and on records made before it was kept (read as none).
   */
  deletedServed?: string[];
}

/** The held store's key of a record: the vault's id, or for items set aside from it, the id with a prefix of its own. */
export function heldRowKey(vaultId: string, setAside: boolean): string {
  return setAside ? `set-aside:${vaultId}` : vaultId;
}

/** §A row 8: the last-known policy bits honored on offline boot (kv:policy). */
export interface CachePolicy {
  offlineCacheAllowed: boolean;
}

/**
 * S4 M2 (2026-07-14 re-review): the OPTIONAL durable twin of store.ts's in-memory
 * pre-edit snapshot, riding its mutation's queue row so a denial classified only
 * AFTER a restart can still revert the optimistic apply (the ordinary flow: edit
 * offline → close the browser → reopen → reconnect → denied — a delta server never
 * re-delivers the unchanged row, so without this the refused value displays forever).
 * LOCAL-ONLY: never part of `mutation`, never pushed. Ciphertext-only at rest (A2):
 * `pre` carries the pre-edit envelope RE-SEALED at enqueue time (`null` = the
 * mutation created the item; revert = drop it). ADDITIVE, no migration: IDB rows are
 * schemaless, so rows written before this field read back with `preEdit` undefined
 * and keep the pre-M2 behavior (write-refused notice, no revert).
 */
export interface QueuedPreEdit {
  op: "put" | "delete";
  /** The sealed pre-edit envelope (itemId/vaultId live on the queue row's mutation). */
  pre: { rev: number; updatedAt: number; formatVersion: number; attachmentIds: string[]; blob: string } | null;
  /** For op "put": the optimistic (rev, updatedAt) pair that gates the revert. */
  optimisticRev: number;
  optimisticUpdatedAt: number;
}

/**
 * The buffered-op surface `applyPull(fn)` hands to its callback (§D.1). Calls
 * only RECORD ops; nothing touches IndexedDB until fn returns, then every
 * recorded op executes in issue order inside ONE transaction over all stores
 * (cursor last is the CALLER's ordering duty, as in core `SyncEngine`). The
 * 410-resync shape is `b.clear()` followed by the full snapshot + setCursor —
 * one tx, so a failed commit strands neither half.
 */
export interface PullBatch {
  setCursor(rev: number): void;
  setLastSyncAt(at: number): void;
  upsertItem(wire: WireItem): void;
  deleteItem(itemId: string): void;
  upsertGrant(grant: WireGrant): void;
  upsertVault(vault: WireVault): void;
  dropVault(vaultId: string): void;
  /**
   * The §D.1 enumerated clear — same contract as the standalone method. [keep]: vaults whose item, grant and vault rows
   * stay as they are (a 410 resync's vault that the fresh list leaves out while its verified log still names this
   * account: kept, as a removal the log does not show keeps it). Read when the commit runs.
   */
  clear(keep?: ReadonlySet<string>): void;
  enqueue(mutation: Mutation): void;
  dequeue(mutationId: string): void;
  dropPending(vaultId: string): void;
  markStagedDenied(mutationId: string): void;
  putHeld(held: HeldVaultRecord & { cachedName?: string }): void;
  /** [vaultId]: the record's key in the held store, {@link heldRowKey} (a vault's id for its held copy). */
  removeHeld(vaultId: string): void;
  addConsumedDeleteId(deleteId: string): void;
  setLastVerifiedTransferSeq(vaultId: string, seq: number): void;
  /** Root cause A §5.1 INV-HOME (branch A1b): record an itemId's home (only ever written while absent). */
  setItemHome(itemId: string, vaultId: string): void;
  /** Root cause A §5.1 INV-HOME (branch A1b): one served row refused by INV-HOME (ciphertext, never applied). */
  addQuarantined(item: WireItem): void;
  /** A shared vault's adoption record ({@link VaultLogRecord}), in the same commit as the rows or held copy it describes. */
  setLogRecord(rec: VaultLogRecord): void;
  /** The record of a vault of which this browser holds nothing any more. */
  removeLogRecord(vaultId: string): void;
}

/**
 * What decides, across a reload, whether a removal from a shared vault is still owed: the number of the vault log's
 * `add` entry under which this browser adopted the vault ([carried] false), or under which it last carried a removal out
 * (the held copy and its notice; [carried] true). Written in the same commit as what it describes, so the rows and the
 * record never say two things. Kept in the key-value store under `logRecord:<vaultId>`, which the full list's clear does
 * not touch.
 */
export interface VaultLogRecord {
  readonly vaultId: string;
  readonly addSeq: number;
  readonly carried: boolean;
}

/**
 * The web VaultCache port — the TypeScript twin of core `VaultCache` (§B.3),
 * async where IndexedDB requires. This surface FREEZES at S1: S2 (store
 * cache-through + hydrate), S3 (offline unlock + wipe wiring) and S4 (durable
 * queue) build against exactly this. Enumerators absent from the native
 * interface (`consumedDeleteIds()`, `transferSeqs()`, `lastSyncAt()`,
 * `policy()`) exist because §D.4 hydrate rebuilds store.ts's in-memory maps
 * from disk — native reads those lazily per-row instead.
 */
export interface VaultCache {
  /** false on NullCache — the §B.5 "signal cache-less" bit for the caller/UI. */
  readonly durable: boolean;

  cursor(): Promise<number>;
  setCursor(rev: number): Promise<void>;
  /** kv:lastSyncAt — restored by hydrate so "vault as of last sync <t>" stays honest (§D.4). */
  lastSyncAt(): Promise<number | null>;

  /** WIRE row only — no decrypted twin at rest (§B.3; A2). Tombstone handling
   *  (delete vs upsert) is the caller's pull logic, as in core SyncEngine. */
  upsertItem(wire: WireItem): Promise<void>;
  deleteItem(itemId: string): Promise<void>;
  /** All persisted ciphertext envelopes — cold-start rehydration input. */
  envelopes(): Promise<WireItem[]>;

  upsertGrant(grant: WireGrant): Promise<void>;
  grants(): Promise<WireGrant[]>;
  upsertVault(vault: WireVault): Promise<void>;
  vaults(): Promise<WireVault[]>;
  /** removedGrants (spec 03 §4): purge the grant, the vault row, and its items. */
  dropVault(vaultId: string): Promise<void>;

  /** §D.1 ENUMERATED contract — see the module doc. */
  clear(): Promise<void>;
  /** §D.1 one-tx commit seam — see PullBatch. Rejects on a failed commit (the
   *  caller's in-memory state is then ahead of disk — safe, A1) unless the
   *  cache is closed, in which case it resolves as a caught no-op (§D.2a). */
  applyPull(fn: (batch: PullBatch) => void): Promise<void>;
  /** Consecutive applyPull commit failures (breaker #6) — 3 ⇒ S2 demotes. */
  consecutiveCommitFailures(): number;

  /** Durable outbound queue (S4 consumes; stores exist from v1). Re-enqueueing
   *  an existing mutationId returns the row to the pushable state at the queue
   *  TAIL (SqliteVaultCache INSERT OR REPLACE parity). `preEdit` (M2, additive)
   *  optionally rides the row LOCALLY — see QueuedPreEdit; a re-enqueue without
   *  one clears any prior snapshot (fresh row, replay parity).
   *  CR-01 (compliance 2026-07-15): resolves TRUE iff the row VERIFIABLY landed
   *  (the mutationId re-read inside the same tx after the write, the setAccountKeys
   *  pattern). A closed/force-wiped cache resolves every write as a guarded no-op
   *  (§D.2a) — it now reports FALSE so the caller can refuse the queue and do the
   *  real send, never report a black-holed write as success. */
  enqueue(mutation: Mutation, preEdit?: QueuedPreEdit): Promise<boolean>;
  /** FIFO, EXCLUDING staged-denied rows — never re-push a denied mutation. */
  pending(): Promise<Mutation[]>;
  /** M2 (additive): every queue row's durable pre-edit snapshot (pending AND
   *  staged-denied — either may be classified a genuine denial after a restart),
   *  keyed by the row's mutation. Rows without one are omitted. */
  queuedPreEdits(): Promise<{ mutationId: string; itemId: string; vaultId: string; preEdit: QueuedPreEdit }[]>;
  /** Remove a queue row (any state — pending or staged-denied). */
  dequeue(mutationId: string): Promise<void>;
  /** Drop queued mutations targeting vaultId, staged or not (spec 03 §4). */
  dropPending(vaultId: string): Promise<void>;
  /** Durably stage a denied row (spec 03 §11 / F21); unknown id = no-op. */
  markStagedDenied(mutationId: string): Promise<void>;
  /** All staged-denied rows (FIFO) — reloaded into staging on hydrate. */
  stagedDenied(): Promise<Mutation[]>;

  /** Persists the record MINUS `cachedName` (A2) — pass store.ts's HeldVault as-is. */
  putHeld(held: HeldVaultRecord & { cachedName?: string }): Promise<void>;
  getHeld(vaultId: string): Promise<HeldVaultRecord | null>;
  heldVaults(): Promise<HeldVaultRecord[]>;
  /** [vaultId]: the record's key in the held store, {@link heldRowKey} (a vault's id for its held copy). */
  removeHeld(vaultId: string): Promise<void>;

  addConsumedDeleteId(deleteId: string): Promise<void>;
  isConsumedDeleteId(deleteId: string): Promise<boolean>;
  /** §D.4 hydrate enumerator (web-only; native checks per-row instead). */
  consumedDeleteIds(): Promise<string[]>;
  lastVerifiedTransferSeq(vaultId: string): Promise<number>;
  setLastVerifiedTransferSeq(vaultId: string, seq: number): Promise<void>;
  /** §D.4 hydrate enumerator (web-only). */
  transferSeqs(): Promise<{ vaultId: string; seq: number }[]>;
  /** Root cause A §5.1 INV-HOME (branch A1b; core `VaultCache.itemHome` twin): every recorded home, for hydrate. */
  itemHomes(): Promise<{ itemId: string; vaultId: string }[]>;
  /** Root cause A §5.1 INV-HOME (branch A1b): the quarantined rows, for diagnosis only (never listed or exported). */
  quarantined(): Promise<WireItem[]>;
  /** Every shared vault's adoption record ({@link VaultLogRecord}), for hydrate. */
  logRecords(): Promise<VaultLogRecord[]>;

  /** Cached server accountKeys payload (§A row 6) — the offline-unlock input.
   *  Returned RAW: the C3 read-time `assertServerKdfParams` gate belongs to
   *  the unlock path (S3), exactly like Android's cachedAccountKeys().takeIf. */
  accountKeys(): Promise<AccountKeys | null>;
  /** §D.2c keep-old-on-bad-write — resolves true iff the payload was written. */
  setAccountKeys(keys: AccountKeys): Promise<boolean>;
  /** The post-cut-over account keys with their genesis (spec 02 §8), for an offline unlock through openAccount. */
  accountKeysV2(): Promise<AccountKeysV2 | null>;
  /**
   * Whether a row for {@link accountKeysV2} is stored at all, usable or not: at an unlock, a copy whose keys cannot be
   * read (a row that is not a usable key set) is told apart from a copy that holds no keys yet (spec 01 §7).
   */
  hasAccountKeysV2Row(): Promise<boolean>;
  setAccountKeysV2(keys: AccountKeysV2): Promise<boolean>;
  /**
   * The wraps of password changes sent with no answer yet (spec 01 §7), kept beside the copy of the account keys, oldest
   * first, as core keeps its pending record: an offline unlock opens with either password until the server's word
   * settles them. A row that is not a list of wraps reads as none.
   */
  pendingWraps(): Promise<PendingWrap[]>;
  /** Replaces that list; an empty one removes the row. Resolves true iff it was written. */
  setPendingWraps(wraps: readonly PendingWrap[]): Promise<boolean>;
  /**
   * Design §3.13: the half-made new vaults of stopped moves that wait for their deletion (store.ts `halfMadeDue`), kept
   * across a reload. Their ids, in the clear as every vault row's id is, each with the copies the move made in it (each
   * copy's item id and its revision at the server, which every item row also carries in the clear), so that it is
   * deleted only while it holds nothing else; a name is read from the vault's own sealed meta when it is needed, never
   * kept here. A row that is not such a list reads as none; an entry kept as a bare id (before the copies were kept)
   * reads with `copies: null` (not known: such a vault is deleted only while it holds nothing at all).
   */
  halfMadeDue(): Promise<HalfMadeDueRow[]>;
  /** Replaces that list; an empty one removes the row. Resolves true iff it was written. */
  setHalfMadeDue(rows: readonly HalfMadeDueRow[]): Promise<boolean>;
  /** R41 (audit H67): drop the cached accountKeys row and NOTHING else — the offline queue,
   *  envelopes and holding all survive. Called on exactly one verdict: the cached payload is
   *  STRUCTURALLY damaged (not decodable base64url / an envelope version this build does not
   *  implement), which is unusable by construction and unusable identically forever, so keeping
   *  it only guarantees the same terminal on every later attempt. Dropping it forces the next
   *  unlock online, where a healthy server row self-heals the cache. Deliberately NOT a wipe:
   *  the member's unsent offline edits are not implicated by a bad key blob. */
  clearAccountKeys(): Promise<void>;
  policy(): Promise<CachePolicy | null>;
  setPolicy(policy: CachePolicy): Promise<void>;

  /** §E.4: deleteDatabase — envelopes, queue, holding AND accountKeys. Never
   *  rejects (demotion "attempts" it); the instance is closed afterwards. */
  wipe(): Promise<void>;
  /** Close the connection; every later call resolves as a caught no-op (§D.2a).
   *  Sync so the sign-out storage listener can call it before phase change (§D.5.3). */
  close(): void;

  /** CR-01 (compliance 2026-07-15): fired ONCE when the connection closes out from
   *  under the live store — the browser force-closes it (eviction/corruption →
   *  `onclose`) or a sibling tab / session-level wipe deletes the DB
   *  (`deleteDatabase` → `versionchange`). VaultStore points this at its
   *  `demoteCache()` so a closed cache can never linger with `durable=true` and
   *  silently swallow offline writes. NOT fired by the programmatic `close()`
   *  (the store already owns that path); NullCache never fires it. */
  onClosed?: () => void;
}

// ---- small IDB plumbing ------------------------------------------------------

interface KvRow {
  key: string;
  value: unknown;
}

interface QueueRow {
  seq?: number; // injected by the key generator on add()
  mutationId: string;
  vaultId: string;
  staged: 0 | 1;
  mutation: Mutation;
  /** M2 (additive, LOCAL-ONLY — never pushed): the durable pre-edit snapshot.
   *  Absent on rows written before the field existed (schemaless — no migration). */
  preEdit?: QueuedPreEdit;
}

type HeldRow = HeldVaultRecord & { vaultId: string };

function factory(): IDBFactory | undefined {
  try {
    // Access can THROW in some privacy modes, not just be undefined (§B.5).
    return (globalThis as { indexedDB?: IDBFactory }).indexedDB ?? undefined;
  } catch {
    return undefined;
  }
}

/** Feature-detect (§B.5): absent/blocked IndexedDB ⇒ the caller runs on NullCache. */
export function idbSupported(): boolean {
  return factory() !== undefined;
}

function req<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error ?? new Error("IndexedDB request failed"));
  });
}

function txDone(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onabort = () => reject(tx.error ?? new Error("IndexedDB transaction aborted"));
    // A failed request aborts the tx (we never preventDefault) — onabort settles it.
  });
}

/** deleteDatabase that never rejects (wipe is an ATTEMPT, §D.1/§E.4). It waits
 *  out `blocked`: §D.5.3 — every sibling connection self-closes on versionchange,
 *  so completion is prompt. */
function deleteDb(f: IDBFactory, name: string): Promise<void> {
  return new Promise((resolve) => {
    let r: IDBOpenDBRequest;
    try {
      r = f.deleteDatabase(name);
    } catch {
      resolve();
      return;
    }
    r.onsuccess = () => resolve();
    r.onerror = () => resolve();
  });
}

/**
 * Opens [name] as it is, never creating it: null when it does not exist (the create that `open` would begin is
 * aborted, so nothing is minted). Rejects when an existing database cannot be opened. The handle closes itself on
 * a sibling's versionchange, so it never blocks a wipe.
 */
function openExisting(f: IDBFactory, name: string): Promise<IDBDatabase | null> {
  return new Promise((resolve, reject) => {
    let missing = false;
    let r: IDBOpenDBRequest;
    try {
      r = f.open(name);
    } catch (e) {
      reject(e instanceof Error ? e : new Error("IndexedDB open failed"));
      return;
    }
    r.onupgradeneeded = () => {
      missing = true;
      try {
        r.transaction?.abort();
      } catch {
        /* already aborting */
      }
    };
    r.onsuccess = () => {
      const db = r.result;
      db.onversionchange = () => db.close();
      resolve(db);
    };
    r.onerror = () => (missing ? resolve(null) : reject(r.error ?? new Error("IndexedDB open failed")));
  });
}

/** What waits in a copy, read without changing it (see {@link readWaiting}). */
export type WaitingRead =
  /** This browser keeps no copy of the account. */
  | { readonly kind: "none" }
  /** A copy exists and cannot be read (another schema, another owner, a broken store, a failed read). */
  | { readonly kind: "unreadable" }
  /** The queue's rows not yet refused ([pending], in order), the rows the server refused for their vault ([staged]),
   *  and the number of changes parked with vaults held back. */
  | { readonly kind: "read"; readonly pending: Mutation[]; readonly staged: Mutation[]; readonly parked: number };

/**
 * The changes that wait in [userId]'s copy, read in one read-only transaction over the copy as it is: nothing is made
 * (no copy is created by asking), repaired or deleted (a copy that exists and cannot be opened stays, and reads as
 * `unreadable`, never as empty). Never rejects.
 */
export async function readWaiting(userId: string): Promise<WaitingRead> {
  const f = factory();
  if (!f) return { kind: "none" };
  let db: IDBDatabase | null;
  try {
    db = await openExisting(f, vaultDbName(userId));
  } catch {
    return { kind: "unreadable" };
  }
  if (db === null) return { kind: "none" };
  try {
    if (db.version !== DB_VERSION || !hasAllStores(db)) return { kind: "unreadable" };
    const tx = db.transaction([STORE_KV, STORE_QUEUE, STORE_HELD], "readonly");
    const [owner, rows, held] = await Promise.all([
      req(tx.objectStore(STORE_KV).get("userId")),
      req(tx.objectStore(STORE_QUEUE).getAll()) as Promise<unknown[]>,
      req(tx.objectStore(STORE_HELD).getAll()) as Promise<unknown[]>,
    ]);
    if (kvValue(owner) !== userId) return { kind: "unreadable" };
    const pending: Mutation[] = [];
    const staged: Mutation[] = [];
    for (const row of rows) {
      const q = row as Partial<QueueRow> | null;
      if (!q || typeof q !== "object" || !q.mutation || typeof q.mutation !== "object" || typeof q.mutation.mutationId !== "string") return { kind: "unreadable" };
      if (q.staged === 0) pending.push(q.mutation);
      else if (q.staged === 1) staged.push(q.mutation);
      else return { kind: "unreadable" };
    }
    let parked = 0;
    for (const h of held) {
      const p = (h as { parked?: unknown } | null)?.parked;
      if (p === undefined) continue;
      if (!Array.isArray(p)) return { kind: "unreadable" };
      parked += p.length;
    }
    return { kind: "read", pending, staged, parked };
  } catch {
    return { kind: "unreadable" };
  } finally {
    try {
      db.close();
    } catch {
      /* already closed */
    }
  }
}

/** How a wipe of a copy ended (see {@link deleteCopy}). */
export type CopyDeletion = "gone" | "blocked" | "failed";

/**
 * Deletes [userId]'s copy and says whether it is gone: `gone` only when the browser said the database was deleted (or
 * there is no IndexedDB at all, so no copy); `failed` when it refused; `blocked` when it was not done within [waitMs]
 * (a connection that does not close holds it). A blocked deletion stays asked: when what blocked it ends, the browser
 * completes it and [later] is called with whether it is gone then.
 */
export function deleteCopy(userId: string, waitMs: number, later?: (gone: boolean) => void): Promise<CopyDeletion> {
  const f = factory();
  if (!f) return Promise.resolve("gone");
  return new Promise((resolve) => {
    let settled = false;
    const settle = (d: CopyDeletion): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(d);
    };
    let r: IDBOpenDBRequest;
    try {
      r = f.deleteDatabase(vaultDbName(userId));
    } catch {
      resolve("failed");
      return;
    }
    const timer = setTimeout(() => settle("blocked"), waitMs);
    r.onsuccess = () => (settled ? later?.(true) : settle("gone"));
    r.onerror = () => (settled ? later?.(false) : settle("failed"));
  });
}

/** Open (creating v1 with the FULL §B.2 schema + owner stamp on fresh create). */
function openDb(f: IDBFactory, name: string, userId: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    let r: IDBOpenDBRequest;
    try {
      r = f.open(name, DB_VERSION);
    } catch (e) {
      reject(e instanceof Error ? e : new Error("IndexedDB open failed"));
      return;
    }
    r.onupgradeneeded = () => {
      const db = r.result;
      if (!db.objectStoreNames.contains(STORE_KV)) db.createObjectStore(STORE_KV, { keyPath: "key" });
      if (!db.objectStoreNames.contains(STORE_ITEMS)) {
        db.createObjectStore(STORE_ITEMS, { keyPath: "itemId" }).createIndex("vaultId", "vaultId", { unique: false });
      }
      if (!db.objectStoreNames.contains(STORE_GRANTS)) db.createObjectStore(STORE_GRANTS, { keyPath: "vaultId" });
      if (!db.objectStoreNames.contains(STORE_VAULTS)) db.createObjectStore(STORE_VAULTS, { keyPath: "vaultId" });
      if (!db.objectStoreNames.contains(STORE_QUEUE)) {
        const q = db.createObjectStore(STORE_QUEUE, { keyPath: "seq", autoIncrement: true });
        q.createIndex("mutationId", "mutationId", { unique: true });
        q.createIndex("vaultId", "vaultId", { unique: false });
      }
      if (!db.objectStoreNames.contains(STORE_HELD)) db.createObjectStore(STORE_HELD, { keyPath: "vaultId" });
      if (!db.objectStoreNames.contains(STORE_CONSUMED)) db.createObjectStore(STORE_CONSUMED, { keyPath: "deleteId" });
      if (!db.objectStoreNames.contains(STORE_TRANSFER)) db.createObjectStore(STORE_TRANSFER, { keyPath: "vaultId" });
      // Fresh create (0→1): stamp the owner inside the version-change tx (§B.4 i).
      const tx = r.transaction;
      if (tx) {
        const kv = tx.objectStore(STORE_KV);
        kv.put({ key: "userId", value: userId } satisfies KvRow);
        kv.put({ key: "createdAt", value: Date.now() } satisfies KvRow);
      }
    };
    r.onsuccess = () => {
      // §D.5.3 (review): bind self-close the MOMENT the connection exists — not later in
      // IdbVaultCache's constructor. A sibling tab's wipe()/deleteDatabase can land during the
      // open window (this success → verifyOwner's tx → the constructor), and versionchange fires
      // exactly ONCE at delete-request time; a handler attached afterwards never sees it, so the
      // connection would never self-close and the sibling's deleteDatabase (no onblocked, by
      // design) would hang forever — wedging sign-out + every future open. The constructor
      // re-points this to () => this.close() once the instance exists.
      r.result.onversionchange = () => r.result.close();
      resolve(r.result);
    };
    r.onerror = () => reject(r.error ?? new Error("IndexedDB open failed"));
  });
}

function hasAllStores(db: IDBDatabase): boolean {
  return ALL_STORES.every((name) => db.objectStoreNames.contains(name));
}

const kvValue = (row: unknown): unknown => (row && typeof row === "object" ? (row as KvRow).value : undefined);

const KV_ACCOUNT_KEYS_V2 = "accountKeys.v2";
const KV_PENDING_WRAPS = "pendingWraps";
const KV_HALF_MADE_DUE = "halfMadeDue";

/** A half-made vault due for deletion, with the copies its move made in it ({@link VaultCache.halfMadeDue}). */
export interface HalfMadeDueRow {
  readonly vaultId: string;
  /** Each copy's item id and its revision at the server (null: not known); null when no record of the copies is kept. */
  readonly copies: readonly (readonly [string, number | null])[] | null;
}

/** One kept entry: a bare id (kept before the copies were: not known) or an id with its copies; null when it is neither. */
function parseHalfMadeDueRow(v: unknown): HalfMadeDueRow | null {
  if (typeof v === "string") return v === "" ? null : { vaultId: v, copies: null };
  if (typeof v !== "object" || v === null) return null;
  const r = v as { vaultId?: unknown; copies?: unknown };
  if (typeof r.vaultId !== "string" || r.vaultId === "") return null;
  if (r.copies === null) return { vaultId: r.vaultId, copies: null };
  if (!Array.isArray(r.copies)) return null;
  const copies: (readonly [string, number | null])[] = [];
  for (const c of r.copies as unknown[]) {
    if (!Array.isArray(c) || c.length !== 2 || typeof c[0] !== "string" || (c[1] !== null && !Number.isSafeInteger(c[1]))) return null;
    copies.push([c[0], c[1] as number | null]);
  }
  return { vaultId: r.vaultId, copies };
}

/** One pending wrap as kept: the salt, cost and wrapped UVK a password change sent (vault/sessionwrap.ts SessionKeys). */
export interface PendingWrap {
  readonly kdfSalt: string;
  readonly kdfParams: AccountKeys["kdfParams"];
  readonly wrappedUvk: string;
  /**
   * When this browser first kept the wrap (ms since the epoch): the day of the change that sent it, for the unlock that
   * finds the change never reached the server. Stamped when the wrap is first written; absent in rows kept before.
   */
  readonly at?: number;
}

const atOf = (v: unknown): number | undefined => (typeof v === "number" && Number.isFinite(v) && v > 0 ? v : undefined);

function isPendingWrap(v: unknown): v is PendingWrap {
  if (!v || typeof v !== "object") return false;
  const w = v as Partial<PendingWrap>;
  return typeof w.kdfSalt === "string" && typeof w.wrappedUvk === "string" && floorGood(w as unknown as AccountKeys);
}

/** A cached post-cut-over key set worth keeping: floor-good KDF parameters and a genesis to check at offline unlock. */
function isCachedKeysV2(v: unknown): v is AccountKeysV2 {
  if (!v || typeof v !== "object") return false;
  const k = v as Partial<AccountKeysV2>;
  return typeof k.genesis === "string" && k.genesis !== "" && typeof k.kdfSalt === "string" && typeof k.wrappedUvk === "string" &&
    typeof k.encryptedIdentitySeed === "string" && typeof k.identityPub === "string" && floorGood(k as unknown as AccountKeys);
}

/** §D.2c/breaker #5: a payload is floor-good iff kdfParams is present AND
 *  passes the H1 fence (same assert as the online path in client.ts). */
function floorGood(keys: AccountKeys | null | undefined): boolean {
  if (!keys || typeof keys !== "object" || !keys.kdfParams) return false;
  try {
    assertServerKdfParams(keys.kdfParams);
    return true;
  } catch {
    return false;
  }
}

/** A2: strip the plaintext `cachedName` and stamp the top-level key (§B.2 keyPath). */
function toHeldRow(held: HeldVaultRecord & { cachedName?: string }): HeldRow {
  const { cachedName: _dropped, ...rec } = held;
  return { vaultId: heldRowKey(rec.vault.vaultId, rec.setAside === true), ...rec };
}

function fromHeldRow(row: HeldRow): HeldVaultRecord {
  const { vaultId: _key, ...rec } = row;
  return rec;
}

// ---- in-transaction op helpers (shared by standalone methods and applyPull) ----

async function clearIn(tx: IDBTransaction, keep: ReadonlySet<string> = new Set()): Promise<void> {
  // §D.1 ENUMERATED contract (breaker #2): items/grants/vaults + kv:cursor ONLY.
  // queue/held/consumedDeleteIds/transferSeq and kv:accountKeys/userId/policy/
  // lastSyncAt are deliberately untouched.
  const items = tx.objectStore(STORE_ITEMS);
  const grants = tx.objectStore(STORE_GRANTS);
  const vaults = tx.objectStore(STORE_VAULTS);
  // The rows of a kept vault are read first and put back as they were, in the same transaction.
  const kept: { items: unknown[]; grants: unknown[]; vaults: unknown[] } = { items: [], grants: [], vaults: [] };
  for (const vaultId of keep) {
    kept.items.push(...((await req(items.index("vaultId").getAll(vaultId))) as unknown[]));
    const g = (await req(grants.get(vaultId))) as unknown;
    if (g !== undefined) kept.grants.push(g);
    const v = (await req(vaults.get(vaultId))) as unknown;
    if (v !== undefined) kept.vaults.push(v);
  }
  items.clear();
  grants.clear();
  vaults.clear();
  for (const r of kept.items) items.put(r);
  for (const r of kept.grants) grants.put(r);
  for (const r of kept.vaults) vaults.put(r);
  tx.objectStore(STORE_KV).put({ key: "cursor", value: 0 } satisfies KvRow);
}

async function dropVaultIn(tx: IDBTransaction, vaultId: string): Promise<void> {
  const items = tx.objectStore(STORE_ITEMS);
  const keys = await req(items.index("vaultId").getAllKeys(vaultId));
  for (const k of keys) items.delete(k);
  tx.objectStore(STORE_GRANTS).delete(vaultId);
  tx.objectStore(STORE_VAULTS).delete(vaultId);
}

async function enqueueIn(tx: IDBTransaction, mutation: Mutation, preEdit?: QueuedPreEdit): Promise<void> {
  // INSERT OR REPLACE parity: a re-enqueue (reinstate replay) deletes the old
  // row and adds a fresh one — staged resets to 0 (pushable) and the row moves
  // to the queue tail with a new monotonic seq, exactly like SQLite. A fresh
  // row also carries only the CALLER's preEdit (a replay enqueue passes none —
  // parked mutations shed their snapshot when they were parked).
  const store = tx.objectStore(STORE_QUEUE);
  const existing = await req(store.index("mutationId").getKey(mutation.mutationId));
  if (existing !== undefined) store.delete(existing);
  const row: QueueRow = { mutationId: mutation.mutationId, vaultId: mutation.vaultId, staged: 0, mutation };
  if (preEdit !== undefined) row.preEdit = preEdit;
  store.add(row);
}

async function dequeueIn(tx: IDBTransaction, mutationId: string): Promise<void> {
  const store = tx.objectStore(STORE_QUEUE);
  const key = await req(store.index("mutationId").getKey(mutationId));
  if (key !== undefined) store.delete(key);
}

async function dropPendingIn(tx: IDBTransaction, vaultId: string): Promise<void> {
  const store = tx.objectStore(STORE_QUEUE);
  const keys = await req(store.index("vaultId").getAllKeys(vaultId));
  for (const k of keys) store.delete(k);
}

async function markStagedDeniedIn(tx: IDBTransaction, mutationId: string): Promise<void> {
  const store = tx.objectStore(STORE_QUEUE);
  const row = (await req(store.index("mutationId").get(mutationId))) as QueueRow | undefined;
  if (row) store.put({ ...row, staged: 1 } satisfies QueueRow);
}

// ---- the durable impl ---------------------------------------------------------

export class IdbVaultCache implements VaultCache {
  readonly durable = true;
  onClosed?: () => void;
  private closed = false;
  private pullFailures = 0;

  private constructor(
    private readonly db: IDBDatabase,
    private readonly f: IDBFactory,
    private readonly name: string,
  ) {
    // §D.5.3: a sibling tab's wipe() (deleteDatabase) fires versionchange here —
    // self-close so the wipe completes promptly; §D.2a turns our in-flight and
    // later calls into caught no-ops. CR-01: also notify the live store (onClosed)
    // so it demotes off this now-dead handle instead of letting durable=true linger
    // and black-hole the next save()/remove().
    this.db.onversionchange = () => {
      this.close();
      this.onClosed?.();
    };
    // Browser-forced close (eviction, corruption): same guarded posture + notify.
    this.db.onclose = () => {
      this.closed = true;
      this.onClosed?.();
    };
  }

  /**
   * Open + §B.4 coherence. Throws on unrecoverable open-time errors — the
   * public `openVaultCache` wrapper translates that into deleteDatabase +
   * NullCache (§B.4 iii). Missing stores get ONE wipe-and-recreate attempt
   * (§B.4 ii); a foreign/absent kv:userId wipes every store in-place, queue
   * included (§B.4 i, SqliteVaultCache.init parity).
   */
  static async open(f: IDBFactory, userId: string): Promise<IdbVaultCache> {
    const name = vaultDbName(userId);
    let db = await openDb(f, name, userId);
    if (!hasAllStores(db)) {
      db.close();
      await deleteDb(f, name);
      db = await openDb(f, name, userId);
      if (!hasAllStores(db)) {
        db.close();
        throw new Error("andvari cache: schema incoherent after recreate");
      }
    }
    try {
      await IdbVaultCache.verifyOwner(db, userId);
    } catch (e) {
      db.close();
      throw e;
    }
    return new IdbVaultCache(db, f, name);
  }

  /** §B.4 (i) in ONE readwrite tx over every store: read kv:userId; a missing
   *  or foreign owner clears ALL stores (queue included) and re-stamps. */
  private static async verifyOwner(db: IDBDatabase, userId: string): Promise<void> {
    const tx = db.transaction([...ALL_STORES], "readwrite");
    const kv = tx.objectStore(STORE_KV);
    const row = await req(kv.get("userId"));
    const owner = kvValue(row);
    if (owner !== userId) {
      for (const store of ALL_STORES) tx.objectStore(store).clear();
      kv.put({ key: "userId", value: userId } satisfies KvRow);
      kv.put({ key: "createdAt", value: Date.now() } satisfies KvRow);
    }
    await txDone(tx);
  }

  consecutiveCommitFailures(): number {
    return this.pullFailures;
  }

  // -- guarded plumbing (§D.2a) --

  private async read<T>(stores: string[], fallback: T, body: (tx: IDBTransaction) => Promise<T>): Promise<T> {
    if (this.closed) return fallback;
    let tx: IDBTransaction;
    try {
      tx = this.db.transaction(stores, "readonly");
    } catch (e) {
      if (this.closed) return fallback;
      throw e;
    }
    try {
      return await body(tx);
    } catch (e) {
      if (this.closed) return fallback;
      throw e;
    }
  }

  private async write(stores: string[], body: (tx: IDBTransaction) => void | Promise<void>): Promise<void> {
    if (this.closed) return; // §D.2a: caught no-op once close has begun
    let tx: IDBTransaction;
    try {
      tx = this.db.transaction(stores, "readwrite");
    } catch (e) {
      if (this.closed) return;
      throw e;
    }
    try {
      await body(tx);
      await txDone(tx);
    } catch (e) {
      if (this.closed) return; // close()/versionchange raced the write — no-op, no rejection
      // A browser-FORCED close (eviction/corruption) aborts the in-flight tx (txDone rejects with
      // AbortError) BEFORE the connection's onclose task fires — so this.closed may not be set yet
      // (review, §D.2a). Yield one task to let onclose land, then re-check: a forced-close abort on a
      // fire-and-forget write (the §D.2a post-push persist) must resolve as a caught no-op, never an
      // unhandled rejection. A genuine commit failure (quota) leaves this.closed false ⇒ it still
      // throws and applyPull counts a strike.
      if (e instanceof DOMException && e.name === "AbortError") {
        await new Promise((r) => setTimeout(r, 0));
        if (this.closed) return;
      }
      try {
        tx.abort();
      } catch {
        /* already aborted or committed */
      }
      throw e;
    }
  }

  // -- cursor + kv --

  cursor(): Promise<number> {
    return this.read([STORE_KV], 0, async (tx) => {
      const v = kvValue(await req(tx.objectStore(STORE_KV).get("cursor")));
      return typeof v === "number" ? v : 0;
    });
  }

  setCursor(rev: number): Promise<void> {
    return this.write([STORE_KV], (tx) => {
      tx.objectStore(STORE_KV).put({ key: "cursor", value: rev } satisfies KvRow);
    });
  }

  lastSyncAt(): Promise<number | null> {
    return this.read([STORE_KV], null, async (tx) => {
      const v = kvValue(await req(tx.objectStore(STORE_KV).get("lastSyncAt")));
      return typeof v === "number" ? v : null;
    });
  }

  // -- items (wire envelopes only) --

  upsertItem(wire: WireItem): Promise<void> {
    return this.write([STORE_ITEMS], (tx) => {
      tx.objectStore(STORE_ITEMS).put(wire);
    });
  }

  deleteItem(itemId: string): Promise<void> {
    return this.write([STORE_ITEMS], (tx) => {
      tx.objectStore(STORE_ITEMS).delete(itemId);
    });
  }

  envelopes(): Promise<WireItem[]> {
    return this.read([STORE_ITEMS], [], async (tx) => (await req(tx.objectStore(STORE_ITEMS).getAll())) as WireItem[]);
  }

  // -- grants + vaults --

  upsertGrant(grant: WireGrant): Promise<void> {
    return this.write([STORE_GRANTS], (tx) => {
      tx.objectStore(STORE_GRANTS).put(grant);
    });
  }

  grants(): Promise<WireGrant[]> {
    return this.read([STORE_GRANTS], [], async (tx) => (await req(tx.objectStore(STORE_GRANTS).getAll())) as WireGrant[]);
  }

  upsertVault(vault: WireVault): Promise<void> {
    return this.write([STORE_VAULTS], (tx) => {
      tx.objectStore(STORE_VAULTS).put(vault);
    });
  }

  vaults(): Promise<WireVault[]> {
    return this.read([STORE_VAULTS], [], async (tx) => (await req(tx.objectStore(STORE_VAULTS).getAll())) as WireVault[]);
  }

  dropVault(vaultId: string): Promise<void> {
    return this.write([STORE_ITEMS, STORE_GRANTS, STORE_VAULTS], (tx) => dropVaultIn(tx, vaultId));
  }

  // -- clear + applyPull (§D.1) --

  clear(): Promise<void> {
    return this.write([STORE_ITEMS, STORE_GRANTS, STORE_VAULTS, STORE_KV], (tx) => clearIn(tx));
  }

  async applyPull(fn: (batch: PullBatch) => void): Promise<void> {
    const ops: Array<(tx: IDBTransaction) => void | Promise<void>> = [];
    const batch: PullBatch = {
      setCursor: (rev) =>
        ops.push((tx) => {
          tx.objectStore(STORE_KV).put({ key: "cursor", value: rev } satisfies KvRow);
        }),
      setLastSyncAt: (at) =>
        ops.push((tx) => {
          tx.objectStore(STORE_KV).put({ key: "lastSyncAt", value: at } satisfies KvRow);
        }),
      upsertItem: (wire) =>
        ops.push((tx) => {
          tx.objectStore(STORE_ITEMS).put(wire);
        }),
      deleteItem: (itemId) =>
        ops.push((tx) => {
          tx.objectStore(STORE_ITEMS).delete(itemId);
        }),
      upsertGrant: (grant) =>
        ops.push((tx) => {
          tx.objectStore(STORE_GRANTS).put(grant);
        }),
      upsertVault: (vault) =>
        ops.push((tx) => {
          tx.objectStore(STORE_VAULTS).put(vault);
        }),
      dropVault: (vaultId) => ops.push((tx) => dropVaultIn(tx, vaultId)),
      clear: (keep) => ops.push((tx) => clearIn(tx, keep)),
      enqueue: (mutation) => ops.push((tx) => enqueueIn(tx, mutation)),
      dequeue: (mutationId) => ops.push((tx) => dequeueIn(tx, mutationId)),
      dropPending: (vaultId) => ops.push((tx) => dropPendingIn(tx, vaultId)),
      markStagedDenied: (mutationId) => ops.push((tx) => markStagedDeniedIn(tx, mutationId)),
      putHeld: (held) => {
        const row = toHeldRow(held); // sanitize at buffer time (A2)
        ops.push((tx) => {
          tx.objectStore(STORE_HELD).put(row);
        });
      },
      removeHeld: (vaultId) =>
        ops.push((tx) => {
          tx.objectStore(STORE_HELD).delete(vaultId);
        }),
      addConsumedDeleteId: (deleteId) =>
        ops.push((tx) => {
          tx.objectStore(STORE_CONSUMED).put({ deleteId });
        }),
      setLastVerifiedTransferSeq: (vaultId, seq) =>
        ops.push((tx) => {
          tx.objectStore(STORE_TRANSFER).put({ vaultId, seq });
        }),
      setItemHome: (itemId, vaultId) =>
        ops.push((tx) => {
          tx.objectStore(STORE_KV).put({ key: `${KV_ITEM_HOME}${itemId}`, value: vaultId } satisfies KvRow);
        }),
      addQuarantined: (item) =>
        ops.push((tx) => {
          // One row per itemId (the newest refusal): bounded by the homes this device holds, whatever the server sends.
          tx.objectStore(STORE_KV).put({ key: `${KV_QUARANTINE}${item.itemId}`, value: item } satisfies KvRow);
        }),
      setLogRecord: (rec) =>
        ops.push((tx) => {
          tx.objectStore(STORE_KV).put({ key: `${KV_LOG_RECORD}${rec.vaultId}`, value: { addSeq: rec.addSeq, carried: rec.carried } } satisfies KvRow);
        }),
      removeLogRecord: (vaultId) =>
        ops.push((tx) => {
          tx.objectStore(STORE_KV).delete(`${KV_LOG_RECORD}${vaultId}`);
        }),
    };
    fn(batch); // pure buffering — a throw here commits nothing and is not a storage strike
    if (this.closed) return; // §D.2a
    try {
      await this.write([...ALL_STORES], async (tx) => {
        for (const op of ops) await op(tx);
      });
      if (!this.closed) this.pullFailures = 0;
    } catch (e) {
      this.pullFailures++; // breaker #6: one stuck-cache strike per failed commit
      throw e;
    }
  }

  // -- outbound queue --

  async enqueue(mutation: Mutation, preEdit?: QueuedPreEdit): Promise<boolean> {
    if (this.closed) return false; // §D.2a: a closed handle black-holes writes — report it (CR-01)
    let landed = false;
    await this.write([STORE_QUEUE], async (tx) => {
      await enqueueIn(tx, mutation, preEdit);
      // CR-01 VERIFIABILITY (the setAccountKeys pattern): re-read the mutationId INSIDE this tx.
      // A force-close/versionchange abort resolves write() as a caught no-op with `landed` never
      // set; a genuine commit failure re-throws (fail-loud, not silent). Only a row actually
      // present after the write earns `true` — never a black-holed enqueue reported as success.
      const key = await req(tx.objectStore(STORE_QUEUE).index("mutationId").getKey(mutation.mutationId));
      landed = key !== undefined;
    });
    return landed && !this.closed;
  }

  pending(): Promise<Mutation[]> {
    return this.read([STORE_QUEUE], [], async (tx) => {
      const rows = (await req(tx.objectStore(STORE_QUEUE).getAll())) as QueueRow[]; // primary-key (seq) order = FIFO
      return rows.filter((r) => r.staged === 0).map((r) => r.mutation);
    });
  }

  queuedPreEdits(): Promise<{ mutationId: string; itemId: string; vaultId: string; preEdit: QueuedPreEdit }[]> {
    return this.read([STORE_QUEUE], [], async (tx) => {
      const rows = (await req(tx.objectStore(STORE_QUEUE).getAll())) as QueueRow[];
      return rows
        .filter((r) => r.preEdit != null) // pre-M2 rows read back undefined — omitted, no migration
        .map((r) => ({ mutationId: r.mutationId, itemId: r.mutation.itemId, vaultId: r.vaultId, preEdit: r.preEdit! }));
    });
  }

  dequeue(mutationId: string): Promise<void> {
    return this.write([STORE_QUEUE], (tx) => dequeueIn(tx, mutationId));
  }

  dropPending(vaultId: string): Promise<void> {
    return this.write([STORE_QUEUE], (tx) => dropPendingIn(tx, vaultId));
  }

  markStagedDenied(mutationId: string): Promise<void> {
    return this.write([STORE_QUEUE], (tx) => markStagedDeniedIn(tx, mutationId));
  }

  stagedDenied(): Promise<Mutation[]> {
    return this.read([STORE_QUEUE], [], async (tx) => {
      const rows = (await req(tx.objectStore(STORE_QUEUE).getAll())) as QueueRow[];
      return rows.filter((r) => r.staged === 1).map((r) => r.mutation);
    });
  }

  // -- holding area + replay floors (spec 03 §11) --

  putHeld(held: HeldVaultRecord & { cachedName?: string }): Promise<void> {
    const row = toHeldRow(held);
    return this.write([STORE_HELD], (tx) => {
      tx.objectStore(STORE_HELD).put(row);
    });
  }

  getHeld(vaultId: string): Promise<HeldVaultRecord | null> {
    return this.read([STORE_HELD], null, async (tx) => {
      const row = (await req(tx.objectStore(STORE_HELD).get(vaultId))) as HeldRow | undefined;
      return row ? fromHeldRow(row) : null;
    });
  }

  heldVaults(): Promise<HeldVaultRecord[]> {
    return this.read([STORE_HELD], [], async (tx) => {
      const rows = (await req(tx.objectStore(STORE_HELD).getAll())) as HeldRow[];
      return rows.map(fromHeldRow);
    });
  }

  removeHeld(vaultId: string): Promise<void> {
    return this.write([STORE_HELD], (tx) => {
      tx.objectStore(STORE_HELD).delete(vaultId);
    });
  }

  addConsumedDeleteId(deleteId: string): Promise<void> {
    return this.write([STORE_CONSUMED], (tx) => {
      tx.objectStore(STORE_CONSUMED).put({ deleteId });
    });
  }

  isConsumedDeleteId(deleteId: string): Promise<boolean> {
    return this.read([STORE_CONSUMED], false, async (tx) => (await req(tx.objectStore(STORE_CONSUMED).getKey(deleteId))) !== undefined);
  }

  consumedDeleteIds(): Promise<string[]> {
    return this.read([STORE_CONSUMED], [], async (tx) => {
      const rows = (await req(tx.objectStore(STORE_CONSUMED).getAll())) as { deleteId: string }[];
      return rows.map((r) => r.deleteId);
    });
  }

  lastVerifiedTransferSeq(vaultId: string): Promise<number> {
    return this.read([STORE_TRANSFER], 0, async (tx) => {
      const row = (await req(tx.objectStore(STORE_TRANSFER).get(vaultId))) as { vaultId: string; seq: number } | undefined;
      return typeof row?.seq === "number" ? row.seq : 0;
    });
  }

  setLastVerifiedTransferSeq(vaultId: string, seq: number): Promise<void> {
    return this.write([STORE_TRANSFER], (tx) => {
      tx.objectStore(STORE_TRANSFER).put({ vaultId, seq });
    });
  }

  transferSeqs(): Promise<{ vaultId: string; seq: number }[]> {
    return this.read([STORE_TRANSFER], [], async (tx) => (await req(tx.objectStore(STORE_TRANSFER).getAll())) as { vaultId: string; seq: number }[]);
  }

  itemHomes(): Promise<{ itemId: string; vaultId: string }[]> {
    return this.read([STORE_KV], [], async (tx) => {
      const rows = (await req(tx.objectStore(STORE_KV).getAll())) as KvRow[];
      return rows
        .filter((r) => r.key.startsWith(KV_ITEM_HOME) && typeof r.value === "string")
        .map((r) => ({ itemId: r.key.slice(KV_ITEM_HOME.length), vaultId: r.value as string }));
    });
  }

  quarantined(): Promise<WireItem[]> {
    return this.read([STORE_KV], [], async (tx) => {
      const rows = (await req(tx.objectStore(STORE_KV).getAll())) as KvRow[];
      return rows.filter((r) => r.key.startsWith(KV_QUARANTINE) && r.value && typeof r.value === "object").map((r) => r.value as WireItem);
    });
  }

  logRecords(): Promise<VaultLogRecord[]> {
    return this.read([STORE_KV], [], async (tx) => {
      const rows = (await req(tx.objectStore(STORE_KV).getAll())) as KvRow[];
      const out: VaultLogRecord[] = [];
      for (const r of rows) {
        if (!r.key.startsWith(KV_LOG_RECORD)) continue;
        const v = r.value as { addSeq?: unknown; carried?: unknown } | null;
        // A record that does not read is no record: hydrate decides that vault as a copy from before records were kept.
        if (v && typeof v === "object" && typeof v.addSeq === "number" && Number.isSafeInteger(v.addSeq) && typeof v.carried === "boolean") {
          out.push({ vaultId: r.key.slice(KV_LOG_RECORD.length), addSeq: v.addSeq, carried: v.carried });
        }
      }
      return out;
    });
  }

  // -- web-only accountKeys + policy (§A rows 6+8, design D5) --

  accountKeys(): Promise<AccountKeys | null> {
    return this.read([STORE_KV], null, async (tx) => {
      const v = kvValue(await req(tx.objectStore(STORE_KV).get("accountKeys")));
      return v && typeof v === "object" ? (v as AccountKeys) : null;
    });
  }

  async setAccountKeys(keys: AccountKeys): Promise<boolean> {
    if (this.closed) return false;
    let written = false;
    await this.write([STORE_KV], async (tx) => {
      const kv = tx.objectStore(STORE_KV);
      if (!floorGood(keys)) {
        // §D.2c (breaker #5): never let an absent/sub-floor/over-ceiling payload
        // displace a good one — a hostile server refusing offline unlock later
        // must not get that for free. Read+decide+write in ONE tx.
        const current = kvValue(await req(kv.get("accountKeys"))) as AccountKeys | undefined;
        if (floorGood(current ?? null)) return; // keep old
      }
      kv.put({ key: "accountKeys", value: keys } satisfies KvRow);
      written = true;
    });
    return written && !this.closed;
  }

  /** The post-cut-over account keys with their genesis (spec 02 §8): what an offline unlock opens with openAccount. */
  accountKeysV2(): Promise<AccountKeysV2 | null> {
    return this.read([STORE_KV], null, async (tx) => {
      const v = kvValue(await req(tx.objectStore(STORE_KV).get(KV_ACCOUNT_KEYS_V2)));
      return isCachedKeysV2(v) ? v : null;
    });
  }

  hasAccountKeysV2Row(): Promise<boolean> {
    return this.read([STORE_KV], false, async (tx) => (await req(tx.objectStore(STORE_KV).get(KV_ACCOUNT_KEYS_V2))) !== undefined);
  }

  /** As {@link setAccountKeys}: a copy without a genesis, or outside the KDF fence, never displaces a good one. */
  async setAccountKeysV2(keys: AccountKeysV2): Promise<boolean> {
    if (this.closed) return false;
    let written = false;
    await this.write([STORE_KV], async (tx) => {
      const kv = tx.objectStore(STORE_KV);
      if (!isCachedKeysV2(keys)) {
        if (isCachedKeysV2(kvValue(await req(kv.get(KV_ACCOUNT_KEYS_V2))))) return; // keep old
      }
      kv.put({ key: KV_ACCOUNT_KEYS_V2, value: keys } satisfies KvRow);
      written = true;
    });
    return written && !this.closed;
  }

  pendingWraps(): Promise<PendingWrap[]> {
    return this.read([STORE_KV], [], async (tx) => {
      const v = kvValue(await req(tx.objectStore(STORE_KV).get(KV_PENDING_WRAPS)));
      return Array.isArray(v) ? v.filter(isPendingWrap).map((w) => ({ kdfSalt: w.kdfSalt, kdfParams: { ...w.kdfParams }, wrappedUvk: w.wrappedUvk, ...(atOf(w.at) !== undefined ? { at: atOf(w.at) } : {}) })) : [];
    });
  }

  async setPendingWraps(wraps: readonly PendingWrap[]): Promise<boolean> {
    if (this.closed) return false;
    let written = false;
    await this.write([STORE_KV], async (tx) => {
      const kv = tx.objectStore(STORE_KV);
      if (wraps.length === 0) kv.delete(KV_PENDING_WRAPS);
      else {
        // A wrap kept again keeps the day it was first kept; a new one is stamped now.
        const held = kvValue(await req(kv.get(KV_PENDING_WRAPS)));
        const firstKept = (w: PendingWrap): number => atOf(w.at) ?? (Array.isArray(held) ? held.filter(isPendingWrap).map((h) => (h.wrappedUvk === w.wrappedUvk ? atOf(h.at) : undefined)).find((a) => a !== undefined) : undefined) ?? Date.now();
        kv.put({ key: KV_PENDING_WRAPS, value: wraps.map((w) => ({ kdfSalt: w.kdfSalt, kdfParams: { ...w.kdfParams }, wrappedUvk: w.wrappedUvk, at: firstKept(w) })) } satisfies KvRow);
      }
      written = true;
    });
    return written && !this.closed;
  }

  halfMadeDue(): Promise<HalfMadeDueRow[]> {
    return this.read([STORE_KV], [], async (tx) => {
      const v = kvValue(await req(tx.objectStore(STORE_KV).get(KV_HALF_MADE_DUE)));
      return Array.isArray(v) ? v.map(parseHalfMadeDueRow).filter((r): r is HalfMadeDueRow => r !== null) : [];
    });
  }

  async setHalfMadeDue(rows: readonly HalfMadeDueRow[]): Promise<boolean> {
    if (this.closed) return false;
    let written = false;
    await this.write([STORE_KV], async (tx) => {
      const kv = tx.objectStore(STORE_KV);
      if (rows.length === 0) kv.delete(KV_HALF_MADE_DUE);
      else kv.put({ key: KV_HALF_MADE_DUE, value: rows.map((r) => ({ vaultId: r.vaultId, copies: r.copies === null ? null : r.copies.map(([id, rev]) => [id, rev]) })) } satisfies KvRow);
      written = true;
    });
    return written && !this.closed;
  }

  async clearAccountKeys(): Promise<void> {
    if (this.closed) return;
    await this.write([STORE_KV], async (tx) => {
      tx.objectStore(STORE_KV).delete(KV_ACCOUNT_KEYS_V2);
      tx.objectStore(STORE_KV).delete("accountKeys");
    });
  }

  policy(): Promise<CachePolicy | null> {
    return this.read([STORE_KV], null, async (tx) => {
      const v = kvValue(await req(tx.objectStore(STORE_KV).get("policy")));
      return v && typeof v === "object" ? (v as CachePolicy) : null;
    });
  }

  setPolicy(policy: CachePolicy): Promise<void> {
    return this.write([STORE_KV], (tx) => {
      tx.objectStore(STORE_KV).put({ key: "policy", value: policy } satisfies KvRow);
    });
  }

  // -- lifecycle --

  async wipe(): Promise<void> {
    this.close();
    await deleteDb(this.f, this.name);
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    try {
      this.db.close();
    } catch {
      /* already closed */
    }
  }
}

// ---- the no-op impl -------------------------------------------------------------

const NOOP_BATCH: PullBatch = {
  setCursor: () => {},
  setLastSyncAt: () => {},
  upsertItem: () => {},
  deleteItem: () => {},
  upsertGrant: () => {},
  upsertVault: () => {},
  dropVault: () => {},
  clear: () => {},
  enqueue: () => {},
  dequeue: () => {},
  dropPending: () => {},
  markStagedDenied: () => {},
  putHeld: () => {},
  removeHeld: () => {},
  addConsumedDeleteId: () => {},
  setLastVerifiedTransferSeq: () => {},
  setItemHome: () => {},
  addQuarantined: () => {},
  setLogRecord: () => {},
  removeLogRecord: () => {},
};

/**
 * The cache-less impl (§B.3/§B.4): per-device opt-out, unsupported/blocked
 * IndexedDB, org policy `offlineCacheAllowed=false`, and the §D.1 stuck-cache
 * demotion all run on this so `store.ts` has ONE code shape. Deliberately
 * EMPTY (not memory-backed): when nothing may persist, hydrate must see a cold
 * start and `VaultStore` keeps its own in-memory working set exactly as today.
 */
export class NullCache implements VaultCache {
  readonly durable = false;

  async cursor(): Promise<number> {
    return 0;
  }
  async setCursor(_rev: number): Promise<void> {}
  async lastSyncAt(): Promise<number | null> {
    return null;
  }

  async upsertItem(_wire: WireItem): Promise<void> {}
  async deleteItem(_itemId: string): Promise<void> {}
  async envelopes(): Promise<WireItem[]> {
    return [];
  }

  async upsertGrant(_grant: WireGrant): Promise<void> {}
  async grants(): Promise<WireGrant[]> {
    return [];
  }
  async upsertVault(_vault: WireVault): Promise<void> {}
  async vaults(): Promise<WireVault[]> {
    return [];
  }
  async dropVault(_vaultId: string): Promise<void> {}

  async clear(): Promise<void> {}
  async applyPull(fn: (batch: PullBatch) => void): Promise<void> {
    fn(NOOP_BATCH); // uniform shape: the caller's buffering closure still runs
  }
  consecutiveCommitFailures(): number {
    return 0;
  }

  async enqueue(_mutation: Mutation, _preEdit?: QueuedPreEdit): Promise<boolean> {
    return false; // nothing persisted — honest (setAccountKeys parity); the caller does the real send
  }
  async pending(): Promise<Mutation[]> {
    return [];
  }
  async queuedPreEdits(): Promise<{ mutationId: string; itemId: string; vaultId: string; preEdit: QueuedPreEdit }[]> {
    return [];
  }
  async dequeue(_mutationId: string): Promise<void> {}
  async dropPending(_vaultId: string): Promise<void> {}
  async markStagedDenied(_mutationId: string): Promise<void> {}
  async stagedDenied(): Promise<Mutation[]> {
    return [];
  }

  async putHeld(_held: HeldVaultRecord & { cachedName?: string }): Promise<void> {}
  async getHeld(_vaultId: string): Promise<HeldVaultRecord | null> {
    return null;
  }
  async heldVaults(): Promise<HeldVaultRecord[]> {
    return [];
  }
  async removeHeld(_vaultId: string): Promise<void> {}

  async addConsumedDeleteId(_deleteId: string): Promise<void> {}
  async isConsumedDeleteId(_deleteId: string): Promise<boolean> {
    return false;
  }
  async consumedDeleteIds(): Promise<string[]> {
    return [];
  }
  async lastVerifiedTransferSeq(_vaultId: string): Promise<number> {
    return 0;
  }
  async setLastVerifiedTransferSeq(_vaultId: string, _seq: number): Promise<void> {}
  async transferSeqs(): Promise<{ vaultId: string; seq: number }[]> {
    return [];
  }
  async itemHomes(): Promise<{ itemId: string; vaultId: string }[]> {
    return [];
  }
  async quarantined(): Promise<WireItem[]> {
    return [];
  }
  async logRecords(): Promise<VaultLogRecord[]> {
    return [];
  }

  async accountKeys(): Promise<AccountKeys | null> {
    return null;
  }
  async setAccountKeys(_keys: AccountKeys): Promise<boolean> {
    return false; // nothing persisted — honest
  }
  async accountKeysV2(): Promise<AccountKeysV2 | null> {
    return null;
  }
  async hasAccountKeysV2Row(): Promise<boolean> {
    return false;
  }
  async setAccountKeysV2(_keys: AccountKeysV2): Promise<boolean> {
    return false;
  }
  async pendingWraps(): Promise<PendingWrap[]> {
    return [];
  }
  async setPendingWraps(_wraps: readonly PendingWrap[]): Promise<boolean> {
    return false; // no copy here, so nothing to keep beside it
  }
  async halfMadeDue(): Promise<HalfMadeDueRow[]> {
    return [];
  }
  async setHalfMadeDue(_rows: readonly HalfMadeDueRow[]): Promise<boolean> {
    return false; // no copy here: the session's own memory keeps the list
  }
  async clearAccountKeys(): Promise<void> {} // nothing cached to clear
  async policy(): Promise<CachePolicy | null> {
    return null;
  }
  async setPolicy(_policy: CachePolicy): Promise<void> {}

  async wipe(): Promise<void> {}
  close(): void {}
}

/**
 * Public factory. Feature-detects IndexedDB (§B.5) and runs the §B.4 open-time
 * coherence story; on ANY open-time failure it attempts deleteDatabase and
 * returns NullCache — the cache-less cold start (the server is truth; a
 * discarded cache costs one since=0 resync, never integrity).
 */
export async function openVaultCache(userId: string): Promise<VaultCache> {
  const f = factory();
  if (!f) return new NullCache();
  try {
    return await IdbVaultCache.open(f, userId);
  } catch {
    await deleteDb(f, vaultDbName(userId)); // never rejects
    return new NullCache();
  }
}
