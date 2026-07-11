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
  kind: "deleted" | "removed" | "left" | "anomaly" | "restored" | "added" | "transfer-complete" | "transfer-anomaly";
  /** verified delete: the server-erase deadline (for the "kept sealed until…" line). */
  purgeAt?: number;
  /** verified delete: N of the member's edits parked for replay on restore (F21). */
  parkedCount?: number;
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
   *  Mutually exclusive with itemsById — an itemId lives in exactly one of the two. */
  private undecryptableById = new Map<string, UndecryptableItem>();
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
  /** Edits denied because their vault went in-grace, staged for the holding area (F21). */
  private preParkedByVault = new Map<string, Mutation[]>();
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

  /** Wall-clock time of the last SUCCESSFUL sync, or null before the first one —
   *  the export flow's "vault as of last sync <time>" banner reads this (spec 07). */
  get lastSyncAt(): number | null {
    return this._lastSyncAt;
  }

  constructor(
    private api: ApiClient,
    private account: Account,
  ) {}

  list(): VaultItem[] {
    return [...this.itemsById.values()].sort((a, b) => a.doc.name.localeCompare(b.doc.name));
  }

  get(itemId: string): VaultItem | undefined {
    return this.itemsById.get(itemId);
  }

  /**
   * Items whose vault key IS held but whose blob failed decryptItem at sync time — a
   * newer formatVersion (spec 02 §3 fail-closed) or a corrupt/mismatched blob. The
   * export flow enumerates these into `skipped.undecryptable` (spec 07 §2.4) instead
   * of silently omitting credentials from a backup; they stay OUT of the visible
   * list()/get() surface. Items of vaults with no key are deliberately absent — those
   * aren't ours to enumerate (the Kotlin clients derive the same held-key set from
   * their retained envelopes). Sorted for deterministic backup bytes.
   */
  undecryptable(): UndecryptableItem[] {
    return [...this.undecryptableById.values()].sort(
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
   * Pull everything new since the cursor. Handles 410 (resync from 0).
   *
   * SINGLE-FLIGHT: concurrent callers (WS bell, socket reopen, the offline poll, the
   * Sync-now button, save/remove reconciles) all join the ONE in-flight pull —
   * overlapping pulls could apply an older response after a newer one and move the
   * cursor backwards, the very corruption the rollback guards below exist to reject.
   */
  sync(): Promise<void> {
    this.syncInFlight ??= this.syncOnce().finally(() => {
      this.syncInFlight = null;
    });
    return this.syncInFlight;
  }

  private async syncOnce(): Promise<void> {
    const since = this.cursor;
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

    if (resyncing) {
      // resync-from-0 re-delivers everything — reset so nothing double-counts.
      this.cursor = 0;
      this.itemsById.clear();
      this.vaultsById.clear();
      this.undecryptableById.clear();
      // F20: a resync re-delivers every current grant — drop the warning set so a vault no longer
      // granted (revoked while offline) doesn't leave a stale "can't open" row; still-bad grants
      // below re-populate it. (addedNoticed is left intact: since=0 never fires an added notice.)
      this.undecryptableGrants.clear();
    }

    // EVERY grant goes through addGrant: the role update always applies (a role change
    // re-delivers the grant while the VK is already held); the key-open only runs when
    // the VK is missing (sealed member grants or UVK-wrapped personal/owner grants).
    // A LIVE grant re-arriving for a vault in the holding area is a reinstate signal
    // (restore / re-add) — collected here, acted on after items apply.
    const reinstated = new Set<string>();
    const newlyAdded = new Set<string>(); // F20: grants for vaults not held before this pull
    for (const grant of resp.grants) {
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
    for (const vault of resp.vaults) {
      this.vaultsById.set(vault.vaultId, vault);
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
            this.consumedDeleteIds.add(vault.deleteId);
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
      if (!this.account.hasVault(item.vaultId)) continue;
      if (item.deleted) {
        this.itemsById.delete(item.itemId);
        this.undecryptableById.delete(item.itemId); // a tombstone ends the enumeration too
        continue;
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
        if (item.conflict) conflictsToMaterialize.push(item);
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

    this.cursor = resp.rev;

    // Reinstate (spec 03 §11): a live grant re-arrived for a held vault (restore / re-add) —
    // the vault + its items are back in the live set via the ordinary backfill above; here we
    // clear the holding record, replay parked mutations, mark the deleteId consumed, and notice
    // it. Runs AFTER items apply so replay sees current state.
    for (const vaultId of reinstated) {
      const held = this.holding.get(vaultId);
      if (!held) continue;
      this.holding.delete(vaultId);
      if (held.deleteId) this.consumedDeleteIds.add(held.deleteId);
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
        } catch {
          /* superseded by backfill or undecryptable — skip */
        }
      }
      for (const m of held.parked) {
        try {
          await this.push([m]);
        } catch (e) {
          console.warn(`parked mutation replay failed for restored vault ${vaultId}`, e);
        }
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
    for (const item of conflictsToMaterialize) {
      // A reader must not materialize — its push would be denied (spec 03 §5); the
      // flag waits for a writer/owner on some device.
      if (this.account.roleFor(item.vaultId) === "reader") continue;
      await this.materializeConflict(item);
    }

    this._lastSyncAt = Date.now();
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
    // Fold in any edits that were denied while this vault was going in-grace (F21).
    const staged = this.preParkedByVault.get(vaultId) ?? [];
    this.preParkedByVault.delete(vaultId);
    const parked = [...(this.holding.get(vaultId)?.parked ?? []), ...staged];
    // Verified deletes expunge at purgeAt (the server erases then); everything else at +30d.
    const expungeAt = verifiedDelete && reason === "deleted" && info?.purgeAt ? info.purgeAt : Date.now() + 30 * 86_400_000;
    this.holding.set(vaultId, {
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
    });
    this.hardDropLocal(vaultId);
    return parked.length;
  }

  /** Drop a vault from the LIVE view: its items, undecryptables, vault row, wire grant, key. */
  private hardDropLocal(vaultId: string): void {
    for (const it of [...this.itemsById.values()]) if (it.vaultId === vaultId) this.itemsById.delete(it.itemId);
    for (const it of [...this.undecryptableById.values()]) if (it.vaultId === vaultId) this.undecryptableById.delete(it.itemId);
    this.vaultsById.delete(vaultId);
    this.grantWireByVault.delete(vaultId);
    this.incomingByVault.delete(vaultId);
    this.undecryptableGrants.delete(vaultId); // F20: access gone → the "can't open" warning is moot
    this.account.removeVault(vaultId);
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
   * F21: an edit was denied. Stage it, reconcile, and see whether the vault went in-grace: if
   * so it is PARKED in the holding area for replay on restore (swallow — the notice explains);
   * otherwise it is a real permission denial and the original error is rethrown.
   */
  private async parkOrRethrowDeniedEdit(vaultId: string, mutation: Mutation, err: ApiError): Promise<void> {
    const staged = this.preParkedByVault.get(vaultId) ?? [];
    staged.push(mutation);
    this.preParkedByVault.set(vaultId, staged);
    try {
      await this.sync();
      if (!this.holding.has(vaultId)) {
        // The awaited sync may have JOINED a pull that started BEFORE the denial and whose
        // snapshot predates the vault delete. One fresh sync — which necessarily STARTS
        // after the denial, so its snapshot includes whatever caused it — settles the
        // question before we conclude this was a genuine permission denial.
        await this.sync();
      }
    } catch {
      /* offline — fall through to un-stage + rethrow (the edit failed cleanly) */
    }
    if (this.holding.has(vaultId)) return; // parked into the holding area — no hard failure
    this.preParkedByVault.set(vaultId, (this.preParkedByVault.get(vaultId) ?? []).filter((x) => x !== mutation));
    if ((this.preParkedByVault.get(vaultId) ?? []).length === 0) this.preParkedByVault.delete(vaultId);
    throw err;
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
   * Create or update an item; returns after the server confirms + local state updates.
   * New attachment blobs upload FIRST (spec 02 §6: blob before the item that
   * references it), so the itemId is fixed before any upload starts.
   *
   * An EXISTING item always stays in its own vault (the server enforces
   * `vault_mismatch`); a new item goes to [vaultId] when given, else the personal vault.
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
    let pushResp: PushResponse;
    try {
      pushResp = await this.push([m]);
    } catch (e) {
      // F21: an edit denied because its vault just went in-grace (an owner's accidental
      // delete) is PARKED for replay on restore, not surfaced as a hard failure. A genuine
      // permission denial (reader, still-live vault) rethrows unchanged.
      if (e instanceof ApiError && e.code === "denied") return this.parkOrRethrowDeniedEdit(targetVaultId, m, e);
      throw e;
    }
    // Past this point the put is COMMITTED server-side (mirror remove()): a failed or
    // rejected reconcile pull must NOT fail the save — the Editor would then claim
    // "Save failed — nothing was changed" about a write the server already holds, and
    // a user retry would commit it a SECOND time (putMutation mints a fresh
    // mutationId, so the retry is not idempotent). Apply the confirmed write locally
    // FIRST — sync() is single-flight, so the reconcile below may legitimately join a
    // pull that started BEFORE our push and does not contain it — then reconcile,
    // letting the next successful sync (and the connectivity dot) surface whatever
    // made a failed reconcile fail (offline, or an F31 integrity rejection).
    this.itemsById.set(id, {
      itemId: id,
      vaultId: targetVaultId,
      rev: pushResp.results[0]?.newItemRev ?? (existing?.rev ?? 0) + 1,
      updatedAt: Date.now(),
      formatVersion: m.item!.formatVersion, // the fv this write actually sealed at
      doc,
    });
    this.undecryptableById.delete(id); // it decrypts by construction — we wrote it
    try {
      await this.sync();
    } catch (e) {
      console.warn("save committed but the reconcile pull failed — local apply kept; a later sync trues up", e);
    }
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

  async remove(itemId: string): Promise<void> {
    const existing = this.itemsById.get(itemId);
    if (!existing) return;
    await this.push([this.deleteMutation(itemId, existing.vaultId, existing.rev)]);
    // Past this point the delete is COMMITTED server-side. A failed reconcile must not
    // resurface the item locally or make remove() report failure (the UI would then tell
    // the user "nothing was removed" about an item that is gone fleet-wide) — drop it
    // from the working set now and let the next successful sync true everything up.
    try {
      await this.sync();
    } catch {
      this.itemsById.delete(itemId);
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
