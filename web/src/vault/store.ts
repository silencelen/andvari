import type { ApiClient } from "../api/client";
import { ApiError } from "../api/client";
import type { AttachmentRef, ItemDoc, Mutation, PushResponse, WireItem, WireVault } from "../api/types";
import { HEADER_BYTES, decryptAttachment, encryptAttachment } from "../crypto/attachments";
import { concat, fromB64, toHexLower, utf8 } from "../crypto/bytes";
import { sha256 } from "../crypto/provider";
import type { Account } from "./account";

export interface VaultItem {
  itemId: string;
  vaultId: string;
  rev: number;
  updatedAt: number;
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

/**
 * UUIDv4-shaped id from sha256("conflict|itemId|rev") (spec 03 §5): concurrent
 * materializers across members/devices converge on ONE copy id, absorbed by the
 * server's idempotent existing-item path. Mirrors core SyncEngine byte-for-byte.
 */
export async function conflictCopyId(itemId: string, rev: number): Promise<string> {
  const h = (await sha256(utf8(`conflict|${itemId}|${rev}`))).slice(0, 16);
  h[6] = (h[6]! & 0x0f) | 0x40; // version nibble 4
  h[8] = (h[8]! & 0x3f) | 0x80; // variant 10
  const hex = toHexLower(h);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
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
    }

    // EVERY grant goes through addGrant: the role update always applies (a role change
    // re-delivers the grant while the VK is already held); the key-open only runs when
    // the VK is missing (sealed member grants or UVK-wrapped personal/owner grants).
    for (const grant of resp.grants) {
      try {
        this.account.addGrant(grant);
      } catch {
        /* undecryptable grant — this vault's items stay skipped below */
      }
    }
    for (const vault of resp.vaults) {
      this.vaultsById.set(vault.vaultId, vault);
      // Discover the personal vault so save()/encrypt default to it.
      if (vault.type === "personal" && this.account.hasVault(vault.vaultId)) {
        this.account.setPersonalVault(vault.vaultId);
      }
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

    // Revoked memberships: purge the vault's items locally and forget its key + role.
    for (const vaultId of resp.removedGrants) {
      for (const it of [...this.itemsById.values()]) {
        if (it.vaultId === vaultId) this.itemsById.delete(it.itemId);
      }
      for (const it of [...this.undecryptableById.values()]) {
        if (it.vaultId === vaultId) this.undecryptableById.delete(it.itemId);
      }
      this.vaultsById.delete(vaultId);
      this.account.removeVault(vaultId);
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
    // The server returned the losing version on the conflicting push; but on a plain
    // pull we only see the winner flagged. Create a dated copy of the winner's current
    // content so nothing is lost, then clear the flag with a normal rewrite. The copy
    // id is deterministic (spec 03 §5) so concurrent materializers converge on one copy.
    const copyId = await conflictCopyId(item.itemId, item.rev);
    if (this.itemsById.has(copyId)) return; // already materialized (by us or a peer)
    const stamp = new Date(item.updatedAt).toISOString().slice(0, 10);
    const copyDoc: ItemDoc = { ...winner.doc, name: `${winner.doc.name} (conflict ${stamp})` };
    await this.push([
      this.putMutation(copyId, item.vaultId, copyDoc, 0),
      this.putMutation(item.itemId, item.vaultId, winner.doc, winner.rev), // clears conflict flag
    ]);
  }

  putMutation(itemId: string, vaultId: string, doc: ItemDoc, baseItemRev: number): Mutation {
    return {
      mutationId: crypto.randomUUID(),
      op: "put",
      itemId,
      vaultId,
      baseItemRev,
      item: {
        // Stays 1 until a coordinated format bump: the AD binding (account.encryptItem) and
        // this wire field must move together, and decrypt fails closed on newer versions.
        formatVersion: 1,
        attachmentIds: doc.attachments?.map((a) => a.id) ?? [],
        blob: this.account.encryptItem(vaultId, itemId, doc),
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
    const pushResp = await this.push([m]);
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
   * Bulk CSV import (spec 06): push planned items into the personal vault in chunks of
   * SERVER_BATCH_MAX, then one sync at the end. Each mutation's mutationId IS its itemId
   * (minted once at plan time) so re-running the SAME plan after a mid-import failure
   * replays idempotently server-side (idempotency key = deviceId+mutationId) instead of
   * duplicating. Mirrors core SyncEngine.importAll. Re-PARSING the file mints new ids.
   */
  async importDocs(
    items: { itemId: string; doc: ItemDoc }[],
    onProgress?: (done: number, total: number) => void,
  ): Promise<void> {
    const vaultId = this.account.personalVaultId;
    const total = items.length;
    let done = 0;
    for (let start = 0; start < items.length; start += VaultStore.SERVER_BATCH_MAX) {
      const chunk = items.slice(start, start + VaultStore.SERVER_BATCH_MAX);
      const mutations: Mutation[] = chunk.map(({ itemId, doc }) => ({
        mutationId: itemId, // stable id → idempotent retry of the same plan
        op: "put",
        itemId,
        vaultId,
        baseItemRev: 0,
        item: {
          formatVersion: 1,
          attachmentIds: doc.attachments?.map((a) => a.id) ?? [],
          blob: this.account.encryptItem(vaultId, itemId, doc),
        },
      }));
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

  private async push(mutations: Mutation[]): Promise<PushResponse> {
    const resp = await this.api.push(mutations);
    // Apply confirmed revs locally where we can (best-effort; sync() reconciles fully).
    for (const r of resp.results) {
      if (r.status === "denied") throw new ApiError(403, "denied", "write denied");
    }
    return resp;
  }
}
