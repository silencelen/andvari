import type { ApiClient } from "../api/client";
import { ApiError } from "../api/client";
import type { ItemDoc, Mutation, WireItem } from "../api/types";
import type { Account } from "./account";

export interface VaultItem {
  itemId: string;
  vaultId: string;
  rev: number;
  updatedAt: number;
  doc: ItemDoc;
}

/**
 * Client sync store: pulls deltas since a cursor, decrypts, materializes conflict
 * copies (spec 03 §5 — the CLIENT does this, the server can't re-encrypt), and pushes
 * mutations with stable mutationIds. Web MVP keeps decrypted items in memory only.
 */
export class VaultStore {
  private cursor = 0;
  private itemsById = new Map<string, VaultItem>();

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

  /** Pull everything new since the cursor. Handles 410 (resync from 0). */
  async sync(): Promise<void> {
    let resp;
    try {
      resp = await this.api.sync(this.cursor);
    } catch (e) {
      if (e instanceof ApiError && e.status === 410) {
        this.cursor = 0;
        this.itemsById.clear();
        resp = await this.api.sync(0);
      } else {
        throw e;
      }
    }

    for (const grant of resp.grants) {
      if (grant.role && !this.account.hasVault(grant.vaultId)) {
        try {
          this.account.addPersonalGrant(grant);
        } catch {
          /* shared-vault grants (sealed to identity key) come in P5 */
        }
      }
    }
    // Discover the personal vault so save()/encrypt target it.
    for (const vault of resp.vaults) {
      if (vault.type === "personal" && this.account.hasVault(vault.vaultId)) {
        this.account.setPersonalVault(vault.vaultId);
      }
    }

    const conflictsToMaterialize: WireItem[] = [];
    for (const item of resp.items) {
      if (!this.account.hasVault(item.vaultId)) continue;
      if (item.deleted) {
        this.itemsById.delete(item.itemId);
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
        if (item.conflict) conflictsToMaterialize.push(item);
      } catch {
        /* undecryptable (missing key) — skip */
      }
    }

    this.cursor = resp.rev;

    // Materialize a visible conflict copy for each flagged item, then clear the flag.
    for (const item of conflictsToMaterialize) {
      await this.materializeConflict(item);
    }
  }

  private async materializeConflict(item: WireItem): Promise<void> {
    const winner = this.itemsById.get(item.itemId);
    if (!winner) return;
    // The server returned the losing version on the conflicting push; but on a plain
    // pull we only see the winner flagged. Create a dated copy of the winner's current
    // content so nothing is lost, then clear the flag with a normal rewrite.
    const copyId = this.account.newItemId();
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
      item: { formatVersion: 1, attachmentIds: [], blob: this.account.encryptItem(vaultId, itemId, doc) },
    };
  }

  deleteMutation(itemId: string, vaultId: string, baseItemRev: number): Mutation {
    return { mutationId: crypto.randomUUID(), op: "delete", itemId, vaultId, baseItemRev };
  }

  /** Create or update an item; returns after the server confirms + local state updates. */
  async save(itemId: string | null, doc: ItemDoc): Promise<void> {
    const vaultId = this.account.personalVaultId;
    const existing = itemId ? this.itemsById.get(itemId) : undefined;
    const id = itemId ?? this.account.newItemId();
    const m = this.putMutation(id, vaultId, doc, existing?.rev ?? 0);
    await this.push([m]);
    await this.sync();
  }

  async remove(itemId: string): Promise<void> {
    const existing = this.itemsById.get(itemId);
    if (!existing) return;
    await this.push([this.deleteMutation(itemId, existing.vaultId, existing.rev)]);
    await this.sync();
  }

  private async push(mutations: Mutation[]): Promise<void> {
    const resp = await this.api.push(mutations);
    // Apply confirmed revs locally where we can (best-effort; sync() reconciles fully).
    for (const r of resp.results) {
      if (r.status === "denied") throw new ApiError(403, "denied", "write denied");
    }
  }
}
