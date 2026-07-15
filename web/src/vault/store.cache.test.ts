import "fake-indexeddb/auto";
import { IDBFactory as FakeIDBFactory } from "fake-indexeddb";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, type ApiClient } from "../api/client";
import type { ItemDoc, Mutation, PushResponse, SyncResponse, WireGrant, WireItem, WireVault } from "../api/types";
import type { AccountKeys } from "../api/types";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { deleteProof, offerProof } from "../crypto/lifecycleproof";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";
import { IdbVaultCache, openVaultCache } from "./idbcache";
import { SyncIntegrityError, VaultStore } from "./store";

/**
 * S2 unit suite (design 2026-07-13-web-offline-cache §D): VaultStore driving a REAL
 * IdbVaultCache over fake-indexeddb, with the REAL Account crypto and the same fake
 * ApiClient pattern as store.test.ts — except sync() here HONORS `since` (a strict
 * delta served from a row ledger, each row delivered once), so no test can lean on a
 * hand-re-delivered row a real server would have withheld. Covers: §D.1 one-tx pull
 * commit (ciphertext-only rows, a failed commit freezing disk coherent, the contiguity
 * refuse that keeps later deltas off a gapped disk + the fresh-session gap re-pull,
 * the 410-resync clear that PRESERVES accountKeys/queue/holding — breaker #2), §D.4
 * hydrate (tri-state parity, holding-name re-derivation without key retention, replay
 * floors, restart-surviving cursor → cross-session F31 — §D.6), §D.5 cross-tab (lock
 * name + the §D.5.1 cursor-skip), §D.2a post-push persist, and the §D.1 stuck-cache
 * demotion (3 non-landing commits: a thrown tx, rejecting reads, or a force-closed
 * cache's silent no-ops).
 */

const g = globalThis as { indexedDB?: IDBFactory };

// Minimum-cost argon2id — these tests exercise cache plumbing, not the KDF.
const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };
const DOC: ItemDoc = { type: "login", name: "Shared login", login: { username: "fam", password: "hunter2" } };

const emptySync = (rev: number): SyncResponse => ({ rev, full: false, vaults: [], grants: [], items: [], removedGrants: [] });

class FakeApi {
  queue: SyncResponse[] = [];
  pushes: Mutation[][] = [];
  sinceLog: number[] = [];
  rev = 1;
  /** The server-side row ledger (newest rev per id), fed by every queued response.
   *  sync() serves a STRICT delta — a row only when its rev > since, the full set at
   *  since=0 — exactly like the real server: each delta row is delivered ONCE, so no
   *  test can lean on a hand-re-delivered row a real server would have withheld. */
  private vaultRows = new Map<string, WireVault>();
  private grantRows = new Map<string, WireGrant>();
  private itemRows = new Map<string, WireItem>();

  private static newest<T extends { rev: number }>(map: Map<string, T>, key: string, row: T): void {
    const cur = map.get(key);
    if (!cur || row.rev >= cur.rev) map.set(key, row);
  }

  async sync(since: number): Promise<SyncResponse> {
    this.sinceLog.push(since);
    const canned = this.queue.shift();
    if (canned) {
      this.rev = Math.max(this.rev, canned.rev);
      for (const v of canned.vaults) FakeApi.newest(this.vaultRows, v.vaultId, v);
      for (const g of canned.grants) FakeApi.newest(this.grantRows, g.vaultId, g);
      for (const i of canned.items) FakeApi.newest(this.itemRows, i.itemId, i);
      return {
        ...canned,
        vaults: canned.vaults.filter((v) => v.rev > since),
        grants: canned.grants.filter((g) => g.rev > since),
        items: canned.items.filter((i) => i.rev > since),
      };
    }
    // Nothing queued: answer straight from the ledger, as the real server would.
    return {
      rev: this.rev,
      full: since === 0,
      vaults: [...this.vaultRows.values()].filter((v) => v.rev > since),
      grants: [...this.grantRows.values()].filter((g) => g.rev > since),
      items: [...this.itemRows.values()].filter((i) => i.rev > since),
      removedGrants: [],
    };
  }

  async push(mutations: Mutation[]): Promise<PushResponse> {
    this.pushes.push(mutations);
    return {
      rev: ++this.rev,
      results: mutations.map((m) => ({ mutationId: m.mutationId, status: "applied" as const, newItemRev: 1 })),
    };
  }

  asClient(): ApiClient {
    return this as unknown as ApiClient;
  }
}

/** An ApiClient whose every call proves hydrate stayed offline. */
const deadApi = (): ApiClient =>
  ({
    sync: async () => {
      throw new TypeError("offline — hydrate must not call the server");
    },
  }) as unknown as ApiClient;

interface Enrolled {
  account: Account;
  password: string;
  /** The server-side AccountKeys payload, reshaped from the register request. */
  keys: AccountKeys;
  /** The account's own personal-vault rows, as the server would deliver them. */
  personalVault: WireVault;
  personalGrant: WireGrant;
}

async function enroll(email: string): Promise<Enrolled> {
  const recovery = boxKeypairFromSeed(randomBytes(32));
  const password = `pw ${email}`;
  const { request, account } = await Account.enroll({
    inviteToken: "test-invite",
    email,
    displayName: email,
    password,
    kdfParams: KDF,
    recoveryPublicKey: recovery.publicKey,
    recoveryFingerprint: await fingerprint(recovery.publicKey),
  });
  return {
    account,
    password,
    keys: {
      kdfSalt: request.kdfSalt,
      kdfParams: request.kdfParams,
      wrappedUvk: request.wrappedUvk,
      encryptedIdentitySeed: request.encryptedIdentitySeed,
      identityPub: request.identityPub,
      escrowFingerprint: request.escrow!.fingerprint,
    },
    personalVault: { vaultId: request.personalVault.vaultId, type: "personal", rev: 1, metaBlob: request.personalVault.metaBlob, createdAt: 0 },
    personalGrant: { vaultId: request.personalVault.vaultId, userId: request.userId, role: "owner", wrappedVk: request.personalVault.wrappedVk, rev: 1, sealedVk: null },
  };
}

/** "Restart": a FRESH full-password unlock of the same account — no vault keys held,
 *  personalVaultId undiscovered — exactly what §D.4 hydrate starts from. */
const relock = (e: Enrolled): Promise<Account> => Account.unlock(e.account.userId, e.password, e.keys);

interface Scenario {
  owner: Enrolled;
  member: Enrolled;
  vaultId: string;
  vault: WireVault;
  grant: WireGrant;
  itemId: string;
  item: WireItem;
}

/** Owner creates a shared vault + item and seals its VK to the member — real client crypto. */
async function scenario(role = "writer"): Promise<Scenario> {
  const owner = await enroll("owner@example.com");
  const member = await enroll("member@example.com");
  const { request, vaultId } = owner.account.buildCreateSharedVault("Family");
  const sealedVk = owner.account.wrapVkForMember(member.account.identityPub, vaultId);
  const itemId = owner.account.newItemId();
  return {
    owner,
    member,
    vaultId,
    vault: { vaultId, type: "shared", rev: 2, metaBlob: request.metaBlob, createdAt: 0 },
    grant: { vaultId, userId: member.account.userId, role, wrappedVk: "", rev: 3, sealedVk },
    itemId,
    item: {
      itemId,
      vaultId,
      rev: 4,
      createdAt: 0,
      updatedAt: 0,
      deleted: false,
      conflict: false,
      formatVersion: 1,
      attachmentIds: [],
      blob: owner.account.encryptItem(vaultId, itemId, DOC).blob,
    },
  };
}

/** Member store on a REAL IdbVaultCache, seeded at cursor 5 with the shared vault,
 *  the member's personal vault, and one shared item. */
async function seeded(role = "writer") {
  const s = await scenario(role);
  const cache = (await openVaultCache(s.member.account.userId)) as IdbVaultCache;
  expect(cache).toBeInstanceOf(IdbVaultCache);
  const api = new FakeApi();
  const store = new VaultStore(api.asClient(), s.member.account, cache);
  api.queue.push({
    rev: 5,
    full: true,
    vaults: [s.vault, s.member.personalVault],
    grants: [s.grant, s.member.personalGrant],
    items: [s.item],
    removedGrants: [],
  });
  await store.sync();
  return { s, api, cache, store };
}

describe("VaultStore durable offline cache (S2, design §D)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  beforeEach(() => {
    // A fresh factory per test = a clean disk; nothing bleeds between tests.
    g.indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
  });

  // ---- §D.1 write point 1: the one-tx pull commit ----

  it("a pull commits wire rows + cursor + lastSyncAt — ciphertext only, no decrypted twin at rest", async () => {
    const { s, cache, store } = await seeded();
    expect(store.get(s.itemId)?.doc).toEqual(DOC); // memory decrypted…
    expect(store.cacheDurable).toBe(true);

    expect(await cache.cursor()).toBe(5);
    expect(await cache.lastSyncAt()).toBe(store.lastSyncAt);
    const rows = await cache.envelopes();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toEqual(s.item); // …disk holds the EXACT wire row (sealed blob string)
    expect(Object.keys(rows[0]!)).not.toContain("doc");
    const atRest = JSON.stringify([rows, await cache.grants(), await cache.vaults()]);
    expect(atRest).not.toContain("hunter2"); // no plaintext in any persisted field
    expect(atRest).not.toContain("Shared login");
    expect((await cache.grants()).map((x) => x.vaultId).sort()).toEqual([s.vaultId, s.member.personalVault.vaultId].sort());
    expect((await cache.vaults()).map((x) => x.vaultId).sort()).toEqual([s.vaultId, s.member.personalVault.vaultId].sort());
  });

  it("a failed commit freezes disk coherent: later deltas are REFUSED (contiguity) and a fresh session re-pulls the gap from the disk cursor, converging with the never-failed twin", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const { s, api, cache, store } = await seeded(); // memory + disk at 5
      const noteId = s.owner.account.newItemId();
      const note: WireItem = { ...s.item, itemId: noteId, rev: 6, blob: s.owner.account.encryptItem(s.vaultId, noteId, { type: "note", name: "new note" }).blob };
      // One transient storage failure (quota-shaped): the commit tx dies whole (A1 —
      // idbcache.test.ts proves mid-tx atomicity; here the commit seam just rejects once).
      vi.spyOn(cache, "applyPull").mockRejectedValueOnce(new Error("quota"));
      api.queue.push({ rev: 6, full: false, vaults: [], grants: [], items: [note], removedGrants: [] });
      await expect(store.sync()).resolves.toBeUndefined(); // a failed commit never fails the sync
      expect(store.get(noteId)?.doc.name).toBe("new note"); // memory applied the pull…
      expect(await cache.cursor()).toBe(5); // …disk kept the OLD cursor and rows
      expect((await cache.envelopes()).map((r) => r.itemId)).toEqual([s.itemId]);

      // Memory (6) now runs ahead of disk (5), and a strict-delta server never re-sends
      // (5, 6] to a cursor past it. Every later delta is therefore based PAST the gap:
      // the contiguity guard refuses each one — the rev-7 tombstone must NOT be stamped
      // over the missing rev-6 row (that resurrection was exactly the F1 hazard) — and a
      // refuse is NOT a storage failure, so a run of them must never demote the cache.
      const tomb: WireItem = { ...s.item, rev: 7, deleted: true, blob: null };
      api.queue.push({ rev: 7, full: false, vaults: [], grants: [], items: [tomb], removedGrants: [] });
      await store.sync();
      await store.sync(); // two more ledger-served deltas —
      await store.sync(); // three refuses in a row, still no demotion
      expect(store.get(s.itemId)).toBeUndefined(); // memory saw the tombstone
      expect(await cache.cursor()).toBe(5); // disk never claimed a rev its rows lack
      expect((await cache.envelopes()).map((r) => r.itemId)).toEqual([s.itemId]);
      expect(store.cacheDemoted).toBe(false); // refuse ≠ failure
      expect(store.cacheDurable).toBe(true);

      // Self-heal (§D.1): a fresh session hydrates from the DISK cursor, so its first
      // pull asks the server for the WHOLE gap (since=5) — the note and the tombstone
      // land, and both memory and disk converge with the twin that never lost a commit.
      const fresh = await relock(s.member);
      const cache2 = (await openVaultCache(fresh.userId)) as IdbVaultCache;
      const store2 = new VaultStore(api.asClient(), fresh, cache2);
      await store2.hydrate();
      await store2.sync(); // the ledger serves the strict delta (5, 7]
      expect(api.sinceLog.at(-1)).toBe(5); // resumed from DISK, not from memory
      expect(store2.list()).toEqual(store.list()); // converged: the one live note
      expect(store2.get(s.itemId)).toBeUndefined(); // the tombstone applied — no resurrection
      expect(await cache2.cursor()).toBe(7);
      expect((await cache2.envelopes()).map((r) => r.itemId)).toEqual([noteId]);
    } finally {
      warn.mockRestore();
    }
  });

  it("contiguity guard: a delta based past the disk cursor is refused outright — applyPull never runs, no gap is stamped; a FULL snapshot stays exempt", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const { s, api, cache, store } = await seeded(); // memory at 5
      await cache.setCursor(4); // force disk BEHIND memory (as if an earlier commit was lost)
      const apply = vi.spyOn(cache, "applyPull");

      const edited: WireItem = { ...s.item, rev: 6, blob: s.owner.account.encryptItem(s.vaultId, s.itemId, { ...DOC, name: "edited" }).blob };
      api.queue.push({ rev: 6, full: false, vaults: [], grants: [], items: [edited], removedGrants: [] });
      await store.sync();
      expect(store.get(s.itemId)?.doc.name).toBe("edited"); // memory applied its pull
      expect(apply).not.toHaveBeenCalled(); // the commit was refused BEFORE the tx
      expect(await cache.cursor()).toBe(4); // no non-contiguous cursor stamped
      expect((await cache.envelopes()).find((r) => r.itemId === s.itemId)?.rev).toBe(4); // old row kept
      expect(store.cacheDemoted).toBe(false); // a refuse is not a storage failure

      // A 410 resync's FULL snapshot is self-contained (in-tx clear + rewrite) — always
      // allowed through the guard: it heals the behind disk in-session.
      let failedOnce = false;
      const real = api.sync.bind(api);
      api.sync = async (since: number) => {
        if (!failedOnce) {
          failedOnce = true;
          throw new ApiError(410, "cursor_gone", "resync required");
        }
        return real(since);
      };
      api.queue.push({ rev: 8, full: true, vaults: [s.vault, s.member.personalVault], grants: [s.grant, s.member.personalGrant], items: [edited], removedGrants: [] });
      await store.sync();
      expect(await cache.cursor()).toBe(8);
      expect((await cache.envelopes()).find((r) => r.itemId === s.itemId)?.rev).toBe(6); // the snapshot landed
    } finally {
      warn.mockRestore();
    }
  });

  it("a 410 resync's in-tx clear replaces the row stores but PRESERVES accountKeys, the queue, and holding (breaker #2)", async () => {
    const { s, api, cache, store } = await seeded();
    // Pre-seed the safety state a resync must never touch (S3/S4 write these for real). The
    // queued row is STAGED-DENIED so the pre-pull flushQueue (S4) leaves it alone — proving
    // clear() preserves the queue STORE, not merely that an unsent row got flushed away.
    expect(await cache.setAccountKeys(s.member.keys)).toBe(true);
    await cache.enqueue({ mutationId: "m-queued", op: "put", itemId: "i-q", vaultId: "v-other", baseItemRev: 0 });
    await cache.markStagedDenied("m-queued");
    await cache.putHeld({
      vault: { vaultId: "held-v", type: "shared", rev: 1, metaBlob: "", createdAt: 0 },
      grant: null,
      items: [],
      reason: "removed",
      verified: false,
      parked: [],
      expungeAt: 999,
      cachedName: "gone",
    });
    // A stale row the snapshot will NOT re-deliver — the same-tx clear must drop it.
    await cache.upsertItem({ ...s.item, itemId: "stale-row", rev: 2 });

    let failedOnce = false;
    const real = api.sync.bind(api);
    api.sync = async (since: number) => {
      if (!failedOnce) {
        failedOnce = true;
        throw new ApiError(410, "cursor_gone", "resync required");
      }
      return real(since);
    };
    api.queue.push({ rev: 9, full: true, vaults: [s.vault, s.member.personalVault], grants: [s.grant, s.member.personalGrant], items: [s.item], removedGrants: [] });
    await store.sync();

    expect(await cache.cursor()).toBe(9);
    expect((await cache.envelopes()).map((r) => r.itemId)).toEqual([s.itemId]); // stale row gone — cleared in the SAME tx
    expect(await cache.accountKeys()).toEqual(s.member.keys); // §D.1 enumerated clear: untouched
    expect((await cache.stagedDenied()).map((m) => m.mutationId)).toEqual(["m-queued"]); // queue store preserved
    expect((await cache.heldVaults()).map((h) => h.vault.vaultId)).toEqual(["held-v"]);
  });

  // ---- §D.4 hydrate ----

  it("hydrate rebuilds a fresh sync's exact tri-state (decryptable / held-key-fail / missing-VK) with no server call", async () => {
    const s = await scenario();
    const fv3Id = s.owner.account.newItemId();
    const fv3: WireItem = { ...s.item, itemId: fv3Id, rev: 6, formatVersion: 3 }; // held key, fails closed pre-open
    const foreignId = s.owner.account.newItemId();
    const foreign: WireItem = { ...s.item, itemId: foreignId, vaultId: "vault-with-no-key", rev: 6 };
    const pull: SyncResponse = {
      rev: 7,
      full: true,
      vaults: [s.vault, s.member.personalVault],
      grants: [s.grant, s.member.personalGrant],
      items: [s.item, fv3, foreign],
      removedGrants: [],
    };

    // Device session A: a real sync populates the cache.
    const apiA = new FakeApi();
    const cache = (await openVaultCache(s.member.account.userId)) as IdbVaultCache;
    const storeA = new VaultStore(apiA.asClient(), s.member.account, cache);
    apiA.queue.push(pull);
    await storeA.sync();

    // "Restart": fresh unlock (no keys, personalVaultId undiscovered), reopened cache, dead network.
    const fresh = await relock(s.member);
    expect(fresh.hasVault(s.vaultId)).toBe(false);
    expect(fresh.personalVaultId).toBe("");
    const storeB = new VaultStore(deadApi(), fresh, (await openVaultCache(fresh.userId)) as IdbVaultCache);
    await storeB.hydrate();

    // The exact tri-state, byte for byte against the synced twin.
    expect(storeB.get(s.itemId)?.doc).toEqual(DOC);
    expect(storeB.list()).toEqual(storeA.list());
    expect(storeB.undecryptable()).toEqual(storeA.undecryptable());
    expect(storeB.undecryptable().map((u) => u.itemId).sort()).toEqual([fv3Id, foreignId].sort());
    expect(storeB.needsUpdateCount()).toBe(1); // the fv=3 held-key item — retried, still newer
    expect(storeB.vaults()).toEqual(storeA.vaults());
    expect(fresh.personalVaultId).toBe(s.member.account.personalVaultId); // rediscovered from the cached row
    expect(fresh.roleFor(s.vaultId)).toBe("writer"); // grant re-opened, role applied
    expect(storeB.lastSyncAt).toBe(storeA.lastSyncAt); // the honest "vault as of last sync <t>" stamp
  });

  it("the cursor survives the restart: hydrate → the next pull is a delta, and the F31 guards now span sessions (§D.6)", async () => {
    const { s } = await seeded(); // disk cursor 5
    const fresh = await relock(s.member);
    const api2 = new FakeApi();
    const store2 = new VaultStore(api2.asClient(), fresh, (await openVaultCache(fresh.userId)) as IdbVaultCache);
    await store2.hydrate();

    // Not a fresh-device since=0 pull — the restored cursor drives the delta…
    api2.queue.push(emptySync(5));
    await store2.sync();
    expect(api2.sinceLog).toEqual([5]);

    // …and a server rolled back BELOW that restart-surviving cursor is REJECTED (today a
    // reload reset the cursor to 0 and a rollback got a free pass — strict improvement).
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      api2.queue.push({ rev: 3, full: false, vaults: [], grants: [], items: [{ ...s.item, rev: 3, deleted: true, blob: null }], removedGrants: [] });
      await expect(store2.sync()).rejects.toBeInstanceOf(SyncIntegrityError);
      expect(store2.get(s.itemId)?.doc).toEqual(DOC); // the replayed tombstone was NOT applied
    } finally {
      warn.mockRestore();
    }
  });

  it("hydrate restores the holding area, re-deriving the name from the retained grant WITHOUT retaining the key (A2)", async () => {
    const { s, api, cache, store } = await seeded();
    const key = await s.owner.account.lifecycleKeyFor(s.vaultId);
    const deleteId = crypto.randomUUID();
    const purgeAt = Date.now() + 7 * 86_400_000;
    api.queue.push({
      rev: 6,
      full: false,
      vaults: [],
      grants: [],
      items: [],
      removedGrants: [s.vaultId],
      removedGrantsInfo: [{ vaultId: s.vaultId, reason: "deleted", deleteId, deleteProof: await deleteProof(key, s.vaultId, deleteId), purgeAt }],
    });
    await store.sync();
    expect(store.heldVaults().find((h) => h.vaultId === s.vaultId)?.verified).toBe(true);

    // At rest: ciphertext snapshot + retained grant, the live rows dropped in the SAME tx,
    // and NO plaintext name (A2).
    const atRest = await cache.getHeld(s.vaultId);
    expect(atRest).toBeTruthy();
    expect("cachedName" in (atRest as object)).toBe(false);
    expect(atRest!.items.map((i) => i.itemId)).toEqual([s.itemId]); // the re-sealed snapshot persisted
    expect(atRest!.grant?.vaultId).toBe(s.vaultId);
    expect(await cache.envelopes()).toEqual([]); // dropVault rode the same commit
    expect((await cache.grants()).map((x) => x.vaultId)).toEqual([s.member.personalVault.vaultId]);

    const fresh = await relock(s.member);
    const store2 = new VaultStore(deadApi(), fresh, (await openVaultCache(fresh.userId)) as IdbVaultCache);
    await store2.hydrate();
    const held = store2.heldVaults().find((h) => h.vaultId === s.vaultId);
    expect(held?.name).toBe("Family"); // re-derived via the retained grant (peek, not retain)
    expect(held?.verified).toBe(true);
    expect(held?.purgeAt).toBe(purgeAt);
    expect(fresh.hasVault(s.vaultId)).toBe(false); // the peek did NOT leave the key open
    expect(store2.list().some((i) => i.vaultId === s.vaultId)).toBe(false); // held ≠ live
  });

  it("hydrate restores consumedDeleteIds: a replayed tombstone bearing a consumed deleteId keeps the vault live", async () => {
    const { s, cache } = await seeded();
    const consumedId = crypto.randomUUID();
    await cache.addConsumedDeleteId(consumedId);

    const fresh = await relock(s.member);
    const api2 = new FakeApi();
    const store2 = new VaultStore(api2.asClient(), fresh, (await openVaultCache(fresh.userId)) as IdbVaultCache);
    await store2.hydrate();

    // A replayed old tombstone bearing the consumed deleteId is recognized as stale —
    // the vault stays live, no holding, no notice (spec 03 §11 #4, across a restart).
    api2.queue.push({
      rev: 6,
      full: false,
      vaults: [],
      grants: [],
      items: [],
      removedGrants: [s.vaultId],
      removedGrantsInfo: [{ vaultId: s.vaultId, reason: "deleted", deleteId: consumedId, deleteProof: "irrelevant" }],
    });
    await store2.sync();
    expect(store2.get(s.itemId)).toBeDefined();
    expect(store2.heldVaults()).toHaveLength(0);
    expect(store2.notices()).toHaveLength(0);
  });

  it("hydrate restores staged denials: a real verified delete folds them into the holding record (F21, across a restart)", async () => {
    const { s, cache } = await seeded();
    // A durably staged-denied offline edit (S4 persists these; here the fixture stands in).
    const stagedMut: Mutation = {
      mutationId: "m-staged",
      op: "put",
      itemId: s.itemId,
      vaultId: s.vaultId,
      baseItemRev: 4,
      item: { formatVersion: 1, attachmentIds: [], blob: s.item.blob! },
    };
    await cache.enqueue(stagedMut);
    await cache.markStagedDenied("m-staged");

    const fresh = await relock(s.member);
    const api2 = new FakeApi();
    const store2 = new VaultStore(api2.asClient(), fresh, (await openVaultCache(fresh.userId)) as IdbVaultCache);
    await store2.hydrate();

    // The vault's REAL verified delete arrives (its grace period): the reconnect pull folds the
    // hydrated staged denial into the holding record for restore replay (F21) — so
    // surfaceStagedDenials finds it already parked and never surfaces it as a genuine denial.
    const key = await s.owner.account.lifecycleKeyFor(s.vaultId);
    const deleteId = crypto.randomUUID();
    api2.queue.push({
      rev: 7,
      full: false,
      vaults: [],
      grants: [],
      items: [],
      removedGrants: [s.vaultId],
      removedGrantsInfo: [{ vaultId: s.vaultId, reason: "deleted", deleteId, deleteProof: await deleteProof(key, s.vaultId, deleteId), purgeAt: Date.now() + 7 * 86_400_000 }],
    });
    await store2.sync(); // must NOT throw — the denial is parked, not a genuine refusal
    expect(store2.notices().find((n) => n.vaultId === s.vaultId)?.parkedCount).toBe(1);
    // The staged queue row was dropped in the same tx it folded into held.parked (no double-load).
    expect(await (await openVaultCache(fresh.userId)).stagedDenied()).toEqual([]);
  });

  it("hydrate restores lastVerifiedTransferSeq — a replayed offer at the already-seen seq stays hidden", async () => {
    const { s, cache } = await seeded();
    await cache.setLastVerifiedTransferSeq(s.vaultId, 7);

    const fresh = await relock(s.member);
    const api2 = new FakeApi();
    const store2 = new VaultStore(api2.asClient(), fresh, (await openVaultCache(fresh.userId)) as IdbVaultCache);
    await store2.hydrate();

    const key = await s.owner.account.lifecycleKeyFor(s.vaultId);
    const offerId = crypto.randomUUID();
    const expiresAt = Date.now() + 14 * 86_400_000;
    // Each re-delivery of the vault row carries the response's rev — the real server
    // bumps the row when pendingTransfer changes, and the honest fake only serves rows
    // newer than `since`.
    const offerAt = async (seq: number, rev: number): Promise<WireVault> => ({
      ...s.vault,
      rev,
      pendingTransfer: { toUserId: s.member.account.userId, offerId, proof: await offerProof(key, s.vaultId, offerId, s.member.account.userId, expiresAt, seq), expiresAt, seq },
    });
    // seq 7 was verified before the restart → suppressed (would surface on a floor-less store)…
    api2.queue.push({ rev: 8, full: false, vaults: [await offerAt(7, 8)], grants: [], items: [], removedGrants: [] });
    await store2.sync();
    expect(store2.incomingTransfers()).toHaveLength(0);
    // …seq 8 is genuinely new → surfaces after its proof verifies.
    api2.queue.push({ rev: 9, full: false, vaults: [await offerAt(8, 9)], grants: [], items: [], removedGrants: [] });
    await store2.sync();
    expect(store2.incomingTransfers().map((t) => t.vaultId)).toEqual([s.vaultId]);
  });

  // ---- §D.5 cross-tab ----

  it("§D.5.1 cursor-skip: a sibling tab committed newer — this tab skips the commit but keeps its OWN in-memory cursor", async () => {
    const { s, api, cache, store } = await seeded(); // memory + disk at 5
    // Simulate the sibling: disk advanced to 9 with a row this tab has not pulled yet.
    const markerId = s.owner.account.newItemId();
    await cache.upsertItem({ ...s.item, itemId: markerId, rev: 9 });
    await cache.setCursor(9);

    const editedBlob = s.owner.account.encryptItem(s.vaultId, s.itemId, { ...DOC, name: "edited elsewhere" }).blob;
    api.queue.push({ rev: 6, full: false, vaults: [], grants: [], items: [{ ...s.item, rev: 6, blob: editedBlob }], removedGrants: [] });
    await store.sync();

    expect(store.get(s.itemId)?.doc.name).toBe("edited elsewhere"); // memory applied ITS pull
    expect(await cache.cursor()).toBe(9); // the sibling's newer commit untouched
    const rows = await cache.envelopes();
    expect(rows.map((r) => r.itemId)).toContain(markerId); // newer rows not clobbered by older ones
    expect(rows.find((r) => r.itemId === s.itemId)?.rev).toBe(4); // our rev-6 row was NOT written
    // Breaker #7: the skipping tab's next pull re-fetches from ITS cursor (6, not 9) —
    // rows hidden by the skipped commit reappear via the server, never fast-forwarded past.
    api.queue.push(emptySync(9));
    await store.sync();
    expect(api.sinceLog.at(-1)).toBe(6);
  });

  it("the queue flush AND the pull commit each run inside the andvari-cache-<userId> Web Lock where Web Locks exist (§D.5)", async () => {
    const s = await scenario();
    const cache = (await openVaultCache(s.member.account.userId)) as IdbVaultCache;
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), s.member.account, cache);
    api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [s.item], removedGrants: [] });

    const requested: string[] = [];
    vi.stubGlobal("navigator", {
      locks: {
        request: async (name: string, _opts: unknown, cb: () => Promise<unknown>) => {
          requested.push(name);
          return cb();
        },
      },
    });
    try {
      await store.sync();
    } finally {
      vi.unstubAllGlobals();
    }
    // §D.5 serializes "each pull-apply commit AND queue flush": sync() = flushQueue (lock)
    // → pull commit (lock) — two sequential acquisitions of the same per-user name.
    expect(requested).toEqual([`andvari-cache-${s.member.account.userId}`, `andvari-cache-${s.member.account.userId}`]);
    expect(await cache.cursor()).toBe(5); // the commit ran (inside the lock)
  });

  // ---- §D.2a write point 2: post-push persist ----

  it("a committed save's sealed envelope survives a restart — a new store + hydrate sees it (§D.2a)", async () => {
    const { s, api, cache, store } = await seeded("writer");
    await store.save(null, { type: "note", name: "made offline-durable" }, [], undefined, s.vaultId);
    const savedId = api.pushes.at(-1)![0]!.itemId;
    // On disk in the same breath as the local apply — the reconcile pull (an empty delta
    // here) did NOT deliver it; only the §D.2a persist could have.
    const persisted = (await cache.envelopes()).find((r) => r.itemId === savedId);
    expect(persisted).toBeTruthy();
    expect(persisted!.blob).toBe(api.pushes.at(-1)![0]!.item!.blob); // the EXACT committed envelope

    const fresh = await relock(s.member);
    const store2 = new VaultStore(deadApi(), fresh, (await openVaultCache(fresh.userId)) as IdbVaultCache);
    await store2.hydrate();
    expect(store2.get(savedId)?.doc).toEqual({ type: "note", name: "made offline-durable" });
  });

  it("a committed remove's disk delete lands in the same breath, independent of the reconcile pull (§D.2a)", async () => {
    const { s, api, cache, store } = await seeded("writer");
    expect((await cache.envelopes()).some((r) => r.itemId === s.itemId)).toBe(true);
    api.sync = async () => {
      throw new TypeError("offline"); // the reconcile dies — the disk delete must not depend on it
    };
    await store.remove(s.itemId);
    expect((await cache.envelopes()).some((r) => r.itemId === s.itemId)).toBe(false);
  });

  // ---- §D.1 stuck-cache demotion ----

  it("3 consecutive non-landing commits wipe + demote to NullCache; an interleaved contiguity refuse neither counts nor resets the streak (§D.1)", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const { s, api, cache, store } = await seeded(); // memory + disk at 5
      // A cache whose READS reject can never land (or verify) a commit — every attempt
      // is a non-landing strike, even though applyPull itself is never reached.
      const broken = vi.spyOn(cache, "cursor").mockRejectedValue(new Error("cache read broke"));
      api.queue.push(emptySync(6));
      await store.sync();
      api.queue.push(emptySync(7));
      await store.sync();
      expect(store.cacheDemoted).toBe(false); // two strikes — still attached
      expect(store.cacheDurable).toBe(true);

      // Reads heal for one pull: disk (5) is now honestly BEHIND memory (7), so this
      // commit is REFUSED (coherent freeze) — which must not demote (it is not strike 3)…
      broken.mockRestore();
      api.queue.push(emptySync(8));
      await store.sync();
      expect(store.cacheDemoted).toBe(false);
      expect(await cache.cursor()).toBe(5); // refused — no gap stamped

      // …and must not RESET the tally either: the next non-landing is strike 3.
      vi.spyOn(cache, "cursor").mockRejectedValue(new Error("cache read broke again"));
      api.queue.push(emptySync(9));
      await expect(store.sync()).resolves.toBeUndefined(); // the third strike is still contained
      expect(store.cacheDemoted).toBe(true);
      expect(store.cacheDurable).toBe(false); // swapped to NullCache

      // The wipe landed: reopening the account's DB sees a FRESH, empty cache…
      const reopened = (await openVaultCache(s.member.account.userId)) as IdbVaultCache;
      expect(await reopened.cursor()).toBe(0);
      expect(await reopened.envelopes()).toEqual([]);
      // …and later pulls run cache-less but fine, writing nothing.
      api.queue.push(emptySync(10));
      await expect(store.sync()).resolves.toBeUndefined();
      expect(await reopened.cursor()).toBe(0);
    } finally {
      warn.mockRestore();
    }
  });

  it("a browser-forced close — reads fall back, writes silently no-op, nothing throws — still reaches demotion after 3 non-landing pulls (§D.1)", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const { api, cache, store } = await seeded(); // memory + disk at 5
      cache.close(); // the §D.2a guarded state: cursor() reads fall back to 0, applyPull resolves as a no-op
      for (const rev of [6, 7]) {
        api.queue.push(emptySync(rev));
        await store.sync();
      }
      expect(store.cacheDemoted).toBe(false);
      api.queue.push(emptySync(8));
      await store.sync();
      expect(store.cacheDemoted).toBe(true); // three silent non-landings — caught without a single throw
      expect(store.cacheDurable).toBe(false);
    } finally {
      warn.mockRestore();
    }
  });

  // ---- one code shape: the NullCache default is exactly today's behavior ----

  it("hydrate on the default NullCache is a cold start — nothing restored, first sync still from 0", async () => {
    const s = await scenario();
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), s.member.account); // two-arg caller, as today
    await store.hydrate();
    expect(store.list()).toEqual([]);
    expect(store.lastSyncAt).toBeNull();
    expect(store.cacheDurable).toBe(false);
    api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [s.item], removedGrants: [] });
    await store.sync();
    expect(api.sinceLog).toEqual([0]); // fresh-device pull, unchanged
    expect(store.get(s.itemId)?.doc).toEqual(DOC);
  });
});
