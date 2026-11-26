import "fake-indexeddb/auto";
import { beforeAll, describe, expect, it } from "vitest";
import type { ApiClient } from "../api/client";
import type { Mutation, PushResponse, SyncResponse, WireGrant, WireVault } from "../api/types";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";
import { memoryClientState } from "./accountstatesync";
import { FakeSharedLogs } from "./fakesharedlogs.testkit";
import { type IdbVaultCache, openVaultCache } from "./idbcache";
import { type ItemWire, VaultStore } from "./store";

/**
 * Before 2026-11-16, one sync answer naming the personal vault as removed took it away (its items left the list,
 * its key was dropped, every later save failed, and with the offline copy on its rows left IndexedDB). A personal vault
 * has no members (design §3.10), so no removal of it can be genuine, and a server must not be able to take a person's
 * saved passwords away from their own device (§4.4): the answer raises a notice and changes nothing.
 */
const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };

class FakeApi {
  queue: SyncResponse[] = [];
  pushes: Mutation[][] = [];
  rev = 10;
  async sync(): Promise<SyncResponse> {
    return this.queue.shift() ?? { rev: this.rev, full: false, vaults: [], grants: [], items: [], removedGrants: [] };
  }
  async pushMutations(mutations: Mutation[]): Promise<PushResponse> {
    this.pushes.push(mutations);
    return { rev: ++this.rev, results: mutations.map((m) => ({ mutationId: m.mutationId, status: "applied" as const, newItemRev: 1 })) };
  }
  async vaultMembers() {
    return [];
  }
  async accountState() {
    return { sealedState: null, seq: 0 };
  }
  asClient(): ApiClient {
    return this as unknown as ApiClient;
  }
  asWire(): ItemWire {
    return this as unknown as ItemWire;
  }
}

describe("a sync answer can never take the personal vault away", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("the items stay listed, the key stays, saves go on, and the offline copy keeps its rows across a reload", async () => {
    const recovery = boxKeypairFromSeed(randomBytes(32));
    const password = "pw personal-removal";
    const { request } = await Account.enroll({ inviteToken: "t", email: "pv@example.com", displayName: "pv", password, kdfParams: KDF, recoveryPublicKey: recovery.publicKey, recoveryFingerprint: await fingerprint(recovery.publicKey) });
    const keys = { kdfSalt: request.kdfSalt, kdfParams: request.kdfParams, wrappedUvk: request.wrappedUvk, encryptedIdentitySeed: request.encryptedIdentitySeed, identityPub: request.identityPub, escrowFingerprint: request.escrow!.fingerprint, personalWrap: request.personalWrap! };
    const pv = request.personalVault.vaultId;
    const row: WireVault = { vaultId: pv, type: "personal", rev: 2, metaBlob: request.personalVault.metaBlob, createdAt: 0 };
    const grant: WireGrant = { vaultId: pv, userId: request.userId, role: "owner", wrappedVk: request.personalVault.wrappedVk, rev: 2 };

    const device = await Account.unlock(request.userId, password, keys);
    const api = new FakeApi();
    api.queue.push({ rev: 9, full: true, vaults: [row], grants: [grant], items: [], removedGrants: [] });
    const cache = (await openVaultCache(request.userId)) as IdbVaultCache;
    const store = new VaultStore(api.asClient(), device, cache, memoryClientState(), api.asWire());
    new FakeSharedLogs(device).attachTo(store);
    await store.sync();
    await store.save(null, { type: "note", name: "Locker code" });
    await store.sync();
    const names = (s: VaultStore) => s.list().map((i) => i.doc.name).sort();
    expect(names(store)).toEqual(["Locker code"]);

    // The hostile answer.
    api.rev = 20;
    api.queue.push({ rev: 20, full: false, vaults: [], grants: [], items: [], removedGrants: [pv], removedGrantsInfo: [{ vaultId: pv, reason: "removed" }] });
    await store.sync();
    expect(names(store)).toEqual(["Locker code"]);
    expect(device.personalVaultId).toBe(pv);
    expect(device.hasVault(pv)).toBe(true);
    expect(store.heldVaults()).toEqual([]);
    expect(store.notices().map((n) => n.kind)).toEqual(["personal-kept"]);
    const before = api.pushes.length;
    await store.save(null, { type: "note", name: "Written after" });
    await store.sync();
    expect(api.pushes.length).toBeGreaterThan(before);
    expect(names(store)).toEqual(["Locker code", "Written after"]);

    // A reload: the offline copy still holds the vault and its items.
    const device2 = await Account.unlock(request.userId, password, keys);
    const store2 = new VaultStore(new FakeApi().asClient(), device2, (await openVaultCache(request.userId)) as IdbVaultCache, memoryClientState(), new FakeApi().asWire());
    new FakeSharedLogs(device2).attachTo(store2);
    await store2.hydrate();
    expect(names(store2)).toEqual(["Locker code", "Written after"]);
    expect(store2.heldVaults()).toEqual([]);
  });
});
