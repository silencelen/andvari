import "fake-indexeddb/auto";
import { IDBFactory as FakeIDBFactory } from "fake-indexeddb";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { ApiClient } from "../api/client";
import type { ItemDoc, Mutation, PushResponse, RemovedGrantInfo, SyncResponse, VaultLeaveRequest, VaultMemberRemoveRequest, WireGrant, WireItem, WireVault } from "../api/types";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { REMOVAL_SKEW_MS, decideRemoval, isV2Nonce, leaveProof, newRemovalNonce, removeProof, removeV2Proof } from "../crypto/lifecycleproof";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";
import { emptyAccountState } from "./accountstate";
import { memoryClientState } from "./accountstatesync";
import { IdbVaultCache, NullCache, type VaultCache } from "./idbcache";
import { ALREADY_RECORDED, LEFT_UNPROVEN, REMOVAL_REPLAY, REMOVED_LEGACY, VaultStore } from "./store";

/**
 * Removal proofs v2 on the web store (security review 2026-10, root cause A §6, §8.6; branch A7; core
 * RemovalProofV2Test twin). The invariant: no removal or leave banner is attributed as genuine without a v2 MAC under
 * the held VK for THIS target, a nonce never consumed here or in account state, and an issuedAt inside this device's
 * own liveSince window; liveSince and the consumed set never come from the server. Same data handling either way.
 */

const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };
const DOC: ItemDoc = { type: "login", name: "Shared login", login: { username: "fam", password: "hunter2" } };
const g = globalThis as { indexedDB?: IDBFactory };

class FakeApi {
  queue: SyncResponse[] = [];
  rev = 1;
  accountStateBlob: string | null = null;
  accountSeq = 0;
  leaves: { id: string; body?: VaultLeaveRequest }[] = [];
  removals: { id: string; userId: string; body?: VaultMemberRemoveRequest }[] = [];

  async sync(): Promise<SyncResponse> {
    const resp = this.queue.shift() ?? { rev: this.rev, full: false, vaults: [], grants: [], items: [], removedGrants: [] };
    this.rev = Math.max(this.rev, resp.rev);
    return resp;
  }
  async push(mutations: Mutation[]): Promise<PushResponse> {
    return { rev: ++this.rev, results: mutations.map((m) => ({ mutationId: m.mutationId, status: "applied" as const, newItemRev: 1 })) };
  }
  async accountState() {
    return { sealedState: this.accountStateBlob, seq: this.accountSeq };
  }
  async putAccountState(sealedState: string, baseSeq: number) {
    if (baseSeq !== this.accountSeq) throw Object.assign(new Error("stale"), { status: 409 });
    this.accountStateBlob = sealedState;
    this.accountSeq += 1;
    return { sealedState, seq: this.accountSeq };
  }
  async leaveVault(id: string, body?: VaultLeaveRequest) {
    this.leaves.push({ id, body });
    return { rev: ++this.rev };
  }
  async removeVaultMember(id: string, userId: string, body?: VaultMemberRemoveRequest) {
    this.removals.push({ id, userId, body });
    return { rev: ++this.rev };
  }
  asClient(): ApiClient {
    return this as unknown as ApiClient;
  }
}

async function enroll(email: string): Promise<Account> {
  const recovery = boxKeypairFromSeed(randomBytes(32));
  const { account } = await Account.enroll({
    inviteToken: "test-invite",
    email,
    displayName: email,
    password: `pw ${email}`,
    kdfParams: KDF,
    recoveryPublicKey: recovery.publicKey,
    recoveryFingerprint: await fingerprint(recovery.publicKey),
  });
  return account;
}

interface Seed {
  owner: Account;
  member: Account;
  api: FakeApi;
  store: VaultStore;
  cache: VaultCache;
  vaultId: string;
  vault: WireVault;
  grant: WireGrant;
  item: WireItem;
  key: Uint8Array;
}

async function seeded(cache: VaultCache = new NullCache()): Promise<Seed> {
  const owner = await enroll("owner@example.com");
  const member = await enroll("member@example.com");
  const { request, vaultId } = owner.buildCreateSharedVault("Family");
  member.authorizeLegacyKey(vaultId, owner.legacyKeyTag(vaultId)!); // as after "Accept" (A6)
  const itemId = owner.newItemId();
  const vault: WireVault = { vaultId, type: "shared", rev: 2, metaBlob: request.metaBlob, createdAt: 0 };
  const grant: WireGrant = { vaultId, userId: member.userId, role: "writer", wrappedVk: "", rev: 3, sealedVk: owner.wrapVkForMember(member.identityPub, vaultId) };
  const item: WireItem = {
    itemId, vaultId, rev: 4, createdAt: 0, updatedAt: 0, deleted: false, conflict: false, formatVersion: 1, attachmentIds: [],
    blob: owner.encryptItem(vaultId, itemId, DOC).blob,
  };
  const api = new FakeApi();
  const store = new VaultStore(api.asClient(), member, cache, memoryClientState());
  api.queue.push({ rev: 5, full: true, vaults: [vault], grants: [grant], items: [item], removedGrants: [] });
  await store.sync();
  api.rev = 5;
  return { owner, member, api, store, cache, vaultId, vault, grant, item, key: await owner.lifecycleKeyFor(vaultId) };
}

const removedV2 = async (s: Seed, opts: { nonce?: string; at?: number; target?: string } = {}): Promise<RemovedGrantInfo> => {
  const nonce = opts.nonce ?? newRemovalNonce();
  const at = opts.at ?? Date.now();
  return { vaultId: s.vaultId, reason: "removed", removeProof: await removeV2Proof(s.key, s.vaultId, opts.target ?? s.member.userId, nonce, at), removeNonce: nonce, proofV: 2, issuedAt: at };
};
const leftV2 = async (s: Seed): Promise<RemovedGrantInfo> => {
  const nonce = newRemovalNonce();
  const at = Date.now();
  return { vaultId: s.vaultId, reason: "left", removeProof: await leaveProof(s.key, s.vaultId, s.member.userId, nonce, at), removeNonce: nonce, proofV: 2, issuedAt: at };
};
async function deliver(s: Seed, info: RemovedGrantInfo | null): Promise<void> {
  s.api.queue.push({ rev: ++s.api.rev + 10, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId], removedGrantsInfo: info ? [info] : [] });
  await s.store.sync();
}
async function reAdd(s: Seed): Promise<void> {
  const rev = ++s.api.rev + 10;
  s.api.queue.push({ rev, full: false, vaults: [s.vault], grants: [{ ...s.grant, rev }], items: [s.item], removedGrants: [] });
  await s.store.sync();
}
const lastNotice = (s: Seed) => s.store.notices().filter((n) => n.vaultId === s.vaultId).at(-1)!;

beforeAll(async () => {
  await initSodium();
});

beforeEach(() => {
  g.indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
});

describe("§6.3 every step, through the store", () => {
  it("a valid v2 removal is attributed, held and consumed", async () => {
    const s = await seeded();
    const info = await removedV2(s);
    await deliver(s, info);
    expect(lastNotice(s).kind).toBe("removed");
    expect(lastNotice(s).reason).toBeUndefined();
    expect(s.store.heldVaults().some((h) => h.vaultId === s.vaultId)).toBe(true);
    expect(s.member.hasVault(s.vaultId)).toBe(false);
    expect(s.store.accountState.deviceConsumed()[s.vaultId]).toEqual([[info.removeNonce, info.issuedAt]]);
  });

  it("a valid v2 leave is the calm 'You left'", async () => {
    const s = await seeded();
    await deliver(s, await leftV2(s));
    expect(lastNotice(s).kind).toBe("left");
    expect(lastNotice(s).reason).toBeUndefined();
  });

  it("a proof for another target is an anomaly and consumes nothing", async () => {
    const s = await seeded();
    await deliver(s, await removedV2(s, { target: s.owner.userId }));
    expect(lastNotice(s).kind).toBe("anomaly");
    expect(s.store.accountState.deviceConsumed()).toEqual({});
    expect(s.store.heldVaults().some((h) => h.vaultId === s.vaultId)).toBe(true); // same data handling
  });

  it("a leave proof relayed as a removal is an anomaly", async () => {
    const s = await seeded();
    await deliver(s, { ...(await leftV2(s)), reason: "removed" });
    expect(lastNotice(s).kind).toBe("anomaly");
  });

  it("a proof issued before this device's liveSince − 10 min is an anomaly", async () => {
    const before = Date.now();
    const s = await seeded();
    await deliver(s, await removedV2(s, { at: before - REMOVAL_SKEW_MS - 1 }));
    expect(lastNotice(s).kind).toBe("anomaly");
  });

  it("a proof issued after now + 10 min is an anomaly", async () => {
    const s = await seeded();
    await deliver(s, await removedV2(s, { at: Date.now() + REMOVAL_SKEW_MS + 60_000 }));
    expect(lastNotice(s).kind).toBe("anomaly");
  });

  it("a v2 row missing its issuedAt is an anomaly", async () => {
    const s = await seeded();
    await deliver(s, { ...(await removedV2(s)), issuedAt: null });
    expect(lastNotice(s).kind).toBe("anomaly");
  });
});

describe("§8.6 in-window rows", () => {
  it("a v1 proof is valid (legacy) once, consumed, then replay-denied after a re-add", async () => {
    const s = await seeded();
    const nonce = crypto.randomUUID();
    const v1: RemovedGrantInfo = { vaultId: s.vaultId, reason: "removed", removeProof: await removeProof(s.key, s.vaultId, s.member.userId, nonce), removeNonce: nonce };
    await deliver(s, v1);
    expect(lastNotice(s).kind).toBe("removed");
    expect(lastNotice(s).reason, "LOW-3: a legacy proof is qualified").toBe(REMOVED_LEGACY);
    expect(s.store.accountState.deviceConsumed()[s.vaultId]?.map(([n]) => n)).toEqual([nonce]);
    await reAdd(s);
    await deliver(s, v1);
    expect(lastNotice(s).kind).toBe("replay-denied");
    expect(lastNotice(s).reason).toBe(REMOVAL_REPLAY);
  });

  it("a proof-less left says 'You left' plus 'tell your admin'", async () => {
    const s = await seeded();
    await deliver(s, { vaultId: s.vaultId, reason: "left" });
    expect(lastNotice(s).kind).toBe("left");
    expect(lastNotice(s).reason).toBe(LEFT_UNPROVEN);
  });
});

describe("replay after a re-add", () => {
  it("is rejected on a device that saw the re-add", async () => {
    const s = await seeded();
    const info = await removedV2(s);
    await deliver(s, info);
    expect(lastNotice(s).kind).toBe("removed");
    await reAdd(s);
    expect(s.member.hasVault(s.vaultId)).toBe(true);
    await deliver(s, info);
    expect(lastNotice(s).kind).toBe("replay-denied");
  });

  it("an older proof fails the window after a re-add even without a consumed record", async () => {
    const s = await seeded();
    const old = Date.now() - 3 * REMOVAL_SKEW_MS;
    await deliver(s, { vaultId: s.vaultId, reason: "removed" });
    await reAdd(s);
    await deliver(s, await removedV2(s, { at: old }));
    expect(lastNotice(s).kind).toBe("anomaly");
  });
});

describe("durability: restart, merge, never shrunk", () => {
  it("the consumed set survives a restart (IndexedDB) and merges into account state", async () => {
    const cache = await IdbVaultCache.open(g.indexedDB!, "member-a7");
    const s = await seeded(cache);
    const info = await removedV2(s);
    await deliver(s, info);
    expect(s.store.accountState.doc.consumedNonces[s.vaultId]?.some(([n]) => n === info.removeNonce)).toBe(true);
    expect(s.api.accountStateBlob).not.toBeNull();
    expect((await cache.consumedNonces()).map((c) => c.nonce)).toEqual([info.removeNonce]);
    // Restart: a new store over the same durable cache, with a fresh (empty) client state.
    const restarted = new VaultStore(s.api.asClient(), s.member, cache, memoryClientState());
    await restarted.hydrate();
    s.store = restarted;
    await reAdd(s);
    await deliver(s, info);
    expect(lastNotice(s).kind).toBe("replay-denied");
  });

  it("served account state never shrinks the consumed set", async () => {
    const s = await seeded();
    const info = await removedV2(s);
    await deliver(s, info);
    s.api.accountStateBlob = s.member.sealAccountState({ ...emptyAccountState(s.member.userId), seq: 1 });
    await s.store.accountState.refresh();
    expect(s.store.accountState.doc.consumedNonces[s.vaultId]?.some(([n]) => n === info.removeNonce)).toBe(true);
    // A second device of this user, with no device record, learns the nonce from account state.
    const second = new VaultStore(s.api.asClient(), s.member, new NullCache(), memoryClientState());
    await second.accountState.refresh();
    expect(second.accountState.doc.consumedNonces[s.vaultId]?.some(([n]) => n === info.removeNonce)).toBe(true);
  });

  it("MEDIUM-2: a nonce only in account state is the calm 'already recorded', consumed here; a later replay is denied", async () => {
    const s = await seeded();
    const info = await removedV2(s);
    s.api.accountStateBlob = s.member.sealAccountState({
      ...emptyAccountState(s.member.userId),
      seq: 3,
      consumedNonces: { [s.vaultId]: [[info.removeNonce!, info.issuedAt!]] },
    });
    s.api.accountSeq = 3;
    await s.store.accountState.refresh();
    expect(s.store.accountState.deviceConsumed()).toEqual({});
    await deliver(s, info);
    expect(lastNotice(s).kind).toBe("removed");
    expect(lastNotice(s).reason).toBe(ALREADY_RECORDED);
    expect(s.store.accountState.deviceConsumed()[s.vaultId]?.map(([n]) => n)).toEqual([info.removeNonce]);
    expect(s.store.heldVaults().some((h) => h.vaultId === s.vaultId)).toBe(true);
    await reAdd(s);
    await deliver(s, info);
    expect(lastNotice(s).kind).toBe("replay-denied");
  });
});

describe("liveSince is device-local", () => {
  it("ignores server timestamps: a proof from before this device's first sight cannot verify", async () => {
    const before = Date.now();
    const s = await seeded();
    // A re-delivered row claiming the vault is ancient changes nothing.
    const rev = ++s.api.rev + 10;
    s.api.queue.push({ rev, full: false, vaults: [{ ...s.vault, createdAt: 1, rev }], grants: [{ ...s.grant, rev: rev + 1 }], items: [], removedGrants: [] });
    await s.store.sync();
    await deliver(s, await removedV2(s, { at: before - 2 * REMOVAL_SKEW_MS }));
    expect(lastNotice(s).kind).toBe("anomaly");
  });

  it("is persisted with the cache, from the device clock", async () => {
    const before = Date.now();
    const cache = await IdbVaultCache.open(g.indexedDB!, "member-a7-live");
    const s = await seeded(cache);
    const stamps = await cache.liveSinces();
    const mine = stamps.find((x) => x.vaultId === s.vaultId);
    expect(mine).toBeDefined();
    expect(mine!.at).toBeGreaterThanOrEqual(before);
  });
});

describe("consume and move-to-holding are one transaction", () => {
  it("a failed commit lands neither; the re-delivered pull lands both", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const cache = await IdbVaultCache.open(g.indexedDB!, "member-a7-atomic");
      const s = await seeded(cache);
      const info = await removedV2(s);
      vi.spyOn(cache, "applyPull").mockRejectedValueOnce(new Error("quota"));
      await deliver(s, info);
      expect(await cache.heldVaults()).toEqual([]);
      expect(await cache.consumedNonces()).toEqual([]);
      // A fresh session hydrates from the (coherent, older) disk and re-pulls the removal: both land together.
      const fresh = new VaultStore(s.api.asClient(), s.member, cache, memoryClientState());
      await fresh.hydrate();
      s.store = fresh;
      await deliver(s, info);
      expect((await cache.heldVaults()).map((h) => h.vault.vaultId)).toEqual([s.vaultId]);
      expect((await cache.consumedNonces()).map((c) => c.nonce)).toEqual([info.removeNonce]);
    } finally {
      warn.mockRestore();
    }
  });
});

describe("the acting clients mint v2", () => {
  it("leave carries a v2 leave proof the member's other devices verify", async () => {
    const s = await seeded();
    await s.store.leaveSharedVault(s.vaultId);
    const body = s.api.leaves.at(-1)!.body!;
    expect(body.proofV).toBe(2);
    expect(isV2Nonce(body.nonce)).toBe(true);
    const d = await decideRemoval({ lifecycleKey: s.key, vaultId: s.vaultId, myUserId: s.member.userId, reason: "left", proofV: body.proofV, proof: body.proof, nonce: body.nonce, issuedAt: body.issuedAt, consumed: new Set(), consumedAccount: new Set(), liveSince: body.issuedAt - 1, now: Date.now() });
    expect(d.verdict).toBe("valid");
  });

  it("removeVaultMember carries a v2 removal proof", async () => {
    const s = await seeded();
    const ownerStore = new VaultStore(s.api.asClient(), s.owner, new NullCache(), memoryClientState());
    await ownerStore.removeVaultMember(s.vaultId, s.member.userId);
    const r = s.api.removals.at(-1)!;
    expect(r.userId).toBe(s.member.userId);
    expect(r.body?.proofV).toBe(2);
    const d = await decideRemoval({ lifecycleKey: s.key, vaultId: s.vaultId, myUserId: s.member.userId, reason: "removed", proofV: r.body!.proofV, proof: r.body!.proof, nonce: r.body!.nonce, issuedAt: r.body!.issuedAt, consumed: new Set(), consumedAccount: new Set(), liveSince: r.body!.issuedAt! - 1, now: Date.now() });
    expect(d.verdict).toBe("valid");
  });
});
