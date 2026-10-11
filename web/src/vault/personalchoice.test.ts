import { beforeAll, describe, expect, it } from "vitest";
import type { ApiClient } from "../api/client";
import type { AccountKeys, PersonalWrap, SyncResponse, VaultMemberSummary, WireGrant, WireVault } from "../api/types";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";
import { memoryClientState } from "./accountstatesync";
import { VaultStore } from "./store";

/**
 * Security review 2026-10, root cause A, branch A5b (A5 re-review M-1, M-2, L-1, L-2) — web twin of core
 * PersonalChoiceHardeningTest. The personal-vault choice is confirmed and informed (co-holders, created or
 * received), a served wrap naming another vault than this device's raises a notice instead of switching, and
 * a junk served wrap never discards a valid cached one.
 */

const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };

interface Enrolled {
  account: Account;
  keys: AccountKeys;
  userId: string;
  password: string;
  identityPub: string;
  personalVaultId: string;
  personalWrappedVk: string;
  personalMeta: string;
  personalWrap: PersonalWrap;
}

async function enroll(tag: string): Promise<Enrolled> {
  const email = `${tag}-${Math.random().toString(16).slice(2)}@example.com`;
  const recovery = boxKeypairFromSeed(randomBytes(32));
  const password = `pw ${email}`;
  const { request, account } = await Account.enroll({ inviteToken: "t", email, displayName: email, password, kdfParams: KDF, recoveryPublicKey: recovery.publicKey, recoveryFingerprint: await fingerprint(recovery.publicKey) });
  return {
    account,
    keys: { kdfSalt: request.kdfSalt, kdfParams: request.kdfParams, wrappedUvk: request.wrappedUvk, encryptedIdentitySeed: request.encryptedIdentitySeed, identityPub: request.identityPub, escrowFingerprint: request.escrow!.fingerprint },
    userId: request.userId,
    password,
    identityPub: request.identityPub,
    personalVaultId: request.personalVault.vaultId,
    personalWrappedVk: request.personalVault.wrappedVk,
    personalMeta: request.personalVault.metaBlob,
    personalWrap: request.personalWrap!,
  };
}

class FakeApi {
  puts: { wrap: PersonalWrap; currentAuthKey?: string }[] = [];
  memberFetches: string[] = [];
  constructor(
    private feed: SyncResponse,
    private members: Record<string, VaultMemberSummary[]> = {},
  ) {}
  async sync(): Promise<SyncResponse> {
    const f = this.feed;
    this.feed = { ...f, full: false, vaults: [], grants: [], items: [], removedGrants: [] };
    return f;
  }
  async push() {
    return { rev: 1, results: [] };
  }
  async putPersonalWrap(wrap: PersonalWrap, currentAuthKey?: string) {
    this.puts.push({ wrap, currentAuthKey });
  }
  async vaultMembers(vaultId: string) {
    this.memberFetches.push(vaultId);
    return this.members[vaultId] ?? [];
  }
  async accountState() {
    return { sealedState: null, seq: 0 };
  }
  asClient(): ApiClient {
    return this as unknown as ApiClient;
  }
}

const member = (e: Enrolled, role: string, displayName: string): VaultMemberSummary => ({ userId: e.userId, email: `${displayName.toLowerCase()}@example.com`, displayName, role, identityPub: e.identityPub, addedAt: 0 });
const personalRow = (e: Enrolled): WireVault => ({ vaultId: e.personalVaultId, type: "personal", rev: 2, metaBlob: e.personalMeta, createdAt: 0 });
const personalGrant = (e: Enrolled): WireGrant => ({ vaultId: e.personalVaultId, userId: e.userId, role: "owner", wrappedVk: e.personalWrappedVk, rev: 2, sealedVk: null });

async function household() {
  const victim = await enroll("a5b");
  const mate = await enroll("a5b-mate");
  const shared = victim.account.buildCreateSharedVault("Household");
  const rows: SyncResponse = {
    rev: 9,
    full: true,
    vaults: [personalRow(victim), { vaultId: shared.vaultId, type: "shared", rev: 3, metaBlob: shared.request.metaBlob, createdAt: 0 }],
    grants: [personalGrant(victim), { vaultId: shared.vaultId, userId: victim.userId, role: "owner", wrappedVk: shared.request.wrappedVk, rev: 3, sealedVk: null }],
    items: [],
    removedGrants: [],
  };
  // A genuine personal wrap for the shared vault: what a designation on another device (or an older one) minted.
  const sharedWrap = victim.account.buildPersonalWrap(shared.vaultId);
  return { victim, mate, sharedId: shared.vaultId, sharedWrap, rows };
}

const unlock = (e: Enrolled, wrap: PersonalWrap | null) => Account.unlock(e.userId, e.password, { ...e.keys, personalWrap: wrap });

describe("A5b — the personal-vault choice", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("M-1: a withheld wrap stays withheld after a reload (the client state outlives the vault cache)", async () => {
    const h = await household();
    const local = memoryClientState();
    await new VaultStore(new FakeApi(h.rows).asClient(), await unlock(h.victim, h.victim.personalWrap), undefined, local).sync();
    const again = await unlock(h.victim, null);
    const store = new VaultStore(new FakeApi(h.rows).asClient(), again, undefined, local); // NullCache: nothing durable
    await store.sync();
    expect(String(again.personalStatus)).toBe("withheld");
    expect(again.personalVaultId).toBe(h.victim.personalVaultId);
  });

  it("M-2: a first designation does not mint without confirmation", async () => {
    const h = await household();
    const api = new FakeApi(h.rows, { [h.sharedId]: [member(h.victim, "owner", "Victim"), member(h.mate, "writer", "Mate")] });
    const device = await unlock(h.victim, null);
    const store = new VaultStore(api.asClient(), device, undefined, memoryClientState());
    await store.sync();
    expect(device.personalStatus).toBe("absent");

    const proposal = await store.proposePersonalVault(h.sharedId);
    expect(api.puts).toHaveLength(0);
    expect(device.personalVaultId).toBe("");
    expect(proposal.name).toBe("Household");
    expect(proposal.coHolders.map((c) => c.userId)).toEqual([h.mate.userId]);

    const other = await store.proposePersonalVault(h.victim.personalVaultId);
    await expect(store.confirmPersonalVault(proposal)).rejects.toThrow();
    const stranger = new VaultStore(api.asClient(), device, undefined, memoryClientState());
    await stranger.sync();
    const foreign = await stranger.proposePersonalVault(h.sharedId);
    await expect(store.confirmPersonalVault(foreign)).rejects.toThrow();
    expect(api.puts).toHaveLength(0);

    await store.confirmPersonalVault(other);
    expect(api.puts).toHaveLength(1);
    expect(api.puts[0]!.wrap.vaultId).toBe(h.victim.personalVaultId);
    expect(device.personalStatus).toBe("confirmed");
    await expect(store.confirmPersonalVault(other)).rejects.toThrow(); // single use
    expect(api.puts).toHaveLength(1);
    // The one-step mint is gone from the store's surface.
    expect((store as unknown as Record<string, unknown>).designatePersonalVault).toBeUndefined();
  });

  it("M-2: the choice list shows co-holders and whether the vault was created here or received by transfer", async () => {
    const h = await household();
    const taxes = h.mate.account.buildCreateSharedVault("Taxes");
    // The mate created "Taxes" and transferred it to the victim; the victim's row is a bare UVK wrap of the VK.
    h.victim.account.addGrant({ vaultId: taxes.vaultId, userId: h.victim.userId, role: "writer", wrappedVk: "", rev: 4, sealedVk: h.mate.account.wrapVkForMember(h.victim.account.identityPub, taxes.vaultId) });
    const victimWrap = h.victim.account.buildSelfWrap(taxes.vaultId);
    const rows: SyncResponse = {
      ...h.rows,
      vaults: [...h.rows.vaults, { vaultId: taxes.vaultId, type: "shared", rev: 5, metaBlob: taxes.request.metaBlob, createdAt: 0, lastTransfer: { offerId: "offer-1", newOwnerUserId: h.victim.userId, acceptProof: "proof", seq: 1, wrapHash: "hash" } }],
      grants: [...h.rows.grants, { vaultId: taxes.vaultId, userId: h.victim.userId, role: "owner", wrappedVk: victimWrap, rev: 5, sealedVk: null }],
    };
    const api = new FakeApi(rows, {
      [h.sharedId]: [member(h.victim, "owner", "Victim"), member(h.mate, "reader", "Mate")],
      [taxes.vaultId]: [member(h.victim, "owner", "Victim"), member(h.mate, "writer", "Mate")],
      [h.victim.personalVaultId]: [member(h.victim, "owner", "Victim")],
    });
    const device = await unlock(h.victim, null);
    const store = new VaultStore(api.asClient(), device, undefined, memoryClientState());
    await store.sync();
    const ids = new Set(store.personalVaultChoices!.map((c) => c.vaultId));
    expect(ids).toEqual(new Set([h.victim.personalVaultId, h.sharedId, taxes.vaultId]));

    await store.refreshPersonalChoiceDetails([...ids]);
    expect(store.personalChoiceInfo(h.victim.personalVaultId).coHolders).toEqual([]);
    expect(store.personalChoiceInfo(h.victim.personalVaultId).origin).toBe("created");
    expect(store.personalChoiceInfo(h.sharedId).coHolders!.map((c) => c.displayName)).toEqual(["Mate"]);
    expect(store.personalChoiceInfo(h.sharedId).origin).toBe("created");
    expect(store.personalChoiceInfo(taxes.vaultId).coHolders!.map((c) => c.displayName)).toEqual(["Mate"]);
    expect(store.personalChoiceInfo(taxes.vaultId).origin).toBe("received");
    expect(store.personalChoiceInfo(taxes.vaultId).name).toBe("Taxes");
  });

  it("M-2 / L-2: a served wrap naming a different vault raises the change notice instead of switching silently", async () => {
    const h = await household();
    const local = memoryClientState();
    await new VaultStore(new FakeApi(h.rows).asClient(), await unlock(h.victim, h.victim.personalWrap), undefined, local).sync();

    const again = await unlock(h.victim, h.sharedWrap);
    const api = new FakeApi(h.rows);
    const store = new VaultStore(api.asClient(), again, undefined, local);
    await store.sync();
    expect(String(again.personalStatus)).toBe("changed");
    expect(again.personalVaultId).toBe(h.victim.personalVaultId);
    expect(store.personalChange()).toEqual({ currentVaultId: h.victim.personalVaultId, servedVaultId: h.sharedId });
    expect(store.vaults().find((x) => x.vaultId === h.victim.personalVaultId)!.type).toBe("personal");
    expect(local.get("personal.wrap")).toContain(h.victim.personalVaultId);
    expect(api.puts).toHaveLength(0);

    store.acceptPersonalChange();
    expect(again.personalStatus).toBe("confirmed");
    expect(again.personalVaultId).toBe(h.sharedId);
    expect(store.personalChange()).toBeNull();
    expect(local.get("personal.wrap")).toContain(h.sharedId);
    expect(api.puts).toHaveLength(0);

    // L-2: the older wrap replayed is a change as well.
    const replay = await unlock(h.victim, h.victim.personalWrap);
    await new VaultStore(new FakeApi(h.rows).asClient(), replay, undefined, local).sync();
    expect(String(replay.personalStatus)).toBe("changed");
    expect(replay.personalVaultId).toBe(h.sharedId);
  });

  it("L-1: a junk served wrap keeps the valid cached wrap, flags it, and marks the device's vault", async () => {
    const h = await household();
    const local = memoryClientState();
    await new VaultStore(new FakeApi(h.rows).asClient(), await unlock(h.victim, h.victim.personalWrap), undefined, local).sync();

    const again = await unlock(h.victim, { vaultId: h.victim.personalVaultId, wrappedVk: h.victim.personalWrappedVk });
    expect(again.personalStatus).toBe("unreadable");
    const api = new FakeApi(h.rows);
    const store = new VaultStore(api.asClient(), again, undefined, local);
    await store.sync();
    expect(String(again.personalStatus)).toBe("unreadable-cached");
    expect(again.personalVaultId).toBe(h.victim.personalVaultId);
    expect(local.get("personal.wrap")).toContain(h.victim.personalVaultId);
    expect(api.puts).toHaveLength(0);
    expect(store.personalChoiceInfo(h.victim.personalVaultId).onThisDevice).toBe(true);
    expect(store.personalChoiceInfo(h.sharedId).onThisDevice).toBe(false);
  });
});
