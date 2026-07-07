import { beforeAll, describe, expect, it } from "vitest";
import type { ApiClient } from "../api/client";
import type { ItemDoc, Mutation, PushResponse, SyncResponse, WireGrant, WireItem, WireVault } from "../api/types";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";
import { VaultStore, conflictCopyId } from "./store";

/**
 * Store-level unit tests for family sharing (P5) against the REAL Account crypto and a
 * fake ApiClient — the same drive pattern as live.e2e.test.ts, without a network.
 */

// Minimum-cost argon2id — these tests exercise sync plumbing, not the KDF.
const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };

const emptySync = (rev: number): SyncResponse => ({ rev, full: false, vaults: [], grants: [], items: [], removedGrants: [] });

class FakeApi {
  queue: SyncResponse[] = [];
  pushes: Mutation[][] = [];
  rev = 1;

  async sync(_since: number): Promise<SyncResponse> {
    return this.queue.shift() ?? emptySync(this.rev);
  }

  async push(mutations: Mutation[]): Promise<PushResponse> {
    this.pushes.push(mutations);
    return { rev: ++this.rev, results: mutations.map((m) => ({ mutationId: m.mutationId, status: "applied" as const, newItemRev: 1 })) };
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

const DOC: ItemDoc = { type: "login", name: "Shared login", login: { username: "fam", password: "hunter2" } };

interface Scenario {
  owner: Account;
  member: Account;
  vaultId: string;
  vault: WireVault;
  grant: WireGrant; // member's sealed grant, role=reader
  itemId: string;
  item: WireItem; // DOC encrypted by the owner under the shared VK
}

/** Owner creates a shared vault + item and seals its VK to the member — real client crypto. */
async function scenario(role = "reader"): Promise<Scenario> {
  const owner = await enroll("owner@example.com");
  const member = await enroll("member@example.com");
  const { request, vaultId } = owner.buildCreateSharedVault("Family");
  const sealedVk = owner.wrapVkForMember(member.identityPub, vaultId);
  const itemId = owner.newItemId();
  return {
    owner,
    member,
    vaultId,
    vault: { vaultId, type: "shared", rev: 2, metaBlob: request.metaBlob, createdAt: 0 },
    grant: { vaultId, userId: member.userId, role, wrappedVk: "", rev: 3, sealedVk },
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
      blob: owner.encryptItem(vaultId, itemId, DOC),
    },
  };
}

describe("VaultStore family sharing (P5)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("opens a sealed member grant and decrypts the shared vault's items", async () => {
    const s = await scenario();
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), s.member);
    api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [s.item], removedGrants: [] });
    await store.sync();

    expect(s.member.hasVault(s.vaultId)).toBe(true);
    expect(s.member.roleFor(s.vaultId)).toBe("reader");
    expect(store.get(s.itemId)?.doc).toEqual(DOC);
    const info = store.vaults().find((v) => v.vaultId === s.vaultId);
    expect(info).toEqual({ vaultId: s.vaultId, type: "shared", name: "Family", role: "reader" });
  });

  it("applies a re-delivered grant's NEW role without re-opening the key", async () => {
    const s = await scenario();
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), s.member);
    api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [s.item], removedGrants: [] });
    await store.sync();
    expect(s.member.roleFor(s.vaultId)).toBe("reader");

    // Role change re-delivers the grant. The sealedVk is POISONED: any attempt to
    // re-open it would throw, so a passing test proves the key-open was skipped while
    // the role update still applied (the adversarial-verification [major] fix).
    const regrant: WireGrant = { ...s.grant, role: "writer", rev: 6, sealedVk: "!!!not-base64url!!!" };
    expect(() => s.member.addGrant(regrant)).not.toThrow();
    expect(s.member.roleFor(s.vaultId)).toBe("writer");

    // Same contract through the store's grants loop (demote back to reader).
    api.queue.push({ rev: 7, full: false, vaults: [], grants: [{ ...regrant, role: "reader", rev: 7 }], items: [], removedGrants: [] });
    await store.sync();
    expect(s.member.roleFor(s.vaultId)).toBe("reader");
    // VK untouched throughout — the item still decrypts on a fresh delivery.
    expect(store.get(s.itemId)?.doc).toEqual(DOC);
  });

  it("materializes conflicts with the deterministic copy id, and skips as reader", async () => {
    const s = await scenario("writer");
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), s.member);
    api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [{ ...s.item, rev: 8, conflict: true }], removedGrants: [] });
    await store.sync();

    expect(api.pushes.length).toBe(1);
    const [copy, rewrite] = api.pushes[0]!;
    expect(copy!.itemId).toBe(await conflictCopyId(s.itemId, 8)); // spec 03 §5: converges across clients
    expect(copy!.itemId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(copy!.vaultId).toBe(s.vaultId);
    expect(rewrite!.itemId).toBe(s.itemId);

    // Demoted to reader: a re-flagged item must NOT be materialized (push would be denied).
    api.queue.push({
      rev: 9,
      full: false,
      vaults: [],
      grants: [{ ...s.grant, role: "reader", rev: 9 }],
      items: [{ ...s.item, rev: 10, conflict: true }],
      removedGrants: [],
    });
    await store.sync();
    expect(api.pushes.length).toBe(1); // unchanged
  });

  it("purges the vault's items and forgets key + role on removedGrants", async () => {
    const s = await scenario();
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), s.member);
    api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [s.item], removedGrants: [] });
    await store.sync();
    expect(store.get(s.itemId)).toBeDefined();

    api.queue.push({ rev: 6, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId] });
    await store.sync();

    expect(store.get(s.itemId)).toBeUndefined();
    expect(store.list().some((i) => i.vaultId === s.vaultId)).toBe(false);
    expect(s.member.hasVault(s.vaultId)).toBe(false);
    expect(s.member.roleFor(s.vaultId)).toBeNull();
    expect(store.vaults().some((v) => v.vaultId === s.vaultId)).toBe(false);
  });

  it("save() keeps an existing item's vaultId and only defaults NEW items to personal", async () => {
    const s = await scenario();
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), s.owner); // owner holds the VK from creation
    api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [], items: [s.item], removedGrants: [] });
    await store.sync();

    // Editing an item that lives in the shared vault must push to THAT vault,
    // not personalVaultId (defect #0.1 / server vault_mismatch rule).
    await store.save(s.itemId, { ...DOC, name: "renamed" });
    expect(api.pushes.at(-1)![0]!.vaultId).toBe(s.vaultId);
    expect(api.pushes.at(-1)![0]!.itemId).toBe(s.itemId);

    // A new item honors the explicit vaultId param…
    await store.save(null, { type: "note", name: "shared note" }, [], undefined, s.vaultId);
    expect(api.pushes.at(-1)![0]!.vaultId).toBe(s.vaultId);

    // …and defaults to the personal vault without one.
    await store.save(null, { type: "note", name: "personal note" });
    expect(api.pushes.at(-1)![0]!.vaultId).toBe(s.owner.personalVaultId);
  });
});
