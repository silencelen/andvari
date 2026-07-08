import { beforeAll, describe, expect, it } from "vitest";
import { ApiError, type ApiClient } from "../api/client";
import type {
  DeletedVaultSummary,
  ItemDoc,
  Mutation,
  MutationResult,
  PushResponse,
  SyncResponse,
  WireGrant,
  WireItem,
  WireVault,
} from "../api/types";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { acceptProofFromHash, deleteProof, offerProof, removeProof, restoreProof } from "../crypto/lifecycleproof";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";
import { CopyDeniedError, ItemChangedError, VaultStore } from "./store";

/**
 * Lifecycle (Skipti, spec 03 §11) store tests against the REAL Account crypto and a fake
 * ApiClient — proof-verify tri-state, holding-area park/reinstate/replay, consumed-deleteId
 * recognition, and the F19 copy-leg-first sequencing. Same drive pattern as store.test.ts.
 */

const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };
const DOC: ItemDoc = { type: "login", name: "Shared login", login: { username: "fam", password: "hunter2" } };

const emptySync = (rev: number): SyncResponse => ({ rev, full: false, vaults: [], grants: [], items: [], removedGrants: [] });

class FakeApi {
  queue: SyncResponse[] = [];
  pushes: Mutation[][] = [];
  sinceLog: number[] = [];
  rev = 1;
  /** Deny every push whose mutation targets one of these vaults (role violation). */
  denyVaults = new Set<string>();
  /** Return `conflict` for a push (put or delete) of one of these itemIds. */
  conflictItems = new Set<string>();
  /** Return an unknown/future per-mutation status for pushes targeting these vaults. */
  unknownStatusVaults = new Set<string>();
  /** Return an EMPTY results array for pushes targeting these vaults (malformed reply). */
  emptyResultsVaults = new Set<string>();
  attachments = new Map<string, Uint8Array>();
  deletedList: DeletedVaultSummary[] = [];
  calls: { name: string; args: Record<string, unknown> }[] = [];

  async sync(since: number): Promise<SyncResponse> {
    this.sinceLog.push(since);
    const resp = this.queue.shift() ?? emptySync(this.rev);
    this.rev = Math.max(this.rev, resp.rev);
    return resp;
  }

  async push(mutations: Mutation[]): Promise<PushResponse> {
    this.pushes.push(mutations);
    if (mutations.some((m) => this.emptyResultsVaults.has(m.vaultId))) {
      return { rev: ++this.rev, results: [] }; // malformed reply — no per-mutation results
    }
    const results: MutationResult[] = mutations.map((m) => {
      let status: MutationResult["status"] = "applied";
      if (this.denyVaults.has(m.vaultId)) status = "denied";
      else if (this.conflictItems.has(m.itemId)) status = "conflict";
      else if (this.unknownStatusVaults.has(m.vaultId)) status = "rate_limited" as MutationResult["status"]; // a future status this client doesn't know
      return { mutationId: m.mutationId, status, newItemRev: status === "conflict" ? undefined : 1 };
    });
    return { rev: ++this.rev, results };
  }

  async uploadAttachment(id: string, itemId: string, vaultId: string, body: Uint8Array) {
    this.attachments.set(id, body);
    return { attachmentId: id, itemId, vaultId, size: body.length, sha256: "", createdAt: 0 };
  }
  async downloadAttachment(id: string): Promise<Uint8Array> {
    const b = this.attachments.get(id);
    if (!b) throw new ApiError(404, "not_found", "no such attachment");
    return b;
  }
  async deleteVault(id: string, body: unknown) {
    this.calls.push({ name: "deleteVault", args: { id, body } });
    return { rev: ++this.rev, purgeAt: Date.now() + 7 * 86_400_000 };
  }
  async restoreVault(id: string, body: unknown) {
    this.calls.push({ name: "restoreVault", args: { id, body } });
    return { rev: ++this.rev };
  }
  async deletedVaults() {
    return this.deletedList;
  }
  async leaveVault(id: string) {
    this.calls.push({ name: "leaveVault", args: { id } });
    return { rev: ++this.rev };
  }
  async offerTransfer(id: string, body: unknown) {
    this.calls.push({ name: "offerTransfer", args: { id, body } });
    return { rev: ++this.rev, expiresAt: (body as { expiresAt: number }).expiresAt };
  }
  async cancelTransfer(id: string) {
    this.calls.push({ name: "cancelTransfer", args: { id } });
    return { rev: ++this.rev };
  }
  async acceptTransfer(id: string, body: unknown) {
    this.calls.push({ name: "acceptTransfer", args: { id, body } });
    return { rev: ++this.rev };
  }
  async updateVaultMeta(id: string, body: unknown) {
    this.calls.push({ name: "updateVaultMeta", args: { id, body } });
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
  store: VaultStore;
  api: FakeApi;
  vaultId: string;
  itemId: string;
  vault: WireVault;
  grant: WireGrant;
  item: WireItem;
}

/** A member holding a shared vault (owner-created, VK sealed to the member) at cursor 5. */
async function seededMember(role = "writer"): Promise<Seed> {
  const owner = await enroll("owner@example.com");
  const member = await enroll("member@example.com");
  const { request, vaultId } = owner.buildCreateSharedVault("Family");
  const sealedVk = owner.wrapVkForMember(member.identityPub, vaultId);
  const itemId = owner.newItemId();
  const vault: WireVault = { vaultId, type: "shared", rev: 2, metaBlob: request.metaBlob, createdAt: 0 };
  const grant: WireGrant = { vaultId, userId: member.userId, role, wrappedVk: "", rev: 3, sealedVk };
  const item: WireItem = {
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
  };
  const api = new FakeApi();
  const store = new VaultStore(api.asClient(), member);
  api.queue.push({ rev: 5, full: true, vaults: [vault], grants: [grant], items: [item], removedGrants: [] });
  await store.sync();
  return { owner, member, store, api, vaultId, itemId, vault, grant, item };
}

describe("Skipti tri-state removedGrants (spec 03 §11)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("VALID delete proof → soft-hide + attributed notice; VK forgotten, item hidden", async () => {
    const s = await seededMember();
    const key = await s.owner.lifecycleKeyFor(s.vaultId);
    const deleteId = crypto.randomUUID();
    const purgeAt = Date.now() + 7 * 86_400_000;
    s.api.queue.push({
      rev: 6, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId],
      removedGrantsInfo: [{ vaultId: s.vaultId, reason: "deleted", deleteId, deleteProof: await deleteProof(key, s.vaultId, deleteId), purgeAt }],
    });
    await store_sync(s);

    expect(s.store.get(s.itemId)).toBeUndefined();
    expect(s.member.hasVault(s.vaultId)).toBe(false);
    const held = s.store.heldVaults().find((h) => h.vaultId === s.vaultId);
    expect(held?.verified).toBe(true);
    expect(held?.purgeAt).toBe(purgeAt);
    const n = s.store.notices().find((x) => x.vaultId === s.vaultId);
    expect(n?.kind).toBe("deleted");
    expect(n?.purgeAt).toBe(purgeAt);
  });

  it("INVALID delete proof → anomaly warning + unverified holding", async () => {
    const s = await seededMember();
    const deleteId = crypto.randomUUID();
    s.api.queue.push({
      rev: 6, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId],
      removedGrantsInfo: [{ vaultId: s.vaultId, reason: "deleted", deleteId, deleteProof: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", purgeAt: Date.now() + 1000 }],
    });
    await store_sync(s);
    expect(s.store.notices().find((x) => x.vaultId === s.vaultId)?.kind).toBe("anomaly");
    expect(s.store.heldVaults().find((h) => h.vaultId === s.vaultId)?.verified).toBe(false);
  });

  it("BARE revocation of a held vault (no info) → anomaly", async () => {
    const s = await seededMember();
    s.api.queue.push({ rev: 6, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId], removedGrantsInfo: [] });
    await store_sync(s);
    expect(s.store.notices().find((x) => x.vaultId === s.vaultId)?.kind).toBe("anomaly");
  });

  it("UNVERIFIABLE (vault never held) → silent no-op: no notice, no holding, held vault untouched", async () => {
    const s = await seededMember();
    s.api.queue.push({ rev: 6, full: false, vaults: [], grants: [], items: [], removedGrants: ["a-vault-we-never-had"], removedGrantsInfo: [] });
    await store_sync(s);
    expect(s.store.notices()).toHaveLength(0);
    expect(s.store.heldVaults()).toHaveLength(0);
    expect(s.store.get(s.itemId)).toBeDefined(); // our real vault is untouched
  });

  it("reason='left' → calm 'you left' notice, not an anomaly", async () => {
    const s = await seededMember();
    s.api.queue.push({
      rev: 6, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId],
      removedGrantsInfo: [{ vaultId: s.vaultId, reason: "left" }],
    });
    await store_sync(s);
    expect(s.store.notices().find((x) => x.vaultId === s.vaultId)?.kind).toBe("left");
  });

  it("reason='removed' with a VALID removeProof → attributed 'removed'; without → anomaly", async () => {
    const s = await seededMember();
    const key = await s.owner.lifecycleKeyFor(s.vaultId);
    const nonce = crypto.randomUUID();
    s.api.queue.push({
      rev: 6, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId],
      removedGrantsInfo: [{ vaultId: s.vaultId, reason: "removed", removeProof: await removeProof(key, s.vaultId, s.member.userId, nonce), removeNonce: nonce }],
    });
    await store_sync(s);
    expect(s.store.notices().find((x) => x.vaultId === s.vaultId)?.kind).toBe("removed");

    // A second held vault, removed WITHOUT a proof → anomaly.
    const s2 = await seededMember();
    s2.api.queue.push({
      rev: 6, full: false, vaults: [], grants: [], items: [], removedGrants: [s2.vaultId],
      removedGrantsInfo: [{ vaultId: s2.vaultId, reason: "removed" }],
    });
    await store_sync(s2);
    expect(s2.store.notices().find((x) => x.vaultId === s2.vaultId)?.kind).toBe("anomaly");
  });

  it("notices never fire on a since=0 / fresh-device pull", async () => {
    const owner = await enroll("owner@example.com");
    const member = await enroll("member@example.com");
    const { vaultId } = owner.buildCreateSharedVault("Family");
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), member);
    // First pull (since=0) already carries a removedGrants for a vault the fresh device never held.
    api.queue.push({ rev: 5, full: true, vaults: [], grants: [], items: [], removedGrants: [vaultId], removedGrantsInfo: [{ vaultId, reason: "deleted", deleteId: "x", deleteProof: "y" }] });
    await store.sync();
    expect(store.notices()).toHaveLength(0);
    expect(store.heldVaults()).toHaveLength(0);
  });
});

describe("Skipti holding area: park, reinstate, replay (F21)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("an edit denied by an in-grace delete is parked (not thrown), surfaced, and replayed on restore", async () => {
    const s = await seededMember("writer");
    const key = await s.owner.lifecycleKeyFor(s.vaultId);
    const deleteId = crypto.randomUUID();
    const purgeAt = Date.now() + 7 * 86_400_000;

    // The owner deletes mid-edit: the member's save is DENIED, then the delete lands next pull.
    s.api.denyVaults.add(s.vaultId);
    s.api.queue.push({
      rev: 6, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId],
      removedGrantsInfo: [{ vaultId: s.vaultId, reason: "deleted", deleteId, deleteProof: await deleteProof(key, s.vaultId, deleteId), purgeAt }],
    });

    // Must NOT throw — the edit is parked, not lost.
    await expect(s.store.save(s.itemId, { ...DOC, name: "edited in-flight" })).resolves.toBeUndefined();
    const n = s.store.notices().find((x) => x.vaultId === s.vaultId);
    expect(n?.kind).toBe("deleted");
    expect(n?.parkedCount).toBe(1);
    expect(s.store.heldVaults().find((h) => h.vaultId === s.vaultId)).toBeDefined();

    // Restore: a live grant + the restore-marked vault + the item re-arrive → reinstate + replay.
    s.api.denyVaults.delete(s.vaultId); // the replayed edit now applies
    const rProof = await restoreProof(key, s.vaultId, deleteId);
    const restoredVault: WireVault = { ...s.vault, rev: 8, restoreProof: rProof, deleteId };
    const before = s.api.pushes.length;
    s.api.queue.push({ rev: 9, full: false, vaults: [restoredVault], grants: [{ ...s.grant, rev: 9 }], items: [{ ...s.item, rev: 9 }], removedGrants: [] });
    await store_sync(s);

    // The parked edit was replayed (a put for the source itemId), and the vault is live again.
    expect(s.api.pushes.length).toBeGreaterThan(before);
    expect(s.api.pushes.flat().some((m) => m.itemId === s.itemId && m.op === "put")).toBe(true);
    expect(s.store.get(s.itemId)).toBeDefined();
    expect(s.store.heldVaults()).toHaveLength(0);
    expect(s.store.notices().some((x) => x.vaultId === s.vaultId && x.kind === "restored")).toBe(true);
  });

  it("a reader-denied edit on a STILL-LIVE vault rethrows (not parked)", async () => {
    const s = await seededMember("reader");
    s.api.denyVaults.add(s.vaultId);
    // No delete arrives — the reconcile pull is empty, so the vault stays live.
    await expect(s.store.save(s.itemId, { ...DOC, name: "reader edit" })).rejects.toBeInstanceOf(ApiError);
    expect(s.store.heldVaults()).toHaveLength(0);
  });
});

describe("Skipti consumed-deleteId recognition", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a replayed tombstone whose deleteId a restore already consumed is recognized, not re-warned", async () => {
    const s = await seededMember("writer");
    const key = await s.owner.lifecycleKeyFor(s.vaultId);
    const deleteId = crypto.randomUUID();

    // The vault re-arrives carrying a valid restore marker → the deleteId is consumed.
    const rProof = await restoreProof(key, s.vaultId, deleteId);
    s.api.queue.push({ rev: 6, full: false, vaults: [{ ...s.vault, rev: 6, restoreProof: rProof, deleteId }], grants: [], items: [], removedGrants: [] });
    await store_sync(s);

    // A stale/malicious server now replays the OLD tombstone bearing that deleteId.
    s.api.queue.push({
      rev: 7, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId],
      removedGrantsInfo: [{ vaultId: s.vaultId, reason: "deleted", deleteId, deleteProof: await deleteProof(key, s.vaultId, deleteId), purgeAt: Date.now() + 1000 }],
    });
    await store_sync(s);

    // Recognized as stale: the vault stays live, nothing held, no notice.
    expect(s.store.get(s.itemId)).toBeDefined();
    expect(s.store.heldVaults()).toHaveLength(0);
    expect(s.store.notices().some((n) => n.vaultId === s.vaultId)).toBe(false);
  });
});

describe("Skipti transfer verification (spec 03 §11)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("surfaces an incoming offer only after its proof verifies; a garbage proof stays hidden", async () => {
    const s = await seededMember("writer");
    const key = await s.owner.lifecycleKeyFor(s.vaultId);
    const offerId = crypto.randomUUID();
    const expiresAt = Date.now() + 14 * 86_400_000;
    const seq = 1;
    const goodProof = await offerProof(key, s.vaultId, offerId, s.member.userId, expiresAt, seq);

    // Valid offer → visible as an acceptable incoming transfer.
    s.api.queue.push({
      rev: 6, full: false,
      vaults: [{ ...s.vault, rev: 6, pendingTransfer: { toUserId: s.member.userId, offerId, proof: goodProof, expiresAt, seq } }],
      grants: [], items: [], removedGrants: [],
    });
    await store_sync(s);
    expect(s.store.incomingTransfers().map((t) => t.vaultId)).toContain(s.vaultId);

    // A tampered proof on a new offer → NOT surfaced (consent screen never renders).
    const s2 = await seededMember("writer");
    s2.api.queue.push({
      rev: 6, full: false,
      vaults: [{ ...s2.vault, rev: 6, pendingTransfer: { toUserId: s2.member.userId, offerId: crypto.randomUUID(), proof: "AAAA", expiresAt, seq: 1 } }],
      grants: [], items: [], removedGrants: [],
    });
    await store_sync(s2);
    expect(s2.store.incomingTransfers()).toHaveLength(0);
  });

  it("an UNVERIFIED completed transfer warns (retain-and-warn) and does NOT burn the seq chain", async () => {
    const s = await seededMember("writer");
    const key = await s.owner.lifecycleKeyFor(s.vaultId);
    const offerId = crypto.randomUUID();
    const seq = 1;
    const wrapHash = "00".repeat(32);

    // Bogus acceptProof (server-side ownership rewrite): anomaly warning, no completion notice.
    s.api.queue.push({
      rev: 6, full: false,
      vaults: [{ ...s.vault, rev: 6, lastTransfer: { offerId, newOwnerUserId: s.member.userId, acceptProof: "AAAA", seq, wrapHash } }],
      grants: [], items: [], removedGrants: [],
    });
    await store_sync(s);
    expect(s.store.notices().find((n) => n.vaultId === s.vaultId)?.kind).toBe("transfer-anomaly");

    // The same row re-delivered later WITH the genuine proof: the unverified sighting must not
    // have marked the seq seen — the real completion notice still fires.
    const goodAccept = await acceptProofFromHash(key, s.vaultId, offerId, s.member.userId, seq, wrapHash);
    s.api.queue.push({
      rev: 7, full: false,
      vaults: [{ ...s.vault, rev: 7, lastTransfer: { offerId, newOwnerUserId: s.member.userId, acceptProof: goodAccept, seq, wrapHash } }],
      grants: [], items: [], removedGrants: [],
    });
    await store_sync(s);
    expect(s.store.notices().find((n) => n.vaultId === s.vaultId)?.kind).toBe("transfer-complete");
  });
});

describe("Skipti F19 move/copy copy-leg-first sequencing (design §8)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a denied COPY leg aborts with the source untouched and no delete leg", async () => {
    const s = await seededMember("writer");
    const target = s.member.personalVaultId; // member holds this VK; the server will deny the copy
    s.api.denyVaults.add(target);
    const g = s.store.newMoveGesture(s.itemId, target, true); // move
    await expect(s.store.runGesture(g)).rejects.toBeInstanceOf(CopyDeniedError);
    expect(s.api.pushes).toHaveLength(1); // ONLY the copy leg — the delete leg never ran
    expect(s.store.get(s.itemId)).toBeDefined(); // source untouched
  });

  it("a delete-leg CONFLICT (source changed since copy) aborts without deleting the source", async () => {
    const s = await seededMember("writer");
    const target = s.member.personalVaultId;
    s.api.conflictItems.add(s.itemId); // the delete of the SOURCE conflicts (source moved on)
    const g = s.store.newMoveGesture(s.itemId, target, true);
    await expect(s.store.runGesture(g)).rejects.toBeInstanceOf(ItemChangedError);
    expect(s.api.pushes.length).toBeGreaterThanOrEqual(2); // copy leg applied, delete leg attempted
    expect(s.store.get(s.itemId)).toBeDefined(); // source NOT deleted
  });

  it("the delete leg uses the rev of the content copied (not the cache rev)", async () => {
    const s = await seededMember("writer");
    const g = s.store.newMoveGesture(s.itemId, s.member.personalVaultId, true);
    await s.store.runGesture(g);
    const delLeg = s.api.pushes.find((p) => p[0]?.op === "delete")![0]!;
    expect(delLeg.baseItemRev).toBe(s.item.rev);
    expect(s.store.get(s.itemId)).toBeUndefined(); // moved out
  });

  it("an UNKNOWN copy-leg status aborts with the source untouched (positive applied/conflict gate)", async () => {
    const s = await seededMember("writer");
    const target = s.member.personalVaultId;
    s.api.unknownStatusVaults.add(target); // future/unknown per-mutation status on the copy
    const g = s.store.newMoveGesture(s.itemId, target, true); // move
    await expect(s.store.runGesture(g)).rejects.toBeInstanceOf(ApiError);
    expect(s.api.pushes).toHaveLength(1); // the delete leg never ran
    expect(s.store.get(s.itemId)).toBeDefined(); // source untouched
  });

  it("an EMPTY copy-leg results array aborts with the source untouched", async () => {
    const s = await seededMember("writer");
    const target = s.member.personalVaultId;
    s.api.emptyResultsVaults.add(target); // malformed reply — no per-mutation result at all
    const g = s.store.newMoveGesture(s.itemId, target, true); // move
    await expect(s.store.runGesture(g)).rejects.toBeInstanceOf(ApiError);
    expect(s.api.pushes).toHaveLength(1);
    expect(s.store.get(s.itemId)).toBeDefined();
  });

  it("a copy retry reuses the same gesture-derived mutationId (server dedup converges)", async () => {
    const s = await seededMember("writer");
    const g = s.store.newMoveGesture(s.itemId, s.member.personalVaultId, false); // copy only
    await s.store.runGesture(g);
    const firstCopyId = s.api.pushes.at(-1)![0]!.mutationId;
    const n = s.api.pushes.length;
    await s.store.runGesture(g); // the SAME gesture again (a retry)
    expect(s.api.pushes.at(-1)![0]!.mutationId).toBe(firstCopyId); // deterministic from gestureId
    expect(s.api.pushes.length).toBeGreaterThan(n);
  });
});

/** store.sync() then read the notices (parallels the Vault shell's syncNow). */
async function store_sync(s: { store: VaultStore }): Promise<void> {
  await s.store.sync();
}
