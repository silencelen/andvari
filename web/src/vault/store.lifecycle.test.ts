import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
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
import { adVaultMeta } from "../crypto/ad";
import { toB64, utf8 } from "../crypto/bytes";
import { seal } from "../crypto/envelope";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";
import { type FakeRole, FakeSharedLogs } from "./fakesharedlogs.testkit";
import { ChangeNotStoredError, CopyDeniedError, HOLDING_MS, type ItemWire, ItemChangedError, VaultStore } from "./store";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { deletedNoteText, RecentlyRemoved } from "../ui/Sharing";
import { DELETED_NOTE_ALONE, DELETED_NOTE_ALONE_NO_DAY, DELETED_NOTE_NO_DAY, fill } from "../ui/copy";
import { fmtDay } from "../ui/format";

/**
 * Lifecycle (Skipti, spec 03 §11) store tests against the REAL Account crypto and a fake
 * ApiClient — the removal verdict read from the verified log (FakeSharedLogs stands in for it),
 * holding-area park/reinstate/replay, a replayed tombstone after a restore, and the F19
 * copy-leg-first sequencing. Same drive pattern as store.test.ts.
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

  async pushMutations(mutations: Mutation[]): Promise<PushResponse> {
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
  async removeVaultMember(id: string, userId: string, body?: unknown) {
    this.calls.push({ name: "removeVaultMember", args: { id, userId, body } });
    return { rev: ++this.rev };
  }

  asClient(): ApiClient {
    return this as unknown as ApiClient;
  }

  /** The item routes the store calls (its ItemWire): this fake serves them too. */
  asWire(): ItemWire {
    return this as unknown as ItemWire;
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
  logs: FakeSharedLogs;
  vk: Uint8Array;
  vaultId: string;
  itemId: string;
  vault: WireVault;
  grant: WireGrant;
  item: WireItem;
}

/** A member holding a shared vault (owner-created, VK sealed to the member) at cursor 5. */
async function seededMember(role: FakeRole = "writer"): Promise<Seed> {
  const owner = await enroll("owner@example.com");
  const member = await enroll("member@example.com");
  // The key and the member's role are what the vault's verified log says (design §3.6); the grant row is a hint only.
  const vaultId = owner.newItemId();
  const vk = randomBytes(32);
  owner.logKeyRing().set(vaultId, vk.slice());
  owner.attachLogRoles(() => "owner", () => true);
  const itemId = owner.newItemId();
  const vault: WireVault = { vaultId, type: "shared", rev: 2, metaBlob: toB64(seal(vk, utf8(JSON.stringify({ name: "Family" })), adVaultMeta(vaultId))), createdAt: 0 };
  const grant: WireGrant = { vaultId, userId: member.userId, role, wrappedVk: "", rev: 3 };
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
    blob: owner.encryptItem(vaultId, itemId, DOC).blob,
  };
  const api = new FakeApi();
  const store = new VaultStore(api.asClient(), member, undefined, undefined, api.asWire());
  const logs = new FakeSharedLogs(member).attachTo(store);
  logs.share(vaultId, vk, role);
  api.queue.push({ rev: 5, full: true, vaults: [vault], grants: [grant], items: [item], removedGrants: [] });
  await store.sync();
  return { owner, member, store, api, logs, vk, vaultId, itemId, vault, grant, item };
}

describe("Skipti tri-state removedGrants (spec 03 §11)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a delete the verified log shows → soft-hide + attributed notice; VK forgotten, item hidden", async () => {
    const s = await seededMember();
    const purgeAt = Date.now() + 7 * 86_400_000;
    s.logs.deleteVault(s.vaultId); // the log ends in the owner's delete (§3.11); the served purge time is only shown
    s.api.queue.push({
      rev: 6, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId],
      removedGrantsInfo: [{ vaultId: s.vaultId, reason: "deleted", purgeAt }],
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

  it("a delete shows the grace end the log answers carried (spec 03 §10.6); the holding's own clock is 30 days from the verification", async () => {
    const s = await seededMember();
    const hinted = Date.now() + 7 * 86_400_000;
    const served = hinted + 3 * 86_400_000; // the server's stored grace end, which the screen shows
    s.logs.deleteVault(s.vaultId, { deletedAt: Date.now(), purgeAt: served });
    s.api.queue.push({
      rev: 6, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId],
      removedGrantsInfo: [{ vaultId: s.vaultId, reason: "deleted", purgeAt: hinted }],
    });
    const before = Date.now();
    await store_sync(s);
    const held = s.store.heldVaults().find((h) => h.vaultId === s.vaultId);
    expect(held?.purgeAt).toBe(served);
    expect(held?.expungeAt, "neither date the server gave").toBeGreaterThanOrEqual(before + HOLDING_MS);
    expect(held?.expungeAt).toBeLessThanOrEqual(Date.now() + HOLDING_MS);
    expect(s.store.notices().find((x) => x.vaultId === s.vaultId)?.purgeAt).toBe(served);
  });

  it("the owner's delete shows the append's grace end; from an older server that serves none, no day, and the note points to the deleted vaults", async () => {
    const day = 86_400_000;
    const s = await seededMember();
    s.logs.share(s.vaultId, s.vk, "owner");
    s.logs.nextAppendGrace = { deletedAt: 1_000, purgeAt: 1_000 + 10 * day };
    expect(await s.store.deleteSharedVault(s.vaultId)).toEqual({ purgeAt: 1_000 + 10 * day });
    expect(deletedNoteText({ name: "Family", purgeAt: 1_000 + 10 * day, alone: true })).toBe(fill(DELETED_NOTE_ALONE, "Family", fmtDay(1_000 + 10 * day)));

    const old = await seededMember();
    old.logs.share(old.vaultId, old.vk, "owner");
    // On the code before: a day computed from the entry's time and this app's usual grace, which the server never said.
    const { purgeAt } = await old.store.deleteSharedVault(old.vaultId);
    expect(purgeAt).toBeNull();
    expect(deletedNoteText({ name: "Family", purgeAt, alone: true })).toBe(fill(DELETED_NOTE_ALONE_NO_DAY, "Family"));
    expect(deletedNoteText({ name: "Family", purgeAt, alone: false })).toBe(fill(DELETED_NOTE_NO_DAY, "Family"));
  });

  it("a removal whose log does not verify → anomaly warning + unverified holding", async () => {
    const s = await seededMember();
    s.logs.fail(s.vaultId);
    s.api.queue.push({
      rev: 6, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId],
      removedGrantsInfo: [{ vaultId: s.vaultId, reason: "deleted", purgeAt: Date.now() + 1000 }],
    });
    await store_sync(s);
    expect(s.store.notices().find((x) => x.vaultId === s.vaultId)?.kind).toBe("anomaly");
    expect(s.store.heldVaults().find((h) => h.vaultId === s.vaultId)?.verified).toBe(false);
  });

  it("a removal the verified log shows (the owner's signed remove) is held as verified, not as an unverified removal", async () => {
    // The 2026-11-16 walk: after alice's signed `remove`, bob's holding area read "unverified removal" (design §3.12:
    // a removal is attributed when the removed device verifies the remove entry).
    const s = await seededMember();
    s.logs.remove(s.vaultId);
    s.api.queue.push({ rev: 6, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId], removedGrantsInfo: [{ vaultId: s.vaultId, reason: "removed" }] });
    await store_sync(s);
    expect(s.store.notices().find((x) => x.vaultId === s.vaultId)?.kind).toBe("removed");
    expect(s.store.heldVaults().find((h) => h.vaultId === s.vaultId)).toMatchObject({ reason: "removed", verified: true });
  });

  it("UNVERIFIABLE (vault never held) → silent no-op: no notice, no holding, held vault untouched", async () => {
    const s = await seededMember();
    s.api.queue.push({ rev: 6, full: false, vaults: [], grants: [], items: [], removedGrants: ["a-vault-we-never-had"], removedGrantsInfo: [] });
    await store_sync(s);
    expect(s.store.notices()).toHaveLength(0);
    expect(s.store.heldVaults()).toHaveLength(0);
    expect(s.store.get(s.itemId)).toBeDefined(); // our real vault is untouched
  });

  it("notices never fire on a since=0 / fresh-device pull", async () => {
    const member = await enroll("member@example.com");
    const vaultId = member.newItemId();
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), member, undefined, undefined, api.asWire());
    const logs = new FakeSharedLogs(member).attachTo(store);
    logs.share(vaultId, randomBytes(32), "writer");
    logs.deleteVault(vaultId); // even a delete the log shows
    // First pull (since=0) already carries a removedGrants for a vault the fresh device never held.
    api.queue.push({ rev: 5, full: true, vaults: [], grants: [], items: [], removedGrants: [vaultId], removedGrantsInfo: [{ vaultId, reason: "deleted" }] });
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
    const purgeAt = Date.now() + 7 * 86_400_000;

    // The owner deletes mid-edit (the log says so): the member's save is DENIED, then the delete lands next pull.
    s.api.denyVaults.add(s.vaultId);
    const realSync = s.api.sync.bind(s.api);
    s.api.sync = async (since: number) => {
      s.logs.deleteVault(s.vaultId); // the reconcile pull is where this browser's log learns of the delete
      s.api.sync = realSync;
      return realSync(since);
    };
    s.api.queue.push({
      rev: 6, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId],
      removedGrantsInfo: [{ vaultId: s.vaultId, reason: "deleted", purgeAt }],
    });

    // Must NOT throw — the edit is parked, not lost.
    await expect(s.store.save(s.itemId, { ...DOC, name: "edited in-flight" }, [], undefined, s.vaultId)).resolves.toBeUndefined();
    const n = s.store.notices().find((x) => x.vaultId === s.vaultId);
    expect(n?.kind).toBe("deleted");
    expect(n?.parkedCount).toBe(1);
    expect(s.store.heldVaults().find((h) => h.vaultId === s.vaultId)).toBeDefined();

    // Restore (the log's `restore`): a live grant + the vault + the item re-arrive → reinstate + replay.
    s.api.denyVaults.delete(s.vaultId); // the replayed edit now applies
    s.logs.share(s.vaultId, s.vk, "writer");
    const restoredVault: WireVault = { ...s.vault, rev: 8 };
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

  it("a grant re-arriving for a held vault whose key the log has not given back yet is no restore (design §3.6)", async () => {
    // The 2026-11-16 walk: alice added bob again after removing him; before he answered, his browser said
    // "“Family” was restored." and the held copy left the holding area, although a re-add is asked first and he went on
    // to decline it. A held shared vault comes back only once its key is adopted again.
    const s = await seededMember("writer");
    s.logs.remove(s.vaultId);
    s.api.queue.push({ rev: 6, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId], removedGrantsInfo: [{ vaultId: s.vaultId, reason: "removed" }] });
    await store_sync(s);
    expect(s.store.heldVaults().find((h) => h.vaultId === s.vaultId)).toBeDefined();

    // Added again: the grant row comes back, but the share is asked and not answered, so the log adopts no key.
    s.logs.pend(s.vaultId, s.vk, "writer");
    s.api.queue.push({ rev: 7, full: false, vaults: [{ ...s.vault, rev: 7 }], grants: [{ ...s.grant, rev: 7 }], items: [], removedGrants: [] });
    await store_sync(s);
    expect(s.store.notices().some((x) => x.vaultId === s.vaultId && x.kind === "restored")).toBe(false);
    expect(s.store.heldVaults().find((h) => h.vaultId === s.vaultId)).toBeDefined();

    // Accepted: the key is adopted again at the next pull, which reinstates it even without a new grant row.
    s.logs.decide(s.vaultId);
    s.api.queue.push({ rev: 8, full: false, vaults: [{ ...s.vault, rev: 8 }], grants: [], items: [{ ...s.item, rev: 8 }], removedGrants: [] });
    await store_sync(s);
    expect(s.store.heldVaults()).toHaveLength(0);
    expect(s.store.notices().some((x) => x.vaultId === s.vaultId && x.kind === "restored")).toBe(true);
  });

  it("a server-denied edit on a STILL-LIVE vault rethrows (not parked)", async () => {
    // A writer by the log, so the edit is sent (a reader's never is: INV-WRITE-KEY refuses it locally); the server
    // denies it and no delete follows.
    const s = await seededMember("writer");
    s.api.denyVaults.add(s.vaultId);
    // No delete arrives — the reconcile pull is empty, so the vault stays live.
    await expect(s.store.save(s.itemId, { ...DOC, name: "reader edit" }, [], undefined, s.vaultId)).rejects.toBeInstanceOf(ApiError);
    expect(s.store.heldVaults()).toHaveLength(0);
  });
});

describe("Skipti replayed tombstone after a restore", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a replayed tombstone after a restore is not re-warned while the verified log shows the vault restored", async () => {
    const s = await seededMember("writer");
    // The log's delete and then its restore: the vault is live again (deleteId cleared).
    s.logs.deleteVault(s.vaultId);
    s.logs.share(s.vaultId, s.vk, "writer");
    // A stale or malicious server now replays the OLD tombstone.
    s.api.queue.push({
      rev: 7, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId],
      removedGrantsInfo: [{ vaultId: s.vaultId, reason: "deleted", purgeAt: Date.now() + 1000 }],
    });
    await store_sync(s);

    // Recognized as stale: the vault stays live, nothing held, no notice.
    expect(s.store.get(s.itemId)).toBeDefined();
    expect(s.store.heldVaults()).toHaveLength(0);
    expect(s.store.notices().some((n) => n.vaultId === s.vaultId)).toBe(false);
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

/**
 * Design §3.8, spec 02 §10.6: when this browser has verified that a shared vault is deleted (in its grace, or for good
 * through the tombstone), its own copy goes into the holding area for 30 days from that verification, or until the
 * person removes it. Never until the vault's own purge time.
 */
describe("the holding area keeps a deleted vault's copy 30 days from the verification", () => {
  const DAY = 86_400_000;
  beforeAll(async () => {
    await initSodium();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  const removal = (s: Seed, purgeAt: number): SyncResponse => ({
    rev: 6, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId],
    removedGrantsInfo: [{ vaultId: s.vaultId, reason: "deleted", purgeAt }],
  });
  const heldAt = async (s: Seed, at: number): Promise<boolean> => {
    vi.setSystemTime(at);
    await s.store.sync(); // every sync drops what is past its date
    return s.store.heldVaults().some((h) => h.vaultId === s.vaultId);
  };

  it("a delete verified in its grace: there on day 29, gone on day 31, whatever the vault's own dates", async () => {
    const s = await seededMember();
    vi.useFakeTimers({ toFake: ["Date"] });
    const t0 = Date.now();
    s.logs.deleteVault(s.vaultId, { deletedAt: t0 - 2 * DAY, purgeAt: t0 + 5 * DAY }); // the server's grace ends in 5 days
    s.api.queue.push(removal(s, t0 + 5 * DAY));
    await s.store.sync();
    expect(s.store.heldVaults().find((h) => h.vaultId === s.vaultId)?.expungeAt).toBe(t0 + 30 * DAY);
    expect(await heldAt(s, t0 + 6 * DAY), "past the vault's purge time").toBe(true);
    expect(await heldAt(s, t0 + 29 * DAY)).toBe(true);
    expect(await heldAt(s, t0 + 31 * DAY)).toBe(false);
  });

  it("a purge the device sees late still gives the full 30 days, counted from the verification", async () => {
    const s = await seededMember();
    vi.useFakeTimers({ toFake: ["Date"] });
    const t0 = Date.now();
    // The browser was away through the whole grace: the delete was 40 days ago, the purge 33 days ago.
    s.logs.deleteVault(s.vaultId, { deletedAt: t0 - 40 * DAY, purgeAt: t0 - 33 * DAY });
    s.logs.purge(s.vaultId, t0 - 33 * DAY);
    s.api.queue.push(removal(s, t0 - 33 * DAY));
    await s.store.sync();
    const held = s.store.heldVaults().find((h) => h.vaultId === s.vaultId);
    expect(held?.reason).toBe("deleted");
    expect(held?.verified).toBe(true);
    expect(held?.expungeAt).toBe(t0 + 30 * DAY);
    const notice = s.store.notices().find((n) => n.vaultId === s.vaultId);
    expect(notice?.keptUntil, "the notice names the day the copy leaves").toBe(t0 + 30 * DAY);
    expect(await heldAt(s, t0 + 29 * DAY)).toBe(true);
    expect(await heldAt(s, t0 + 31 * DAY)).toBe(false);
  });

  it("a purge verified for a copy held since the delete keeps it 30 days from the purge's verification", async () => {
    const s = await seededMember();
    vi.useFakeTimers({ toFake: ["Date"] });
    const t0 = Date.now();
    s.logs.deleteVault(s.vaultId, { deletedAt: t0, purgeAt: t0 + 7 * DAY });
    s.api.queue.push(removal(s, t0 + 7 * DAY));
    await s.store.sync();
    vi.setSystemTime(t0 + 8 * DAY);
    s.logs.purge(s.vaultId, t0 + 7 * DAY);
    s.api.queue.push({ ...removal(s, t0 + 7 * DAY), rev: 7 }); // the purge, seen a day after it happened
    await s.store.sync();
    expect(s.store.heldVaults().find((h) => h.vaultId === s.vaultId)?.expungeAt).toBe(t0 + 38 * DAY);
    expect(await heldAt(s, t0 + 37 * DAY)).toBe(true);
    expect(await heldAt(s, t0 + 39 * DAY)).toBe(false);
  });

  it("the person's “Remove from this device” drops the copy at once, whatever its date, and tells the server nothing", async () => {
    const s = await seededMember();
    s.logs.deleteVault(s.vaultId);
    s.api.queue.push(removal(s, Date.now() + 7 * DAY));
    await s.store.sync();
    expect(s.store.heldVaults().map((h) => h.vaultId)).toEqual([s.vaultId]);
    const pushes = s.api.pushes.length;
    const calls = s.api.calls.length;
    const syncs = s.api.sinceLog.length;
    await s.store.removeHeldCopy(s.vaultId);
    expect(s.store.heldVaults()).toEqual([]);
    expect([s.api.pushes.length, s.api.calls.length, s.api.sinceLog.length]).toEqual([pushes, calls, syncs]);
  });

  /** The seeded vault, held by this account as its owner (the verified log names it). */
  const owned = async (): Promise<Seed> => {
    const s = await seededMember();
    s.logs.share(s.vaultId, s.vk, "owner");
    return s;
  };

  it("the owner's own delete puts the copy into the holding area, 30 days from the verification, with no notice", async () => {
    const s = await owned();
    vi.useFakeTimers({ toFake: ["Date"] });
    const t0 = Date.now();
    s.api.queue.push(removal(s, t0 + 7 * DAY)); // the reconcile pull after the delete
    await s.store.deleteSharedVault(s.vaultId);
    expect(s.store.get(s.itemId), "out of the live view").toBeUndefined();
    const held = s.store.heldVaults().find((h) => h.vaultId === s.vaultId);
    expect(held).toMatchObject({ reason: "deleted", verified: true, byMe: true, itemCount: 1, expungeAt: t0 + 30 * DAY });
    expect(s.store.notices(), "never \"deleted by its owner\" for the owner's own delete").toEqual([]);
  });

  it("the review's sequence: the owner deletes, then restores; the server withholds the restore and serves the purge: the copy is held, with its 30 days", async () => {
    const s = await owned();
    vi.useFakeTimers({ toFake: ["Date"] });
    const t0 = Date.now();
    s.api.queue.push(removal(s, t0 + 7 * DAY));
    await s.store.deleteSharedVault(s.vaultId);
    const deleteId = (s.logs.logs.verifiedState(s.vaultId) as unknown as { deleteId: string }).deleteId;
    // The restore gets no answer: the server keeps it and never stores it.
    s.logs.nextAppend = "pending";
    await expect(s.store.restoreSharedVault(s.vaultId, deleteId)).rejects.toBeInstanceOf(ChangeNotStoredError);
    // A day after the grace, the server serves the purge.
    vi.setSystemTime(t0 + 8 * DAY);
    s.logs.purge(s.vaultId, t0 + 7 * DAY);
    s.api.queue.push({ ...removal(s, t0 + 7 * DAY), rev: 7 });
    await s.store.sync();
    const held = s.store.heldVaults().find((h) => h.vaultId === s.vaultId);
    expect(held).toMatchObject({ reason: "deleted", verified: true, byMe: true, itemCount: 1, expungeAt: t0 + 38 * DAY });
    expect(s.store.notices()).toEqual([]);
    expect(await heldAt(s, t0 + 37 * DAY)).toBe(true);
    expect(await heldAt(s, t0 + 39 * DAY)).toBe(false);
  });

  it("an owner's delete the server stored while its answer was lost, seen at a later pull: held, with no notice", async () => {
    const s = await owned();
    s.logs.deleteVault(s.vaultId); // stored by the server; this browser learns of it from the pull
    s.api.queue.push(removal(s, Date.now() + 7 * DAY));
    await s.store.sync();
    expect(s.store.heldVaults().find((h) => h.vaultId === s.vaultId)).toMatchObject({ byMe: true, verified: true });
    expect(s.store.notices()).toEqual([]);
  });

  it("a member's view of the owner's delete is unchanged: held, as deleted by its owner, with the notice", async () => {
    const s = await seededMember();
    s.logs.deleteVault(s.vaultId);
    s.api.queue.push(removal(s, Date.now() + 7 * DAY));
    await s.store.sync();
    expect(s.store.heldVaults().find((h) => h.vaultId === s.vaultId)).toMatchObject({ byMe: false, verified: true, reason: "deleted" });
    expect(s.store.notices().map((n) => n.kind)).toEqual(["deleted"]);
  });

  it("the owner's held copy is removed from this device at once, telling the server nothing; its line says the owner deleted it", async () => {
    const s = await owned();
    s.api.queue.push(removal(s, Date.now() + 7 * DAY));
    await s.store.deleteSharedVault(s.vaultId);
    const html = renderToStaticMarkup(createElement(RecentlyRemoved, { store: s.store, hide: [] }));
    expect(html).toContain("you deleted it · kept sealed until");
    expect(html).not.toContain("deleted by its owner");
    const calls = [s.api.pushes.length, s.api.calls.length, s.api.sinceLog.length];
    await s.store.removeHeldCopy(s.vaultId);
    expect(s.store.heldVaults()).toEqual([]);
    expect([s.api.pushes.length, s.api.calls.length, s.api.sinceLog.length]).toEqual(calls);
  });

  it("a leave this browser made still drops the vault at once", async () => {
    const s = await seededMember();
    s.api.queue.push({ rev: 6, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId], removedGrantsInfo: [{ vaultId: s.vaultId, reason: "left" }] });
    await s.store.leaveSharedVault(s.vaultId);
    expect(s.store.heldVaults()).toEqual([]);
    expect(s.store.notices()).toEqual([]);
  });

  it("a removal that fails on disk throws and leaves the copy in view", async () => {
    const s = await seededMember();
    s.logs.deleteVault(s.vaultId);
    s.api.queue.push(removal(s, Date.now() + 7 * DAY));
    await s.store.sync();
    const cache = (s.store as unknown as { cache: { removeHeld: (id: string) => Promise<void> } }).cache;
    cache.removeHeld = async () => {
      throw new Error("disk");
    };
    await expect(s.store.removeHeldCopy(s.vaultId)).rejects.toThrow("disk");
    expect(s.store.heldVaults().map((h) => h.vaultId)).toEqual([s.vaultId]);
  });
});

/** store.sync() then read the notices (parallels the Vault shell's syncNow). */
async function store_sync(s: { store: VaultStore }): Promise<void> {
  await s.store.sync();
}
