import { beforeAll, describe, expect, it, vi } from "vitest";
import { ApiError, type ApiClient } from "../api/client";
import type { DeletedItem, DeletedItemsResponse, ItemDoc, ItemRestoreResponse, ItemUpload, ItemVersion, ItemVersionsResponse, Mutation, PushResponse, SyncResponse, WireGrant, WireItem, WireVault } from "../api/types";
import { concat } from "../crypto/bytes";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { type BackupPayload, buildBackup, openBackup } from "../export/export";
import { Account } from "./account";
import { SyncIntegrityError, VaultStore, conflictCopyId } from "./store";

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
  /** `since` of every sync call — lets tests assert the store's cursor did not move. */
  sinceLog: number[] = [];
  rev = 1;
  /** PDD-1: arm a one-shot conflict result (carrying the losing serverItem) for an itemId. */
  conflictOnce = new Map<string, { serverItem: WireItem; newItemRev: number }>();
  /** Item history: archived versions the server would hold, keyed by itemId. */
  itemVersionsById = new Map<string, ItemVersion[]>();

  async itemVersions(itemId: string): Promise<ItemVersionsResponse> {
    return { itemId, versions: this.itemVersionsById.get(itemId) ?? [] };
  }

  /** Item undelete: tombstoned items the server would list + a capture of restore POSTs. */
  deletedList: DeletedItem[] = [];
  restored: { itemId: string; upload: ItemUpload }[] = [];
  async deletedItems(): Promise<DeletedItemsResponse> {
    return { items: this.deletedList };
  }
  async restoreItem(itemId: string, upload: ItemUpload): Promise<ItemRestoreResponse> {
    this.restored.push({ itemId, upload });
    this.deletedList = this.deletedList.filter((d) => d.itemId !== itemId); // un-tombstoned
    return { rev: 999 };
  }

  async sync(since: number): Promise<SyncResponse> {
    this.sinceLog.push(since);
    const resp = this.queue.shift() ?? emptySync(this.rev);
    // A real server's rev never goes below what it already served (the F31 rollback
    // guard exists precisely for servers that break this) — keep the fake honest so
    // a post-push reconcile doesn't fabricate a regression.
    this.rev = Math.max(this.rev, resp.rev);
    return resp;
  }

  async push(mutations: Mutation[]): Promise<PushResponse> {
    this.pushes.push(mutations);
    return {
      rev: ++this.rev,
      results: mutations.map((m) => {
        const c = this.conflictOnce.get(m.itemId);
        if (c) {
          this.conflictOnce.delete(m.itemId);
          return { mutationId: m.mutationId, status: "conflict" as const, newItemRev: c.newItemRev, serverItem: c.serverItem };
        }
        return { mutationId: m.mutationId, status: "applied" as const, newItemRev: 1 };
      }),
    };
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
      blob: owner.encryptItem(vaultId, itemId, DOC).blob,
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

  it("conflict materialization preserves unknown fields in BOTH pushed mutations", async () => {
    const s = await scenario("writer");
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), s.member);
    // The flagged winner's plaintext carries unknown fields at top, login, and
    // history-entry level (a future client wrote it) — spec 02 §3.
    const futureDoc = JSON.parse(
      '{"type":"login","name":"Future","x-top":{"a":1},"login":{"username":"u","password":"p1","x-flag":true,"passwordHistory":[{"password":"p0","retiredAt":1690000000000,"x-hist":"h"}]}}',
    ) as ItemDoc;
    const item: WireItem = { ...s.item, rev: 8, conflict: true, blob: s.owner.encryptItem(s.vaultId, s.itemId, futureDoc).blob };
    api.queue.push({ rev: 9, full: true, vaults: [s.vault], grants: [s.grant], items: [item], removedGrants: [] });
    await store.sync();

    expect(api.pushes.length).toBe(1);
    const [copy, rewrite] = api.pushes[0]!;
    // Decrypt both pushed mutations and walk the unknown paths per-field.
    for (const [label, m] of [["copy", copy!], ["rewrite", rewrite!]] as const) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const doc = s.member.decryptItem({
        ...item,
        itemId: m.itemId,
        conflict: false,
        formatVersion: m.item!.formatVersion,
        blob: m.item!.blob,
      }) as any;
      expect(doc["x-top"], `${label} lost top-level unknown`).toEqual({ a: 1 });
      expect(doc.login["x-flag"], `${label} lost login-level unknown`).toBe(true);
      expect(doc.login.passwordHistory[0]["x-hist"], `${label} lost history-entry unknown`).toBe("h");
    }
  });

  it("fails closed on a newer formatVersion: decryptItem throws, sync skips the item", async () => {
    const s = await scenario("writer");
    // Direct: the gate fires before the envelope is opened (same blob, claimed v3 —
    // one past this build's ceiling of 2).
    expect(() => s.member.decryptItem({ ...s.item, formatVersion: 3 })).toThrow(/newer/);

    // Through the store: the v3 item is skipped (envelope-only, retried after upgrade),
    // never materialized (a rewrite would silently downgrade it), and the rest of the
    // pull still lands.
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), s.member);
    const goodId = s.owner.newItemId();
    const good: WireItem = {
      ...s.item,
      itemId: goodId,
      rev: 6,
      blob: s.owner.encryptItem(s.vaultId, goodId, { type: "note", name: "still fine" }).blob,
    };
    api.queue.push({
      rev: 9,
      full: true,
      vaults: [s.vault],
      grants: [s.grant],
      items: [{ ...s.item, rev: 8, conflict: true, formatVersion: 3 }, good],
      removedGrants: [],
    });
    await store.sync(); // must not throw
    expect(store.get(s.itemId)).toBeUndefined(); // v3 item skipped, not surfaced
    expect(store.get(goodId)?.doc.name).toBe("still fine"); // pull continued past it
    expect(store.list().some((i) => i.itemId === s.itemId)).toBe(false);
    expect(api.pushes.length).toBe(0); // no conflict materialization of an undecryptable item
  });

  it("push side materializes the conflict copy from the LOSING serverItem, keeping our value live (PDD-1)", async () => {
    const s = await scenario("writer");
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), s.member);
    // Member holds the shared vault + item (our local base = the future winner).
    api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [s.item], removedGrants: [] });
    await store.sync();
    expect(store.get(s.itemId)?.doc).toEqual(DOC);

    // The DISPLACED (losing) value the server returns on our conflicting push: a different
    // concurrent edit by another device, encrypted under the shared VK.
    const losingDoc: ItemDoc = { type: "login", name: "Shared login", login: { username: "fam", password: "THEIRS-lost" } };
    const losing: WireItem = {
      ...s.item,
      rev: 6,
      updatedAt: 1_690_000_000_000,
      conflict: false,
      blob: s.owner.encryptItem(s.vaultId, s.itemId, losingDoc).blob,
    };
    api.conflictOnce.set(s.itemId, { serverItem: losing, newItemRev: 9 });
    const pushesBefore = api.pushes.length;

    // Our edit — the winner. save() pushes it; the server keeps ours live (LWW) and returns
    // the losing value, so the push side must materialize the copy FROM THE LOSING value.
    const ourDoc: ItemDoc = { type: "login", name: "Shared login", login: { username: "fam", password: "OURS-wins" } };
    await store.save(s.itemId, ourDoc);

    // A copy was pushed, keyed by the deterministic id over the WINNER rev (9) — the SAME id
    // the pull-side fallback uses, so the two converge (spec 03 §5).
    const copyId = await conflictCopyId(s.itemId, 9);
    const copyMut = api.pushes.slice(pushesBefore).flat().find((m) => m.itemId === copyId);
    expect(copyMut, "a conflict copy must be materialized from the losing serverItem").toBeTruthy();
    expect(copyMut!.baseItemRev).toBe(0); // a fresh item, not a rewrite of the winner
    // Its content is the LOSING value (their password), dated — NOT ours.
    const copyDoc = s.member.decryptItem({
      ...losing,
      itemId: copyId,
      conflict: false,
      formatVersion: copyMut!.item!.formatVersion,
      blob: copyMut!.item!.blob,
    }) as ItemDoc & { login: { password: string } };
    expect(copyDoc.login.password).toBe("THEIRS-lost");
    expect(copyDoc.name).toMatch(/\(conflict \d{4}-\d\d-\d\d\)$/);
    // Our value stays live locally (the winner), never overwritten by the copy.
    expect(store.get(s.itemId)?.doc).toEqual(ourDoc);
  });

  it("a losing delete (edit-beats-delete) does NOT materialize a spurious copy (PDD-1)", async () => {
    const s = await scenario("writer");
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), s.member);
    api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [s.item], removedGrants: [] });
    await store.sync();

    // On a delete that loses to a newer concurrent edit the server returns conflict + serverItem,
    // but serverItem is the SURVIVING winner, not a displaced value — nothing to preserve.
    const survivor: WireItem = { ...s.item, rev: 7, conflict: false };
    api.conflictOnce.set(s.itemId, { serverItem: survivor, newItemRev: 7 });
    const pushesBefore = api.pushes.length;

    await store.remove(s.itemId);

    // No conflict copy must be pushed (the op was a delete).
    const copyId = await conflictCopyId(s.itemId, 7);
    const spurious = api.pushes.slice(pushesBefore).flat().find((m) => m.itemId === copyId);
    expect(spurious, "a losing delete must not spawn a conflict-copy duplicate").toBeFalsy();
  });

  it("itemVersions fetches + decrypts archived versions under the held VK; restore is a put (item history)", async () => {
    const s = await scenario("writer");
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), s.member);
    api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [s.item], removedGrants: [] });
    await store.sync();

    // Two archived ciphertext versions (encrypted by the owner under the shared VK — as the server holds).
    const v1: ItemDoc = { type: "login", name: "Netflix", login: { username: "fam", password: "old-1" } };
    const v2: ItemDoc = { type: "login", name: "Netflix", login: { username: "fam", password: "old-2" } };
    api.itemVersionsById.set(s.itemId, [
      { rev: 8, blob: s.owner.encryptItem(s.vaultId, s.itemId, v2).blob, formatVersion: 1, archivedAt: 1_690_000_100_000 },
      { rev: 7, blob: s.owner.encryptItem(s.vaultId, s.itemId, v1).blob, formatVersion: 1, archivedAt: 1_690_000_000_000 },
    ]);

    const versions = await store.itemVersions(s.itemId, s.vaultId);
    expect(versions.map((v) => v.rev)).toEqual([8, 7]); // newest first
    expect(versions[0]!.doc.login?.password).toBe("old-2");
    expect(versions[1]!.doc.login?.password).toBe("old-1");

    // Restore the older version — an ordinary put over the live item.
    const pushesBefore = api.pushes.length;
    await store.save(s.itemId, versions[1]!.doc);
    expect(api.pushes.length).toBeGreaterThan(pushesBefore);
    expect(store.get(s.itemId)?.doc.login?.password).toBe("old-1");
  });

  it("deletedItems names each tombstone from its last version; restoreDeleted re-encrypts + restores (undelete)", async () => {
    const s = await scenario("writer");
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), s.member);
    // The item is DELETED — not in the live set; the vault + grant are, so the member holds the VK.
    api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [], removedGrants: [] });
    await store.sync();

    // A tombstone whose last value is in the archive (encrypted by the owner under the shared VK).
    // It HAD an attachment — whose blob was hard-unlinked at delete — so restore must drop the ref.
    const lastDoc: ItemDoc = {
      type: "login",
      name: "Deleted Netflix",
      login: { username: "fam", password: "p" },
      attachments: [{ id: "att-1", name: "recovery.txt", size: 10, fileKey: "k" }],
    };
    api.deletedList = [{ itemId: s.itemId, vaultId: s.vaultId, deletedAt: 1_690_000_000_000 }];
    api.itemVersionsById.set(s.itemId, [
      { rev: 9, blob: s.owner.encryptItem(s.vaultId, s.itemId, lastDoc).blob, formatVersion: 1, archivedAt: 1_690_000_000_000 },
    ]);

    const trash = await store.deletedItems();
    expect(trash).toHaveLength(1);
    expect(trash[0]!.doc?.name).toBe("Deleted Netflix"); // named from its last archived version

    await store.restoreDeleted(s.itemId, s.vaultId, trash[0]!.doc!);
    expect(api.restored.map((r) => r.itemId)).toEqual([s.itemId]);
    expect(api.restored[0]!.upload.blob.length).toBeGreaterThan(0); // re-encrypted content POSTed
    expect(api.restored[0]!.upload.attachmentIds).toEqual([]); // attachment ref dropped — its blob is gone
    expect(await store.deletedItems()).toHaveLength(0); // restored item leaves the trash
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

  it("records lastSyncAt only after a successful sync (export offline banner)", async () => {
    const s = await scenario();
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), s.member);
    expect(store.lastSyncAt).toBeNull();

    // A failing pull leaves it untouched…
    const failing = { sync: async () => { throw new Error("offline"); } } as unknown as ApiClient;
    const offlineStore = new VaultStore(failing, s.member);
    await expect(offlineStore.sync()).rejects.toThrow();
    expect(offlineStore.lastSyncAt).toBeNull();

    // …a successful one stamps the wall clock.
    const before = Date.now();
    await store.sync();
    expect(store.lastSyncAt).not.toBeNull();
    expect(store.lastSyncAt!).toBeGreaterThanOrEqual(before);
  });
});

/**
 * spec 07 §2.4: items the client holds the vault key for but cannot decrypt must be
 * RETAINED (itemId/vaultId/formatVersion) so a backup enumerates them in
 * `skipped.undecryptable` instead of silently omitting credentials — while staying
 * out of the visible list()/get() surface.
 */
describe("VaultStore undecryptable retention (spec 07 §2.4)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("retains a held-key formatVersion=3 item — and it lands in a backup's skipped set", async () => {
    const s = await scenario();
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), s.member);
    const goodId = s.owner.newItemId();
    const good: WireItem = {
      ...s.item,
      itemId: goodId,
      rev: 6,
      blob: s.owner.encryptItem(s.vaultId, goodId, { type: "note", name: "still fine" }).blob,
    };
    api.queue.push({
      rev: 9,
      full: true,
      vaults: [s.vault],
      grants: [s.grant],
      items: [{ ...s.item, formatVersion: 3 }, good],
      removedGrants: [],
    });
    await store.sync();

    // Side-channel list only: the visible surface still silently skips it.
    expect(store.get(s.itemId)).toBeUndefined();
    expect(store.list().some((i) => i.itemId === s.itemId)).toBe(false);
    expect(store.undecryptable()).toEqual([{ itemId: s.itemId, vaultId: s.vaultId, formatVersion: 3 }]);
    // A normally decrypted item is NOT enumerated.
    expect(store.undecryptable().some((u) => u.itemId === goodId)).toBe(false);

    // The list flows into a built container's authenticated skipped set (§2.4).
    const payload: BackupPayload = {
      v: 1,
      exportedAt: Date.now(),
      origin: "",
      userId: s.member.userId,
      identityFingerprint: "",
      vaults: [],
      items: [],
      attachments: [],
      skipped: { undecryptable: store.undecryptable(), attachmentsOverCap: [], attachmentFetchFailed: [] },
    };
    const parts = await buildBackup("pw pw pw", crypto.randomUUID(), randomBytes(16), KDF, payload, []);
    const opened = await openBackup("pw pw pw", concat(...parts));
    expect(opened.payload.skipped.undecryptable).toEqual([
      { itemId: s.itemId, vaultId: s.vaultId, formatVersion: 3 },
    ]);
  });

  it("enumerates BOTH a corrupt held-key blob AND items of a no-key vault (spec 07 §2.4 — never silently omitted)", async () => {
    const s = await scenario();
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), s.member);
    // AD mismatch: a blob sealed for a DIFFERENT itemId fails decrypt under the held VK.
    const corrupt: WireItem = { ...s.item, blob: s.owner.encryptItem(s.vaultId, s.owner.newItemId(), DOC).blob };
    // A vault we hold no key for: spec 07 §2.4 requires it be SKIPPED but ENUMERATED (missing VK),
    // never silently omitted from a backup (the Kotlin ExportPlanner enumerates it too).
    const foreignId = s.owner.newItemId();
    const foreign: WireItem = { ...s.item, itemId: foreignId, vaultId: "vault-with-no-key", formatVersion: 3 };
    api.queue.push({ rev: 9, full: true, vaults: [s.vault], grants: [s.grant], items: [corrupt, foreign], removedGrants: [] });
    await store.sync();

    const expected = [
      { itemId: s.itemId, vaultId: s.vaultId, formatVersion: 1 },
      { itemId: foreignId, vaultId: "vault-with-no-key", formatVersion: 3 },
    ].sort((a, b) => a.vaultId.localeCompare(b.vaultId) || a.itemId.localeCompare(b.itemId));
    expect(store.undecryptable()).toEqual(expected);
  });

  it("clears a missing-VK enumeration when the no-VK item is tombstoned (spec 07 §2.4 lifecycle, A3)", async () => {
    const s = await scenario();
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), s.member);
    const foreignId = s.owner.newItemId();
    const foreign: WireItem = { ...s.item, itemId: foreignId, vaultId: "vault-with-no-key", formatVersion: 3 };
    api.queue.push({ rev: 9, full: true, vaults: [s.vault], grants: [s.grant], items: [foreign], removedGrants: [] });
    await store.sync();
    expect(store.undecryptable().map((u) => u.itemId)).toContain(foreignId);

    // A tombstone for the no-VK item ends its enumeration. A no-key item's tombstone has !hasVault
    // and never reaches the held-path tombstone clear, so the new !hasVault branch must handle it.
    api.queue.push({ rev: 10, full: false, vaults: [], grants: [], items: [{ ...foreign, deleted: true }], removedGrants: [] });
    await store.sync();
    expect(store.undecryptable()).toEqual([]);
  });

  it("clears the entry when the item becomes decryptable, is tombstoned, or its grant is revoked", async () => {
    const s = await scenario();
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), s.member);
    api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [{ ...s.item, formatVersion: 3 }], removedGrants: [] });
    await store.sync();
    expect(store.undecryptable()).toHaveLength(1);

    // Re-delivered decryptable (an upgraded writer re-encrypted at v1) → cleared, visible again.
    api.queue.push({ rev: 6, full: false, vaults: [], grants: [], items: [{ ...s.item, rev: 6 }], removedGrants: [] });
    await store.sync();
    expect(store.undecryptable()).toEqual([]);
    expect(store.get(s.itemId)?.doc).toEqual(DOC);

    // A newer undecryptable rev supersedes the held plaintext (never BOTH surfaces)…
    api.queue.push({ rev: 7, full: false, vaults: [], grants: [], items: [{ ...s.item, rev: 7, formatVersion: 3 }], removedGrants: [] });
    await store.sync();
    expect(store.get(s.itemId)).toBeUndefined();
    expect(store.undecryptable()).toHaveLength(1);

    // …a tombstone ends the enumeration…
    api.queue.push({ rev: 8, full: false, vaults: [], grants: [], items: [{ ...s.item, rev: 8, deleted: true }], removedGrants: [] });
    await store.sync();
    expect(store.undecryptable()).toEqual([]);

    // …and a revoked membership purges the vault's entries with it.
    api.queue.push({ rev: 9, full: false, vaults: [], grants: [], items: [{ ...s.item, rev: 9, formatVersion: 3 }], removedGrants: [] });
    await store.sync();
    expect(store.undecryptable()).toHaveLength(1);
    api.queue.push({ rev: 10, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId] });
    await store.sync();
    expect(store.undecryptable()).toEqual([]);
  });

  it("does not double-count across a 410 resync-from-0", async () => {
    const s = await scenario();
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), s.member);
    api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [{ ...s.item, formatVersion: 3 }], removedGrants: [] });
    await store.sync();
    expect(store.undecryptable()).toHaveLength(1);

    // Cursor expired: the next pull 410s and the retry-from-0 re-delivers the SAME item.
    let failedOnce = false;
    const realSync = api.sync.bind(api);
    api.sync = async (since: number) => {
      if (!failedOnce) {
        failedOnce = true;
        throw new ApiError(410, "cursor_gone", "resync required");
      }
      return realSync(since);
    };
    api.queue.push({ rev: 6, full: true, vaults: [s.vault], grants: [s.grant], items: [{ ...s.item, formatVersion: 3 }], removedGrants: [] });
    await store.sync();
    expect(store.undecryptable()).toEqual([{ itemId: s.itemId, vaultId: s.vaultId, formatVersion: 3 }]);
  });
});

/**
 * F31 rollback guards (spec 05 T1, core SyncEngine.pull parity): a non-full response
 * below the cursor, or a full snapshot we did not ask for via the 410 path, is a
 * server rollback/replay signal and must be REJECTED — nothing applied, cursor
 * unmoved — so a rolled-back server can never delete or overwrite newer local state.
 */
describe("VaultStore rollback guards (F31)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  /** Seed a store at cursor 5 holding the scenario item. */
  async function seeded() {
    const s = await scenario();
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), s.member);
    api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [s.item], removedGrants: [] });
    await store.sync();
    return { s, api, store };
  }

  it("rejects a non-full response whose rev is below the cursor — nothing applied, cursor kept", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const { s, api, store } = await seeded();
      const stamped = store.lastSyncAt;

      // A rolled-back server re-serves rev 3 — including a tombstone for our item. If
      // the guard failed, the item would vanish and the cursor would move backwards.
      api.queue.push({
        rev: 3,
        full: false,
        vaults: [],
        grants: [],
        items: [{ ...s.item, rev: 3, deleted: true, blob: null }],
        removedGrants: [],
      });
      await expect(store.sync()).rejects.toBeInstanceOf(SyncIntegrityError);

      expect(warn).toHaveBeenCalledWith(expect.stringMatching(/went backwards/)); // surfaced, not silent
      expect(store.get(s.itemId)?.doc).toEqual(DOC); // the tombstone was NOT applied
      expect(store.lastSyncAt).toBe(stamped); // not stamped as a successful sync
      api.queue.push(emptySync(5));
      await store.sync();
      expect(api.sinceLog).toEqual([0, 5, 5]); // the next pull still asked from the KEPT cursor
    } finally {
      warn.mockRestore();
    }
  });

  it("rejects an unsolicited full snapshot once the cursor has advanced", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const { s, api, store } = await seeded();

      // full=true with rev AHEAD of the cursor — still rejected: outside the 410 path a
      // snapshot means the server lost its delta history (rollback / replaced DB), and
      // applying this EMPTY one would wipe the local working set.
      api.queue.push({ rev: 9, full: true, vaults: [], grants: [], items: [], removedGrants: [] });
      await expect(store.sync()).rejects.toThrow(/unsolicited full snapshot/);

      expect(warn).toHaveBeenCalledWith(expect.stringMatching(/unsolicited full snapshot/));
      expect(store.get(s.itemId)?.doc).toEqual(DOC); // store not wiped
      api.queue.push(emptySync(5));
      await store.sync();
      expect(api.sinceLog).toEqual([0, 5, 5]); // cursor never moved to 9
    } finally {
      warn.mockRestore();
    }
  });

  it("accepts an equal-rev empty delta (a quiet server is not a rollback)", async () => {
    const { api, store } = await seeded();
    api.queue.push(emptySync(5));
    await expect(store.sync()).resolves.toBeUndefined();
  });

  it("still accepts the full snapshot that follows a 410 resync", async () => {
    const { s, api, store } = await seeded();

    let failedOnce = false;
    const realSync = api.sync.bind(api);
    api.sync = async (since: number) => {
      if (!failedOnce) {
        failedOnce = true;
        throw new ApiError(410, "cursor_gone", "resync required");
      }
      return realSync(since);
    };
    api.queue.push({ rev: 8, full: true, vaults: [s.vault], grants: [s.grant], items: [s.item], removedGrants: [] });
    await store.sync(); // must NOT trip the unsolicited-snapshot guard
    expect(store.get(s.itemId)?.doc).toEqual(DOC);
    api.queue.push(emptySync(8));
    await store.sync();
    expect(api.sinceLog.at(-1)).toBe(8); // cursor followed the resync snapshot
  });

  it("keeps the working set when the 410 refetch itself fails (fetch-first, core parity)", async () => {
    const { s, api, store } = await seeded();

    let calls = 0;
    api.sync = async () => {
      calls++;
      if (calls === 1) throw new ApiError(410, "cursor_gone", "resync required");
      throw new TypeError("network down"); // the replacement snapshot dies mid-flight
    };
    await expect(store.sync()).rejects.toThrow(/network down/);
    // The store was NOT emptied ahead of a snapshot that never arrived.
    expect(store.get(s.itemId)?.doc).toEqual(DOC);
    expect(store.list()).toHaveLength(1);
  });

  it("rejects a 410 resync whose replacement is NOT a full snapshot — working set intact", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const { s, api, store } = await seeded();

      let failedOnce = false;
      const realSync = api.sync.bind(api);
      api.sync = async (since: number) => {
        if (!failedOnce) {
          failedOnce = true;
          throw new ApiError(410, "cursor_gone", "resync required");
        }
        return realSync(since);
      };
      // The server said our cursor is gone, then answered the from-0 pull with a
      // PARTIAL response. Applying it would wipe the store and repopulate a sliver.
      api.queue.push({ rev: 8, full: false, vaults: [], grants: [], items: [], removedGrants: [] });
      await expect(store.sync()).rejects.toBeInstanceOf(SyncIntegrityError);

      expect(warn).toHaveBeenCalledWith(expect.stringMatching(/resync returned a non-full/));
      expect(store.get(s.itemId)?.doc).toEqual(DOC); // nothing wiped, nothing applied
      expect(store.list()).toHaveLength(1);
      api.queue.push(emptySync(5));
      await store.sync();
      expect(api.sinceLog.at(-1)).toBe(5); // cursor unmoved by the rejected resync
    } finally {
      warn.mockRestore();
    }
  });
});

/** Overlapping pulls could apply an older response after a newer one and move the
 *  cursor backwards — the very corruption the rollback guards reject — so sync() is
 *  single-flight: concurrent callers (bell, poll, Sync-now, reconciles) join one pull. */
describe("VaultStore sync single-flight", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("concurrent sync() calls share ONE underlying api.sync", async () => {
    const s = await scenario();
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), s.member);
    api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [s.item], removedGrants: [] });

    await Promise.all([store.sync(), store.sync(), store.sync()]);
    expect(api.sinceLog).toEqual([0]); // three callers, one pull

    // The handle is released after settling: a later sync pulls again…
    api.queue.push(emptySync(6));
    await store.sync();
    expect(api.sinceLog).toEqual([0, 5]);
  });

  it("all joiners see the same rejection; the flight is released afterwards", async () => {
    const s = await scenario();
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), s.member);
    api.sync = async () => {
      throw new TypeError("offline");
    };
    const [a, b] = await Promise.allSettled([store.sync(), store.sync()]);
    expect(a.status).toBe("rejected");
    expect(b.status).toBe("rejected");

    // Released: the next call really pulls (and succeeds).
    api.sync = FakeApi.prototype.sync.bind(api);
    api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [s.item], removedGrants: [] });
    await store.sync();
    expect(store.get(s.itemId)?.doc).toEqual(DOC);
  });
});

/** A push that reached the server is COMMITTED — the save must never be reported as
 *  failed afterwards (the Editor would say "nothing was changed" about a live write,
 *  and a user retry would commit a SECOND copy since put mutationIds are fresh). */
describe("VaultStore save() post-push reconcile (mirror of remove())", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a reconcile rejected by the rollback guard does not fail the save — local apply instead", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const s = await scenario("writer");
      const api = new FakeApi();
      const store = new VaultStore(api.asClient(), s.member);
      api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [s.item], removedGrants: [] });
      await store.sync();

      // The post-push reconcile pull will be REJECTED by the F31 rev-regression guard.
      api.queue.push({ rev: 3, full: false, vaults: [], grants: [], items: [], removedGrants: [] });
      await expect(store.save(s.itemId, { ...DOC, name: "renamed" })).resolves.toBeUndefined();

      expect(api.pushes).toHaveLength(1); // committed exactly once — no retry bait
      expect(store.get(s.itemId)?.doc.name).toBe("renamed"); // optimistic local apply
      expect(warn).toHaveBeenCalled(); // the integrity problem is surfaced, not hidden
    } finally {
      warn.mockRestore();
    }
  });

  it("a reconcile that dies on the network does not fail the save either", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const s = await scenario("writer");
      const api = new FakeApi();
      const store = new VaultStore(api.asClient(), s.member);
      api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [s.item], removedGrants: [] });
      await store.sync();

      api.sync = async () => {
        throw new TypeError("offline");
      };
      await expect(store.save(s.itemId, { ...DOC, name: "renamed offline" })).resolves.toBeUndefined();
      expect(store.get(s.itemId)?.doc.name).toBe("renamed offline");
    } finally {
      warn.mockRestore();
    }
  });
});

/**
 * F20 (member transparency): an "added to vault" notice fires ONCE for a genuinely new grant
 * (never on the fresh-device since=0 pull), and an undecryptable grant becomes a persistent
 * warning that clears itself once a later pull opens it.
 */
describe("VaultStore F20 member transparency", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("fires an 'added' notice once for a newly-granted vault, but never on the fresh-device (since=0) pull", async () => {
    const s = await scenario();
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), s.member);

    // Fresh-device pull (since=0, full snapshot): the grant is delivered but this is the device's
    // FIRST sight of everything — the hazard says notices fire only for verifiable NEW state, so
    // no "added" notice may fire here.
    api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [s.item], removedGrants: [] });
    await store.sync();
    expect(store.notices().some((n) => n.kind === "added")).toBe(false);

    // A SECOND shared vault is granted on a later DELTA pull → exactly one "added" notice, named.
    const { request: req2, vaultId: v2 } = s.owner.buildCreateSharedVault("Work");
    const vault2: WireVault = { vaultId: v2, type: "shared", rev: 6, metaBlob: req2.metaBlob, createdAt: 0 };
    const grant2: WireGrant = { vaultId: v2, userId: s.member.userId, role: "writer", wrappedVk: "", rev: 7, sealedVk: s.owner.wrapVkForMember(s.member.identityPub, v2) };
    api.queue.push({ rev: 7, full: false, vaults: [vault2], grants: [grant2], items: [], removedGrants: [] });
    await store.sync();

    const added = store.notices().filter((n) => n.kind === "added");
    expect(added).toHaveLength(1);
    expect(added[0]!.vaultId).toBe(v2);
    expect(added[0]!.vaultName).toBe("Work");

    // An idempotent re-pull of the same grant must NOT fire a second notice (fires once).
    api.queue.push({ rev: 8, full: false, vaults: [vault2], grants: [{ ...grant2, rev: 8 }], items: [], removedGrants: [] });
    await store.sync();
    expect(store.notices().filter((n) => n.kind === "added")).toHaveLength(1);
  });

  /**
   * The owner's SECOND device sees a vault the same account created on device A as a brand-new
   * grant on a delta pull (owner grants carry a `wrappedVk` the UVK opens, so `addGrant` succeeds
   * and `heldBefore` is false). "You were added to Work" would misattribute the account's own
   * creation to someone else sharing with it. Owner-role grants never emit the notice.
   */
  it("never fires an 'added' notice for a vault this account owns (the owner's second device)", async () => {
    const s = await scenario();
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), s.owner); // the OWNER's second device

    api.queue.push({ rev: 5, full: true, vaults: [], grants: [], items: [], removedGrants: [] });
    await store.sync(); // establishes a cursor, so the next pull is a genuine delta (since > 0)

    // Device A creates "Work". Device B holds the same UVK but has never seen this vault, so
    // `removeVault` drops the key `buildCreateSharedVault` cached locally — without it the account
    // would already hold the VK, `heldBefore` would be true, and this test would pass even with
    // the owner guard reverted.
    const { request: req2, vaultId: v2 } = s.owner.buildCreateSharedVault("Work");
    s.owner.removeVault(v2);

    // Device B's delta pull delivers the vault + the owner's OWN grant (wrappedVk, no sealedVk):
    // `addGrant` opens it under the UVK, so heldBefore=false and it lands in `newlyAdded`.
    const vault2: WireVault = { vaultId: v2, type: "shared", rev: 6, metaBlob: req2.metaBlob, createdAt: 0 };
    const ownerGrant2: WireGrant = { vaultId: v2, userId: s.owner.userId, role: "owner", wrappedVk: req2.wrappedVk, rev: 7, sealedVk: "" };
    api.queue.push({ rev: 7, full: false, vaults: [vault2], grants: [ownerGrant2], items: [], removedGrants: [] });
    await store.sync();

    expect(store.vaults().some((v) => v.vaultId === v2)).toBe(true); // the vault DID arrive & open
    expect(s.owner.roleFor(v2)).toBe("owner");
    expect(store.notices().filter((n) => n.kind === "added")).toHaveLength(0); // ...silently
  });

  it("retains an undecryptable grant as a persistent warning, and clears it when a later pull opens it", async () => {
    const s = await scenario();
    const stranger = await enroll("stranger@example.com");
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), s.member);

    // The grant's VK is sealed to a DIFFERENT identity (another household device) — this device
    // cannot open it, so addGrant throws and the vault never becomes usable.
    const badGrant: WireGrant = { ...s.grant, sealedVk: s.owner.wrapVkForMember(stranger.identityPub, s.vaultId) };
    api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [badGrant], items: [s.item], removedGrants: [] });
    await store.sync();

    expect(s.member.hasVault(s.vaultId)).toBe(false); // never opened
    expect(store.undecryptableGrantVaults()).toEqual([s.vaultId]); // persistent warning surfaced
    expect(store.vaults().some((v) => v.vaultId === s.vaultId)).toBe(false); // not a usable vault
    expect(store.notices().some((n) => n.kind === "added")).toBe(false); // no false "added" — we can't open it

    // A later pull re-delivers the grant sealed correctly to THIS device → it opens → warning clears.
    api.queue.push({ rev: 6, full: false, vaults: [s.vault], grants: [s.grant], items: [s.item], removedGrants: [] });
    await store.sync();

    expect(s.member.hasVault(s.vaultId)).toBe(true);
    expect(store.undecryptableGrantVaults()).toEqual([]); // cleared once openable
    expect(store.get(s.itemId)?.doc).toEqual(DOC);
  });

  it("clears the undecryptable-grant warning when the grant is revoked", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const s = await scenario();
      const stranger = await enroll("stranger2@example.com");
      const api = new FakeApi();
      const store = new VaultStore(api.asClient(), s.member);

      const badGrant: WireGrant = { ...s.grant, sealedVk: s.owner.wrapVkForMember(stranger.identityPub, s.vaultId) };
      api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [badGrant], items: [s.item], removedGrants: [] });
      await store.sync();
      expect(store.undecryptableGrantVaults()).toEqual([s.vaultId]);

      // Access revoked before this device ever opened it — the "can't open" row is moot, drop it.
      api.queue.push({ rev: 6, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId] });
      await store.sync();
      expect(store.undecryptableGrantVaults()).toEqual([]);
    } finally {
      warn.mockRestore();
    }
  });
});

describe("VaultStore import destination vault (S2)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  /** Member holds personal + shared (writer), with one item in EACH vault, post-sync. */
  async function seeded() {
    const s = await scenario("writer");
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), s.member);
    const personalId = s.member.newItemId();
    const personalItem: WireItem = {
      itemId: personalId,
      vaultId: s.member.personalVaultId,
      rev: 5,
      createdAt: 0,
      updatedAt: 0,
      deleted: false,
      conflict: false,
      formatVersion: 1,
      attachmentIds: [],
      blob: s.member.encryptItem(s.member.personalVaultId, personalId, {
        type: "login",
        name: "Personal login",
        login: { username: "me", password: "solo" },
      }).blob,
    };
    api.queue.push({ rev: 6, full: true, vaults: [s.vault], grants: [s.grant], items: [s.item, personalItem], removedGrants: [] });
    await store.sync();
    return { s, api, store };
  }

  it("importProjections(sharedVaultId) projects ONLY that vault's items", async () => {
    const { s, store } = await seeded();
    // Shared destination: only the shared item's identity feeds the F75 dedupe…
    const shared = store.importProjections(s.vaultId);
    expect(shared.names).toEqual(["Shared login"]);
    expect(shared.logins.map((l) => l.username)).toEqual(["fam"]);
    // …and the no-arg default is still personal-only — the projections never bleed across.
    const personal = store.importProjections();
    expect(personal.names).toEqual(["Personal login"]);
    expect(personal.logins.map((l) => l.username)).toEqual(["me"]);
  });

  it("importDocs(..., sharedVaultId) commits every row into that vault, sealed under its VK", async () => {
    const { s, api, store } = await seeded();
    await store.importDocs(
      [
        { itemId: s.member.newItemId(), doc: { type: "login", name: "Imported login", login: { username: "new", password: "pw" } } },
        { itemId: s.member.newItemId(), doc: { type: "note", name: "Imported note" } },
      ],
      undefined,
      s.vaultId,
    );
    const puts = api.pushes.flat().filter((m) => m.op === "put");
    expect(puts).toHaveLength(2);
    for (const m of puts) {
      expect(m.vaultId).toBe(s.vaultId); // rows land in the CHOSEN vault, not personal
      // …and are encrypted under the shared VK: the OWNER can open what the member pushed.
      const doc = s.owner.decryptItem({
        itemId: m.itemId,
        vaultId: s.vaultId,
        rev: 1,
        createdAt: 0,
        updatedAt: 0,
        deleted: false,
        conflict: false,
        formatVersion: m.item!.formatVersion,
        attachmentIds: [],
        blob: m.item!.blob,
      });
      expect(doc.name).toMatch(/^Imported/);
    }
  });
});
