import { beforeAll, describe, expect, it, vi } from "vitest";
import { ApiError, type ApiClient } from "../api/client";
import type { DeletedItem, DeletedItemsResponse, ItemDoc, ItemRestoreResponse, ItemUpload, ItemVersion, ItemVersionsResponse, Mutation, PushResponse, SyncResponse, WireGrant, WireItem, WireVault } from "../api/types";
import { adVaultMeta } from "../crypto/ad";
import { concat, toB64, utf8 } from "../crypto/bytes";
import { seal } from "../crypto/envelope";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes, sealTo } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { type BackupPayload, buildBackup, openBackup } from "../export/export";
import { Account } from "./account";
import { type FakeRole, FakeSharedLogs, vaultMadeBy } from "./fakesharedlogs.testkit";
import { type ItemWire, SyncIntegrityError, VaultStore, conflictCopyId } from "./store";
import { fill, ITEM_BROUGHT_BACK } from "../ui/copy";
import { noticeBody } from "../ui/Vault";

/**
 * Store-level unit tests for shared vaults against the REAL Account crypto and a fake ApiClient. A shared vault's key
 * and role come from its verified log (design §3.6), stood in for by FakeSharedLogs: these tests are about the store.
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

  async pushMutations(mutations: Mutation[]): Promise<PushResponse> {
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

const DOC: ItemDoc = { type: "login", name: "Shared login", login: { username: "fam", password: "hunter2" } };

interface Scenario {
  owner: Account;
  member: Account;
  vaultId: string;
  vk: Uint8Array;
  vault: WireVault;
  grant: WireGrant; // the member's grant row: a hint only, the log decides (design §3.6)
  itemId: string;
  item: WireItem; // DOC encrypted by the owner under the shared VK
  /** What the verified logs say, on the member's and on the owner's devices. */
  memberLogs: FakeSharedLogs;
  ownerLogs: FakeSharedLogs;
  /** A store for [who] on [api], with its log layer attached (as enterVault does). */
  storeFor(api: ApiClient, who?: "member" | "owner"): VaultStore;
}

/** A shared vault's row as the server serves it, its meta sealed under [vk]. */
function vaultRow(vaultId: string, vk: Uint8Array, name: string, rev = 2): WireVault {
  return { vaultId, type: "shared", rev, metaBlob: toB64(seal(vk, utf8(JSON.stringify({ name })), adVaultMeta(vaultId))), createdAt: 0 };
}

/** The owner's shared vault with one item, and the member listed in its log with [role] — real client crypto. */
async function scenario(role: FakeRole = "reader"): Promise<Scenario> {
  const owner = await enroll("owner@example.com");
  const member = await enroll("member@example.com");
  const vaultId = crypto.randomUUID();
  const vk = randomBytes(32);
  owner.logKeyRing().set(vaultId, vk.slice());
  owner.attachLogRoles(() => "owner", () => true);
  const ownerLogs = new FakeSharedLogs(owner);
  ownerLogs.share(vaultId, vk, "owner");
  const memberLogs = new FakeSharedLogs(member);
  memberLogs.share(vaultId, vk, role);
  const itemId = owner.newItemId();
  return {
    owner,
    member,
    vaultId,
    vk,
    memberLogs,
    ownerLogs,
    storeFor: (api, who = "member") => {
      const store = new VaultStore(api, who === "owner" ? owner : member, undefined, undefined, api as unknown as ItemWire); // the fake serves the item routes too
      (who === "owner" ? ownerLogs : memberLogs).attachTo(store);
      return store;
    },
    vault: vaultRow(vaultId, vk, "Family"),
    grant: { vaultId, userId: member.userId, role, wrappedVk: "", rev: 3 },
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

  it("adopts the shared vault through its log and decrypts its items", async () => {
    const s = await scenario();
    const api = new FakeApi();
    const store = s.storeFor(api.asClient());
    api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [s.item], removedGrants: [] });
    await store.sync();

    expect(s.member.hasVault(s.vaultId)).toBe(true);
    expect(s.member.roleFor(s.vaultId)).toBe("reader");
    expect(store.get(s.itemId)?.doc).toEqual(DOC);
    const info = store.vaults().find((v) => v.vaultId === s.vaultId);
    expect(info).toEqual({ vaultId: s.vaultId, type: "shared", name: "Family", role: "reader", createdAt: 0 });
  });

  it("materializes conflicts with the deterministic copy id, and skips as reader", async () => {
    const s = await scenario("writer");
    const api = new FakeApi();
    const store = s.storeFor(api.asClient());
    api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [{ ...s.item, rev: 8, conflict: true }], removedGrants: [] });
    await store.sync();

    expect(api.pushes.length).toBe(1);
    const [copy, rewrite] = api.pushes[0]!;
    expect(copy!.itemId).toBe(await conflictCopyId(s.itemId, 8)); // spec 03 §5: converges across clients
    expect(copy!.itemId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(copy!.vaultId).toBe(s.vaultId);
    expect(rewrite!.itemId).toBe(s.itemId);

    // Demoted to reader in the log: a re-flagged item must NOT be materialized (push would be denied).
    s.memberLogs.share(s.vaultId, s.vk, "reader");
    api.queue.push({
      rev: 9,
      full: false,
      vaults: [],
      grants: [],
      items: [{ ...s.item, rev: 10, conflict: true }],
      removedGrants: [],
    });
    await store.sync();
    expect(api.pushes.length).toBe(1); // unchanged
  });

  it("conflict materialization preserves unknown fields in BOTH pushed mutations", async () => {
    const s = await scenario("writer");
    const api = new FakeApi();
    const store = s.storeFor(api.asClient());
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
    const store = s.storeFor(api.asClient());
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
    const store = s.storeFor(api.asClient());
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
    await store.save(s.itemId, ourDoc, [], undefined, s.vaultId);

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

  /**
   * Spec 03 §5 as the server answers since 2026-11-18: a put over a deleted item brings it back (edit beats delete); the
   * answer is `conflict` with the deletion's mark (`serverItem` = the tombstone: `deleted: true`, `blob: null`), on the
   * first answer and on a replay, and the restored row is stored WITHOUT the conflict mark. [rowMarked]: the reconcile
   * pull serves the restored row marked as a conflict anyway (an older server's way).
   */
  async function putOverDeleted(rowMarked: boolean) {
    const s = await scenario("writer");
    const api = new FakeApi();
    const store = s.storeFor(api.asClient());
    api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [s.item], removedGrants: [] });
    await store.sync();
    const tombstone: WireItem = { ...s.item, rev: 6, updatedAt: 1_690_000_000_000, deleted: true, conflict: false, attachmentIds: [], blob: null };
    api.conflictOnce.set(s.itemId, { serverItem: tombstone, newItemRev: 9 });
    const ourDoc: ItemDoc = { type: "login", name: "Shared login", login: { username: "fam", password: "OURS" } };
    const restored: WireItem = { ...s.item, rev: 9, conflict: rowMarked, blob: s.member.encryptItem(s.vaultId, s.itemId, ourDoc).blob };
    api.queue.push({ rev: 9, full: false, vaults: [], grants: [], items: [restored], removedGrants: [] });
    const pushesBefore = api.pushes.length;
    await store.save(s.itemId, ourDoc, [], undefined, s.vaultId);
    await store.sync();
    const copyId = await conflictCopyId(s.itemId, 9);
    const after = api.pushes.slice(pushesBefore).flat();
    return { s, api, store, ourDoc, copyId, after };
  }

  it("a put that brings a deleted item back: no \"(conflict)\" copy, the item is live with our value, and the person is told once that the change brought back an item deleted elsewhere", async () => {
    const { s, store, ourDoc, copyId, after } = await putOverDeleted(false);
    expect(after.some((m) => m.itemId === copyId), "no copy of the item that came back").toBe(false);
    expect(store.list().filter((i) => i.doc.name.startsWith("Shared login"))).toHaveLength(1);
    expect(store.get(s.itemId)?.doc).toMatchObject(ourDoc);
    // On the code before: nothing was said.
    const n = store.notices().filter((x) => x.kind === "item-brought-back");
    expect(n).toHaveLength(1);
    expect(n[0]).toMatchObject({ vaultId: s.vaultId, parkedCount: 1, itemName: "Shared login" });
    expect(noticeBody(n[0]!).body).toBe(fill(ITEM_BROUGHT_BACK, "Shared login", n[0]!.vaultName || "a vault"));
    // Once: a later sync says nothing more of it.
    await store.sync();
    expect(store.notices().filter((x) => x.kind === "item-brought-back")).toHaveLength(1);
  });

  it("the same where the restored row still comes marked as a conflict (an older server, or a replay journaled before the change): no copy either, the mark is cleared, and it is said once", async () => {
    const { s, store, copyId, after } = await putOverDeleted(true);
    // On the code before: the reconcile pull's fallback made "Shared login (conflict <date>)", a copy of the very item
    // that came back.
    expect(after.some((m) => m.itemId === copyId), "no copy of the item that came back").toBe(false);
    expect(store.list().filter((i) => i.doc.name.startsWith("Shared login"))).toHaveLength(1);
    // The mark is still cleared: our value is put again over the restored row.
    expect(after.filter((m) => m.itemId === s.itemId && m.op === "put").length).toBeGreaterThanOrEqual(2);
    expect(store.notices().filter((x) => x.kind === "item-brought-back")).toHaveLength(1);
  });

  it("a conflict answer that omits the displaced item (serverItemOmitted) takes it from the item's history (spec 03 §5)", async () => {
    const s = await scenario("writer");
    const api = new FakeApi();
    const store = s.storeFor(api.asClient());
    api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [s.item], removedGrants: [] });
    await store.sync();
    const losingDoc: ItemDoc = { type: "login", name: "Shared login", login: { username: "fam", password: "THEIRS-archived" } };
    // The server archived the displaced version (rev 6) when ours (rev 10) replaced it; one archived after a later edit
    // (rev 11) and an older one (rev 3) must not be taken.
    api.itemVersionsById.set(s.itemId, [
      { rev: 11, blob: s.owner.encryptItem(s.vaultId, s.itemId, { ...losingDoc, name: "later" }).blob!, formatVersion: s.item.formatVersion, archivedAt: 3 },
      { rev: 6, blob: s.owner.encryptItem(s.vaultId, s.itemId, losingDoc).blob!, formatVersion: s.item.formatVersion, archivedAt: 2 },
      { rev: 3, blob: s.owner.encryptItem(s.vaultId, s.itemId, { ...losingDoc, name: "old" }).blob!, formatVersion: s.item.formatVersion, archivedAt: 1 },
    ]);
    const realPush = api.pushMutations.bind(api);
    let omitOnce = true;
    api.pushMutations = async (mutations: Mutation[]) => {
      const resp = await realPush(mutations);
      if (!omitOnce) return resp;
      omitOnce = false;
      return { ...resp, results: resp.results.map((r) => ({ mutationId: r.mutationId, status: "conflict" as const, newItemRev: 10, serverItemOmitted: true })) };
    };
    const pushesBefore = api.pushes.length;
    await store.save(s.itemId, { type: "login", name: "Shared login", login: { username: "fam", password: "OURS" } }, [], undefined, s.vaultId);
    const copyId = await conflictCopyId(s.itemId, 10);
    const copyMut = api.pushes.slice(pushesBefore).flat().find((m) => m.itemId === copyId);
    expect(copyMut, "the copy is materialized from the archived displaced version").toBeTruthy();
    const copyDoc = s.member.decryptItem({ ...s.item, itemId: copyId, formatVersion: copyMut!.item!.formatVersion, blob: copyMut!.item!.blob }) as ItemDoc & { login: { password: string } };
    expect(copyDoc.login.password).toBe("THEIRS-archived");
    expect(copyDoc.name).toMatch(/^Shared login \(conflict /);
  });

  it("a losing delete (edit-beats-delete) does NOT materialize a spurious copy (PDD-1)", async () => {
    const s = await scenario("writer");
    const api = new FakeApi();
    const store = s.storeFor(api.asClient());
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
    const store = s.storeFor(api.asClient());
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
    await store.save(s.itemId, versions[1]!.doc, [], undefined, s.vaultId);
    expect(api.pushes.length).toBeGreaterThan(pushesBefore);
    expect(store.get(s.itemId)?.doc.login?.password).toBe("old-1");
  });

  it("deletedItems names each tombstone from its last version; restoreDeleted re-encrypts + restores (undelete)", async () => {
    const s = await scenario("writer");
    const api = new FakeApi();
    const store = s.storeFor(api.asClient());
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

    // Spec 03 §5.1: a row of a vault this account holds no key for (not adopted yet, or another account's) is left out,
    // never shown as an unnamed item, and nothing is fetched for it.
    const unread = crypto.randomUUID();
    const unreadItem = crypto.randomUUID();
    api.deletedList = [...api.deletedList, { itemId: unreadItem, vaultId: unread, deletedAt: 1_680_000_000_000 }];
    const asked: string[] = [];
    const versions = api.itemVersions.bind(api);
    api.itemVersions = async (id: string) => (asked.push(id), versions(id));

    const trash = await store.deletedItems();
    expect(trash).toHaveLength(1);
    expect(trash[0]!.doc?.name).toBe("Deleted Netflix"); // named from its last archived version
    expect(asked).toEqual([s.itemId]);

    await store.restoreDeleted(s.itemId, s.vaultId, trash[0]!.doc!);
    expect(api.restored.map((r) => r.itemId)).toEqual([s.itemId]);
    expect(api.restored[0]!.upload.blob.length).toBeGreaterThan(0); // re-encrypted content POSTed
    expect(api.restored[0]!.upload.attachmentIds).toEqual([]); // attachment ref dropped — its blob is gone
    expect(await store.deletedItems()).toHaveLength(0); // restored item leaves the trash
  });

  it("purges the vault's items and forgets key + role on a removal the log explains", async () => {
    const s = await scenario();
    const api = new FakeApi();
    const store = s.storeFor(api.asClient());
    api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [s.item], removedGrants: [] });
    await store.sync();
    expect(store.get(s.itemId)).toBeDefined();

    s.memberLogs.remove(s.vaultId);
    api.queue.push({ rev: 6, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId] });
    await store.sync();

    expect(store.get(s.itemId)).toBeUndefined();
    expect(store.list().some((i) => i.vaultId === s.vaultId)).toBe(false);
    expect(s.member.hasVault(s.vaultId)).toBe(false);
    expect(s.member.roleFor(s.vaultId)).toBeNull();
    expect(store.vaults().some((v) => v.vaultId === s.vaultId)).toBe(false);
  });

  it("a removal's banner is the verified log's: removed, left, an anomaly, or none while the log still lists us", async () => {
    const cases: { say: (s: Scenario) => void; kind: string | null }[] = [
      { say: (s) => s.memberLogs.remove(s.vaultId, true), kind: "removed" },
      { say: (s) => s.memberLogs.remove(s.vaultId, false), kind: "left" },
      { say: (s) => s.memberLogs.fail(s.vaultId), kind: "anomaly" },
      { say: () => {}, kind: null }, // the server lists a removal; the log still lists the member
    ];
    for (const c of cases) {
      const s = await scenario();
      const api = new FakeApi();
      const store = s.storeFor(api.asClient());
      api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [s.item], removedGrants: [] });
      await store.sync();
      c.say(s);
      // The served reason says "removed" every time: it is a hint, never the verdict.
      api.queue.push({ rev: 6, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId], removedGrantsInfo: [{ vaultId: s.vaultId, reason: "removed" }] });
      await store.sync();
      const kinds = store.notices().filter((n) => n.vaultId === s.vaultId).map((n) => n.kind);
      if (c.kind === null) {
        expect(kinds, "kept").toEqual([]);
        expect(store.get(s.itemId)?.doc).toEqual(DOC);
      } else {
        expect(kinds, c.kind).toEqual([c.kind]);
        expect(store.get(s.itemId), c.kind).toBeUndefined();
        expect(store.heldVaults().map((h) => h.vaultId), c.kind).toEqual([s.vaultId]);
      }
    }
  });

  it("save() keeps an existing item's vaultId and only defaults NEW items to personal", async () => {
    const s = await scenario();
    const api = new FakeApi();
    const store = s.storeFor(api.asClient(), "owner"); // owner holds the VK from creation
    api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [], items: [s.item], removedGrants: [] });
    await store.sync();

    // Editing an item that lives in the shared vault must push to THAT vault,
    // not personalVaultId (defect #0.1 / server vault_mismatch rule).
    await store.save(s.itemId, { ...DOC, name: "renamed" }, [], undefined, s.vaultId);
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
    const store = s.storeFor(api.asClient());
    expect(store.lastSyncAt).toBeNull();

    // A failing pull leaves it untouched…
    const failing = { sync: async () => { throw new Error("offline"); } } as unknown as ApiClient;
    const offlineStore = s.storeFor(failing);
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
    const store = s.storeFor(api.asClient());
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
    const store = s.storeFor(api.asClient());
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
    const store = s.storeFor(api.asClient());
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
    const store = s.storeFor(api.asClient());
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
    s.memberLogs.remove(s.vaultId);
    api.queue.push({ rev: 10, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId] });
    await store.sync();
    expect(store.undecryptable()).toEqual([]);
  });

  it("does not double-count across a 410 resync-from-0", async () => {
    const s = await scenario();
    const api = new FakeApi();
    const store = s.storeFor(api.asClient());
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
    const store = s.storeFor(api.asClient());
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
    const store = s.storeFor(api.asClient());
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
    const store = s.storeFor(api.asClient());
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
      const store = s.storeFor(api.asClient());
      api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [s.item], removedGrants: [] });
      await store.sync();

      // The post-push reconcile pull will be REJECTED by the F31 rev-regression guard.
      api.queue.push({ rev: 3, full: false, vaults: [], grants: [], items: [], removedGrants: [] });
      await expect(store.save(s.itemId, { ...DOC, name: "renamed" }, [], undefined, s.vaultId)).resolves.toBeUndefined();

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
      const store = s.storeFor(api.asClient());
      api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [s.item], removedGrants: [] });
      await store.sync();

      api.sync = async () => {
        throw new TypeError("offline");
      };
      await expect(store.save(s.itemId, { ...DOC, name: "renamed offline" }, [], undefined, s.vaultId)).resolves.toBeUndefined();
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
    const store = s.storeFor(api.asClient());

    // Fresh-device pull (since=0, full snapshot): the grant is delivered but this is the device's
    // FIRST sight of everything — the hazard says notices fire only for verifiable NEW state, so
    // no "added" notice may fire here.
    api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [s.item], removedGrants: [] });
    await store.sync();
    expect(store.notices().some((n) => n.kind === "added")).toBe(false);

    // A SECOND shared vault lists the member in its log, delivered on a later DELTA pull → exactly one "added" notice.
    const v2 = crypto.randomUUID();
    const vk2 = randomBytes(32);
    s.memberLogs.share(v2, vk2, "writer");
    const vault2 = vaultRow(v2, vk2, "Work", 6);
    const grant2: WireGrant = { vaultId: v2, userId: s.member.userId, role: "writer", wrappedVk: "", rev: 7 };
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
   * vault on a delta pull (its key not yet held here, so `heldBefore` is false). "You were added to
   * Work" would misattribute the account's own creation to someone else sharing with it. A vault
   * whose log names this account its owner never emits the notice.
   */
  it("never fires an 'added' notice for a vault this account owns (the owner's second device)", async () => {
    const s = await scenario();
    const api = new FakeApi();
    const store = s.storeFor(api.asClient(), "owner"); // the OWNER's second device

    api.queue.push({ rev: 5, full: true, vaults: [], grants: [], items: [], removedGrants: [] });
    await store.sync(); // establishes a cursor, so the next pull is a genuine delta (since > 0)

    // Device A creates "Work"; device B has never held its key. Its log names this account the owner.
    const v2 = crypto.randomUUID();
    const vk2 = randomBytes(32);
    s.ownerLogs.share(v2, vk2, "owner");
    const vault2 = vaultRow(v2, vk2, "Work", 6);
    const ownerGrant2: WireGrant = { vaultId: v2, userId: s.owner.userId, role: "owner", wrappedVk: "", rev: 7 };
    api.queue.push({ rev: 7, full: false, vaults: [vault2], grants: [ownerGrant2], items: [], removedGrants: [] });
    await store.sync();

    expect(store.vaults().some((v) => v.vaultId === v2)).toBe(true); // the vault DID arrive & open
    expect(s.owner.roleFor(v2)).toBe("owner");
    expect(store.notices().filter((n) => n.kind === "added")).toHaveLength(0); // ...silently
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
    const store = s.storeFor(api.asClient());
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

describe("VaultStore shared keys come from the log alone (design §3.6, §15)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a key the log adopts after its items arrived makes them readable at the next pull, with nothing re-sent", async () => {
    const s = await scenario("writer");
    const memberLogs = new FakeSharedLogs(s.member);
    memberLogs.pend(s.vaultId, s.vk, "writer"); // an open ask: the log lists the member, nothing adopted yet
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), s.member, undefined, undefined, api.asWire());
    memberLogs.attachTo(store);
    api.queue.push({ rev: 5, full: true, vaults: [s.vault], grants: [s.grant], items: [s.item], removedGrants: [] });
    await store.sync();
    expect(store.get(s.itemId)).toBeUndefined();
    expect(store.undecryptable().map((u) => u.itemId)).toEqual([s.itemId]); // enumerated, waiting for the key

    memberLogs.decide(s.vaultId); // the person accepted
    api.queue.push(emptySync(6)); // a delta: the vault row and the item are not re-sent
    await store.sync();
    expect(s.member.hasVault(s.vaultId)).toBe(true);
    expect(store.get(s.itemId)?.doc).toEqual(DOC);
    expect(store.undecryptable()).toEqual([]);
  });

  it("a store with no log layer opens no shared grant row, not even one sealed to this account", async () => {
    const owner = await enroll("owner@example.com");
    const member = await enroll("member@example.com");
    const { request, vaultId } = vaultMadeBy(owner, "Family");
    // A grant frame sealed to this account (the old code opened such a row for its key).
    const signedGrant = toB64(sealTo(member.identityPub, randomBytes(96)));
    const grant: WireGrant = { vaultId, userId: member.userId, role: "writer", wrappedVk: "", rev: 3, signedGrant };
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), member, undefined, undefined, api.asWire()); // no log layer attached
    const addGrant = vi.spyOn(member, "addGrant");
    api.queue.push({ rev: 5, full: true, vaults: [{ vaultId, type: "shared", rev: 2, metaBlob: request.metaBlob, createdAt: 0 }], grants: [grant], items: [], removedGrants: [] });
    await store.sync();
    await store.sync();
    expect(addGrant.mock.calls.map(([g]) => g.vaultId).filter((id) => id !== member.personalVaultId)).toEqual([]);
    expect(member.hasVault(vaultId)).toBe(false);
  });

  it("a store opened without an item wire refuses every item route, and the transport is never asked for one", async () => {
    const s = await scenario("writer");
    const api = new FakeApi(); // it answers sync and push, but only as an ItemWire
    const store = new VaultStore(api.asClient(), s.member);
    await expect(store.sync()).rejects.toThrow(/no item wire/);
    await expect(store.itemVersions(s.itemId, s.vaultId)).rejects.toThrow(/no item wire/);
    await expect(store.deletedItems()).rejects.toThrow(/no item wire/);
    expect(api.sinceLog).toEqual([]);
    expect(api.pushes).toEqual([]);
  });
});
