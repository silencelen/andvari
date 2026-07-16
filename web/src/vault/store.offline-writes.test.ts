import "fake-indexeddb/auto";
import { IDBFactory as FakeIDBFactory } from "fake-indexeddb";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, type ApiClient } from "../api/client";
import type { ItemDoc, Mutation, PushResponse, SyncResponse, WireGrant, WireItem, WireVault } from "../api/types";
import type { AccountKeys } from "../api/types";
import { toB64 } from "../crypto/bytes";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { deleteProof } from "../crypto/lifecycleproof";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";
import { IdbVaultCache, openVaultCache } from "./idbcache";
import { VaultStore } from "./store";

/**
 * S4 suite (design 2026-07-13-web-offline-cache §D.3): durable offline WRITES — the queue,
 * the persist-gate (breaker #1), denial unification + the epoch guard (breaker #3), the
 * sign-out-with-queue count (breaker #9), parked-mutation durability across a restart +
 * reinstate replay, the S2 no-double-load-after-hydrate note, and the attachments-refuse-to-
 * queue scope guard. Drives a REAL IdbVaultCache over fake-indexeddb with the REAL Account
 * crypto and an honest strict-delta fake server (each row delivered once), extended with an
 * OFFLINE switch, per-vault DENY, and a one-shot pull GATE for the epoch case.
 */

const g = globalThis as { indexedDB?: IDBFactory };
const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };
const DOC: ItemDoc = { type: "login", name: "Shared login", login: { username: "fam", password: "hunter2" } };

class FakeApi {
  queue: SyncResponse[] = [];
  pushes: Mutation[][] = [];
  sinceLog: number[] = [];
  uploads: string[] = [];
  rev = 1;
  /** api.push / api.sync / api.uploadAttachment all reject as a transport failure while true. */
  offline = false;
  /** api.push ALONE rejects as a transport failure while true (sync stays up) — the C1
   *  reinstate case needs a pull that succeeds while its post-commit replay flush dies. */
  failPushes = false;
  /** a push mutation whose vaultId is here comes back `denied` (a reader / an in-grace vault). */
  denyVaults = new Set<string>();
  /** Gate the NEXT api.sync (pull): it parks at the gate until releaseSync(), and `gated`
   *  resolves the instant it is reached — so a test knows the pull is IN FLIGHT (flush done,
   *  pull-start counter already bumped). */
  gateNextSync = false;
  private release: (() => void) | null = null;
  private reached: (() => void) | null = null;
  gated = new Promise<void>((r) => (this.reached = r));
  releaseSync(): void {
    const r = this.release;
    this.release = null;
    r?.();
  }

  private vaultRows = new Map<string, WireVault>();
  private grantRows = new Map<string, WireGrant>();
  private itemRows = new Map<string, WireItem>();
  private static newest<T extends { rev: number }>(map: Map<string, T>, key: string, row: T): void {
    const cur = map.get(key);
    if (!cur || row.rev >= cur.rev) map.set(key, row);
  }

  async sync(since: number): Promise<SyncResponse> {
    if (this.offline) throw new TypeError("offline");
    this.sinceLog.push(since);
    if (this.gateNextSync) {
      this.gateNextSync = false;
      this.reached?.(); // the pull reached the gate: its flush finished + counter bumped
      await new Promise<void>((res) => (this.release = res));
    }
    const canned = this.queue.shift();
    if (canned) {
      this.rev = Math.max(this.rev, canned.rev);
      for (const v of canned.vaults) FakeApi.newest(this.vaultRows, v.vaultId, v);
      for (const gr of canned.grants) FakeApi.newest(this.grantRows, gr.vaultId, gr);
      for (const i of canned.items) FakeApi.newest(this.itemRows, i.itemId, i);
      return {
        ...canned,
        vaults: canned.vaults.filter((v) => v.rev > since),
        grants: canned.grants.filter((gr) => gr.rev > since),
        items: canned.items.filter((i) => i.rev > since),
      };
    }
    return {
      rev: this.rev,
      full: since === 0,
      vaults: [...this.vaultRows.values()].filter((v) => v.rev > since),
      grants: [...this.grantRows.values()].filter((gr) => gr.rev > since),
      items: [...this.itemRows.values()].filter((i) => i.rev > since),
      removedGrants: [],
    };
  }

  async push(mutations: Mutation[]): Promise<PushResponse> {
    if (this.offline || this.failPushes) throw new TypeError("offline");
    this.pushes.push(mutations);
    return {
      rev: ++this.rev,
      results: mutations.map((m) =>
        this.denyVaults.has(m.vaultId)
          ? { mutationId: m.mutationId, status: "denied" as const }
          : { mutationId: m.mutationId, status: "applied" as const, newItemRev: 1 },
      ),
    };
  }

  async uploadAttachment(): Promise<void> {
    if (this.offline) throw new TypeError("offline");
    this.uploads.push("ok");
  }

  asClient(): ApiClient {
    return this as unknown as ApiClient;
  }
}

interface Enrolled {
  account: Account;
  password: string;
  keys: AccountKeys;
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

async function seeded(role = "writer") {
  const s = await scenario(role);
  const cache = (await openVaultCache(s.member.account.userId)) as IdbVaultCache;
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

/** Stub navigator so offlineQueueAllowed() reads a known persistence verdict (and no Web
 *  Locks, so cache commits run unlocked — fine for these single-tab tests). */
function stubPersisted(value: boolean): void {
  vi.stubGlobal("navigator", { storage: { persisted: async () => value } });
}

/** Tick the event loop until `p()` is truthy (bounded) — for the gated epoch case. */
async function waitFor(p: () => Promise<boolean> | boolean, tries = 50): Promise<void> {
  for (let i = 0; i < tries; i++) {
    if (await p()) return;
    await new Promise((r) => setTimeout(r, 1));
  }
  throw new Error("waitFor timed out");
}

describe("VaultStore durable offline writes (S4, design §D.3)", () => {
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(() => {
    g.indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // ---- breaker #1 persist-gate + the queued convergence ----

  it("offline save with persistence GRANTED queues, then a reconnect flush converges on the SAME mutationId (D4)", async () => {
    const { api, cache, store } = await seeded("writer");
    stubPersisted(true);
    api.offline = true;

    // The Editor sees SUCCESS, not "nothing was changed" — the save resolves, queued.
    await expect(store.save(null, { type: "note", name: "made offline" })).resolves.toBeUndefined();
    const queued = await cache.pending();
    expect(queued).toHaveLength(1);
    const savedId = queued[0]!.itemId;
    const mutId = queued[0]!.mutationId;
    expect(store.get(savedId)?.doc.name).toBe("made offline"); // optimistic apply — the item renders
    expect(store.hasPendingSync(savedId)).toBe(true); // pending-sync affordance
    expect(api.pushes).toHaveLength(0); // nothing sent while offline
    // The optimistic envelope is on disk, so a restart would still show the queued edit.
    expect((await cache.envelopes()).some((r) => r.itemId === savedId)).toBe(true);

    // Reconnect: the flush sends the queued mutation with the SAME id (server dedup = idempotent).
    api.offline = false;
    await store.sync();
    expect(api.pushes.flat().map((m) => m.mutationId)).toContain(mutId); // SAME mutationId
    expect(await cache.pending()).toHaveLength(0); // flushed
    expect(store.hasPendingSync(savedId)).toBe(false); // no longer awaiting a first flush
    expect(store.get(savedId)?.doc.name).toBe("made offline"); // still present, now committed
  });

  it("offline save with persistence DENIED throws — no QUEUED return, the item reverts (breaker #1)", async () => {
    const { api, cache, store } = await seeded("writer");
    stubPersisted(false); // an evicted queue would be unrecoverable — refuse, don't degrade
    api.offline = true;

    await expect(store.save(null, { type: "note", name: "no queue" })).rejects.toThrow();
    expect(await cache.pending()).toHaveLength(0); // the row was dropped (refuse-not-degrade)
    expect(store.list().some((i) => i.doc.name === "no queue")).toBe(false); // optimistic apply reverted
  });

  it("an EXISTING-item offline edit reverts to its pre-edit value when persistence is denied", async () => {
    const { s, api, cache, store } = await seeded("writer");
    stubPersisted(false);
    api.offline = true;
    await expect(store.save(s.itemId, { ...DOC, name: "renamed offline" })).rejects.toThrow();
    expect(store.get(s.itemId)?.doc.name).toBe(DOC.name); // pre-edit value restored
    expect(await cache.pending()).toHaveLength(0);
  });

  // ---- CR-01: in-session cache close must never black-hole a write (breaker-level) ----

  it("a force-closed cache mid-session does the REAL send while ONLINE — never a silent black hole (CR-01)", async () => {
    const { api, cache, store } = await seeded("writer");
    stubPersisted(true); // the durable-queue path is armed — exactly when the black hole opens
    // Force-close the LIVE handle mid-session (a sibling-tab wipe / browser eviction: durable stays
    // true, every write no-ops §D.2a). Programmatic close does NOT fire onClosed, so the store still
    // sees durable=true — the precise CR-01 precondition where enqueue would black-hole yet succeed.
    cache.close();
    expect(store.cacheDurable).toBe(true);

    await expect(store.save(null, { type: "note", name: "post-close online" })).resolves.toBeUndefined();
    // The write actually reached the server via the direct flushChunk fallback — not a black hole.
    expect(api.pushes.flat().some((m) => m.op === "put")).toBe(true);
    expect(store.list().some((i) => i.doc.name === "post-close online")).toBe(true);
    // …and the store demoted off the dead handle, so subsequent writes route correctly too.
    expect(store.cacheDurable).toBe(false);
  });

  it("a force-closed cache mid-session while OFFLINE refuses (throws) — never a silent success (CR-01)", async () => {
    const { api, cache, store } = await seeded("writer");
    stubPersisted(true);
    cache.close();
    api.offline = true; // the direct send transport-fails; with no durable queue it must REFUSE

    await expect(store.save(null, { type: "note", name: "post-close offline" })).rejects.toThrow();
    expect(store.list().some((i) => i.doc.name === "post-close offline")).toBe(false); // optimistic apply reverted
    expect(await cache.pending()).toHaveLength(0); // nothing durably queued into the dead handle
    expect(store.cacheDurable).toBe(false); // demoted
  });

  it("remove() with a force-closed cache does the REAL delete online — never a silent black hole (CR-01)", async () => {
    const { s, api, cache, store } = await seeded("writer");
    stubPersisted(true);
    cache.close();

    await expect(store.remove(s.itemId)).resolves.toBeUndefined();
    expect(api.pushes.flat().some((m) => m.op === "delete")).toBe(true); // the delete really shipped
    expect(store.get(s.itemId)).toBeUndefined(); // stays removed (it is gone server-side)
    expect(store.cacheDurable).toBe(false);
  });

  // ---- breaker #3 epoch guard ----

  it("a denial staged while an earlier pull is IN FLIGHT is NOT classified by that pull — only by one that STARTED after it (breaker #3)", async () => {
    const { s, api, cache, store } = await seeded("reader"); // a reader's edit is genuinely denied
    stubPersisted(true);
    api.denyVaults.add(s.vaultId);

    // Cycle X: its flush finds nothing, then its pull STARTS (counter → 1) and parks at the gate.
    api.gateNextSync = true;
    const pollP = store.sync().then(() => "ok", (e) => e);
    await api.gated; // X's pull is in flight — flush done, pull-start counter bumped to 1

    // Stage a reader denial NOW, while X's pull is still in flight: cycle Y's flush pushes the
    // just-enqueued row → denied → staged with stagedBefore = 1 (X's start-id); Y's pull JOINS X.
    const m: Mutation = {
      mutationId: "m-epoch",
      op: "put",
      itemId: s.itemId,
      vaultId: s.vaultId,
      baseItemRev: 4,
      item: { formatVersion: 1, attachmentIds: [], blob: s.item.blob! },
    };
    await cache.enqueue(m);
    const syncYP = store.sync().then(() => "ok", (e) => e);
    await waitFor(async () => (await cache.stagedDenied()).length === 1); // Y's flush staged it

    // Release X. X (start-id 1) COMPLETES — but 1 is NOT > stagedBefore 1, so surface DECLINES:
    // the denial must not be classified off a snapshot that predates it.
    api.releaseSync();
    expect(await pollP).toBe("ok"); // X's surface did not throw — it declined the too-fresh entry
    expect(await syncYP).toBe("ok"); // Y (joined X) likewise declined
    expect((await cache.stagedDenied()).map((x) => x.mutationId)).toEqual(["m-epoch"]); // STILL staged

    // A fresh pull (start-id 2 > 1) is finally allowed to classify it — genuine → thrown.
    await expect(store.sync()).rejects.toMatchObject({ code: "denied" });
    expect(await cache.stagedDenied()).toEqual([]); // now durably dropped
  });

  // ---- breaker #9 sign-out-with-queue count ----

  it("queuedMutationCount counts BOTH pending and staged-denied rows (breaker #9 sign-out count)", async () => {
    const { api, cache, store } = await seeded("writer");
    stubPersisted(true);
    // Two queued offline edits.
    api.offline = true;
    await store.save(null, { type: "note", name: "a" });
    await store.save(null, { type: "note", name: "b" });
    expect(await store.queuedMutationCount()).toBe(2);

    // A staged-denied row also counts — the wipe destroys the whole queue.
    await cache.enqueue({ mutationId: "m-x", op: "put", itemId: "ix", vaultId: "vx", baseItemRev: 0 });
    await cache.markStagedDenied("m-x");
    expect(await store.queuedMutationCount()).toBe(3);
  });

  // ---- scope guard: attachments are online-only ----

  it("a save carrying newFiles refuses to queue offline — push-or-throw even WITH persistence granted", async () => {
    const { api, cache, store } = await seeded("writer");
    stubPersisted(true); // persistence granted, yet an attachment save still must not queue
    api.offline = true;
    const fileId = crypto.randomUUID();
    const doc: ItemDoc = {
      type: "login",
      name: "with attach",
      login: { username: "u", password: "p" },
      attachments: [{ id: fileId, name: "f", size: 3, fileKey: toB64(randomBytes(32)) }],
    };
    await expect(store.save(null, doc, [{ id: fileId, data: new Uint8Array([1, 2, 3]) }])).rejects.toThrow();
    expect(await cache.pending()).toHaveLength(0); // the upload threw BEFORE the mutation was enqueued
    expect(api.pushes).toHaveLength(0);
  });

  // ---- F21 parked durability across a restart + reinstate replay ----

  it("a denied edit whose vault went in-grace is PARKED, survives a restart, and replays on reinstate (F21)", async () => {
    const { s, api, cache, store } = await seeded("writer");
    stubPersisted(true);
    api.denyVaults.add(s.vaultId); // the vault went in-grace server-side → the edit is denied

    // The reconcile pull will deliver the vault's verified delete in the SAME cycle.
    const key = await s.owner.account.lifecycleKeyFor(s.vaultId);
    const deleteId = crypto.randomUUID();
    api.queue.push({
      rev: 6,
      full: false,
      vaults: [],
      grants: [],
      items: [],
      removedGrants: [s.vaultId],
      removedGrantsInfo: [{ vaultId: s.vaultId, reason: "deleted", deleteId, deleteProof: await deleteProof(key, s.vaultId, deleteId), purgeAt: Date.now() + 7 * 86_400_000 }],
    });

    // The edit is denied (flush) then PARKED (the same cycle's pull moves the vault to holding)
    // — never surfaced as a hard failure.
    await expect(store.save(s.itemId, { ...DOC, name: "edited before delete" })).resolves.toBeUndefined();
    const held = await cache.getHeld(s.vaultId);
    expect(held?.parked.map((p) => p.itemId)).toEqual([s.itemId]); // parked for restore replay
    expect(await cache.stagedDenied()).toEqual([]); // its queue row dropped in the SAME tx (no double-load)

    // Restart: the holding record + its parked mutation survive.
    const fresh = await relock(s.member);
    const api2 = new FakeApi();
    const cache2 = (await openVaultCache(fresh.userId)) as IdbVaultCache;
    const store2 = new VaultStore(api2.asClient(), fresh, cache2);
    await store2.hydrate();
    expect(store2.heldVaults().find((h) => h.vaultId === s.vaultId)?.name).toBe("Family");

    // The owner restores the vault → the grant re-arrives (rev ABOVE the restored cursor, so the
    // strict-delta fake actually delivers it) → reinstate replays the parked edit ONCE.
    api2.queue.push({ rev: 8, full: false, vaults: [{ ...s.vault, rev: 8 }], grants: [{ ...s.grant, rev: 8 }], items: [{ ...s.item, rev: 8 }], removedGrants: [] });
    await store2.sync();
    const replays = api2.pushes.flat().filter((m) => m.itemId === s.itemId && m.op === "put");
    expect(replays).toHaveLength(1); // the parked edit replayed — exactly once (no double-load)
    expect(store2.heldVaults().find((h) => h.vaultId === s.vaultId)).toBeUndefined(); // out of holding
  });

  // ---- S2 note: no double-load after hydrate ----

  it("a parked staged-denial loads exactly ONCE after a restart — held.parked, never also via stagedDenied", async () => {
    const { s, api, cache, store } = await seeded("writer");
    stubPersisted(true);
    api.denyVaults.add(s.vaultId);
    const key = await s.owner.account.lifecycleKeyFor(s.vaultId);
    const deleteId = crypto.randomUUID();
    api.queue.push({
      rev: 6,
      full: false,
      vaults: [],
      grants: [],
      items: [],
      removedGrants: [s.vaultId],
      removedGrantsInfo: [{ vaultId: s.vaultId, reason: "deleted", deleteId, deleteProof: await deleteProof(key, s.vaultId, deleteId), purgeAt: Date.now() + 7 * 86_400_000 }],
    });
    await store.save(s.itemId, { ...DOC, name: "parked edit" });

    // On disk: the mutation lives ONLY in held.parked; the staged queue row was dropped in the
    // fold tx. So hydrate can't reload it into preParkedByVault (the double-load the S2 note warns of).
    expect((await cache.getHeld(s.vaultId))?.parked).toHaveLength(1);
    expect(await cache.stagedDenied()).toEqual([]);
    expect(await cache.pending()).toEqual([]);

    const fresh = await relock(s.member);
    const api2 = new FakeApi();
    const store2 = new VaultStore(api2.asClient(), fresh, (await openVaultCache(fresh.userId)) as IdbVaultCache);
    await store2.hydrate();
    // A plain reconcile (no delete) must NOT surface a spurious duplicate denial from a
    // double-loaded staging — nothing staged means nothing to classify.
    api2.queue.push({ rev: 7, full: false, vaults: [], grants: [], items: [], removedGrants: [] });
    await expect(store2.sync()).resolves.toBeUndefined();
    expect(store2.heldVaults().find((h) => h.vaultId === s.vaultId)?.name).toBe("Family"); // still held, once
  });

  // ---- the genuine online denial still throws (Editor failure UX unchanged) ----

  it("a genuine online denial (a reader edit on a live vault) throws and reverts — Editor failure UX unchanged", async () => {
    const { s, api, store } = await seeded("reader");
    stubPersisted(true);
    api.denyVaults.add(s.vaultId); // a live vault the reader can't write
    await expect(store.save(s.itemId, { ...DOC, name: "reader tried" })).rejects.toMatchObject({ code: "denied" });
    expect(store.get(s.itemId)?.doc.name).toBe(DOC.name); // reverted to the live value
  });

  // ==== converged data-loss review fixes (2026-07-14): C1 reinstate replay, C2 denial
  // revert + notice + epoch-deferral, C3 FIFO send, C4 id-scoped queue drop ====

  /** Queue a VERIFIED owner delete of the shared vault at `rev`; returns its deleteId. */
  async function queueVerifiedDelete(s: Scenario, api: FakeApi, rev: number): Promise<string> {
    const key = await s.owner.account.lifecycleKeyFor(s.vaultId);
    const deleteId = crypto.randomUUID();
    api.queue.push({
      rev,
      full: false,
      vaults: [],
      grants: [],
      items: [],
      removedGrants: [s.vaultId],
      removedGrantsInfo: [
        { vaultId: s.vaultId, reason: "deleted", deleteId, deleteProof: await deleteProof(key, s.vaultId, deleteId), purgeAt: Date.now() + 7 * 86_400_000 },
      ],
    });
    return deleteId;
  }

  /** Queue the vault's reinstate (grant + vault + item re-delivered above the cursor). */
  const queueRestore = (s: Scenario, api: FakeApi, rev: number): void => {
    api.queue.push({ rev, full: false, vaults: [{ ...s.vault, rev }], grants: [{ ...s.grant, rev }], items: [{ ...s.item, rev }], removedGrants: [] });
  };

  it("C1: a reinstate replay whose push FAILS (transport) keeps the parked edit durably queued — it survives a restart and flushes on reconnect", async () => {
    const { s, api, cache, store } = await seeded("writer");
    stubPersisted(true);
    api.denyVaults.add(s.vaultId);
    await queueVerifiedDelete(s, api, 6);
    await store.save(s.itemId, { ...DOC, name: "edited before delete" }); // denied → parked (F21)
    const parkedId = (await cache.getHeld(s.vaultId))!.parked[0]!.mutationId;

    // The owner restores the vault, but the replay PUSH dies on the network (the pull itself
    // succeeds). The retired direct push([m]) replay lost the edit here — memory had already
    // dropped the holding record and disk had removed it in the same commit.
    api.denyVaults.delete(s.vaultId);
    api.failPushes = true;
    queueRestore(s, api, 8);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      await expect(store.sync()).resolves.toBeUndefined(); // offline replay failure ≠ pull failure
    } finally {
      warn.mockRestore();
    }
    expect(store.heldVaults()).toHaveLength(0); // reinstated
    expect(store.notices().some((n) => n.vaultId === s.vaultId && n.kind === "restored")).toBe(true);
    expect((await cache.pending()).map((m) => m.mutationId)).toEqual([parkedId]); // STILL durably queued
    expect(store.hasPendingSync(s.itemId)).toBe(true); // the affordance mark is back

    // Restart: the queued replay survives on disk and flushes on the next reconnect with its
    // ORIGINAL mutationId (server dedup converges).
    const fresh = await relock(s.member);
    const api2 = new FakeApi();
    const cache2 = (await openVaultCache(fresh.userId)) as IdbVaultCache;
    const store2 = new VaultStore(api2.asClient(), fresh, cache2);
    await store2.hydrate();
    expect(store2.hasPendingSync(s.itemId)).toBe(true);
    api2.queue.push({ rev: 9, full: false, vaults: [], grants: [], items: [], removedGrants: [] });
    await store2.sync();
    expect(api2.pushes.flat().map((m) => m.mutationId)).toEqual([parkedId]); // flushed, same id
    expect(await cache2.pending()).toEqual([]);
  });

  it("C1: a reinstate replay that is DENIED again re-parks when the vault is re-deleted — the edit is never lost", async () => {
    const { s, api, cache, store } = await seeded("writer");
    stubPersisted(true);
    api.denyVaults.add(s.vaultId);
    await queueVerifiedDelete(s, api, 6);
    await store.save(s.itemId, { ...DOC, name: "parked edit" });
    const parkedId = (await cache.getHeld(s.vaultId))!.parked[0]!.mutationId;

    // Restore arrives but the vault is ALREADY going back in-grace server-side: the replay
    // push is denied. It must STAGE (durable), not throw and not vanish.
    queueRestore(s, api, 8); // denyVaults still contains the vault
    await expect(store.sync()).resolves.toBeUndefined(); // a replay denial never fails the sync
    expect((await cache.stagedDenied()).map((m) => m.mutationId)).toEqual([parkedId]); // staged, awaiting a fresh verdict
    expect(await cache.pending()).toEqual([]);

    // The second delete lands on the NEXT cycle: the staged replay folds back into the
    // holding record (re-parked, survives the next restore) instead of being dropped.
    await queueVerifiedDelete(s, api, 10);
    await expect(store.sync()).resolves.toBeUndefined();
    const held = await cache.getHeld(s.vaultId);
    expect(held?.parked.map((m) => m.mutationId)).toEqual([parkedId]); // re-parked, not lost
    expect(await cache.stagedDenied()).toEqual([]); // its queue row dropped in the SAME tx
    expect(store.notices().find((n) => n.vaultId === s.vaultId && n.kind === "deleted")?.parkedCount).toBe(1);
  });

  it("C1: a replay denied on a STILL-LIVE vault drains into the calm replay-denied notice — never a thrown sync failure", async () => {
    const { s, api, cache, store } = await seeded("writer");
    stubPersisted(true);
    api.denyVaults.add(s.vaultId);
    await queueVerifiedDelete(s, api, 6);
    await store.save(s.itemId, { ...DOC, name: "parked edit" });

    // Restore arrives; the replay is denied (the member came back as effectively read-only),
    // and the vault STAYS live — the next cycle classifies it as a wasReplay denial.
    queueRestore(s, api, 8);
    await expect(store.sync()).resolves.toBeUndefined(); // replay denied → staged, too fresh to classify
    await expect(store.sync()).resolves.toBeUndefined(); // classified now: CALM notice, no throw
    const notice = store.notices().find((n) => n.vaultId === s.vaultId && n.kind === "replay-denied");
    expect(notice?.parkedCount).toBe(1);
    expect(store.notices().some((n) => n.kind === "write-refused")).toBe(false); // not a first-hand refusal
    expect(await cache.stagedDenied()).toEqual([]); // definitively (and durably) settled
    expect(await store.queuedMutationCount()).toBe(0);
  });

  it("C2: a genuinely-denied offline EDIT reverts to its pre-edit value — memory, a fresh hydrate, and a durable notice", async () => {
    const { s, api, cache, store } = await seeded("writer");
    stubPersisted(true);
    api.offline = true;
    await store.save(s.itemId, { ...DOC, name: "renamed offline" }); // success-as-QUEUED
    expect(store.get(s.itemId)?.doc.name).toBe("renamed offline"); // optimistic apply

    // Reconnect — but the member's write access was revoked while offline (no removedGrants:
    // the vault stays live, the flush is a GENUINE denial). Pre-fix, the refused value stayed
    // in memory + on disk forever (a delta server never re-delivers the unchanged row).
    api.offline = false;
    api.denyVaults.add(s.vaultId);
    await expect(store.sync()).rejects.toMatchObject({ code: "denied" }); // Editor-visible when awaited
    expect(store.get(s.itemId)?.doc.name).toBe(DOC.name); // pre-edit value restored in memory
    expect(store.get(s.itemId)?.rev).toBe(4);
    expect(store.hasPendingSync(s.itemId)).toBe(false);
    const notice = store.notices().find((n) => n.vaultId === s.vaultId && n.kind === "write-refused");
    expect(notice?.parkedCount).toBe(1); // the durable surface — the throw above is often swallowed
    expect(await cache.stagedDenied()).toEqual([]);
    expect(await cache.pending()).toEqual([]);

    // The revert landed on DISK too: a fresh session hydrates the pre-edit value.
    const fresh = await relock(s.member);
    const store2 = new VaultStore(new FakeApi().asClient(), fresh, (await openVaultCache(fresh.userId)) as IdbVaultCache);
    await store2.hydrate();
    expect(store2.get(s.itemId)?.doc.name).toBe(DOC.name);
  });

  it("C2: a genuinely-denied offline DELETE restores the item live — it is still live server-side", async () => {
    const { s, api, cache, store } = await seeded("writer");
    stubPersisted(true);
    api.offline = true;
    await store.remove(s.itemId); // success-as-QUEUED; locally deleted
    expect(store.get(s.itemId)).toBeUndefined();
    expect((await cache.envelopes()).some((r) => r.itemId === s.itemId)).toBe(false);

    api.offline = false;
    api.denyVaults.add(s.vaultId); // the flush of the queued delete is genuinely denied
    await expect(store.sync()).rejects.toMatchObject({ code: "denied" });
    expect(store.get(s.itemId)?.doc.name).toBe(DOC.name); // restored to the live view
    expect(store.notices().find((n) => n.vaultId === s.vaultId && n.kind === "write-refused")?.parkedCount).toBe(1);

    // And on disk: a fresh hydrate still shows the item.
    const fresh = await relock(s.member);
    const store2 = new VaultStore(new FakeApi().asClient(), fresh, (await openVaultCache(fresh.userId)) as IdbVaultCache);
    await store2.hydrate();
    expect(store2.get(s.itemId)?.doc.name).toBe(DOC.name);
  });

  it("C2: the epoch-DEFERRAL case — a save whose reconcile joined a stale pull does NOT return success for a denied write", async () => {
    const { s, api, cache, store } = await seeded("reader");
    stubPersisted(true);
    api.denyVaults.add(s.vaultId);

    // Cycle X's pull STARTS (counter → 2) and parks at the gate — a stale snapshot in flight.
    api.gateNextSync = true;
    const pollP = store.sync().then(() => "ok", (e) => e);
    await api.gated;

    // The save's own flush stages its denial with stagedBefore = 2 (X's start); its reconcile
    // sync JOINS X, whose completion is NOT fresh enough to classify (2 > 2 is false).
    // Pre-fix, save() returned SUCCESS here for a denied write. Post-fix it runs ONE more
    // cycle, whose fresh pull classifies the denial: revert + notice + thrown `denied`.
    const saveP = store.save(s.itemId, { ...DOC, name: "denied mid-flight" }).then(() => "ok", (e) => e);
    await waitFor(async () => (await cache.stagedDenied()).length === 1);
    api.releaseSync();
    expect(await pollP).toBe("ok"); // X itself declines the too-fresh entry

    const res = await saveP;
    expect(res).toBeInstanceOf(ApiError);
    expect((res as ApiError).code).toBe("denied"); // NOT a silent success
    expect(store.get(s.itemId)?.doc.name).toBe(DOC.name); // and the optimistic apply reverted
    expect(store.notices().find((n) => n.vaultId === s.vaultId && n.kind === "write-refused")?.parkedCount).toBe(1);
    expect(await cache.stagedDenied()).toEqual([]);
  });

  it("C3: an offline backlog e1,e2 then an online save e3 of the same item flushes in FIFO order — one drain, e3 last (the live value)", async () => {
    const { s, api, cache, store } = await seeded("writer");
    stubPersisted(true);
    api.offline = true;
    await store.save(s.itemId, { ...DOC, name: "draft 1" });
    const e1 = (await cache.pending())[0]!.mutationId;
    await store.save(s.itemId, { ...DOC, name: "draft 2" });
    const e2 = (await cache.pending())[1]!.mutationId;
    expect(api.pushes).toHaveLength(0); // nothing sent while offline

    // Online save e3 of the SAME item: the send must ride the queue drain — e1, e2 flush
    // BEFORE e3, so LWW leaves e3 (the user's NEWEST edit) as the live value instead of
    // enthroning a stale draft and demoting e3 to a conflict copy (the pre-fix direct send).
    api.offline = false;
    await store.save(s.itemId, { ...DOC, name: "final" });
    expect(api.pushes[0]!.map((m) => m.mutationId)).toEqual([e1, e2, expect.any(String)]); // ONE FIFO batch
    expect(api.pushes[0]![2]!.mutationId).not.toBe(e1);
    expect(store.get(s.itemId)?.doc.name).toBe("final"); // the newest edit is the live value
    expect(store.list().some((i) => i.doc.name.includes("(conflict"))).toBe(false); // no spurious copy
    expect(await cache.pending()).toEqual([]);
  });

  it("C4: a row staged after moveToHolding's fold-read but before the commit is NOT collaterally erased", async () => {
    const { s, api, cache, store } = await seeded("writer");
    stubPersisted(true);
    api.denyVaults.add(s.vaultId);
    await queueVerifiedDelete(s, api, 6);

    // Interleave a concurrent enqueue for the SAME vault between the pull's in-memory apply
    // (fold-read) and its disk commit — exactly the window the vault-wide dropPending erased.
    const lateM: Mutation = {
      mutationId: "m-late",
      op: "put",
      itemId: "late-item",
      vaultId: s.vaultId,
      baseItemRev: 0,
      item: { formatVersion: 1, attachmentIds: [], blob: s.item.blob! },
    };
    const realApply = cache.applyPull.bind(cache);
    vi.spyOn(cache, "applyPull").mockImplementationOnce(async (fn) => {
      await cache.enqueue(lateM); // lands before the commit tx runs
      return realApply(fn);
    });

    await store.save(s.itemId, { ...DOC, name: "parked edit" }); // denied → folded → held (F21)
    const held = await cache.getHeld(s.vaultId);
    expect(held?.parked.map((m) => m.itemId)).toEqual([s.itemId]); // only the folded edit parked
    expect(await cache.stagedDenied()).toEqual([]); // the folded row's dequeue rode the tx (id-scoped)
    expect((await cache.pending()).map((m) => m.mutationId)).toEqual(["m-late"]); // the late row SURVIVES
  });

  // ==== re-review residuals (2026-07-14): M1 tombstone-vs-denied-delete, M2 durable
  // pre-edit snapshots across a restart, and the M3 notice-honesty counts ====

  it("M1: a denied offline DELETE racing a server tombstone for the SAME item stays deleted — never resurrected", async () => {
    const { s, api, cache, store } = await seeded("writer");
    stubPersisted(true);
    api.offline = true;
    await store.remove(s.itemId); // success-as-QUEUED; locally deleted (memory + disk)
    expect(store.get(s.itemId)).toBeUndefined();

    // Reconnect: the flush is genuinely denied AND the classifying pull delivers another
    // member's ACCEPTED delete of the very same item (a tombstone). Pre-fix, the C2 revert
    // restored the pre-delete snapshot — resurrecting a credential the server deleted, and
    // the delta server never re-delivers a rev-passed tombstone, so it showed live forever.
    api.offline = false;
    api.denyVaults.add(s.vaultId);
    api.queue.push({
      rev: 6,
      full: false,
      vaults: [],
      grants: [],
      items: [{ ...s.item, rev: 6, deleted: true, blob: null }],
      removedGrants: [],
    });
    await expect(store.sync()).rejects.toMatchObject({ code: "denied" });
    expect(store.get(s.itemId)).toBeUndefined(); // NOT resurrected in memory
    expect((await cache.envelopes()).some((r) => r.itemId === s.itemId)).toBe(false); // nor on disk
    const notice = store.notices().find((n) => n.vaultId === s.vaultId && n.kind === "write-refused");
    expect(notice?.parkedCount).toBe(1); // the durable notice still fires
    expect(notice?.removedCount).toBe(1); // and reports the server-side delete (M3) …
    expect(notice?.revertedCount).toBe(0); // … never a restore that didn't happen
    expect(await cache.stagedDenied()).toEqual([]); // the snapshot was dropped with its row

    // A fresh session agrees: the item is gone.
    const fresh = await relock(s.member);
    const store2 = new VaultStore(new FakeApi().asClient(), fresh, (await openVaultCache(fresh.userId)) as IdbVaultCache);
    await store2.hydrate();
    expect(store2.get(s.itemId)).toBeUndefined();
  });

  it("M2: an offline EDIT denied only AFTER a restart still reverts — the durable snapshot rides the queue row", async () => {
    const { s, api, store } = await seeded("writer");
    stubPersisted(true);
    api.offline = true;
    await store.save(s.itemId, { ...DOC, name: "renamed offline" }); // success-as-QUEUED
    expect(store.get(s.itemId)?.doc.name).toBe("renamed offline");

    // Close the browser: a NEW store hydrates from disk — the in-memory C2 snapshot is gone,
    // but its durable twin rides the queue row. Pre-fix, this ORDINARY flow (edit offline →
    // close → reopen → reconnect → denied) left the refused value on display indefinitely.
    const fresh = await relock(s.member);
    const api2 = new FakeApi();
    const cache2 = (await openVaultCache(fresh.userId)) as IdbVaultCache;
    const store2 = new VaultStore(api2.asClient(), fresh, cache2);
    await store2.hydrate();
    expect(store2.get(s.itemId)?.doc.name).toBe("renamed offline"); // optimistic value survived the restart

    // Reconnect: write access was revoked meanwhile — the flush is a GENUINE denial.
    api2.denyVaults.add(s.vaultId);
    api2.queue.push({ rev: 6, full: false, vaults: [], grants: [], items: [], removedGrants: [] });
    await expect(store2.sync()).rejects.toMatchObject({ code: "denied" });
    expect(store2.get(s.itemId)?.doc.name).toBe(DOC.name); // REVERTED to the pre-edit value
    expect(store2.get(s.itemId)?.rev).toBe(4);
    const notice = store2.notices().find((n) => n.vaultId === s.vaultId && n.kind === "write-refused");
    expect(notice?.parkedCount).toBe(1);
    expect(notice?.revertedCount).toBe(1); // the copy may honestly claim the restore (M3)
    expect(await cache2.pending()).toEqual([]);
    expect(await cache2.stagedDenied()).toEqual([]);

    // The revert landed on DISK too: a SECOND fresh hydrate shows the pre-edit value.
    const fresh2 = await relock(s.member);
    const store3 = new VaultStore(new FakeApi().asClient(), fresh2, (await openVaultCache(fresh2.userId)) as IdbVaultCache);
    await store3.hydrate();
    expect(store3.get(s.itemId)?.doc.name).toBe(DOC.name);
  });

  it("M2: an offline DELETE denied only AFTER a restart still restores the item live", async () => {
    const { s, api, store } = await seeded("writer");
    stubPersisted(true);
    api.offline = true;
    await store.remove(s.itemId); // success-as-QUEUED; locally deleted (memory + disk)
    expect(store.get(s.itemId)).toBeUndefined();

    const fresh = await relock(s.member);
    const api2 = new FakeApi();
    const store2 = new VaultStore(api2.asClient(), fresh, (await openVaultCache(fresh.userId)) as IdbVaultCache);
    await store2.hydrate();
    expect(store2.get(s.itemId)).toBeUndefined(); // still deleted after the restart

    api2.denyVaults.add(s.vaultId); // genuinely denied — the item is still live server-side
    api2.queue.push({ rev: 6, full: false, vaults: [], grants: [], items: [], removedGrants: [] });
    await expect(store2.sync()).rejects.toMatchObject({ code: "denied" });
    expect(store2.get(s.itemId)?.doc.name).toBe(DOC.name); // restored live from the durable snapshot
    expect(store2.notices().find((n) => n.kind === "write-refused")?.revertedCount).toBe(1);

    // And on disk: a second fresh hydrate still shows it.
    const fresh2 = await relock(s.member);
    const store3 = new VaultStore(new FakeApi().asClient(), fresh2, (await openVaultCache(fresh2.userId)) as IdbVaultCache);
    await store3.hydrate();
    expect(store3.get(s.itemId)?.doc.name).toBe(DOC.name);
  });

  it("M2: a queue row WITHOUT a durable snapshot (pre-M2 build) keeps today's behavior — notice fires, no revert, no migration", async () => {
    const { s, api, cache, store } = await seeded("writer");
    stubPersisted(true);
    api.offline = true;
    await store.save(s.itemId, { ...DOC, name: "renamed offline" });
    // Simulate a row enqueued by a pre-M2 build: re-enqueue bare (INSERT OR REPLACE sheds
    // the snapshot) — the row itself reads back fine, its preEdit reads undefined.
    const row = (await cache.pending())[0]!;
    await cache.enqueue(row);
    expect(await cache.queuedPreEdits()).toEqual([]);
    expect((await cache.pending()).map((m) => m.mutationId)).toEqual([row.mutationId]);

    const fresh = await relock(s.member);
    const api2 = new FakeApi();
    const store2 = new VaultStore(api2.asClient(), fresh, (await openVaultCache(fresh.userId)) as IdbVaultCache);
    await store2.hydrate();
    api2.denyVaults.add(s.vaultId);
    api2.queue.push({ rev: 6, full: false, vaults: [], grants: [], items: [], removedGrants: [] });
    await expect(store2.sync()).rejects.toMatchObject({ code: "denied" });
    // No snapshot ⇒ no revert (the pre-M2 posture) — and the M3 copy no longer claims one.
    expect(store2.get(s.itemId)?.doc.name).toBe("renamed offline");
    const notice = store2.notices().find((n) => n.kind === "write-refused");
    expect(notice?.parkedCount).toBe(1);
    expect(notice?.revertedCount).toBe(0);
    expect(notice?.removedCount).toBe(0);
  });
});
