import "fake-indexeddb/auto";
import { IDBFactory as FakeIDBFactory } from "fake-indexeddb";
import { beforeEach, describe, expect, it } from "vitest";
import type { AccountKeys, KdfParams, Mutation, WireGrant, WireItem, WireVault } from "../api/types";
import {
  type HeldVaultRecord,
  IdbVaultCache,
  NullCache,
  openVaultCache,
  type QueuedPreEdit,
  vaultDbName,
} from "./idbcache";

/**
 * S1 unit suite (design 2026-07-13-web-offline-cache §G, vitest + fake-indexeddb):
 * transliterates core `VaultCacheContractTest` (+ the SqliteVaultCacheTest
 * durable-only cases) onto the IndexedDB impl, plus the web-specific MUSTs —
 * §B.4 coherence wipes, the §D.1 enumerated clear() (breaker #2 regression),
 * one-tx pull-commit atomicity (A1), the stuck-cache strike counter
 * (breaker #6), §D.2c setAccountKeys keep-old-on-bad-write (breaker #5),
 * §D.2a guarded writes after close, §E.4 wipe, and A2 putHeld cachedName drop.
 */

const g = globalThis as { indexedDB?: IDBFactory };

beforeEach(() => {
  // A fresh factory per test = a clean disk; instances opened in one test can
  // never bleed into the next.
  g.indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
});

// ---- fixtures (VaultCacheContractTest's wire()/vitem() shapes, TS twin) ----

const wire = (id: string, vaultId: string, rev: number, over: Partial<WireItem> = {}): WireItem => ({
  itemId: id,
  vaultId,
  rev,
  createdAt: 1000,
  updatedAt: 2000,
  deleted: false,
  conflict: false,
  formatVersion: 1,
  attachmentIds: [`att-${id}`],
  blob: `blob-${id}`,
  ...over,
});

const grant = (vaultId: string, over: Partial<WireGrant> = {}): WireGrant => ({
  vaultId,
  userId: "u",
  role: "owner",
  wrappedVk: "wv",
  rev: 3,
  sealedVk: null,
  ...over,
});

const vaultRow = (vaultId: string, over: Partial<WireVault> = {}): WireVault => ({
  vaultId,
  type: "personal",
  rev: 3,
  metaBlob: "meta1",
  createdAt: 100,
  ...over,
});

const mut = (id: string, vaultId = "v1", op: "put" | "delete" = "put"): Mutation => ({
  mutationId: id,
  op,
  itemId: `item-${id}`,
  vaultId,
  baseItemRev: 0,
});

const kdf = (over: Partial<KdfParams> = {}): KdfParams => ({ v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864, ...over });

const keys = (over: Partial<AccountKeys> = {}): AccountKeys => ({
  kdfSalt: "c2FsdA",
  kdfParams: kdf(),
  wrappedUvk: "wrap",
  encryptedIdentitySeed: "seed",
  identityPub: "pub",
  escrowFingerprint: "fp",
  ...over,
});

const heldRec = (vaultId: string): HeldVaultRecord & { cachedName: string } => ({
  vault: vaultRow(vaultId, { type: "shared" }),
  grant: grant(vaultId),
  items: [wire("h1", vaultId, 4)],
  reason: "deleted",
  verified: true,
  purgeAt: 111,
  deleteId: `del-${vaultId}`,
  parked: [{ ...mut(`p-${vaultId}`, vaultId), item: { formatVersion: 1, attachmentIds: [], blob: "parked-blob" } }],
  expungeAt: 999,
  cachedName: "Family passwords", // the ONE plaintext field — must never persist (A2)
});

/** A value structured-clone rejects (a function) — forces the commit tx to fail. */
const poison = (id: string): WireItem => ({ ...wire(id, "v1", 1), blob: (() => {}) as unknown as string });

async function open(userId = "u"): Promise<IdbVaultCache> {
  const c = await openVaultCache(userId);
  expect(c).toBeInstanceOf(IdbVaultCache);
  return c as IdbVaultCache;
}

// Raw IndexedDB access, for building corrupt fixtures + inspecting at-rest state.
function rawReq<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

function rawOpen(name: string, version?: number, upgrade?: (db: IDBDatabase) => void): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const r = g.indexedDB!.open(name, version);
    r.onupgradeneeded = () => upgrade?.(r.result);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

async function rawKvWrite(name: string, fn: (kv: IDBObjectStore) => void): Promise<void> {
  const db = await rawOpen(name);
  const tx = db.transaction("kv", "readwrite");
  fn(tx.objectStore("kv"));
  await new Promise<void>((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onabort = () => reject(tx.error);
  });
  db.close();
}

// ---- VaultCacheContractTest transliteration ----------------------------------

describe("idbcache: VaultCache contract (core VaultCacheContractTest twin)", () => {
  it("cursor defaults to zero and round-trips", async () => {
    const c = await open();
    expect(await c.cursor()).toBe(0);
    await c.setCursor(42);
    expect(await c.cursor()).toBe(42);
  });

  it("item upsert / envelopes / delete (wire-only — no decrypted twin at rest)", async () => {
    const c = await open();
    await c.upsertItem(wire("a", "v1", 1));
    await c.upsertItem(wire("b", "v1", 2));
    expect((await c.envelopes()).map((w) => w.itemId).sort()).toEqual(["a", "b"]);
    await c.deleteItem("a");
    expect((await c.envelopes()).some((w) => w.itemId === "a")).toBe(false);
    expect((await c.envelopes()).map((w) => w.itemId)).toEqual(["b"]);
  });

  it("envelopes round-trip every field (incl. conflict flag, attachmentIds, null blob)", async () => {
    const c = await open();
    const w: WireItem = {
      itemId: "i",
      vaultId: "v9",
      rev: 7,
      createdAt: 111,
      updatedAt: 222,
      deleted: false,
      conflict: true,
      formatVersion: 1,
      attachmentIds: ["p", "q"],
      blob: "B",
    };
    const tombstone = wire("t", "v9", 8, { deleted: true, blob: null, attachmentIds: [] });
    await c.upsertItem(w);
    await c.upsertItem(tombstone);
    expect((await c.envelopes()).find((x) => x.itemId === "i")).toEqual(w);
    expect((await c.envelopes()).find((x) => x.itemId === "t")).toEqual(tombstone);
  });

  it("grants and vaults upsert + list (incl. sealedVk and lifecycle wire fields verbatim)", async () => {
    const c = await open();
    await c.upsertGrant(grant("v1"));
    await c.upsertGrant(grant("v2", { role: "writer", wrappedVk: "", rev: 4, sealedVk: "sealed" }));
    const fullVault: WireVault = {
      ...vaultRow("v1"),
      pendingTransfer: { toUserId: "u2", offerId: "o1", proof: "pf", expiresAt: 99, seq: 2 },
      lastTransfer: { offerId: "o0", newOwnerUserId: "u9", acceptProof: "ap", seq: 1, wrapHash: "wh" },
      restoreProof: "rp",
      deleteId: "d1",
    };
    await c.upsertVault(fullVault);
    expect((await c.grants()).length).toBe(2);
    expect((await c.grants()).find((x) => x.vaultId === "v2")!.sealedVk).toBe("sealed");
    expect((await c.vaults()).find((x) => x.vaultId === "v1")).toEqual(fullVault); // WireVault verbatim (§B.2)
  });

  it("dropVault purges grant, vault row, and items — other vaults untouched", async () => {
    const c = await open();
    await c.upsertGrant(grant("v1"));
    await c.upsertVault(vaultRow("v1", { type: "shared" }));
    await c.upsertItem(wire("a", "v1", 2));
    await c.upsertItem(wire("b", "v2", 3));
    await c.dropVault("v1");
    expect((await c.grants()).some((x) => x.vaultId === "v1")).toBe(false);
    expect((await c.vaults()).some((x) => x.vaultId === "v1")).toBe(false);
    expect((await c.envelopes()).some((w) => w.vaultId === "v1")).toBe(false);
    expect((await c.envelopes()).map((w) => w.itemId)).toEqual(["b"]);
  });

  it("queue keeps FIFO order across interleaved enqueue/dequeue", async () => {
    const c = await open();
    // CR-01: an open cache VERIFIES the row landed and reports true (the setAccountKeys pattern).
    expect(await c.enqueue(mut("1"))).toBe(true);
    await c.enqueue(mut("2"));
    await c.enqueue(mut("3"));
    expect((await c.pending()).map((m) => m.mutationId)).toEqual(["1", "2", "3"]);
    await c.dequeue("2");
    expect((await c.pending()).map((m) => m.mutationId)).toEqual(["1", "3"]);
    await c.enqueue(mut("4"));
    expect((await c.pending()).map((m) => m.mutationId)).toEqual(["1", "3", "4"]);
  });

  it("dropPending removes only the matching vault's rows — staged or not", async () => {
    const c = await open();
    await c.enqueue(mut("a", "v1"));
    await c.enqueue(mut("b", "v2"));
    await c.enqueue(mut("c", "v1"));
    await c.markStagedDenied("c"); // staged rows go too (SQLite DELETE WHERE vaultId parity)
    await c.dropPending("v1");
    expect((await c.pending()).map((m) => m.mutationId)).toEqual(["b"]);
    expect(await c.stagedDenied()).toEqual([]);
  });

  it("staged-denied lifecycle: mark hides from pending, re-enqueue restores pushable at tail, dequeue removes staged", async () => {
    const c = await open();
    await c.enqueue(mut("1"));
    await c.enqueue(mut("2"));
    await c.markStagedDenied("1");
    expect((await c.pending()).map((m) => m.mutationId)).toEqual(["2"]);
    expect((await c.stagedDenied()).map((m) => m.mutationId)).toEqual(["1"]);
    await c.markStagedDenied("does-not-exist"); // unknown id = no-op (UPDATE ... WHERE parity)
    expect((await c.stagedDenied()).map((m) => m.mutationId)).toEqual(["1"]);
    await c.enqueue(mut("1")); // reinstate replay: back to pushable, at the tail
    expect((await c.pending()).map((m) => m.mutationId)).toEqual(["2", "1"]);
    expect(await c.stagedDenied()).toEqual([]);
    await c.markStagedDenied("2");
    await c.dequeue("2"); // dequeue removes rows in ANY state
    expect(await c.stagedDenied()).toEqual([]);
    expect((await c.pending()).map((m) => m.mutationId)).toEqual(["1"]);
  });

  it("M2 preEdit snapshots: additive round-trip — pre-M2 rows read undefined; mark preserves; re-enqueue sheds; dequeue drops", async () => {
    const c = await open();
    // Rows written WITHOUT a snapshot (every pre-M2 row — schemaless, no migration) read
    // back with none, and their queue lifecycle is untouched.
    await c.enqueue(mut("old"));
    expect(await c.queuedPreEdits()).toEqual([]);
    expect((await c.pending()).map((m) => m.mutationId)).toEqual(["old"]);

    // A snapshot rides its row and round-trips every field — and is NEVER part of the
    // mutation pending() returns (local-only, nothing new goes to the server).
    const pe: QueuedPreEdit = {
      op: "put",
      pre: { rev: 4, updatedAt: 2000, formatVersion: 1, attachmentIds: ["att-x"], blob: "sealed-pre" },
      optimisticRev: 5,
      optimisticUpdatedAt: 3000,
    };
    await c.enqueue(mut("m1"), pe);
    expect(await c.queuedPreEdits()).toEqual([{ mutationId: "m1", itemId: "item-m1", vaultId: "v1", preEdit: pe }]);
    expect((await c.pending()).find((m) => m.mutationId === "m1")).toEqual(mut("m1"));

    // Staging the denial PRESERVES the snapshot — the post-restart classification reverts from it.
    await c.markStagedDenied("m1");
    expect((await c.stagedDenied()).map((m) => m.mutationId)).toEqual(["m1"]);
    expect((await c.queuedPreEdits()).find((r) => r.mutationId === "m1")?.preEdit).toEqual(pe);

    // pre: null (a NEW item — revert = drop it) round-trips too.
    const peNew: QueuedPreEdit = { op: "put", pre: null, optimisticRev: 1, optimisticUpdatedAt: 3000 };
    await c.enqueue(mut("m2", "v2"), peNew);
    expect((await c.queuedPreEdits()).find((r) => r.mutationId === "m2")?.preEdit).toEqual(peNew);

    // INSERT OR REPLACE without a snapshot (the reinstate-replay enqueue) sheds the old one.
    await c.enqueue(mut("m1"));
    expect((await c.queuedPreEdits()).map((r) => r.mutationId)).toEqual(["m2"]);

    // dequeue drops the row and its snapshot together.
    await c.dequeue("m2");
    expect(await c.queuedPreEdits()).toEqual([]);
    expect((await c.pending()).map((m) => m.mutationId)).toEqual(["old", "m1"]);
  });

  it("clear resets rows and cursor but preserves the queue (core parity)", async () => {
    const c = await open();
    await c.upsertItem(wire("a", "v1", 1));
    await c.upsertGrant(grant("v1"));
    await c.upsertVault(vaultRow("v1"));
    await c.setCursor(99);
    await c.enqueue(mut("q"));
    await c.clear();
    expect(await c.cursor()).toBe(0);
    expect(await c.envelopes()).toEqual([]);
    expect(await c.grants()).toEqual([]);
    expect(await c.vaults()).toEqual([]);
    expect((await c.pending()).map((m) => m.mutationId)).toEqual(["q"]); // survives a 410 resync
  });

  it("everything survives close + reopen (SqliteVaultCacheTest durable twin)", async () => {
    const c1 = await open("user-1");
    await c1.setCursor(1234);
    await c1.upsertItem(wire("a", "v1", 5));
    await c1.upsertItem(wire("u", "v1", 6, { attachmentIds: [], blob: "blobU" }));
    await c1.upsertGrant(grant("v1", { userId: "user-1", rev: 5 }));
    await c1.upsertVault(vaultRow("v1"));
    await c1.enqueue(mut("q1"));
    await c1.putHeld(heldRec("hv"));
    await c1.addConsumedDeleteId("del-x");
    await c1.setLastVerifiedTransferSeq("v1", 7);
    await c1.setAccountKeys(keys());
    await c1.setPolicy({ offlineCacheAllowed: true });
    await c1.applyPull((b) => b.setLastSyncAt(5555));
    c1.close();

    const c2 = await open("user-1");
    expect(await c2.cursor()).toBe(1234);
    expect((await c2.envelopes()).length).toBe(2);
    expect((await c2.envelopes()).find((w) => w.itemId === "a")!.blob).toBe("blob-a");
    expect((await c2.grants()).length).toBe(1);
    expect((await c2.vaults()).length).toBe(1);
    expect((await c2.pending()).map((m) => m.mutationId)).toEqual(["q1"]);
    expect(await c2.getHeld("hv")).not.toBeNull();
    expect(await c2.isConsumedDeleteId("del-x")).toBe(true);
    expect(await c2.consumedDeleteIds()).toEqual(["del-x"]);
    expect(await c2.lastVerifiedTransferSeq("v1")).toBe(7);
    expect(await c2.transferSeqs()).toEqual([{ vaultId: "v1", seq: 7 }]);
    expect(await c2.accountKeys()).toEqual(keys());
    expect(await c2.policy()).toEqual({ offlineCacheAllowed: true });
    expect(await c2.lastSyncAt()).toBe(5555);
    c2.close();
  });
});

// ---- §B.4 coherence ------------------------------------------------------------

describe("idbcache: open-time coherence (§B.4) — cold start, never partial trust", () => {
  it("a foreign kv:userId wipes EVERYTHING including the queue (differentAccountWipesFile twin)", async () => {
    const a = await open("alice");
    await a.upsertGrant(grant("v1", { userId: "alice" }));
    await a.enqueue(mut("q"));
    await a.setCursor(9);
    await a.setAccountKeys(keys());
    a.close();
    // Tamper: rewrite the owner stamp out-of-band (the per-user DB NAME normally
    // prevents a mismatch — this is the defense-in-depth path, native init parity).
    await rawKvWrite(vaultDbName("alice"), (kv) => {
      kv.put({ key: "userId", value: "mallory" });
    });
    const again = await open("alice");
    expect(await again.cursor()).toBe(0);
    expect(await again.grants()).toEqual([]);
    expect(await again.pending()).toEqual([]); // the queue belongs to another account — gone
    expect(await again.accountKeys()).toBeNull();
    await again.setCursor(5); // and the wiped cache is USABLE (fresh, re-stamped)
    expect(await again.cursor()).toBe(5);
    again.close();
  });

  it("corrupt kv (missing userId stamp on an existing DB) wipes to a cold start", async () => {
    const c = await open("u");
    await c.upsertItem(wire("a", "v1", 1));
    await c.enqueue(mut("q"));
    c.close();
    await rawKvWrite(vaultDbName("u"), (kv) => {
      kv.delete("userId");
    });
    const again = await open("u");
    expect(await again.envelopes()).toEqual([]);
    expect(await again.pending()).toEqual([]);
    expect(await again.cursor()).toBe(0);
    again.close();
  });

  it("a missing object store (half-created v1) is wiped and recreated fresh", async () => {
    // Fabricate a v1 DB that has ONLY the kv store — my open() must not trust it.
    const name = vaultDbName("half");
    const db = await rawOpen(name, 1, (d) => {
      d.createObjectStore("kv", { keyPath: "key" });
    });
    const tx = db.transaction("kv", "readwrite");
    tx.objectStore("kv").put({ key: "userId", value: "half" });
    tx.objectStore("kv").put({ key: "cursor", value: 77 });
    await new Promise<void>((resolve) => {
      tx.oncomplete = () => resolve();
    });
    db.close();

    const c = await open("half"); // wiped + recreated: full schema, cold start
    expect(await c.cursor()).toBe(0);
    expect(await c.envelopes()).toEqual([]);
    await c.enqueue(mut("q")); // all stores exist now
    expect((await c.pending()).map((m) => m.mutationId)).toEqual(["q"]);
    c.close();
  });

  it("an open-time error ⇒ deleteDatabase attempted + NullCache (cache-less cold start)", async () => {
    let deletes = 0;
    g.indexedDB = {
      open() {
        throw new Error("boom");
      },
      deleteDatabase() {
        deletes++;
        throw new Error("boom too"); // even a failing delete must not reject openVaultCache
      },
    } as unknown as IDBFactory;
    const c = await openVaultCache("u");
    expect(c).toBeInstanceOf(NullCache);
    expect(c.durable).toBe(false);
    expect(deletes).toBe(1);
  });

  it("feature-detect: absent indexedDB ⇒ NullCache", async () => {
    delete g.indexedDB;
    const c = await openVaultCache("u");
    expect(c).toBeInstanceOf(NullCache);
    expect(c.durable).toBe(false);
  });
});

// ---- §D.1 applyPull: one-tx commit + stuck-cache strikes ------------------------

describe("idbcache: applyPull one-tx commit (§D.1, invariant A1)", () => {
  it("a failed commit moves NOTHING — old cursor and old rows stay (abort mid-tx)", async () => {
    const c = await open();
    await c.setCursor(5);
    await c.upsertItem(wire("a", "v1", 1));
    await expect(
      c.applyPull((b) => {
        b.upsertItem(wire("c", "v1", 3));
        b.upsertGrant(grant("v9"));
        b.upsertVault(vaultRow("v9"));
        b.enqueue(mut("qq", "v9"));
        b.setCursor(9);
        b.upsertItem(poison("bad")); // structured-clone failure ⇒ whole tx aborts
      }),
    ).rejects.toThrow();
    expect(c.consecutiveCommitFailures()).toBe(1);
    expect(await c.cursor()).toBe(5); // unmoved
    expect((await c.envelopes()).map((w) => w.itemId)).toEqual(["a"]); // zero rows moved
    expect(await c.grants()).toEqual([]);
    expect(await c.vaults()).toEqual([]);
    expect(await c.pending()).toEqual([]);
    c.close();
  });

  it("a successful commit applies everything at once and resets the strike counter", async () => {
    const c = await open();
    await expect(c.applyPull((b) => b.upsertItem(poison("bad")))).rejects.toThrow();
    expect(c.consecutiveCommitFailures()).toBe(1);
    await c.applyPull((b) => {
      b.upsertGrant(grant("v1"));
      b.upsertVault(vaultRow("v1"));
      b.upsertItem(wire("a", "v1", 1));
      b.upsertItem(wire("gone", "v1", 2, { deleted: true, blob: null }));
      b.deleteItem("gone"); // tombstone ⇒ delete is the caller's pull logic
      b.putHeld(heldRec("hv"));
      b.addConsumedDeleteId("d-1");
      b.setLastVerifiedTransferSeq("v1", 3);
      b.enqueue(mut("park", "v1"));
      b.setLastSyncAt(4242);
      b.setCursor(50); // cursor last (caller ordering, core parity)
    });
    expect(c.consecutiveCommitFailures()).toBe(0); // consecutive — success resets
    expect(await c.cursor()).toBe(50);
    expect((await c.envelopes()).map((w) => w.itemId)).toEqual(["a"]);
    expect((await c.grants()).length).toBe(1);
    expect(await c.getHeld("hv")).not.toBeNull();
    expect(await c.isConsumedDeleteId("d-1")).toBe(true);
    expect(await c.lastVerifiedTransferSeq("v1")).toBe(3);
    expect((await c.pending()).map((m) => m.mutationId)).toEqual(["park"]);
    expect(await c.lastSyncAt()).toBe(4242);
    c.close();
  });

  it("stuck cache (breaker #6): 3 consecutive failed commits are countable; standalone write successes do NOT reset", async () => {
    const c = await open();
    for (let i = 1; i <= 3; i++) {
      await expect(c.applyPull((b) => b.upsertItem(poison(`bad-${i}`)))).rejects.toThrow();
      expect(c.consecutiveCommitFailures()).toBe(i);
      // Small writes may still succeed under pressure that kills the big pull
      // tx — they must not mask the frozen-cursor hazard the counter guards.
      await c.setCursor(i);
      expect(c.consecutiveCommitFailures()).toBe(i);
    }
    // S1 exposes count + wipe(); the demotion ORCHESTRATION (swap to NullCache)
    // is S2's. Prove the demotion path's wipe leaves a clean slate:
    await c.wipe();
    const fresh = await open();
    expect(await fresh.cursor()).toBe(0);
    expect(c.consecutiveCommitFailures()).toBe(3); // the demoted handle keeps its tally
    fresh.close();
  });

  it("fn throwing during buffering commits nothing and is NOT a storage strike", async () => {
    const c = await open();
    await c.setCursor(4);
    await expect(
      c.applyPull((b) => {
        b.setCursor(9);
        throw new Error("caller bug");
      }),
    ).rejects.toThrow("caller bug");
    expect(c.consecutiveCommitFailures()).toBe(0);
    expect(await c.cursor()).toBe(4);
    c.close();
  });
});

// ---- §D.1 clear(): the enumerated 410 contract (breaker #2 regression) ---------

describe("idbcache: clear() enumerated contract (§D.1, breaker #2)", () => {
  async function populated(): Promise<IdbVaultCache> {
    const c = await open();
    await c.setAccountKeys(keys());
    await c.setPolicy({ offlineCacheAllowed: true });
    await c.applyPull((b) => {
      b.upsertItem(wire("a", "v1", 1));
      b.upsertGrant(grant("v1"));
      b.upsertVault(vaultRow("v1"));
      b.setLastSyncAt(1234);
      b.setCursor(50);
    });
    await c.enqueue(mut("q1"));
    await c.putHeld(heldRec("hv"));
    await c.addConsumedDeleteId("d-1");
    await c.setLastVerifiedTransferSeq("v1", 7);
    return c;
  }

  async function assertPreserved(c: IdbVaultCache): Promise<void> {
    // wiped: items/grants/vaults, cursor reset
    expect(await c.envelopes()).toEqual([]);
    expect(await c.grants()).toEqual([]);
    expect(await c.vaults()).toEqual([]);
    // PRESERVED: queue + held + consumedDeleteIds + transferSeq (spec 03 §4 safety state)
    expect((await c.pending()).map((m) => m.mutationId)).toEqual(["q1"]);
    expect(await c.getHeld("hv")).not.toBeNull();
    expect(await c.isConsumedDeleteId("d-1")).toBe(true);
    expect(await c.lastVerifiedTransferSeq("v1")).toBe(7);
    // PRESERVED: kv:accountKeys/policy/lastSyncAt (breaker #2 — offline unlock
    // after a mid-session resync-then-lock must still find the keys)
    expect(await c.accountKeys()).toEqual(keys());
    expect(await c.policy()).toEqual({ offlineCacheAllowed: true });
    expect(await c.lastSyncAt()).toBe(1234);
  }

  it("standalone clear(): resets kv:cursor ONLY; queue/held/floors/accountKeys/userId/policy/lastSyncAt survive", async () => {
    const c = await populated();
    await c.clear();
    expect(await c.cursor()).toBe(0);
    await assertPreserved(c);
    c.close();
    // kv:userId preserved too — a reopen under the same user keeps everything
    // (a clear() that dropped the owner stamp would trigger the §B.4 wipe here).
    const again = await open();
    await assertPreserved(again);
    again.close();
  });

  it("410 resync shape: ONE tx of clear + full snapshot + new cursor — preserved state intact, snapshot applied", async () => {
    const c = await populated();
    await c.applyPull((b) => {
      b.clear();
      b.upsertGrant(grant("v2", { rev: 60 }));
      b.upsertVault(vaultRow("v2", { rev: 60 }));
      b.upsertItem(wire("z", "v2", 60));
      b.setLastSyncAt(2222);
      b.setCursor(60);
    });
    expect(await c.cursor()).toBe(60);
    expect((await c.envelopes()).map((w) => w.itemId)).toEqual(["z"]);
    expect((await c.grants()).map((x) => x.vaultId)).toEqual(["v2"]);
    // safety state + keys still there (lastSyncAt legitimately moved with the pull)
    expect((await c.pending()).map((m) => m.mutationId)).toEqual(["q1"]);
    expect(await c.getHeld("hv")).not.toBeNull();
    expect(await c.isConsumedDeleteId("d-1")).toBe(true);
    expect(await c.accountKeys()).toEqual(keys());
    expect(await c.policy()).toEqual({ offlineCacheAllowed: true });
    expect(await c.lastSyncAt()).toBe(2222);
    c.close();
  });
});

// ---- §D.2c setAccountKeys keep-old-on-bad-write (breaker #5) --------------------

describe("idbcache: setAccountKeys (§D.2c keep-old-on-bad-write, breaker #5)", () => {
  it("allows the first write even sub-floor (C3's read gate is the belt), then a good write replaces it", async () => {
    const c = await open();
    const bad = keys({ kdfParams: kdf({ memBytes: 1024 }) });
    expect(await c.setAccountKeys(bad)).toBe(true); // first write allowed
    expect((await c.accountKeys())!.kdfParams.memBytes).toBe(1024);
    expect(await c.setAccountKeys(keys())).toBe(true); // good over bad: allowed
    expect((await c.accountKeys())!.kdfParams.memBytes).toBe(67_108_864);
    c.close();
  });

  it("never overwrites a good payload with a sub-floor, over-ceiling, or params-less one", async () => {
    const c = await open();
    expect(await c.setAccountKeys(keys())).toBe(true);
    const subFloor = keys({ kdfParams: kdf({ memBytes: 1024 }), wrappedUvk: "evil" });
    const lowOps = keys({ kdfParams: kdf({ ops: 1 }), wrappedUvk: "evil" });
    const overCeiling = keys({ kdfParams: kdf({ memBytes: 2_147_483_648 }), wrappedUvk: "evil" });
    const { kdfParams: _absent, ...missing } = keys({ wrappedUvk: "evil" }); // payload that LACKS kdfParams
    const nonNumeric = keys({ kdfParams: { v: 1, alg: "argon2id13", ops: "3", memBytes: 67_108_864 } as unknown as KdfParams, wrappedUvk: "evil" });
    for (const attempt of [subFloor, lowOps, overCeiling, missing as AccountKeys, nonNumeric]) {
      expect(await c.setAccountKeys(attempt)).toBe(false);
      expect(await c.accountKeys()).toEqual(keys()); // untouched
    }
    c.close();
  });

  it("a good payload replaces a good one (E.4 password-change row: fresh wrap wins)", async () => {
    const c = await open();
    await c.setAccountKeys(keys());
    const rotated = keys({ wrappedUvk: "wrap-2", kdfSalt: "salt-2" });
    expect(await c.setAccountKeys(rotated)).toBe(true);
    expect((await c.accountKeys())!.wrappedUvk).toBe("wrap-2");
    c.close();
  });
});

// ---- holding area (A2) + replay floors ------------------------------------------

describe("idbcache: holding area + replay floors (spec 03 §11)", () => {
  it("putHeld drops cachedName (A2) and round-trips every other field", async () => {
    const c = await open();
    const rec = heldRec("hv");
    await c.putHeld(rec);
    const { cachedName: _dropped, ...want } = rec;
    const got = await c.getHeld("hv");
    expect(got).toEqual(want); // deep-equal: cachedName absent, ciphertext snapshot + parked intact
    expect(got && "cachedName" in got).toBe(false);
    expect((await c.heldVaults()).length).toBe(1);
    expect(await c.getHeld("nope")).toBeNull();
    await c.removeHeld("hv");
    expect(await c.getHeld("hv")).toBeNull();
    expect(await c.heldVaults()).toEqual([]);
    c.close();
  });

  it("consumedDeleteIds and lastVerifiedTransferSeq default empty/0 and round-trip", async () => {
    const c = await open();
    expect(await c.isConsumedDeleteId("d-1")).toBe(false);
    expect(await c.lastVerifiedTransferSeq("v1")).toBe(0);
    await c.addConsumedDeleteId("d-1");
    await c.addConsumedDeleteId("d-1"); // idempotent
    await c.addConsumedDeleteId("d-2");
    expect(await c.isConsumedDeleteId("d-1")).toBe(true);
    expect((await c.consumedDeleteIds()).sort()).toEqual(["d-1", "d-2"]);
    await c.setLastVerifiedTransferSeq("v1", 4);
    await c.setLastVerifiedTransferSeq("v1", 9);
    expect(await c.lastVerifiedTransferSeq("v1")).toBe(9);
    expect(await c.transferSeqs()).toEqual([{ vaultId: "v1", seq: 9 }]);
    c.close();
  });
});

// ---- §E.4 wipe + §D.2a guarded close ---------------------------------------------

describe("idbcache: wipe (§E.4) and guarded close (§D.2a)", () => {
  it("wipe() deletes the database — envelopes, queue, holding AND accountKeys; next open is a fresh cold start", async () => {
    const c = await open();
    await c.upsertItem(wire("a", "v1", 1));
    await c.enqueue(mut("q"));
    await c.putHeld(heldRec("hv"));
    await c.setAccountKeys(keys());
    await c.setCursor(9);
    await c.wipe();
    const fresh = await open();
    expect(await fresh.cursor()).toBe(0);
    expect(await fresh.envelopes()).toEqual([]);
    expect(await fresh.pending()).toEqual([]);
    expect(await fresh.heldVaults()).toEqual([]);
    expect(await fresh.accountKeys()).toBeNull(); // the ONLY op that removes them
    fresh.close();
  });

  it("after close(), writes resolve as caught no-ops (no rejection, no strike, disk untouched); reads fall back", async () => {
    const c = await open();
    await c.setCursor(7);
    c.close();
    await expect(c.upsertItem(wire("a", "v1", 1))).resolves.toBeUndefined();
    await expect(c.applyPull((b) => b.setCursor(99))).resolves.toBeUndefined();
    await expect(c.clear()).resolves.toBeUndefined();
    // CR-01: a closed handle black-holes the write — enqueue must report FALSE (not a silent
    // resolve), so the store demotes and does the real send instead of reporting queued-success.
    expect(await c.enqueue(mut("q"))).toBe(false);
    expect(await c.setAccountKeys(keys())).toBe(false);
    expect(c.consecutiveCommitFailures()).toBe(0);
    expect(await c.cursor()).toBe(0); // read fallback, not the stored 7
    expect(await c.envelopes()).toEqual([]);
    const again = await open();
    expect(await again.cursor()).toBe(7); // nothing above touched the disk
    expect(await again.envelopes()).toEqual([]);
    again.close();
  });

  it("a sibling connection self-closes on versionchange so wipe() completes; its writes then no-op (D.5.3 + D.2a)", async () => {
    const c1 = await open();
    await c1.setCursor(4);
    const c2 = await open();
    await c2.wipe(); // would BLOCK forever if c1 didn't self-close on versionchange
    await expect(c1.setCursor(9)).resolves.toBeUndefined(); // caught no-op, never an uncaught rejection
    const fresh = await open();
    expect(await fresh.cursor()).toBe(0);
    fresh.close();
  });

  it("onClosed fires when a sibling deleteDatabase closes this connection — the store's demote hook (CR-01)", async () => {
    const c1 = await open();
    let closedFired = 0;
    c1.onClosed = () => {
      closedFired++;
    };
    const c2 = await open();
    await c2.wipe(); // deleteDatabase → versionchange on c1 → self-close + onClosed
    // enqueue() into the now-closed handle reports FALSE (black-hole guard), never a silent land.
    expect(await c1.enqueue(mut("q"))).toBe(false);
    expect(closedFired).toBeGreaterThanOrEqual(1); // the store would have demoted off this dead handle
    // The programmatic close() path does NOT re-fire onClosed (no reentrancy for the store).
    const before = closedFired;
    c1.close();
    expect(closedFired).toBe(before);
  });

  it("a deleteDatabase racing the OPEN window (openDb→verifyOwner→constructor) still settles — versionchange bound at openDb, not late (review regression)", async () => {
    // Establish the DB so the reopen traverses the full open path (openDb → verifyOwner tx →
    // constructor). The regression: if the self-close handler were bound only in the constructor,
    // a sibling deleteDatabase landing mid-open fires versionchange at a handler-less connection
    // (fired once, never re-fired) and blocks FOREVER. The fix binds it in openDb's onsuccess.
    const c0 = await open();
    await c0.setCursor(5);
    c0.close();
    const reopenP = open(); // enters the open window
    const del = g.indexedDB!.deleteDatabase(vaultDbName("u")); // sibling wipe in the same turn
    const settled = new Promise<string>((res) => {
      del.onsuccess = () => res("success");
      del.onerror = () => res("error");
    });
    const reopened = await reopenP;
    const outcome = await Promise.race([
      settled,
      new Promise<string>((res) => setTimeout(() => res("HUNG"), 1000)),
    ]);
    reopened.close();
    expect(outcome).not.toBe("HUNG"); // the delete must settle, never wedge the wipe path
  });
});

// ---- NullCache -------------------------------------------------------------------

describe("idbcache: NullCache (opt-out / unsupported / demoted path)", () => {
  it("presents the full interface as durable=false no-ops", async () => {
    const n = new NullCache();
    expect(n.durable).toBe(false);
    await n.setCursor(9);
    expect(await n.cursor()).toBe(0);
    await n.upsertItem(wire("a", "v1", 1));
    expect(await n.envelopes()).toEqual([]);
    await n.upsertGrant(grant("v1"));
    expect(await n.grants()).toEqual([]);
    await n.upsertVault(vaultRow("v1"));
    expect(await n.vaults()).toEqual([]);
    await n.dropVault("v1");
    await n.clear();
    await n.enqueue(mut("1"), { op: "put", pre: null, optimisticRev: 1, optimisticUpdatedAt: 1 });
    expect(await n.pending()).toEqual([]);
    expect(await n.queuedPreEdits()).toEqual([]);
    await n.markStagedDenied("1");
    expect(await n.stagedDenied()).toEqual([]);
    await n.dequeue("1");
    await n.dropPending("v1");
    await n.putHeld(heldRec("hv"));
    expect(await n.getHeld("hv")).toBeNull();
    expect(await n.heldVaults()).toEqual([]);
    await n.removeHeld("hv");
    await n.addConsumedDeleteId("d");
    expect(await n.isConsumedDeleteId("d")).toBe(false);
    expect(await n.consumedDeleteIds()).toEqual([]);
    await n.setLastVerifiedTransferSeq("v1", 5);
    expect(await n.lastVerifiedTransferSeq("v1")).toBe(0);
    expect(await n.transferSeqs()).toEqual([]);
    expect(await n.setAccountKeys(keys())).toBe(false);
    expect(await n.accountKeys()).toBeNull();
    await n.setPolicy({ offlineCacheAllowed: false });
    expect(await n.policy()).toBeNull();
    expect(await n.lastSyncAt()).toBeNull();
    expect(n.consecutiveCommitFailures()).toBe(0);
    let ran = false;
    await n.applyPull((b) => {
      ran = true; // the caller's buffering closure runs — ONE code shape in store.ts
      b.upsertItem(wire("a", "v1", 1));
      b.setCursor(3);
    });
    expect(ran).toBe(true);
    expect(await n.cursor()).toBe(0);
    await n.wipe();
    n.close();
  });
});
