// node --test. Security review 2026-10, branch A15: the trust state moved out of chrome.storage.local, which content
// scripts can read and write (Chrome by default, and from Chrome 140 only once `setAccessLevel` locks it; Firefox
// always), into the extension origin's IndexedDB, which a content script runs in the wrong origin to open.
//
// trustedkv.ts is the store. These tests drive its IndexedDB adapter against a small in-memory IDBFactory stand-in
// (the real one does not exist under node), its fail-safe when IndexedDB is missing or refuses to open, and the
// prefix sweep the per-origin purge uses.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { idbKv, removeByPrefix, TRUSTED_DB_NAME, TRUSTED_STORE_NAME, TrustedStoreUnavailable, trustedStore, type KvArea } from "./trustedkv.ts";

// ---- a minimal IDBFactory: open / upgrade / one object store / get, put, delete, getAll, getAllKeys ----

type Req = { result?: unknown; error?: unknown; onsuccess?: (() => void) | null; onerror?: (() => void) | null; onupgradeneeded?: (() => void) | null; onblocked?: (() => void) | null };

// Transactional like the real thing (A15 review S2): requests work on a copy that replaces the store only when the
// transaction completes; abort() discards it. put() clones synchronously, so an uncloneable value throws from put()
// itself (DataCloneError) after earlier puts in the same transaction were already issued. `hangOpen` never answers an
// open; `lateOpenMs` answers it that late; `hangTx` never completes a transaction (the S1 cases).
function fakeIdb(opts: { failOpen?: "throw" | "error"; failTx?: boolean; hangOpen?: boolean; lateOpenMs?: number; hangTx?: boolean } = {}) {
  const dbs = new Map<string, Map<string, Map<string, unknown>>>(); // db name → store name → key → value
  const stats = { opens: 0, closes: 0, txs: 0, aborts: 0, commits: 0 };
  const later = (f: () => void) => setTimeout(f, 0);
  const clone = <T>(v: T): T => structuredClone(v);
  function makeDb(name: string) {
    const stores = dbs.get(name)!;
    return {
      objectStoreNames: { contains: (s: string) => stores.has(s) },
      createObjectStore(s: string) {
        stores.set(s, new Map());
      },
      close() {
        stats.closes++;
      },
      transaction(storeName: string, _mode: string) {
        if (opts.failTx) throw new Error("tx refused");
        stats.txs++;
        const data = stores.get(storeName);
        if (!data) throw new Error(`no store ${storeName}`);
        const work = new Map(data); // this transaction's view; committed on complete
        let finished = false;
        const complete = () => {
          if (finished || opts.hangTx) return;
          finished = true;
          data.clear();
          for (const [k, v] of work) data.set(k, v);
          stats.commits++;
          tx.oncomplete?.();
        };
        const tx: { oncomplete?: () => void; onerror?: () => void; onabort?: () => void; error?: unknown; abort: () => void; objectStore: (n: string) => unknown } = {
          abort() {
            if (finished) throw new Error("InvalidStateError: the transaction has finished");
            finished = true;
            stats.aborts++;
            later(() => tx.onabort?.());
          },
          objectStore(n: string) {
            assert.equal(n, storeName);
            const req = (fn: () => unknown): Req => {
              const r: Req = {};
              pending++;
              later(() => {
                if (finished) return;
                r.result = fn();
                r.onsuccess?.();
                if (--pending === 0) later(complete);
              });
              return r;
            };
            return {
              get: (k: string) => req(() => (work.has(k) ? clone(work.get(k)) : undefined)),
              put: (v: unknown, k: string) => {
                const c = clone(v); // synchronous, like IDBObjectStore.put: an uncloneable value throws HERE
                return req(() => void work.set(k, c));
              },
              delete: (k: string) => req(() => void work.delete(k)),
              getAllKeys: () => req(() => [...work.keys()].sort()),
              getAll: () => req(() => [...work.keys()].sort().map((k) => clone(work.get(k)))),
            };
          },
        };
        let pending = 0;
        // A transaction with no request still completes.
        later(() => {
          if (pending === 0) complete();
        });
        return tx;
      },
    };
  }
  const factory = {
    open(name: string, version: number) {
      stats.opens++;
      assert.equal(version, 1);
      if (opts.failOpen === "throw") throw new Error("SecurityError: the operation is insecure");
      const r: Req = {};
      if (opts.hangOpen) return r; // never answers
      (opts.lateOpenMs === undefined ? later : (f: () => void) => setTimeout(f, opts.lateOpenMs))(() => {
        if (opts.failOpen === "error") {
          r.error = new Error("InvalidStateError");
          r.onerror?.();
          return;
        }
        const fresh = !dbs.has(name);
        if (fresh) dbs.set(name, new Map());
        r.result = makeDb(name);
        if (fresh) r.onupgradeneeded?.();
        r.onsuccess?.();
      });
      return r;
    },
  };
  return { factory, dbs, stats };
}

test("the IndexedDB adapter behaves like a StorageArea: set, get one / many / all, remove", async () => {
  const idb = fakeIdb();
  const kv = idbKv(() => idb.factory as unknown as IDBFactory);
  assert.deepEqual(await kv.get("serverUrl"), {}, "an empty store answers {} like storage.local");
  await kv.set({ serverUrl: "https://self.example", "ns.0123456789abcdef.quOfferDismissed": true });
  assert.deepEqual(await kv.get("serverUrl"), { serverUrl: "https://self.example" });
  assert.deepEqual(await kv.get(["serverUrl", "missing"]), { serverUrl: "https://self.example" }, "absent keys are omitted");
  assert.deepEqual(await kv.get(null), { serverUrl: "https://self.example", "ns.0123456789abcdef.quOfferDismissed": true });
  await kv.remove("serverUrl");
  assert.deepEqual(await kv.get(null), { "ns.0123456789abcdef.quOfferDismissed": true });
  await kv.remove(["ns.0123456789abcdef.quOfferDismissed", "never-there"]);
  assert.deepEqual(await kv.get(null), {});
  // One database, one object store, named as the module says; every connection is closed again.
  assert.deepEqual([...idb.dbs.keys()], [TRUSTED_DB_NAME]);
  assert.deepEqual([...idb.dbs.get(TRUSTED_DB_NAME)!.keys()], [TRUSTED_STORE_NAME]);
  assert.equal(idb.stats.closes, idb.stats.opens, "each op closes the connection it opened");
});

test("a value read back is a copy: changing it does not change the store", async () => {
  const idb = fakeIdb();
  const kv = idbKv(() => idb.factory as unknown as IDBFactory);
  await kv.set({ homes: { a: "b" } });
  const got = (await kv.get("homes")).homes as Record<string, string>;
  got.a = "poison";
  assert.deepEqual((await kv.get("homes")).homes, { a: "b" });
});

test("IndexedDB missing, throwing on open or failing to open: every call rejects with TrustedStoreUnavailable", async () => {
  const cases: [string, () => IDBFactory | null | undefined][] = [
    ["no indexedDB global", () => undefined],
    ["null factory", () => null],
    ["the resolver itself throws", () => {
      throw new Error("indexedDB getter threw");
    }],
    ["open() throws (Firefox private browsing before 115)", () => fakeIdb({ failOpen: "throw" }).factory as unknown as IDBFactory],
    ["the open request errors", () => fakeIdb({ failOpen: "error" }).factory as unknown as IDBFactory],
    ["the transaction is refused", () => fakeIdb({ failTx: true }).factory as unknown as IDBFactory],
  ];
  for (const [name, resolve] of cases) {
    const kv = idbKv(resolve);
    await assert.rejects(() => kv.get("serverUrl"), TrustedStoreUnavailable, `${name}: get`);
    await assert.rejects(() => kv.get(null), TrustedStoreUnavailable, `${name}: get(null)`);
    await assert.rejects(() => kv.set({ serverUrl: "https://evil.example" }), TrustedStoreUnavailable, `${name}: set`);
    await assert.rejects(() => kv.remove("serverUrl"), TrustedStoreUnavailable, `${name}: remove`);
  }
});

test("a store that failed once is tried again on the next call (no sticky failure)", async () => {
  let fail = true;
  const good = fakeIdb();
  const kv = idbKv(() => (fail ? undefined : (good.factory as unknown as IDBFactory)));
  await assert.rejects(() => kv.get("serverUrl"), TrustedStoreUnavailable);
  fail = false;
  await kv.set({ serverUrl: "https://self.example" });
  assert.deepEqual(await kv.get("serverUrl"), { serverUrl: "https://self.example" });
});

test("trustedStore() reads globalThis.indexedDB — never chrome.storage — and fails safe under plain node", async () => {
  const g = globalThis as { chrome?: unknown; indexedDB?: unknown };
  const prior = { chrome: g.chrome, indexedDB: g.indexedDB };
  let localTouched = 0;
  const local = new Proxy({}, { get: () => (localTouched++, async () => ({ serverUrl: "https://evil.example" })) });
  g.chrome = { storage: { local, sync: local, session: local } };
  try {
    delete g.indexedDB;
    await assert.rejects(() => trustedStore().get("serverUrl"), TrustedStoreUnavailable, "no IndexedDB here: unavailable, not storage.local");
    const idb = fakeIdb();
    g.indexedDB = idb.factory;
    await trustedStore().set({ serverUrl: "https://self.example" });
    assert.deepEqual(await trustedStore().get("serverUrl"), { serverUrl: "https://self.example" });
    assert.equal(idb.stats.opens > 0, true);
  } finally {
    g.chrome = prior.chrome;
    if (prior.indexedDB === undefined) delete g.indexedDB;
    else g.indexedDB = prior.indexedDB;
  }
  assert.equal(localTouched, 0, "chrome.storage is never touched by the trusted store");
});

test("removeByPrefix removes exactly the keys under the prefix and reports how many", async () => {
  const map = new Map<string, unknown>([
    ["ns.aaaaaaaaaaaaaaaa.itemHomes:u1", {}],
    ["ns.aaaaaaaaaaaaaaaa.personalWrap:u1", {}],
    ["ns.aaaaaaaaaaaaaaaaX", 1], // not under "ns.aaaaaaaaaaaaaaaa." (no dot after the key)
    ["ns.bbbbbbbbbbbbbbbb.itemHomes:u1", {}],
    ["serverUrl", "https://self.example"],
  ]);
  const area: KvArea = {
    async get(keys) {
      assert.equal(keys, null);
      return Object.fromEntries(map);
    },
    async set() {
      throw new Error("never written");
    },
    async remove(keys) {
      for (const k of typeof keys === "string" ? [keys] : keys) map.delete(k);
    },
  };
  assert.equal(await removeByPrefix(area, "ns.aaaaaaaaaaaaaaaa."), 2);
  assert.deepEqual([...map.keys()].sort(), ["ns.aaaaaaaaaaaaaaaaX", "ns.bbbbbbbbbbbbbbbb.itemHomes:u1", "serverUrl"]);
  assert.equal(await removeByPrefix(area, "ns.aaaaaaaaaaaaaaaa."), 0, "nothing left: no remove call needed");
  await assert.rejects(() => removeByPrefix(area, ""), /prefix/, "an empty prefix would sweep everything: refused");
});

// ---- A15 review S1: a store that never answers must not wedge the worker ----

/** Fails (rather than hangs the suite) when [p] has not settled within [ms]: the pre-fix store had no bound at all. */
function within<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  return Promise.race([p, new Promise<T>((_, rej) => setTimeout(() => rej(new Error(`${what}: still pending after ${ms} ms (no bound)`)), ms))]);
}

test("S1: an open that never settles rejects as a timed-out TrustedStoreUnavailable within the bound", async () => {
  const idb = fakeIdb({ hangOpen: true });
  const kv = (idbKv as unknown as (r: () => IDBFactory, n?: string, o?: { timeoutMs: number }) => KvArea)(() => idb.factory as unknown as IDBFactory, undefined, { timeoutMs: 40 });
  for (const [name, op] of [
    ["get", () => kv.get("serverUrl")],
    ["get(null)", () => kv.get(null)],
    ["set", () => kv.set({ serverUrl: "https://self.example" })],
    ["remove", () => kv.remove("serverUrl")],
  ] as const) {
    const t0 = Date.now();
    const e = await within((op as () => Promise<unknown>)().then(() => null, (x: unknown) => x), 1000, name);
    assert.ok(e instanceof TrustedStoreUnavailable, `${name}: rejects with TrustedStoreUnavailable`);
    assert.equal((e as { timedOut?: unknown }).timedOut, true, `${name}: and says it timed out (not "no IndexedDB here")`);
    assert.ok(Date.now() - t0 < 900, `${name}: within the bound`);
  }
});

test("S1: an open that answers after the bound has its connection closed at once (nobody holds it)", async () => {
  const idb = fakeIdb({ lateOpenMs: 80 });
  const kv = (idbKv as unknown as (r: () => IDBFactory, n?: string, o?: { timeoutMs: number }) => KvArea)(() => idb.factory as unknown as IDBFactory, undefined, { timeoutMs: 20 });
  await assert.rejects(() => within(kv.get("serverUrl"), 1000, "late open"), TrustedStoreUnavailable);
  await new Promise((r) => setTimeout(r, 150));
  assert.equal(idb.stats.opens, 1);
  assert.equal(idb.stats.closes, 1, "the late connection was closed");
});

test("S1: a transaction that never completes rejects within the bound and is aborted, so a failed write cannot land later", async () => {
  const idb = fakeIdb({ hangTx: true });
  const kv = (idbKv as unknown as (r: () => IDBFactory, n?: string, o?: { timeoutMs: number }) => KvArea)(() => idb.factory as unknown as IDBFactory, undefined, { timeoutMs: 40 });
  const e = await within(kv.set({ serverUrl: "https://self.example" }).then(() => null, (x: unknown) => x), 1000, "hung tx");
  assert.ok(e instanceof TrustedStoreUnavailable);
  assert.equal((e as { timedOut?: unknown }).timedOut, true);
  assert.equal(idb.stats.aborts, 1, "the transaction was aborted");
  assert.equal(idb.stats.commits, 0);
});

test("S1: the default bound is a few seconds, and the shared store uses it", async () => {
  const mod = (await import("./trustedkv.ts")) as Record<string, unknown>;
  const ms = mod.TRUSTED_OP_TIMEOUT_MS;
  assert.equal(typeof ms, "number", "trustedkv.ts exports TRUSTED_OP_TIMEOUT_MS");
  assert.ok((ms as number) >= 1000 && (ms as number) <= 10_000, `a bound of ${ms} ms`);
  assert.equal(typeof mod.openBoundedIdb, "function", "the worker's co-key database opens through the same bound");
});

// ---- A15 review S2: a body that throws aborts its transaction ----

test("S2: a set whose second value cannot be stored writes NOTHING (the first put is aborted, not auto-committed)", async () => {
  const idb = fakeIdb();
  const kv = idbKv(() => idb.factory as unknown as IDBFactory);
  await kv.set({ keep: "before" });
  await assert.rejects(() => kv.set({ a: "first", b: () => "a function is not cloneable" }), TrustedStoreUnavailable);
  await new Promise((r) => setTimeout(r, 20)); // give an un-aborted transaction time to auto-commit
  assert.deepEqual(await kv.get(null), { keep: "before" }, "the put issued before the throw did not commit");
  assert.equal(idb.stats.closes, idb.stats.opens, "and the connection was closed");
});
