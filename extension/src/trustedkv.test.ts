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

function fakeIdb(opts: { failOpen?: "throw" | "error"; failTx?: boolean } = {}) {
  const dbs = new Map<string, Map<string, Map<string, unknown>>>(); // db name → store name → key → value
  const stats = { opens: 0, closes: 0, txs: 0 };
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
        const tx: { oncomplete?: () => void; onerror?: () => void; onabort?: () => void; error?: unknown; objectStore: (n: string) => unknown } = {
          objectStore(n: string) {
            assert.equal(n, storeName);
            const req = (fn: () => unknown): Req => {
              const r: Req = {};
              pending++;
              later(() => {
                r.result = fn();
                r.onsuccess?.();
                if (--pending === 0) later(() => tx.oncomplete?.());
              });
              return r;
            };
            return {
              get: (k: string) => req(() => (data.has(k) ? clone(data.get(k)) : undefined)),
              put: (v: unknown, k: string) => req(() => void data.set(k, clone(v))),
              delete: (k: string) => req(() => void data.delete(k)),
              getAllKeys: () => req(() => [...data.keys()].sort()),
              getAll: () => req(() => [...data.keys()].sort().map((k) => clone(data.get(k)))),
            };
          },
        };
        let pending = 0;
        // A transaction with no request still completes.
        later(() => {
          if (pending === 0) tx.oncomplete?.();
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
      later(() => {
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
