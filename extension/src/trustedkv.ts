/**
 * The trusted store: the extension's trust state in the extension origin's IndexedDB (security review 2026-10,
 * branch A15).
 *
 * Why not chrome.storage.local: content scripts can read and write it, and they receive its `onChanged` events. On
 * Chrome that is the default (`setAccessLevel` restricts `local` only from Chrome 140); on Firefox it is by design
 * (Mozilla bug 2018494, RESOLVED INVALID, whose advice is origin-bound storage such as IndexedDB). A compromised
 * renderer, the A14 F11 precondition, could therefore repoint the server or plant an update link without ever
 * passing the worker's sender gate. A content script runs in the WEB page's origin, so the extension origin's
 * IndexedDB is out of its reach on both engines: the browser process binds IndexedDB to the frame's committed origin
 * (Chromium `CanAccessDataForOrigin`; Firefox's IndexedDB parent actor checks the principal).
 *
 * This leaf is the store: a get/set/remove surface shaped like a StorageArea, so the call sites that took
 * `chrome.storage.local` take this instead, and node tests keep injecting a plain object. The service worker is its
 * only reader and writer: the popup and the options page ask the worker. That also matters on Firefox, where an
 * extension page shown in a private window runs with private-browsing origin attributes and cannot open the
 * extension's IndexedDB at all.
 *
 * Fail safe: when IndexedDB is missing or refuses to open — Firefox blocks it for extension pages in private browsing,
 * including the background page under permanent private browsing ("Never remember history"; bug 1841806, Firefox 117,
 * 116.0.3 and ESR 115.2) — every call rejects with [TrustedStoreUnavailable] and each caller falls back to its safe
 * default (the default server, no item homes, no cached personal wrap). Nothing falls back to storage.local.
 *
 * Chrome-free (no chrome import, no chrome types); IndexedDB is resolved structurally at call time.
 */

/** The StorageArea subset the extension uses. `get(null)` answers every key, like chrome.storage. */
export interface KvArea {
  get(keys: string | readonly string[] | null): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string | readonly string[]): Promise<void>;
}

/** The store could not be opened or used. Callers treat it as "no record" and use their safe default. [timedOut] says the
 *  store did not answer within its bound (a hung open or transaction), as opposed to refusing outright (no IndexedDB in
 *  this browser mode): the worker cannot tell then which server the user chose, so it signs in nowhere (serverstate.ts). */
export class TrustedStoreUnavailable extends Error {
  readonly timedOut: boolean;
  constructor(detail: string, timedOut = false) {
    super(`trusted store unavailable: ${detail}`);
    this.name = "TrustedStoreUnavailable";
    this.timedOut = timedOut;
  }
}

/** A15 review S1: the bound on one store operation (open + transaction). An IndexedDB open that never settles used to
 *  wedge the worker: serverReady waited on it, and every message (a lock included) waited on serverReady. */
export const TRUSTED_OP_TIMEOUT_MS = 4000;

export const TRUSTED_DB_NAME = "andvari-trusted";
export const TRUSTED_STORE_NAME = "kv";

/** The one IDBFactory method used (structural, so tests can stand one in). */
export type IdbFactoryLike = Pick<IDBFactory, "open">;

const describe = (e: unknown): string => (e instanceof Error ? `${e.name}: ${e.message}` : String(e));

/**
 * Open [name] (version 1, creating [storeName] on first use) within [timeoutMs] (A15 review S1). A request that has not
 * succeeded by then rejects as a timed-out [TrustedStoreUnavailable]; should it succeed later, that connection is closed
 * at once. Also used by the worker for the quick-unlock co-key database, which is the same IndexedDB.
 */
export function openBoundedIdb(
  resolve: () => IdbFactoryLike | null | undefined,
  name: string,
  storeName: string,
  timeoutMs: number = TRUSTED_OP_TIMEOUT_MS,
): Promise<IDBDatabase> {
  return new Promise((res, rej) => {
    let settled = false;
    const finish = (f: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      f();
    };
    const timer = setTimeout(() => finish(() => rej(new TrustedStoreUnavailable(`opening ${name} took over ${timeoutMs} ms`, true))), timeoutMs);
    let factory: IdbFactoryLike | null | undefined;
    try {
      factory = resolve();
    } catch (e) {
      finish(() => rej(new TrustedStoreUnavailable(describe(e))));
      return;
    }
    if (!factory || typeof factory.open !== "function") {
      finish(() => rej(new TrustedStoreUnavailable("IndexedDB is not available here")));
      return;
    }
    let req: IDBOpenDBRequest;
    try {
      req = factory.open(name, 1);
    } catch (e) {
      finish(() => rej(new TrustedStoreUnavailable(describe(e))));
      return;
    }
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(storeName)) db.createObjectStore(storeName);
    };
    req.onsuccess = () => {
      if (settled) {
        req.result.close(); // it answered after the bound: nobody holds this connection
        return;
      }
      finish(() => res(req.result));
    };
    req.onerror = () => finish(() => rej(new TrustedStoreUnavailable(describe(req.error))));
    // No onblocked: the store is only ever opened at version 1, so no upgrade can wait on another connection.
  });
}

/**
 * Run one transaction. [body] issues its requests and returns a collector that runs once the transaction COMPLETED
 * (so a write is never reported before it is durable). The connection is closed on every exit. The whole operation,
 * open included, is bounded by [timeoutMs] (S1): a transaction still running then is aborted, so a write reported as
 * failed cannot land later. A [body] that throws aborts the transaction too (A15 review S2): without that, the puts it
 * issued before the throw would auto-commit, and a write reported as failed would have half happened.
 */
async function runTx<T>(
  resolve: () => IdbFactoryLike | null | undefined,
  name: string,
  mode: IDBTransactionMode,
  body: (store: IDBObjectStore) => () => T,
  timeoutMs: number,
): Promise<T> {
  const started = Date.now();
  const db = await openBoundedIdb(resolve, name, TRUSTED_STORE_NAME, timeoutMs);
  return new Promise<T>((res, rej) => {
    let collect: () => T;
    let tx: IDBTransaction | undefined;
    let settled = false;
    const finish = (f: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      db.close();
      f();
    };
    const timer = setTimeout(
      () =>
        finish(() => {
          try {
            tx?.abort();
          } catch {
            /* already finished */
          }
          rej(new TrustedStoreUnavailable(`a transaction on ${name} took over ${timeoutMs} ms`, true));
        }),
      Math.max(0, timeoutMs - (Date.now() - started)),
    );
    try {
      tx = db.transaction(TRUSTED_STORE_NAME, mode);
      collect = body(tx.objectStore(TRUSTED_STORE_NAME));
    } catch (e) {
      finish(() => {
        try {
          tx?.abort(); // S2: nothing [body] issued before the throw may commit
        } catch {
          /* the transaction was never created, or is already finishing */
        }
        rej(new TrustedStoreUnavailable(describe(e)));
      });
      return;
    }
    tx.oncomplete = () =>
      finish(() => {
        try {
          res(collect());
        } catch (e) {
          rej(new TrustedStoreUnavailable(describe(e)));
        }
      });
    tx.onerror = () => finish(() => rej(new TrustedStoreUnavailable(describe(tx?.error))));
    tx.onabort = () => finish(() => rej(new TrustedStoreUnavailable(describe(tx?.error ?? "transaction aborted"))));
  });
}

const keyList = (keys: string | readonly string[]): string[] => (typeof keys === "string" ? [keys] : [...keys]);

/** A [KvArea] over one IndexedDB object store. [resolve] is called on every operation, so a store that failed to
 *  open is simply tried again next time (no sticky failure, no cached connection to go stale). Each operation is bounded
 *  by [opts.timeoutMs] (default [TRUSTED_OP_TIMEOUT_MS]). */
export function idbKv(resolve: () => IdbFactoryLike | null | undefined, name: string = TRUSTED_DB_NAME, opts: { timeoutMs?: number } = {}): KvArea {
  const timeoutMs = opts.timeoutMs ?? TRUSTED_OP_TIMEOUT_MS;
  return {
    get(keys) {
      return runTx(resolve, name, "readonly", (store) => {
        if (keys === null) {
          const ks = store.getAllKeys();
          const vs = store.getAll();
          return () => {
            const out: Record<string, unknown> = {};
            const kk = ks.result as IDBValidKey[];
            const vv = vs.result as unknown[];
            kk.forEach((k, i) => {
              if (typeof k === "string" && vv[i] !== undefined) out[k] = vv[i];
            });
            return out;
          };
        }
        const reqs = keyList(keys).map((k) => [k, store.get(k)] as const);
        return () => {
          const out: Record<string, unknown> = {};
          for (const [k, r] of reqs) if (r.result !== undefined) out[k] = r.result;
          return out;
        };
      }, timeoutMs);
    },
    set(items) {
      return runTx(resolve, name, "readwrite", (store) => {
        for (const [k, v] of Object.entries(items)) store.put(v, k);
        return () => undefined;
      }, timeoutMs);
    },
    remove(keys) {
      return runTx(resolve, name, "readwrite", (store) => {
        for (const k of keyList(keys)) store.delete(k);
        return () => undefined;
      }, timeoutMs);
    },
  };
}

const globalIdb = (): IdbFactoryLike | null | undefined => (globalThis as { indexedDB?: IdbFactoryLike }).indexedDB;

let shared: KvArea | null = null;
/** The extension's trusted store (the service worker's; pages ask the worker). Resolves `globalThis.indexedDB` on
 *  every call — never chrome.storage. */
export function trustedStore(): KvArea {
  shared ??= idbKv(globalIdb);
  return shared;
}

/** Remove every key of [area] that starts with [prefix] (the per-origin purge: `ns.<originKey>.`). An empty prefix
 *  would match everything, so it is refused. Returns how many keys went. */
export async function removeByPrefix(area: KvArea, prefix: string): Promise<number> {
  if (prefix === "") throw new Error("removeByPrefix: an empty prefix would remove everything");
  const keys = Object.keys(await area.get(null)).filter((k) => k.startsWith(prefix));
  if (keys.length > 0) await area.remove(keys);
  return keys.length;
}
