import "fake-indexeddb/auto";
import { IDBFactory as FakeIDBFactory } from "fake-indexeddb";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AccountKeys, KdfParams, Mutation } from "../api/types";
import { openVaultCache, vaultDbName } from "../vault/idbcache";
import {
  applyOrgOfflineCachePolicy,
  ensureCachePersistenceRequested,
  offlineCopyStamp,
  orgOfflineCacheDisallowed,
  requestCachePersistence,
  setOfflineCopyEnabled,
  webCacheEnabled,
} from "./session";

/**
 * S5 unit suite (design 2026-07-13-web-offline-cache §E.3/§E.4/§B.5): the settings-surface
 * seams in session.ts —
 *  - the EXTENDED webCacheEnabled() gate (org policy bit > per-device opt-out > origin
 *    default > public-origin opt-in);
 *  - setOfflineCopyEnabled (§E.3.2 toggle): OFF wipes immediately + pins the opt-out marker
 *    (the gate blocks re-creation); ON clears it + requests persist();
 *  - applyOrgOfflineCachePolicy (§E.4 policy row): false force-wipes (QUEUE included) + pins
 *    the last-known bit so an OFFLINE boot honors it; true clears the pin;
 *  - requestCachePersistence / ensureCachePersistenceRequested (§B.5): requested once,
 *    marker-deduped, safe without the API;
 *  - offlineCopyStamp (§E.3.4 Unlock transparency line): non-null ONLY with a real cache, and
 *    the probe itself NEVER creates a DB.
 */

const g = globalThis as { indexedDB?: IDBFactory; window?: { location: { origin: string } } };

const PRIVATE_ORIGIN = "https://andvari.taila2dff2.ts.net";
const PUBLIC_ORIGIN = "https://andvari.monahanhosting.com";
const setOrigin = (origin: string): void => {
  g.window = { location: { origin } };
};

/** Map-backed localStorage for the node test environment (session.test.ts twin). */
function fakeStorage(): Storage {
  const m = new Map<string, string>();
  return {
    get length() {
      return m.size;
    },
    clear: () => m.clear(),
    getItem: (k: string) => m.get(k) ?? null,
    key: (i: number) => [...m.keys()][i] ?? null,
    removeItem: (k: string) => void m.delete(k),
    setItem: (k: string, v: string) => void m.set(k, v),
  } as Storage;
}

const kdf = (): KdfParams => ({ v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 });
const keys = (): AccountKeys => ({
  kdfSalt: "c2FsdA",
  kdfParams: kdf(),
  wrappedUvk: "wrap",
  encryptedIdentitySeed: "seed",
  identityPub: "pub",
  escrowFingerprint: "fp",
});
const mut = (id: string): Mutation => ({ mutationId: id, op: "put", itemId: `item-${id}`, vaultId: "v1", baseItemRev: 0 });

const UID = "user-s5";

/** The non-creating existence check the assertions lean on (fake-indexeddb implements databases()). */
async function dbExists(userId: string): Promise<boolean> {
  const list = await (g.indexedDB as unknown as { databases: () => Promise<{ name?: string }[]> }).databases();
  return list.some((d) => d.name === vaultDbName(userId));
}

/** Seed a durable cache the way a prior online session would (accountKeys + optionally queue rows). */
async function seedCache(userId = UID, queued: Mutation[] = []): Promise<void> {
  const cache = await openVaultCache(userId);
  await cache.setAccountKeys(keys());
  for (const m of queued) await cache.enqueue(m);
  cache.close();
}

beforeEach(() => {
  g.indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
  vi.stubGlobal("localStorage", fakeStorage());
  setOrigin(PRIVATE_ORIGIN);
});

afterEach(() => {
  vi.unstubAllGlobals();
  delete g.window;
});

describe("webCacheEnabled — the extended §F.1 gate (org bit > opt-out > origin default > opt-in)", () => {
  it("private origin, no markers → ON (unchanged S3 default)", () => {
    expect(webCacheEnabled()).toBe(true);
  });

  it("public origin, no markers → OFF (unchanged S3 default)", () => {
    setOrigin(PUBLIC_ORIGIN);
    expect(webCacheEnabled()).toBe(false);
  });

  it("public origin + explicit opt-in marker → ON (§E.3.3)", () => {
    setOrigin(PUBLIC_ORIGIN);
    localStorage.setItem("andvari.cacheOptIn", "1");
    expect(webCacheEnabled()).toBe(true);
  });

  it("the opt-out marker beats the private-origin default AND a stale opt-in", () => {
    localStorage.setItem("andvari.cacheOptOut", "1");
    expect(webCacheEnabled()).toBe(false);
    setOrigin(PUBLIC_ORIGIN);
    localStorage.setItem("andvari.cacheOptIn", "1");
    expect(webCacheEnabled()).toBe(false);
  });

  it("the org policy pin beats EVERYTHING — private default and public opt-in alike (§E.4)", () => {
    localStorage.setItem("andvari.orgCacheOff", "1");
    expect(webCacheEnabled()).toBe(false); // private origin
    expect(orgOfflineCacheDisallowed()).toBe(true);
    setOrigin(PUBLIC_ORIGIN);
    localStorage.setItem("andvari.cacheOptIn", "1");
    expect(webCacheEnabled()).toBe(false);
  });
});

describe("setOfflineCopyEnabled — the §E.3.2 per-device toggle", () => {
  it("OFF wipes the cache DB immediately, pins the marker, and the gate blocks re-creation", async () => {
    await seedCache();
    expect(await dbExists(UID)).toBe(true);

    await setOfflineCopyEnabled(UID, false);

    expect(await dbExists(UID)).toBe(false); // wiped — envelopes, queue, accountKeys, everything
    expect(localStorage.getItem("andvari.cacheOptOut")).not.toBeNull(); // pinned for the S3 gate
    expect(webCacheEnabled()).toBe(false); // the next unlock's gated factory returns NullCache
  });

  it("ON clears the opt-out and requests persist() (an explicit gesture — always re-requests)", async () => {
    localStorage.setItem("andvari.cacheOptOut", "1");
    const persist = vi.fn(async () => true);
    vi.stubGlobal("navigator", { storage: { persist } });

    await setOfflineCopyEnabled(UID, true);

    expect(localStorage.getItem("andvari.cacheOptOut")).toBeNull();
    expect(webCacheEnabled()).toBe(true); // private origin default resumes
    expect(persist).toHaveBeenCalledTimes(1);
    expect(await dbExists(UID)).toBe(false); // creation stays with the next unlock/sign-in — ON creates nothing
  });

  it("ON on the PUBLIC origin additionally pins the explicit opt-in marker (§E.3.3)", async () => {
    setOrigin(PUBLIC_ORIGIN);
    expect(webCacheEnabled()).toBe(false);
    await setOfflineCopyEnabled(UID, true);
    expect(localStorage.getItem("andvari.cacheOptIn")).not.toBeNull();
    expect(webCacheEnabled()).toBe(true);
    // …and OFF removes it again (no stale opt-in survives an opt-out round-trip).
    await setOfflineCopyEnabled(UID, false);
    expect(localStorage.getItem("andvari.cacheOptIn")).toBeNull();
    expect(webCacheEnabled()).toBe(false);
  });
});

describe("applyOrgOfflineCachePolicy — the §E.4 policy row", () => {
  it("offlineCacheAllowed=false force-wipes (QUEUE included) and pins the last-known bit", async () => {
    await seedCache(UID, [mut("q1"), mut("q2")]); // two unsynced offline edits in the queue
    expect(await dbExists(UID)).toBe(true);

    await applyOrgOfflineCachePolicy(false, UID);

    expect(await dbExists(UID)).toBe(false); // deleteDatabase — the queue died with it (server-initiated)
    expect(orgOfflineCacheDisallowed()).toBe(true);
    expect(webCacheEnabled()).toBe(false); // refuses future cache creation…
    const reopened = await openVaultCache(UID); // …and a gate-bypassing reopen proves the rows are GONE
    expect(await reopened.accountKeys()).toBeNull();
    expect(await reopened.pending()).toEqual([]);
    reopened.close();
  });

  it("the pin is honored on OFFLINE boot: no fetch needed for the gate to stay closed", async () => {
    // A PREVIOUS session saw policy=false (marker persisted); this boot fetches nothing.
    localStorage.setItem("andvari.orgCacheOff", "1");
    expect(webCacheEnabled()).toBe(false); // private origin notwithstanding
  });

  it("offlineCacheAllowed=true clears the pin and never touches the cache", async () => {
    localStorage.setItem("andvari.orgCacheOff", "1");
    await seedCache();
    await applyOrgOfflineCachePolicy(true, UID);
    expect(orgOfflineCacheDisallowed()).toBe(false);
    expect(webCacheEnabled()).toBe(true);
    expect(await dbExists(UID)).toBe(true); // allowed ⇒ nothing wiped, nothing created
  });

  it("false with no signed-in user still pins the bit (wipe skipped, gate closed)", async () => {
    await applyOrgOfflineCachePolicy(false, null);
    expect(orgOfflineCacheDisallowed()).toBe(true);
    expect(webCacheEnabled()).toBe(false);
  });
});

describe("persist() request — §B.5", () => {
  it("ensureCachePersistenceRequested asks exactly once per device (marker-deduped)", async () => {
    const persist = vi.fn(async () => true);
    vi.stubGlobal("navigator", { storage: { persist } });

    ensureCachePersistenceRequested();
    await Promise.resolve(); // let the fire-and-forget land
    ensureCachePersistenceRequested();
    ensureCachePersistenceRequested();
    await Promise.resolve();

    expect(persist).toHaveBeenCalledTimes(1);
    expect(localStorage.getItem("andvari.persistRequested")).not.toBeNull();
  });

  it("is safe without the StorageManager API — no throw, and NO marker (a later browser still asks)", async () => {
    vi.stubGlobal("navigator", {}); // no .storage
    expect(await requestCachePersistence()).toBe(false);
    ensureCachePersistenceRequested(); // must not throw either
    expect(localStorage.getItem("andvari.persistRequested")).toBeNull();
  });

  it("a rejecting persist() reads as not-granted, never an unhandled rejection", async () => {
    vi.stubGlobal("navigator", { storage: { persist: async () => Promise.reject(new Error("nope")) } });
    expect(await requestCachePersistence()).toBe(false);
  });
});

describe("offlineCopyStamp — the §E.3.4 Unlock transparency probe", () => {
  it("returns null when no cache DB exists — and the probe CREATES nothing", async () => {
    expect(await offlineCopyStamp(UID)).toBeNull();
    // Not just "our DB absent" — NO andvari-vault-* DB exists at all: the probe's open-and-abort
    // rolled the creation back entirely (F1: the probe must never mint a DB).
    const list = await (g.indexedDB as unknown as { databases: () => Promise<{ name?: string }[]> }).databases();
    expect(list.filter((d) => d.name?.startsWith("andvari-vault-"))).toEqual([]);
  });

  it("a stale exists-signal cannot mint a DB — the wipe-races-probe TOCTOU (S5 review F1)", async () => {
    // The pre-F1 shape checked existence (indexedDB.databases()) and THEN did a CREATING open —
    // a concurrent wipe (org-policy flip / sign-out) landing between the two deleted the DB and
    // the re-open minted an empty owner-stamped husk on a device where caching was just
    // forbidden. Simulate the losing side of that race: databases() REPORTS the DB present while
    // it is actually gone. The probe must be non-creating END-TO-END: null, and no DB minted.
    const f = g.indexedDB as unknown as { databases: () => Promise<{ name?: string }[]> };
    const real = f.databases;
    f.databases = async () => [{ name: vaultDbName(UID) }]; // the pre-wipe world view
    try {
      expect(await offlineCopyStamp(UID)).toBeNull();
    } finally {
      f.databases = real;
    }
    expect(await dbExists(UID)).toBe(false); // no husk (kv:userId/createdAt never stamped)
  });

  it("returns the stamp when a durable copy exists (accountKeys cached, lastSyncAt set)", async () => {
    const cache = await openVaultCache(UID);
    await cache.setAccountKeys(keys());
    await cache.applyPull((b) => {
      b.setCursor(7);
      b.setLastSyncAt(1_720_900_000_000);
    });
    cache.close();

    expect(await offlineCopyStamp(UID)).toEqual({ lastSyncAt: 1_720_900_000_000 });
  });

  it("a cache with keys but no sync yet stamps lastSyncAt null (line reads 'not yet')", async () => {
    await seedCache();
    expect(await offlineCopyStamp(UID)).toEqual({ lastSyncAt: null });
  });

  it("an EMPTY husk DB (no keys, no stamp) reads as null — nothing there to disclose", async () => {
    const cache = await openVaultCache(UID); // creates the DB with only the kv:userId row
    cache.close();
    expect(await offlineCopyStamp(UID)).toBeNull();
  });

  it("returns null after a wipe (sign-out / policy-off leaves no copy to announce)", async () => {
    await seedCache();
    expect(await offlineCopyStamp(UID)).not.toBeNull();
    await setOfflineCopyEnabled(UID, false);
    expect(await offlineCopyStamp(UID)).toBeNull();
    expect(await dbExists(UID)).toBe(false); // and probing the wiped account re-created nothing (F1)
  });
});
