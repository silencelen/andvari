import "fake-indexeddb/auto";
import { IDBFactory as FakeIDBFactory } from "fake-indexeddb";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AccountKeys, KdfParams, Mutation } from "../api/types";
import { openVaultCache, vaultDbName } from "../vault/idbcache";
import {
  applyOrgOfflineCachePolicy,
  declineCacheNudge,
  ensureCachePersistenceRequested,
  migrateCacheConsentOnce,
  offlineCopyStamp,
  orgOfflineCacheDisallowed,
  requestCachePersistence,
  setOfflineCopyEnabled,
  shouldOfferCacheNudge,
  webCacheEnabled,
} from "./session";

/**
 * S5 unit suite (design 2026-07-13-web-offline-cache §E.3/§E.4/§B.5) as amended by the
 * endpoint-agnostic pivot (design 2026-07-15 §5.4.1 — origin.ts deleted): the settings-surface
 * seams in session.ts —
 *  - the CONSENT-KEYED webCacheEnabled(userId) gate: `idbUsable && !orgCacheOff && !deviceOptOut
 *    && deviceOptIn(userId)` — default OFF on every origin, per-(device, user) opt-in only;
 *  - setOfflineCopyEnabled (§E.3.2 toggle): OFF wipes immediately + pins the opt-out marker
 *    (the gate blocks re-creation); ON pins the opt-in UNCONDITIONALLY (no origin guard) +
 *    requests persist();
 *  - migrateCacheConsentOnce (§5.4.1 continuity): the one-time boot migration adopting a
 *    pre-pivot cache into an explicit opt-in;
 *  - shouldOfferCacheNudge / declineCacheNudge (B2-11): the one-time origin-move nudge formula;
 *  - applyOrgOfflineCachePolicy (§E.4 policy row): false force-wipes (QUEUE included) + pins
 *    the last-known bit so an OFFLINE boot honors it; true clears the pin;
 *  - requestCachePersistence / ensureCachePersistenceRequested (§B.5): requested once,
 *    marker-deduped, safe without the API;
 *  - offlineCopyStamp (§E.3.4 Unlock transparency line): non-null ONLY with a real cache, and
 *    the probe itself NEVER creates a DB.
 */

const g = globalThis as { indexedDB?: IDBFactory };

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
const OPT_IN = `andvari.cacheOptIn.${UID}`;
const OPT_OUT = "andvari.cacheOptOut";
const ORG_OFF = "andvari.orgCacheOff";
const MIGRATED = "andvari.cacheConsentMigrated"; // PREFIX — the live flag is per-user: `${MIGRATED}.${userId}`
const migratedKey = (uid: string): string => `${MIGRATED}.${uid}`;
const optInKeyFor = (uid: string): string => `andvari.cacheOptIn.${uid}`;

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
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("webCacheEnabled — the consent-keyed §F.1 gate (§5.4.1: org bit > opt-out > per-user opt-in, NO origin)", () => {
  it("no markers → OFF: default OFF for every device, user, and origin", () => {
    expect(webCacheEnabled(UID)).toBe(false);
  });

  it("the explicit per-(device, user) opt-in turns it ON", () => {
    localStorage.setItem(OPT_IN, "1");
    expect(webCacheEnabled(UID)).toBe(true);
  });

  it("one user's opt-in never enables another user on the same browser", () => {
    localStorage.setItem(OPT_IN, "1");
    expect(webCacheEnabled("someone-else")).toBe(false);
  });

  it("the device opt-out beats an opt-in", () => {
    localStorage.setItem(OPT_IN, "1");
    localStorage.setItem(OPT_OUT, "1");
    expect(webCacheEnabled(UID)).toBe(false);
  });

  it("the org policy pin beats EVERYTHING (§E.4)", () => {
    localStorage.setItem(OPT_IN, "1");
    localStorage.setItem(ORG_OFF, "1");
    expect(webCacheEnabled(UID)).toBe(false);
    expect(orgOfflineCacheDisallowed()).toBe(true);
  });

  it("the legacy device-wide opt-in key (pre-pivot public-origin marker) is dead — it enables nothing", () => {
    localStorage.setItem("andvari.cacheOptIn", "1");
    expect(webCacheEnabled(UID)).toBe(false);
  });
});

describe("setOfflineCopyEnabled — the §E.3.2 per-device toggle (consent-keyed, origin-free)", () => {
  it("OFF wipes the cache DB immediately, pins the opt-out, drops this user's opt-in, and the gate blocks re-creation", async () => {
    localStorage.setItem(OPT_IN, "1"); // an opted-in device with a standing cache
    await seedCache();
    expect(await dbExists(UID)).toBe(true);

    await setOfflineCopyEnabled(UID, false);

    expect(await dbExists(UID)).toBe(false); // wiped — envelopes, queue, accountKeys, everything
    expect(localStorage.getItem(OPT_OUT)).not.toBeNull(); // pinned for the gate
    expect(localStorage.getItem(OPT_IN)).toBeNull(); // no stale opt-in survives the round-trip
    expect(webCacheEnabled(UID)).toBe(false); // the next unlock's gated factory returns NullCache
  });

  it("ON pins the opt-in UNCONDITIONALLY (the old !isPrivateOrigin guard is gone), clears the opt-out, requests persist()", async () => {
    localStorage.setItem(OPT_OUT, "1");
    const persist = vi.fn(async () => true);
    vi.stubGlobal("navigator", { storage: { persist } });

    await setOfflineCopyEnabled(UID, true);

    expect(localStorage.getItem(OPT_OUT)).toBeNull();
    expect(localStorage.getItem(OPT_IN)).not.toBeNull(); // written on EVERY origin — §5.4.1
    expect(webCacheEnabled(UID)).toBe(true);
    expect(persist).toHaveBeenCalledTimes(1); // an explicit gesture — always re-requests
    expect(await dbExists(UID)).toBe(false); // creation stays with the next unlock/sign-in — ON creates nothing
  });
});

describe("migrateCacheConsentOnce — §5.4.1 continuity (a standing pre-pivot cache becomes an explicit opt-in)", () => {
  it("an existing cache DB with no opt-out marker writes the opt-in marker — offline access survives the flip", async () => {
    await seedCache(); // the pre-pivot private-origin default-ON cache (no marker anywhere)
    expect(webCacheEnabled(UID)).toBe(false); // the new gate alone would strand it…

    await migrateCacheConsentOnce(UID);

    expect(localStorage.getItem(OPT_IN)).not.toBeNull(); // …but continuity adopts it
    expect(webCacheEnabled(UID)).toBe(true);
    expect(localStorage.getItem(migratedKey(UID))).not.toBeNull();
    expect(await dbExists(UID)).toBe(true); // adoption never touches the cache itself
  });

  it("no standing cache ⇒ no opt-in — the new default (OFF) stands for fresh devices", async () => {
    await migrateCacheConsentOnce(UID);
    expect(localStorage.getItem(OPT_IN)).toBeNull();
    expect(localStorage.getItem(migratedKey(UID))).not.toBeNull(); // still evaluated + burned
    expect(webCacheEnabled(UID)).toBe(false);
  });

  it("an empty husk DB (no keys, no stamp) grandfathers nothing — offlineCopyStamp is the probe", async () => {
    const cache = await openVaultCache(UID); // mints the DB with only the kv:userId row
    cache.close();
    await migrateCacheConsentOnce(UID);
    expect(localStorage.getItem(OPT_IN)).toBeNull();
  });

  it("an explicit opt-out always wins — never resurrected by a leftover cache DB", async () => {
    await seedCache();
    localStorage.setItem(OPT_OUT, "1");
    await migrateCacheConsentOnce(UID);
    expect(localStorage.getItem(OPT_IN)).toBeNull();
    expect(webCacheEnabled(UID)).toBe(false);
  });

  it("is ONE-TIME per user: the same user's second boot changes nothing even if conditions changed", async () => {
    await migrateCacheConsentOnce(UID); // fresh device — burns this user's one shot
    await seedCache(); // a cache appears later (post-pivot, e.g. after a real opt-in was withdrawn oddly)
    await migrateCacheConsentOnce(UID);
    expect(localStorage.getItem(OPT_IN)).toBeNull(); // no second evaluation
  });

  it("is per-USER, not per-device: a second account on a shared browser still migrates its own standing cache", async () => {
    const UID2 = "user-s6";
    await seedCache(UID); // account A had a pre-pivot cache
    await migrateCacheConsentOnce(UID); // A boots first — adopts + burns A's flag only
    expect(localStorage.getItem(OPT_IN)).not.toBeNull();

    await seedCache(UID2); // account B on the SAME browser also has a standing cache
    await migrateCacheConsentOnce(UID2); // must NOT be blocked by A's device-wide flag (the bug)
    expect(localStorage.getItem(optInKeyFor(UID2))).not.toBeNull(); // B keeps offline access too
    expect(localStorage.getItem(migratedKey(UID2))).not.toBeNull();
  });

  it("a signed-out boot does NOT burn the one shot — the signed-in boot after it still migrates", async () => {
    await migrateCacheConsentOnce(null); // App boots signed out
    expect(localStorage.getItem(migratedKey(UID))).toBeNull(); // nothing evaluated, nothing burned
    await seedCache();
    await migrateCacheConsentOnce(UID); // next boot, signed in
    expect(localStorage.getItem(OPT_IN)).not.toBeNull();
  });

  it("drops the dead legacy device-wide opt-in key", async () => {
    localStorage.setItem("andvari.cacheOptIn", "1");
    await migrateCacheConsentOnce(UID);
    expect(localStorage.getItem("andvari.cacheOptIn")).toBeNull();
  });
});

describe("shouldOfferCacheNudge / declineCacheNudge — the B2-11 one-time origin-move nudge", () => {
  it("fires when policy allows and NO per-device marker exists (the unanswered state)", () => {
    expect(shouldOfferCacheNudge(UID)).toBe(true);
  });

  it("never fires where the org forbids caching (§E.4 pin)", () => {
    localStorage.setItem(ORG_OFF, "1");
    expect(shouldOfferCacheNudge(UID)).toBe(false);
  });

  it("never fires on a device that declined (opt-out marker) — asked once, answered once", () => {
    declineCacheNudge();
    expect(localStorage.getItem(OPT_OUT)).not.toBeNull();
    expect(shouldOfferCacheNudge(UID)).toBe(false);
    expect(webCacheEnabled(UID)).toBe(false); // and the gate stays closed
  });

  it("never fires once THIS user opted in — but a second user on the device gets their own one ask", async () => {
    await setOfflineCopyEnabled(UID, true); // the accept path writes the opt-in
    expect(shouldOfferCacheNudge(UID)).toBe(false);
    expect(shouldOfferCacheNudge("someone-else")).toBe(true); // consent is per-user (§5.4.1)
  });

  it("accept ⇒ gate ON; the settings toggle remains the way back after a decline", async () => {
    declineCacheNudge();
    await setOfflineCopyEnabled(UID, true); // toggle ON clears the opt-out (§E.3.2)
    expect(webCacheEnabled(UID)).toBe(true);
    expect(shouldOfferCacheNudge(UID)).toBe(false);
  });
});

describe("applyOrgOfflineCachePolicy — the §E.4 policy row", () => {
  it("offlineCacheAllowed=false force-wipes (QUEUE included) and pins the last-known bit", async () => {
    localStorage.setItem(OPT_IN, "1"); // an opted-in device — policy-false must beat consent
    await seedCache(UID, [mut("q1"), mut("q2")]); // two unsynced offline edits in the queue
    expect(await dbExists(UID)).toBe(true);

    await applyOrgOfflineCachePolicy(false, UID);

    expect(await dbExists(UID)).toBe(false); // deleteDatabase — the queue died with it (server-initiated)
    expect(orgOfflineCacheDisallowed()).toBe(true);
    expect(webCacheEnabled(UID)).toBe(false); // refuses future cache creation despite the opt-in…
    const reopened = await openVaultCache(UID); // …and a gate-bypassing reopen proves the rows are GONE
    expect(await reopened.accountKeys()).toBeNull();
    expect(await reopened.pending()).toEqual([]);
    reopened.close();
  });

  it("the pin is honored on OFFLINE boot: no fetch needed for the gate to stay closed", async () => {
    // A PREVIOUS session saw policy=false (marker persisted); this boot fetches nothing.
    localStorage.setItem(ORG_OFF, "1");
    localStorage.setItem(OPT_IN, "1");
    expect(webCacheEnabled(UID)).toBe(false); // consent notwithstanding
  });

  it("offlineCacheAllowed=true clears the pin and never touches the cache — and alone enables NOTHING", async () => {
    localStorage.setItem(ORG_OFF, "1");
    await seedCache();
    await applyOrgOfflineCachePolicy(true, UID);
    expect(orgOfflineCacheDisallowed()).toBe(false);
    expect(webCacheEnabled(UID)).toBe(false); // §2.3: true is necessary but never sufficient — no consent yet
    localStorage.setItem(OPT_IN, "1");
    expect(webCacheEnabled(UID)).toBe(true); // consent + allowance together
    expect(await dbExists(UID)).toBe(true); // allowed ⇒ nothing wiped, nothing created
  });

  it("false with no signed-in user still pins the bit (wipe skipped, gate closed)", async () => {
    await applyOrgOfflineCachePolicy(false, null);
    expect(orgOfflineCacheDisallowed()).toBe(true);
    expect(webCacheEnabled(UID)).toBe(false);
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
