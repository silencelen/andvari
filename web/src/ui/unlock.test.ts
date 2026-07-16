import "fake-indexeddb/auto";
import { IDBFactory as FakeIDBFactory } from "fake-indexeddb";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, type ApiClient } from "../api/client";
import type { AccountKeys, Mutation, SyncResponse, WireGrant, WireItem, WireVault } from "../api/types";
import { toB64 } from "../crypto/bytes";
import { fingerprint } from "../crypto/escrow";
import { KdfPolicyError, WEAK_KDF_MESSAGE, type KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account, IdentityMismatchError } from "../vault/account";
import { NullCache, openVaultCache, type VaultCache } from "../vault/idbcache";
import { SyncIntegrityError, VaultStore } from "../vault/store";
import { UNREACHABLE } from "./errors";
import { refreshCachedAccountKeys, wipeVaultCache } from "./session";
import { unlockExistingSession } from "./unlock";

/**
 * S3 unit suite (design 2026-07-13-web-offline-cache §C offline unlock + §D.2c accountKeys
 * caching + §E.4 wipe): the returning-session unlock seam {@link unlockExistingSession} driven
 * with the REAL Account crypto + a REAL IdbVaultCache over fake-indexeddb, the same posture as
 * store.cache.test.ts. Because the node-env/renderToStaticMarkup harness cannot drive a React
 * form, the whole flow lives in this seam and is tested here (Welcome's Unlock.submit is a thin
 * outcome→state map). Covers: offline fallback on NetworkError ONLY (never 4xx/5xx); the C3 H1
 * floor refusal at cache-READ; the C4 identity hard-fail on a tampered cached identityPub; the
 * C6 nag (offline PROCEEDS with the reminder while the online gate still hard-blocks); the
 * §D.2c online-unlock re-cache; the definitive-401 → `expired` (→ App.signOut wipe); and the
 * §E.4 wipe-by-userId (sign-out/revoked/401 wipe vs lock-retains) + wipe-then-offline cold state.
 *
 * The KDF is AT the H1 floor (64 MiB / ops 3) — the offline path asserts the floor at cache-READ
 * (C3), so a sub-floor test KDF would (correctly) refuse every offline unlock. Enrolled ONCE and
 * reused; each test's own argon2id is a single at-floor derivation.
 */

const g = globalThis as { indexedDB?: IDBFactory; window?: { location: { origin: string } } };

/** Origin stubs kept ONLY to prove the gate is origin-INDEPENDENT now (design 2026-07-15 §5.4.1:
 *  webCacheEnabled is consent-keyed — `idbUsable && !orgCacheOff && !deviceOptOut &&
 *  deviceOptIn(userId)` — and never reads window.location). */
const TAILNET_ORIGIN = "https://andvari.example.net";
const PUBLIC_ORIGIN = "https://andvari.monahanhosting.com";
function setOrigin(origin: string): void {
  g.window = { location: { origin } };
}

/** Map-backed localStorage for the node test environment — the consent markers need a store. */
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

/** §5.4.1: write base.userId's per-(device, user) opt-in — the ONLY thing that turns the gate on. */
function optIn(): void {
  localStorage.setItem(`andvari.cacheOptIn.${base.userId}`, "1");
}

const AT_FLOOR_KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 };
const SUB_FLOOR_KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };
const DOC = { type: "login", name: "Seed login", login: { username: "fam", password: "hunter2" } } as const;

interface Base {
  userId: string;
  password: string;
  /** Floor-good AccountKeys; `recoveryConfirmed` deliberately UNSET (enroll doesn't set it) so
   *  needsRecoveryCapture is true by default — each test opts into confirmed where it matters. */
  keys: AccountKeys;
  account: Account;
  personalVault: WireVault;
  personalGrant: WireGrant;
}

let base: Base;

beforeAll(async () => {
  await initSodium();
  const recovery = boxKeypairFromSeed(randomBytes(32));
  const password = "correct horse battery staple";
  const { request, account } = await Account.enroll({
    inviteToken: "test-invite",
    email: "fam@example.com",
    displayName: "fam",
    password,
    kdfParams: AT_FLOOR_KDF,
    recoveryPublicKey: recovery.publicKey,
    recoveryFingerprint: await fingerprint(recovery.publicKey),
  });
  base = {
    userId: account.userId,
    password,
    keys: {
      kdfSalt: request.kdfSalt,
      kdfParams: request.kdfParams,
      wrappedUvk: request.wrappedUvk,
      encryptedIdentitySeed: request.encryptedIdentitySeed,
      identityPub: request.identityPub,
      escrowFingerprint: request.escrow!.fingerprint,
    },
    account,
    personalVault: { vaultId: request.personalVault.vaultId, type: "personal", rev: 1, metaBlob: request.personalVault.metaBlob, createdAt: 0 },
    personalGrant: { vaultId: request.personalVault.vaultId, userId: account.userId, role: "owner", wrappedVk: request.personalVault.wrappedVk, rev: 1, sealedVk: null },
  };
});

// A fresh IDB universe + marker store per test — no cache DB or consent bleeds between cases.
// Default the suite to an OPTED-IN device (§5.4.1: the per-user opt-in marker is what the old
// private-origin default used to be) so the §F.1 dark-ship gate enables the durable cache exactly
// as a consented device; the gate tests below drop the marker per-case.
beforeEach(() => {
  g.indexedDB = new FakeIDBFactory();
  setOrigin(TAILNET_ORIGIN);
  vi.stubGlobal("localStorage", fakeStorage());
  optIn();
});

const confirmed = (): AccountKeys => ({ ...base.keys, recoveryConfirmed: true });

const emptyFull = async (since: number): Promise<SyncResponse> => ({ rev: 1, full: since === 0, vaults: [], grants: [], items: [], removedGrants: [] });
const offlineSync = async (): Promise<SyncResponse> => { throw new TypeError("offline — no server"); };

/** A minimal ApiClient: only accountKeys/sync/push are reached by the unlock flow + store. */
function fakeClient(opts: { accountKeys: () => Promise<AccountKeys>; sync?: (since: number) => Promise<SyncResponse> }): ApiClient {
  return {
    accountKeys: opts.accountKeys,
    sync: opts.sync ?? emptyFull,
    push: async (muts: Mutation[]) => ({ rev: 1, results: muts.map((m) => ({ mutationId: m.mutationId, status: "applied" as const, newItemRev: 1 })) }),
  } as unknown as ApiClient;
}

/** Plant a cached accountKeys payload (a prior online session's write point), then release the
 *  connection so the unlock flow opens its own. */
async function plantKeys(keys: AccountKeys): Promise<void> {
  const cache = await openVaultCache(base.userId);
  await cache.setAccountKeys(keys);
  cache.close();
}

/** Seed a FULL offline cache the way a prior online session would: rows via a real store.sync()
 *  through the cache, PLUS the accountKeys write point. Returns the seeded itemId. */
async function seedFullCache(keys: AccountKeys = confirmed()): Promise<string> {
  const cache = await openVaultCache(base.userId);
  const itemId = base.account.newItemId();
  const item: WireItem = {
    itemId,
    vaultId: base.personalVault.vaultId,
    rev: 2,
    createdAt: 0,
    updatedAt: 0,
    deleted: false,
    conflict: false,
    formatVersion: 1,
    attachmentIds: [],
    blob: base.account.encryptItem(base.personalVault.vaultId, itemId, DOC).blob,
  };
  const seedClient = fakeClient({
    accountKeys: async () => keys,
    sync: async (since) => ({ rev: 3, full: since === 0, vaults: [base.personalVault], grants: [base.personalGrant], items: [item], removedGrants: [] }),
  });
  const store = new VaultStore(seedClient, base.account, cache);
  await store.sync(); // writes envelopes + cursor to disk (S2 cache-through)
  await cache.setAccountKeys(keys); // §D.2c write point
  cache.close();
  return itemId;
}

const reopen = (): Promise<VaultCache> => openVaultCache(base.userId);

describe("unlockExistingSession — online path (§C.1 step 1)", () => {
  it("online success returns ready and re-caches accountKeys (§D.2c write point)", async () => {
    const client = fakeClient({ accountKeys: async () => confirmed() });
    const r = await unlockExistingSession(client, { userId: base.userId, isAdmin: false }, base.password);
    expect(r.kind).toBe("ready");
    if (r.kind !== "ready") return;
    expect(r.meta.offlineRecoveryReminder).toBe(false); // never nags on the online path
    // The online unlock wrote the fresh payload to the durable cache (a later offline unlock can use it).
    const c = await reopen();
    expect(await c.accountKeys()).toMatchObject({ wrappedUvk: base.keys.wrappedUvk });
    c.close();
  });

  it("online + recoveryConfirmed !== true → CAPTURE (the online gate still hard-blocks)", async () => {
    // base.keys leaves recoveryConfirmed unset → needsRecoveryCapture true.
    const client = fakeClient({ accountKeys: async () => base.keys });
    const r = await unlockExistingSession(client, { userId: base.userId, isAdmin: false }, base.password);
    expect(r.kind).toBe("capture"); // NOT ready — online never rides the C6 nag
    if (r.kind !== "capture") return;
    expect(r.currentAuthKey).toBeTruthy();
  });

  it("a definitive 401 from accountKeys → expired (routes through App.signOut → §E.4 wipe), NOT offline", async () => {
    await plantKeys(confirmed()); // cache HAS keys — a server answer must still never fall back
    const client = fakeClient({ accountKeys: async () => { throw new ApiError(401, "unauthorized", "no"); } });
    const r = await unlockExistingSession(client, { userId: base.userId, isAdmin: false }, base.password);
    expect(r.kind).toBe("expired");
  });

  it("a 5xx from accountKeys keeps the server-problem copy, NOT offline fallback", async () => {
    await plantKeys(confirmed());
    const client = fakeClient({ accountKeys: async () => { throw new ApiError(503, "server_error", "boom"); } });
    const r = await unlockExistingSession(client, { userId: base.userId, isAdmin: false }, base.password);
    expect(r.kind).toBe("error");
    if (r.kind !== "error") return;
    expect(r.message).toMatch(/server had a problem/i);
  });

  it("S3-4a — a 200-empty (undefined) accountKeys body is a SERVER answer, NOT an offline fallback", async () => {
    // ApiClient.json() returns undefined for an empty 2xx body; a hostile server answering 200-empty
    // must NOT route to the OFFLINE cached branch ("a server-answered response never falls back").
    await seedFullCache(confirmed()); // cache HAS keys — the fallback must still be refused
    const client = fakeClient({ accountKeys: async () => undefined as unknown as AccountKeys, sync: offlineSync });
    const r = await unlockExistingSession(client, { userId: base.userId, isAdmin: false }, base.password);
    expect(r.kind).toBe("error");
    if (r.kind !== "error") return;
    expect(r.message).toMatch(/server had a problem/i); // server problem copy, not an offline unlock
  });

  it("an online weak-KDF (KdfPolicyError) surfaces WEAK_KDF_MESSAGE (H1)", async () => {
    const client = fakeClient({ accountKeys: async () => { throw new KdfPolicyError("kdf_below_floor", SUB_FLOOR_KDF); } });
    const r = await unlockExistingSession(client, { userId: base.userId, isAdmin: false }, base.password);
    expect(r).toEqual({ kind: "error", message: WEAK_KDF_MESSAGE });
  });

  it("a SyncIntegrityError on the first (delta) sync is non-fatal — proceeds to ready (§D.6)", async () => {
    // With a disk-restored cursor the first sync is a DELTA, so the F31 guards can trip
    // cross-session; state is kept + coherent, so the unlock must PROCEED (offline dot surfaces it).
    const client = fakeClient({ accountKeys: async () => confirmed(), sync: async () => { throw new SyncIntegrityError("rev went backwards"); } });
    const r = await unlockExistingSession(client, { userId: base.userId, isAdmin: false }, base.password);
    expect(r.kind).toBe("ready");
  });
});

describe("unlockExistingSession — offline fallback (§C.1 step 2, NetworkError ONLY)", () => {
  it("NetworkError + cached keys → offline unlock succeeds and restores the vault via hydrate", async () => {
    const itemId = await seedFullCache(confirmed());
    const client = fakeClient({ accountKeys: async () => { throw new TypeError("offline"); }, sync: offlineSync });
    const r = await unlockExistingSession(client, { userId: base.userId, isAdmin: false }, base.password);
    expect(r.kind).toBe("ready");
    if (r.kind !== "ready") return;
    expect(r.meta.offlineRecoveryReminder).toBe(false); // confirmed → no nag
    // §D.4 hydrate rebuilt the working set from cached envelopes — the seeded item is listable offline.
    expect(r.store.list().map((i) => i.itemId)).toContain(itemId);
  });

  it("NetworkError but NO cached keys → today's cold UNREACHABLE copy (no offline unlock)", async () => {
    const client = fakeClient({ accountKeys: async () => { throw new TypeError("offline"); }, sync: offlineSync });
    const r = await unlockExistingSession(client, { userId: base.userId, isAdmin: false }, base.password);
    expect(r).toEqual({ kind: "error", message: UNREACHABLE });
  });

  it("C3 — planted WEAK cached kdfParams refuse offline unlock (fail closed → WEAK_KDF_MESSAGE)", async () => {
    // First-write of a sub-floor payload is allowed by setAccountKeys (no good payload to keep) —
    // exactly the disk-tamper the C3 read-time assert is the belt for.
    await plantKeys({ ...confirmed(), kdfParams: SUB_FLOOR_KDF });
    const client = fakeClient({ accountKeys: async () => { throw new TypeError("offline"); }, sync: offlineSync });
    const r = await unlockExistingSession(client, { userId: base.userId, isAdmin: false }, base.password);
    expect(r).toEqual({ kind: "error", message: WEAK_KDF_MESSAGE });
  });

  it("C4 — a tampered cached identityPub hard-fails as tampering, never softened to wrong-password", async () => {
    await plantKeys({ ...confirmed(), identityPub: toB64(randomBytes(32)) }); // floor-good params, wrong identity
    const client = fakeClient({ accountKeys: async () => { throw new TypeError("offline"); }, sync: offlineSync });
    const r = await unlockExistingSession(client, { userId: base.userId, isAdmin: false }, base.password);
    expect(r.kind).toBe("error");
    if (r.kind !== "error") return;
    expect(r.message).toBe(new IdentityMismatchError().message);
    expect(r.message).not.toMatch(/wrong master password/i);
  });

  it("a wrong password on the offline path is 'wrong master password' (UVK unwrap fails)", async () => {
    await plantKeys(confirmed());
    const client = fakeClient({ accountKeys: async () => { throw new TypeError("offline"); }, sync: offlineSync });
    const r = await unlockExistingSession(client, { userId: base.userId, isAdmin: false }, "not the password");
    expect(r).toEqual({ kind: "error", message: "Wrong master password." });
  });

  it("C6 — an offline unlock with cached recoveryConfirmed !== true PROCEEDS with the nag flag", async () => {
    await seedFullCache(base.keys); // recoveryConfirmed unset
    const client = fakeClient({ accountKeys: async () => { throw new TypeError("offline"); }, sync: offlineSync });
    const r = await unlockExistingSession(client, { userId: base.userId, isAdmin: false }, base.password);
    expect(r.kind).toBe("ready"); // never blocks
    if (r.kind !== "ready") return;
    expect(r.meta.offlineRecoveryReminder).toBe(true); // the persistent in-vault reminder
  });
});

describe("§E.4 wipe-by-userId (wipeVaultCache) + cold state", () => {
  it("wipeVaultCache deletes envelopes AND cached accountKeys (sign-out/revoked/401 row)", async () => {
    await seedFullCache(confirmed());
    // seeded: both present
    let c = await reopen();
    expect(await c.accountKeys()).not.toBeNull();
    expect((await c.envelopes()).length).toBeGreaterThan(0);
    c.close();

    await wipeVaultCache(base.userId);

    // wiped: a fresh open sees a cold DB (no keys, no rows)
    c = await reopen();
    expect(await c.accountKeys()).toBeNull();
    expect(await c.envelopes()).toEqual([]);
    c.close();
  });

  it("wipe completes while a sibling cache connection is OPEN (real sign-out-from-vault path)", async () => {
    // The vault's live store still holds a cache connection when the user signs out; wipeVaultCache
    // opens its own and deleteDatabase makes the sibling self-close (onversionchange, idbcache §D.5.3).
    const live = await openVaultCache(base.userId);
    await live.setAccountKeys(confirmed());
    await live.upsertItem({ itemId: "x", vaultId: "v", rev: 1, createdAt: 0, updatedAt: 0, deleted: false, conflict: false, formatVersion: 1, attachmentIds: [], blob: "AAAA" });
    // `live` stays open on purpose.
    await wipeVaultCache(base.userId);
    const c = await reopen();
    expect(await c.accountKeys()).toBeNull();
    expect(await c.envelopes()).toEqual([]);
    c.close();
  });

  it("LOCK retains the cache — NOT calling wipe leaves keys + rows intact", async () => {
    await seedFullCache(confirmed());
    // A lock never calls wipeVaultCache (App.lock keeps the session + cache); the data survives.
    const c = await reopen();
    expect(await c.accountKeys()).not.toBeNull();
    expect((await c.envelopes()).length).toBeGreaterThan(0);
    c.close();
  });

  it("wipe-then-offline-unlock falls back to the password-only cold state (UNREACHABLE)", async () => {
    await seedFullCache(confirmed());
    await wipeVaultCache(base.userId); // e.g. a definitive-401 wipe
    const client = fakeClient({ accountKeys: async () => { throw new TypeError("offline"); }, sync: offlineSync });
    const r = await unlockExistingSession(client, { userId: base.userId, isAdmin: false }, base.password);
    // Cache is gone → no cached keys → cannot offline-unlock → today's cold copy.
    expect(r).toEqual({ kind: "error", message: UNREACHABLE });
  });

  it("S3-1 — a SignIn-seeded cache is WIPED on the capture-gate sign-out (shared-computer leak)", async () => {
    // SignIn.submit seeds the durable cache (openVaultCache + setAccountKeys + hydrate + sync) BEFORE
    // the recovery-capture gate mounts; seedFullCache reproduces exactly that write set. recoveryConfirmed
    // is UNSET, so on a real sign-in the gate WOULD mount — and its onSignOut (App.signOut is unreachable
    // there) is the fixed path: it must wipe by userId, or crackable ciphertext + the email linger forever.
    await seedFullCache(base.keys); // recoveryConfirmed unset → the gate would mount
    let c = await reopen();
    expect(await c.accountKeys()).not.toBeNull();
    expect((await c.envelopes()).length).toBeGreaterThan(0);
    c.close();

    // The fixed SignIn capture-gate onSignOut: clearSession + setTokens(null) + wipeVaultCache(uid).
    await wipeVaultCache(base.userId);

    c = await reopen();
    expect(await c.accountKeys()).toBeNull();
    expect(await c.envelopes()).toEqual([]);
    c.close();
  });
});

describe("§F.1 dark-ship gate — CONSENT-keyed, origin-independent (design 2026-07-15 §5.4.1)", () => {
  it("an opted-in device stands up a DURABLE cache — even on the public origin (origin is just an address)", async () => {
    setOrigin(PUBLIC_ORIGIN); // would have been NullCache under the deleted origin heuristic
    const client = fakeClient({ accountKeys: async () => confirmed() });
    const r = await unlockExistingSession(client, { userId: base.userId, isAdmin: false }, base.password);
    expect(r.kind).toBe("ready");
    if (r.kind !== "ready") return;
    expect(r.store.cacheDurable).toBe(true); // durable IndexedDB cache attached
    // …and the online re-cache wrote to a real DB a later offline unlock could read.
    const c = await reopen();
    expect(await c.accountKeys()).not.toBeNull();
    c.close();
  });

  it("WITHOUT the opt-in the unlock uses a NullCache — even on the tailnet origin (the old private default is GONE)", async () => {
    setOrigin(TAILNET_ORIGIN);
    localStorage.removeItem(`andvari.cacheOptIn.${base.userId}`); // a fresh, never-asked device
    const client = fakeClient({ accountKeys: async () => confirmed() });
    const r = await unlockExistingSession(client, { userId: base.userId, isAdmin: false }, base.password);
    expect(r.kind).toBe("ready");
    if (r.kind !== "ready") return;
    expect(r.store.cacheDurable).toBe(false); // no consent → NullCache, default OFF everywhere
    // Nothing was persisted by the gated unlock: a fresh open (reopen bypasses the gate) sees a cold DB.
    const c = await reopen();
    expect(await c.accountKeys()).toBeNull();
    expect(await c.envelopes()).toEqual([]);
    c.close();
  });

  it("another user's opt-in is NOT this user's consent (per-(device, user) marker)", async () => {
    localStorage.removeItem(`andvari.cacheOptIn.${base.userId}`);
    localStorage.setItem("andvari.cacheOptIn.somebody-else", "1");
    const client = fakeClient({ accountKeys: async () => confirmed() });
    const r = await unlockExistingSession(client, { userId: base.userId, isAdmin: false }, base.password);
    expect(r.kind).toBe("ready");
    if (r.kind !== "ready") return;
    expect(r.store.cacheDurable).toBe(false);
  });
});

describe("§D.2c refreshCachedAccountKeys after changePassword (S3-2)", () => {
  it("overwrites the cached accountKeys so the cached wrappedUvk changes post-change", async () => {
    await plantKeys(base.keys); // a prior online session cached the OLD payload
    const before = await reopen();
    expect((await before.accountKeys())?.wrappedUvk).toBe(base.keys.wrappedUvk);
    before.close();

    // After changePassword the client returns the NEW accountKeys (a fresh wrappedUvk).
    const newKeys: AccountKeys = { ...base.keys, wrappedUvk: toB64(randomBytes(48)) };
    const client = fakeClient({ accountKeys: async () => newKeys });
    await refreshCachedAccountKeys(client, base.userId);

    const after = await reopen();
    const cached = await after.accountKeys();
    expect(cached?.wrappedUvk).toBe(newKeys.wrappedUvk);
    expect(cached?.wrappedUvk).not.toBe(base.keys.wrappedUvk); // the T3 stale-wrap window is closed
    after.close();
  });

  it("is a no-op without this user's consent — never CREATES a cache where caching is off", async () => {
    localStorage.removeItem(`andvari.cacheOptIn.${base.userId}`); // non-consented device (any origin)
    const client = fakeClient({ accountKeys: async () => confirmed() });
    await refreshCachedAccountKeys(client, base.userId);
    const c = await reopen(); // reopen (gate-bypassing) makes a fresh empty DB — proving refresh wrote nothing
    expect(await c.accountKeys()).toBeNull();
    c.close();
  });
});

describe("§B.4(iii) runtime cache-failure resilience (S3-4b — never brick the unlock)", () => {
  it("a cache setAccountKeys failure degrades cache-less and STILL unlocks (online)", async () => {
    const client = fakeClient({ accountKeys: async () => confirmed() }); // online success; emptyFull sync
    const brokenWrite: VaultCache = Object.assign(new NullCache(), {
      setAccountKeys: async (): Promise<boolean> => { throw new DOMException("quota", "QuotaExceededError"); },
    });
    const r = await unlockExistingSession(client, { userId: base.userId, isAdmin: false }, base.password, async () => brokenWrite);
    expect(r.kind).toBe("ready"); // the write failure never reaches the outer "server problem" catch
    if (r.kind !== "ready") return;
    expect(r.store.cacheDurable).toBe(false); // degraded to a NullCache and proceeded
  });

  it("a cache hydrate (read) failure is skipped and the unlock STILL proceeds (online)", async () => {
    const client = fakeClient({ accountKeys: async () => confirmed() });
    const brokenRead: VaultCache = Object.assign(new NullCache(), {
      grants: async (): Promise<never> => { throw new DOMException("corrupt", "UnknownError"); }, // hydrate's first read
    });
    const r = await unlockExistingSession(client, { userId: base.userId, isAdmin: false }, base.password, async () => brokenRead);
    expect(r.kind).toBe("ready"); // skip-hydrate + proceed in-memory, never bricked
  });
});

describe("§B.5 (S5) — persist() requested at cache-enable", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("a DURABLE unlock (opted-in device, default gate) requests navigator.storage.persist() exactly once", async () => {
    const persist = vi.fn(async () => true);
    vi.stubGlobal("navigator", { storage: { persist, persisted: async () => true } });
    vi.stubGlobal("localStorage", fakeStorage()); // fresh store for the once-marker…
    optIn(); // …so re-pin this user's consent (§5.4.1)

    const client = fakeClient({ accountKeys: async () => confirmed() });
    const r1 = await unlockExistingSession(client, { userId: base.userId, isAdmin: false }, base.password);
    expect(r1.kind).toBe("ready");
    expect(persist).toHaveBeenCalledTimes(1); // the S4 queue path lights up from here (offlineQueueAllowed)

    // A second unlock on the same device never re-nags (the request marker dedupes).
    const r2 = await unlockExistingSession(client, { userId: base.userId, isAdmin: false }, base.password);
    expect(r2.kind).toBe("ready");
    expect(persist).toHaveBeenCalledTimes(1);
  });

  it("a NullCache unlock (no consent — any origin) never requests persist()", async () => {
    const persist = vi.fn(async () => true);
    vi.stubGlobal("navigator", { storage: { persist, persisted: async () => true } });
    vi.stubGlobal("localStorage", fakeStorage()); // fresh store, NO opt-in marker

    const client = fakeClient({ accountKeys: async () => confirmed() });
    const r = await unlockExistingSession(client, { userId: base.userId, isAdmin: false }, base.password);
    expect(r.kind).toBe("ready");
    expect(persist).not.toHaveBeenCalled(); // nothing durable to protect — and no doorhanger on borrowed machines
  });
});
