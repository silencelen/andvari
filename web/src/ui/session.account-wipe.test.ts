import "fake-indexeddb/auto";
import { IDBFactory as FakeIDBFactory } from "fake-indexeddb";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { AccountKeys } from "../api/types";
import { initSodium } from "../crypto/sodium";
import { openVaultCache, vaultDbName } from "../vault/idbcache";
import { forgetSelfIdentity } from "../vault/selfidentity";
import { isAccountScopedKey, SESSION_STORAGE_KEY, TAB_TOKENS_KEY, wipeLocalAccountState } from "./session";

/**
 * Account deletion, client duty (spec 03 §13; design 2026-11-10 §11): once the server CONFIRMED the deletion, this browser
 * forgets the account — the session and the tab's token slot, every localStorage key scoped to its userId, the spec 01 §5
 * self-identity records (so the address can register again here), and the offline copy — while device-wide settings and
 * every OTHER account's state on a shared browser stay exactly as they were.
 */

const g = globalThis as { indexedDB?: IDBFactory };

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

const GONE = "11111111-1111-4111-8111-111111111111";
const OTHER = "22222222-2222-4222-8222-222222222222";
const PUB = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"; // 32 bytes, base64url

async function dbExists(userId: string): Promise<boolean> {
  const list = await (g.indexedDB as unknown as { databases: () => Promise<{ name?: string }[]> }).databases();
  return list.some((d) => d.name === vaultDbName(userId));
}

async function seedCache(userId: string): Promise<void> {
  const cache = await openVaultCache(userId);
  await cache.setAccountKeys({
    kdfSalt: "c2FsdA",
    kdfParams: { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 },
    wrappedUvk: "wrap",
    encryptedIdentitySeed: "seed",
    identityPub: "pub",
    escrowFingerprint: "fp",
  } as AccountKeys);
  cache.close();
}

/** Everything a signed-in account leaves in localStorage over time, for [userId]. */
function seedAccountKeys(userId: string): string[] {
  const keys = [
    `andvari.cs.${userId}.accountState.seq`,
    `andvari.cs.${userId}.personalWrap`,
    `andvari.cacheOptIn.${userId}`,
    `andvari.cacheConsentMigrated.${userId}`,
    `andvari.autoLockSeconds.${userId}`,
    `andvari.lastExportAt.${userId}`,
    `andvari.selfIdentityPub.${userId}`,
  ];
  for (const k of keys) localStorage.setItem(k, k === `andvari.selfIdentityPub.${userId}` ? PUB : "1");
  return keys;
}

const DEVICE_WIDE = ["andvari.theme", "andvari.installId", "andvari.baseUrl", "andvari.cacheOptOut", "andvari.orgCacheOff", "andvari.persistRequested"];

// The self-identity records decode base64url through libsodium, which the app initialises at boot (App.tsx).
beforeAll(async () => {
  await initSodium();
});

beforeEach(() => {
  g.indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
  vi.stubGlobal("localStorage", fakeStorage());
  vi.stubGlobal("sessionStorage", fakeStorage());
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("wipeLocalAccountState — what a confirmed deletion leaves in this browser: nothing of the account", () => {
  it("removes the session, the tab's pair, every userId-scoped key, the self-identity records and the offline copy", async () => {
    const accountKeys = seedAccountKeys(GONE);
    localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify({ baseUrl: "", userId: GONE, personalVaultId: "pv", email: "Gone@X.com", isAdmin: false, tokens: null }));
    sessionStorage.setItem(TAB_TOKENS_KEY, JSON.stringify({ tabId: "t", userId: GONE, tokens: { accessToken: "a", refreshToken: "r" } }));
    localStorage.setItem("andvari.selfIdentityByEmail.gone@x.com", `${GONE}\n${PUB}`);
    await seedCache(GONE);
    expect(await dbExists(GONE)).toBe(true);

    await wipeLocalAccountState(GONE, " Gone@X.com ");

    expect(localStorage.getItem(SESSION_STORAGE_KEY)).toBeNull();
    expect(sessionStorage.getItem(TAB_TOKENS_KEY)).toBeNull();
    for (const k of accountKeys) expect(localStorage.getItem(k), k).toBeNull();
    expect(localStorage.getItem("andvari.selfIdentityByEmail.gone@x.com"), "the email binding naming the account goes").toBeNull();
    expect(await dbExists(GONE)).toBe(false);
  });

  it("keeps device-wide settings and another account's state on a shared browser", async () => {
    seedAccountKeys(GONE);
    const otherKeys = seedAccountKeys(OTHER);
    for (const k of DEVICE_WIDE) localStorage.setItem(k, "1");
    localStorage.setItem("andvari.selfIdentityByEmail.other@x.com", `${OTHER}\n${PUB}`);
    await seedCache(OTHER);

    await wipeLocalAccountState(GONE, "gone@x.com");

    for (const k of DEVICE_WIDE) expect(localStorage.getItem(k), k).toBe("1");
    for (const k of otherKeys) expect(localStorage.getItem(k), k).not.toBeNull();
    expect(localStorage.getItem("andvari.selfIdentityByEmail.other@x.com")).not.toBeNull();
    expect(await dbExists(OTHER), "another account's offline copy stays").toBe(true);
  });

  it("never rejects with no IndexedDB and no storage to speak of", async () => {
    g.indexedDB = undefined;
    await expect(wipeLocalAccountState(GONE, "gone@x.com")).resolves.toBeUndefined();
  });
});

describe("forgetSelfIdentity — the deleting device's own spec 01 §5 records", () => {
  it("drops the email binding only when it names the deleted account", () => {
    // Another account was later unlocked here under the same address: its binding is not this deletion's to remove.
    localStorage.setItem(`andvari.selfIdentityPub.${GONE}`, PUB);
    localStorage.setItem("andvari.selfIdentityByEmail.shared@x.com", `${OTHER}\n${PUB}`);
    forgetSelfIdentity(GONE, "shared@x.com");
    expect(localStorage.getItem(`andvari.selfIdentityPub.${GONE}`)).toBeNull();
    expect(localStorage.getItem("andvari.selfIdentityByEmail.shared@x.com")).toBe(`${OTHER}\n${PUB}`);
  });

  it("without an address, drops the userId pin alone", () => {
    localStorage.setItem(`andvari.selfIdentityPub.${GONE}`, PUB);
    localStorage.setItem("andvari.selfIdentityByEmail.gone@x.com", `${GONE}\n${PUB}`);
    forgetSelfIdentity(GONE);
    expect(localStorage.getItem(`andvari.selfIdentityPub.${GONE}`)).toBeNull();
    expect(localStorage.getItem("andvari.selfIdentityByEmail.gone@x.com")).not.toBeNull();
  });
});

describe("isAccountScopedKey — the per-account key grammar", () => {
  it("matches andvari.<what>.<userId> and andvari.<what>.<userId>.<sub>, nothing else", () => {
    expect(isAccountScopedKey(`andvari.cacheOptIn.${GONE}`, GONE)).toBe(true);
    expect(isAccountScopedKey(`andvari.cs.${GONE}.seq`, GONE)).toBe(true);
    expect(isAccountScopedKey(`andvari.cs.${OTHER}.seq`, GONE)).toBe(false);
    expect(isAccountScopedKey("andvari.cacheOptIn", GONE)).toBe(false);
    expect(isAccountScopedKey(`other.cacheOptIn.${GONE}`, GONE), "only this client's namespace").toBe(false);
    expect(isAccountScopedKey(`andvari.x.${GONE}extra`, GONE), "a whole segment, never a prefix of one").toBe(false);
  });
});
