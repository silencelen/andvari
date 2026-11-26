import "fake-indexeddb/auto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { DEVICE_KEY, DeviceIdentity } from "../api/devicesecret";
import { randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import type { Account } from "../vault/account";
import { boundAccountAt, forgettingMarks, recordSelfIdentityPub } from "../vault/selfidentity";
import { browserStorages } from "./forget-earlier.testkit";
import { earlierCopyOf, forgetEarlierAccount, TAB_TOKENS_KEY } from "./session";

/**
 * Two lesser points of the forgetting. A write of this browser's own record that fails during it is never answered
 * "forgotten": the mark stands and the next click finishes it. And the walk that removes an account's records finds them
 * by how they are keyed (the account's id as the third segment), so every kind of record this web app keeps is listed
 * here with how it is keyed: a kind of any other name or shape, added later, fails the first test until it is placed.
 */
const EMAIL = "alice@example.com";
const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";

/** `andvari.<kind>.<userId>[.<sub>]`: removed by the forgetting's walk (and by an account's deletion here). */
const BY_ACCOUNT_ID = ["cs", "as2", "log2", "recmirror", "escrowfp", "current", "onetap", "how", "cacheOptIn", "autoLockSeconds", "lastExportAt", "wipeOwed", "copyBeingRemoved"];
/** `andvari.selfIdentityPub.<userId>`: keyed by the id, and KEPT by the forgetting (the record of the account's key). */
const KEPT_BY_ACCOUNT_ID = ["selfIdentityPub"];
/** Keyed by the address: the forgetting removes the one that names the earlier account (selfidentity.ts). */
const BY_ADDRESS = ["selfIdentityByEmail"];
/** One key for the browser, naming an account in its value; each handled by name (session.ts, devicesecret.ts, selfidentity.ts). */
const NAMED_IN_VALUE = ["session", "tabTokens", "tabLockRevoke", "device", "policyWipeNotice", "forgetting", "rememberNext", "rememberedNew", "unconfirmedRefresh"];
/** The browser's or the server's, never an account's. */
const NOT_AN_ACCOUNTS = ["theme", "installId", "baseUrl", "cacheOptOut", "orgCacheOff", "persistRequested", "cacheConsentMigrated", "pin2"];

/** Every `andvari.<kind>` a source of the web app names (tests, test kits and the journeys' harness aside). */
function kindsInSources(): string[] {
  const root = new URL("../", import.meta.url);
  const out = new Set<string>();
  const walk = (dir: URL) => {
    for (const f of readdirSync(dir)) {
      const u = new URL(f, dir);
      if (statSync(u).isDirectory()) {
        if (f !== "journeys" && f !== "node_modules") walk(new URL(`${f}/`, dir));
        continue;
      }
      if (!/\.tsx?$/.test(f) || /\.test\.ts$|\.testkit\.ts$/.test(f)) continue;
      for (const m of readFileSync(u, "utf8").matchAll(/["'`]andvari\.([A-Za-z0-9_-]+)/g)) out.add(m[1]!);
    }
  };
  walk(root);
  return [...out].sort();
}

describe("the kinds of record the forgetting walks", () => {
  let st: ReturnType<typeof browserStorages>;
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(() => {
    st = browserStorages();
    vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new Error("nothing may be sent"))));
    recordSelfIdentityPub(A, { identityPub: randomBytes(32) } as unknown as Account, EMAIL);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    st.restore();
    indexedDB.deleteDatabase(`andvari-vault-${A}`);
  });

  it("every kind of record the web app keeps is placed by how it is keyed: a new kind fails here until it is", () => {
    const placed = [...BY_ACCOUNT_ID, ...KEPT_BY_ACCOUNT_ID, ...BY_ADDRESS, ...NAMED_IN_VALUE, ...NOT_AN_ACCOUNTS].sort();
    expect(new Set(placed).size).toBe(placed.length);
    expect(kindsInSources()).toEqual(placed);
  });

  it("the walk removes every kind keyed by the account's id, in both its shapes, keeps the record of its key, and leaves another account's", async () => {
    for (const u of [A, B]) for (const k of BY_ACCOUNT_ID) {
      st.local.setItem(`andvari.${k}.${u}`, "x");
      st.local.setItem(`andvari.${k}.${u}.sub`, "x");
    }
    recordSelfIdentityPub(B, { identityPub: randomBytes(32) } as unknown as Account, "bob@example.com");
    const keyOfA = st.local.getItem(`andvari.selfIdentityPub.${A}`);
    expect(await forgetEarlierAccount(EMAIL, A, await earlierCopyOf(A), B)).toEqual({ kind: "forgotten" });
    expect([...st.local.map.keys()].filter((k) => k.includes(A))).toEqual([`andvari.selfIdentityPub.${A}`]);
    expect(st.local.getItem(`andvari.selfIdentityPub.${A}`)).toBe(keyOfA);
    for (const k of BY_ACCOUNT_ID) expect(st.local.getItem(`andvari.${k}.${B}.sub`), k).toBe("x");
    expect(st.local.getItem(`andvari.selfIdentityPub.${B}`)).not.toBeNull();
  });

  it("a write of the device record that fails: not forgotten, the mark stands, and the next click finishes it", async () => {
    new DeviceIdentity().remember(EMAIL, A, "d0000000-0000-4000-8000-00000000000a");
    const shown = await earlierCopyOf(A);
    const real = st.local.setItem.bind(st.local);
    let fail = true;
    st.local.setItem = (k: string, v: string) => {
      if (fail && k === DEVICE_KEY) {
        fail = false;
        throw new Error("quota");
      }
      real(k, v);
    };
    await expect(forgetEarlierAccount(EMAIL, A, shown, B)).rejects.toThrow("quota");
    expect(forgettingMarks()).toEqual([{ email: EMAIL, userId: A }]);
    expect(st.local.getItem(DEVICE_KEY)).toContain(A);
    expect(boundAccountAt(EMAIL)).toBeNull(); // what was removed before it is said as "part of it may be done"
    expect(await forgetEarlierAccount(EMAIL, A, shown, B)).toEqual({ kind: "forgotten" });
    expect(st.local.getItem(DEVICE_KEY)).not.toContain(A);
    expect(forgettingMarks()).toEqual([]);
  });

  it("a removal of this tab's record of the account that fails: not forgotten, the mark stands", async () => {
    st.tab.setItem(TAB_TOKENS_KEY, JSON.stringify({ tabId: "t", userId: A, tokens: { accessToken: "a", refreshToken: "r" } }));
    const shown = await earlierCopyOf(A);
    const real = st.tab.removeItem.bind(st.tab);
    st.tab.removeItem = (k: string) => {
      if (k === TAB_TOKENS_KEY) throw new Error("storage failed");
      real(k);
    };
    await expect(forgetEarlierAccount(EMAIL, A, shown, B)).rejects.toThrow();
    expect(forgettingMarks()).toEqual([{ email: EMAIL, userId: A }]);
    st.tab.removeItem = real;
    expect(await forgetEarlierAccount(EMAIL, A, shown, B)).toEqual({ kind: "forgotten" });
    expect(st.tab.getItem(TAB_TOKENS_KEY)).toBeNull();
  });
});
