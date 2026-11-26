import "fake-indexeddb/auto";
import { readFileSync } from "node:fs";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mutation } from "../api/types";
import { initSodium } from "../crypto/sodium";
import { randomBytes } from "../crypto/provider";
import type { Account } from "../vault/account";
import { openVaultCache, readWaiting } from "../vault/idbcache";
import { boundAccountAt, FORGETTING_KEY, forgettingMarks, recordSelfIdentityPub } from "../vault/selfidentity";
import { browserStorages } from "./forget-earlier.testkit";
import { accountOpenLockName, earlierCopyOf, forgetEarlierAccount, holdAccountOpen, loadSession, saveSession, SESSION_STORAGE_KEY, settleForgettings } from "./session";
import { type TabLocks, useTabLocks } from "./weblocks.testkit";

/**
 * A tab holds a lock for an account for as long as it has that account open, and a forgetting of that account in another
 * tab is refused while the lock is held: the session record alone did not show a tab whose write of it failed (a full
 * storage), which then went on using the account while another tab removed its records and copy.
 */
const EMAIL = "alice@example.com";
const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const mut = (id: string): Mutation => ({ mutationId: id, op: "put", itemId: `item-${id}`, vaultId: "v1", baseItemRev: 0 });
const settle = () => new Promise((r) => setTimeout(r, 0));

describe("the forgetting and a tab that has the earlier account open", () => {
  let st: ReturnType<typeof browserStorages>;
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(async () => {
    st = browserStorages();
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.reject(new Error("nothing may be sent"))),
    );
    recordSelfIdentityPub(A, { identityPub: randomBytes(32) } as unknown as Account, EMAIL);
    st.local.setItem(`andvari.cs.${A}.accountState.seq`, "x");
    const c = await openVaultCache(A);
    await c.enqueue(mut("a-1"));
    c.close();
  });
  afterEach(async () => {
    vi.unstubAllGlobals();
    st.restore();
    indexedDB.deleteDatabase(`andvari-vault-${A}`);
  });

  /** Tab 1 opens A; its write of the session record fails (the storage is full), as in the check's probe. */
  async function tabOpensWithoutRecord(tab: TabLocks): Promise<() => void> {
    const real = st.local.setItem.bind(st.local);
    st.local.setItem = (k: string, v: string) => {
      if (k === SESSION_STORAGE_KEY) throw new DOMException("full", "QuotaExceededError");
      real(k, v);
    };
    const back = useTabLocks(tab);
    try {
      saveSession({ baseUrl: "", userId: A, personalVaultId: "", email: EMAIL, tokens: null });
      const release = holdAccountOpen(A);
      await settle();
      return release;
    } finally {
      back();
      st.local.setItem = real;
    }
  }
  const nothingOfARemoved = async () => {
    expect(boundAccountAt(EMAIL)).toBe(A);
    expect(st.local.getItem(`andvari.cs.${A}.accountState.seq`)).toBe("x");
    expect((await readWaiting(A)).kind).toBe("read");
  };

  it("the check's probe: tab 1 has A open with no session record; the forgetting in tab 2 removes nothing and says so; once tab 1 closes A it goes", async () => {
    const release = await tabOpensWithoutRecord(st.locks.tab());
    expect(loadSession()).toBeNull(); // the record that the forgetting used to look at was never written
    expect(st.locks.holders(accountOpenLockName(A))).toBe(1);
    const shown = await earlierCopyOf(A);
    expect(await forgetEarlierAccount(EMAIL, A, shown, B)).toEqual({ kind: "account_open" });
    await nothingOfARemoved();
    expect(forgettingMarks()).toEqual([]);
    // Tab 1 locks or signs out: the vault's store closes and the lock goes.
    release();
    await settle();
    expect(st.locks.holders(accountOpenLockName(A))).toBe(0);
    expect(await forgetEarlierAccount(EMAIL, A, shown, B)).toEqual({ kind: "forgotten" });
    expect(boundAccountAt(EMAIL)).toBeNull();
    expect((await readWaiting(A)).kind).toBe("none");
  });

  it("a tab that closed or crashed holds nothing: the browser let its lock go, with no record left to clean up", async () => {
    const tab1 = st.locks.tab();
    await tabOpensWithoutRecord(tab1); // never released by the app: the tab just ends
    const before = new Map(st.local.map);
    expect(await forgetEarlierAccount(EMAIL, A, await earlierCopyOf(A), B)).toEqual({ kind: "account_open" });
    expect(new Map(st.local.map)).toEqual(before); // the lock is the browser's: nothing at rest names it
    tab1.end();
    await settle();
    expect(await forgetEarlierAccount(EMAIL, A, await earlierCopyOf(A), B)).toEqual({ kind: "forgotten" });
    expect((await readWaiting(A)).kind).toBe("none");
  });

  it("every tab with A open holds the lock at once: the forgetting waits for the last of them", async () => {
    const r1 = await tabOpensWithoutRecord(st.locks.tab());
    const r2 = await tabOpensWithoutRecord(st.locks.tab());
    expect(st.locks.holders(accountOpenLockName(A))).toBe(2);
    r1();
    await settle();
    expect(await forgetEarlierAccount(EMAIL, A, await earlierCopyOf(A), B)).toEqual({ kind: "account_open" });
    await nothingOfARemoved();
    r2();
    await settle();
    expect(await forgetEarlierAccount(EMAIL, A, await earlierCopyOf(A), B)).toEqual({ kind: "forgotten" });
  });

  it("a forgetting cut short is not finished at a start while a tab has the account open; it is at a later start", async () => {
    st.local.removeItem(`andvari.selfIdentityByEmail.${EMAIL}`); // the first removal was made
    st.local.setItem(FORGETTING_KEY, JSON.stringify([{ email: EMAIL, userId: A }]));
    const release = await tabOpensWithoutRecord(st.locks.tab());
    await settleForgettings();
    expect(forgettingMarks()).toEqual([{ email: EMAIL, userId: A }]);
    expect((await readWaiting(A)).kind).toBe("read");
    release();
    await settle();
    await settleForgettings();
    expect(forgettingMarks()).toEqual([]);
    expect((await readWaiting(A)).kind).toBe("none");
  });

  it("a tab's hold of A's lock asked while a forgetting of A runs is granted only after the forgetting ends (the tab itself is not held back)", async () => {
    const shown = await earlierCopyOf(A);
    const order: string[] = [];
    const going = forgetEarlierAccount(EMAIL, A, shown, B).then((r) => order.push(`forgetting:${r.kind}`));
    await Promise.resolve();
    const back = useTabLocks(st.locks.tab());
    const release = holdAccountOpen(A);
    back();
    void navigatorLocksGrant(A).then(() => order.push("opened"));
    await going;
    await settle();
    expect(order).toEqual(["forgetting:forgotten", "opened"]);
    release();
  });

  /** Resolves once a shared hold of A's lock was granted somewhere (asked from a fresh tab, after every earlier ask). */
  async function navigatorLocksGrant(userId: string): Promise<void> {
    await st.locks.tab().request(accountOpenLockName(userId), { mode: "shared" }, () => undefined);
  }

  it("without Web Locks it cannot be told whether a tab has A open: nothing is removed, and a mark waits", async () => {
    const back = useTabLocks(undefined);
    try {
      const before = new Map(st.local.map);
      expect(await forgetEarlierAccount(EMAIL, A, await earlierCopyOf(A), B)).toEqual({ kind: "open_cannot_tell" });
      expect(new Map(st.local.map)).toEqual(before);
      await nothingOfARemoved();
      st.local.removeItem(`andvari.selfIdentityByEmail.${EMAIL}`);
      st.local.setItem(FORGETTING_KEY, JSON.stringify([{ email: EMAIL, userId: A }]));
      await settleForgettings();
      expect(forgettingMarks()).toEqual([{ email: EMAIL, userId: A }]);
      expect((await readWaiting(A)).kind).toBe("read");
    } finally {
      back();
    }
  });
});

describe("the app holds the lock for as long as a tab has the account open", () => {
  const source = (rel: string) => readFileSync(new URL(rel, import.meta.url), "utf8");

  it("App holds it from the open vault until its store closes; the screen says each refusal", () => {
    const app = source("./App.tsx");
    expect(app).toContain('const openAccountId = phase.kind === "vault" ? phase.account.userId : null;');
    expect(app).toMatch(/if \(openStore === null \|\| openAccountId === null\) return;\s*return holdAccountOpen\(openAccountId\);\s*\}, \[openStore, openAccountId\]\);/);
    const offer = source("./ForgetEarlier.tsx");
    expect(offer).toMatch(/case "account_open":\s*setCopy\(null\);\s*setLine\(REMADE_ACCOUNT_FORGET_ACCOUNT_OPEN\);/);
    expect(offer).toMatch(/case "open_cannot_tell":\s*setCopy\(null\);\s*setLine\(REMADE_ACCOUNT_FORGET_CANNOT_TELL_OPEN\);/);
  });

  it("the lock is the account's own, apart from the tab's token slot", () => {
    expect(accountOpenLockName(A)).toBe(`andvari-account-open-${A}`);
    expect(source("./session.ts")).toContain("const tabLockName = (tabId: string): string => `andvari-tab-${tabId}`;");
  });
});
