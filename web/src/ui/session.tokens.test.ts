import "fake-indexeddb/auto";
import { IDBFactory as FakeIDBFactory } from "fake-indexeddb";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Tokens } from "../api/client";
import {
  TAB_TOKENS_KEY,
  applyOrgOfflineCachePolicy,
  claimTabTokens,
  clearSession,
  loadSession,
  makeClient,
  migrateLegacySessionTokens,
  resetTabClaim,
  saveSession,
  setOfflineCopyEnabled,
  tokensKeptAcrossLock,
  type Session,
} from "./session";

/**
 * Security review 2026-10, A14 (F5) — owner decision: "a browser not opted into the offline copy
 * keeps no token once locked". The whole session, refresh token included, sat in plaintext
 * localStorage and survived a lock, so anyone at the browser afterwards (DevTools, the profile's
 * Local Storage files) could replay it for the refresh lifetime and pull the wrapped key for an
 * offline guess. Now, unless this browser keeps the offline copy for this user:
 *  - the token pair lives in sessionStorage, per tab, never in localStorage (the non-secret
 *    metadata stays there: the cross-tab sign-out signal, F27, is its removal);
 *  - a lock revokes the pair and drops it, so unlocking is a full sign-in;
 *  - a legacy pair in localStorage is moved off disk at load;
 *  - toggling the offline copy moves the pair between the two stores at once.
 * A browser with the offline copy ON keeps today's behaviour exactly.
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

/** A minimal Web Locks stand-in: a held name blocks a second request until its signal aborts; a name is let go when its
 *  callback's promise settles (as the browser does), and both forms of the call are taken (with and without options). */
function fakeLocks() {
  const held = new Set<string>();
  return {
    held,
    request(name: string, a: { signal?: AbortSignal; ifAvailable?: boolean } | ((lock: unknown) => unknown), b?: (lock: unknown) => unknown): Promise<unknown> {
      const opts = typeof a === "function" ? {} : a;
      const cb = (typeof a === "function" ? a : b)!;
      if (!held.has(name)) {
        held.add(name);
        const run = Promise.resolve(cb({ name }));
        void run.finally(() => held.delete(name)).catch(() => {});
        return run;
      }
      if (opts.ifAvailable) return Promise.resolve(cb(null));
      return new Promise((_, reject) => opts.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError"))));
    },
  };
}

const UID = "11111111-1111-4111-8111-111111111111";
const T1: Tokens = { accessToken: "acc-1", refreshToken: "ref-1" };
const T2: Tokens = { accessToken: "acc-2", refreshToken: "ref-2" };
const sess = (userId: string, tokens: Tokens | null): Session => ({
  baseUrl: "",
  userId,
  personalVaultId: "pv",
  email: "m@example.com",
  tokens,
});
const optIn = (uid: string) => localStorage.setItem(`andvari.cacheOptIn.${uid}`, "1");
const persisted = () => JSON.parse(localStorage.getItem("andvari.session") ?? "null") as Session | null;
/** Every value in localStorage, concatenated: no refresh token may appear anywhere in it. */
const diskText = () => {
  let all = "";
  for (let i = 0; i < localStorage.length; i++) all += localStorage.getItem(localStorage.key(i)!) ?? "";
  return all;
};

beforeEach(() => {
  g.indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
  vi.stubGlobal("localStorage", fakeStorage());
  vi.stubGlobal("sessionStorage", fakeStorage());
  vi.stubGlobal("navigator", { locks: fakeLocks() });
  resetTabClaim();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("A14 F5 — where the session's tokens live", () => {
  it("a browser NOT opted into the offline copy keeps the pair in this tab's sessionStorage, never on disk", () => {
    saveSession(sess(UID, T1));
    expect(persisted()).toMatchObject({ userId: UID, email: "m@example.com", personalVaultId: "pv", tokens: null });
    expect(diskText()).not.toContain("ref-1");
    expect(diskText()).not.toContain("acc-1");
    expect(sessionStorage.getItem(TAB_TOKENS_KEY)).toContain("ref-1");
    expect(loadSession()?.tokens).toEqual(T1);
    expect(tokensKeptAcrossLock(UID)).toBe(false);
  });

  it("a browser WITH the offline copy keeps today's behaviour: the pair in the localStorage session", () => {
    optIn(UID);
    saveSession(sess(UID, T1));
    expect(persisted()?.tokens).toEqual(T1);
    expect(sessionStorage.getItem(TAB_TOKENS_KEY)).toBeNull();
    expect(loadSession()?.tokens).toEqual(T1);
    expect(tokensKeptAcrossLock(UID)).toBe(true);
  });

  it("migration: a legacy pair in localStorage leaves disk at load, into this tab", () => {
    localStorage.setItem("andvari.session", JSON.stringify(sess(UID, T1)));
    migrateLegacySessionTokens();
    expect(persisted()?.tokens).toBeNull();
    expect(diskText()).not.toContain("ref-1");
    expect(loadSession()?.tokens).toEqual(T1);
  });

  it("migration leaves an opted-in browser exactly as it was", () => {
    optIn(UID);
    const before = JSON.stringify(sess(UID, T1));
    localStorage.setItem("andvari.session", before);
    migrateLegacySessionTokens();
    expect(localStorage.getItem("andvari.session")).toBe(before);
    expect(sessionStorage.getItem(TAB_TOKENS_KEY)).toBeNull();
  });

  it("opting in moves the pair to localStorage at once; opting out moves it back into this tab", async () => {
    saveSession(sess(UID, T1));
    await setOfflineCopyEnabled(UID, true);
    expect(persisted()?.tokens).toEqual(T1);
    expect(sessionStorage.getItem(TAB_TOKENS_KEY)).toBeNull();
    await setOfflineCopyEnabled(UID, false);
    expect(persisted()?.tokens).toBeNull();
    expect(diskText()).not.toContain("ref-1");
    expect(loadSession()?.tokens).toEqual(T1);
  });

  it("the org forbidding the offline copy takes the pair off disk too", async () => {
    optIn(UID);
    saveSession(sess(UID, T1));
    await applyOrgOfflineCachePolicy(false, UID);
    expect(diskText()).not.toContain("ref-1");
    expect(loadSession()?.tokens).toEqual(T1);
  });

  it("a rotation on a non-opted-in browser lands in this tab's slot, never on disk", () => {
    saveSession(sess(UID, T1));
    const client = makeClient(loadSession(), "http://server");
    client.setTokens(T2);
    expect(diskText()).not.toContain("ref-2");
    expect(loadSession()?.tokens).toEqual(T2);
  });

  it("a tab's pair for one user is never grafted onto another user's persisted session", () => {
    saveSession(sess(UID, T1));
    saveSessionMetaOnly(sess("22222222-2222-4222-8222-222222222222", null));
    expect(loadSession()?.userId).toBe("22222222-2222-4222-8222-222222222222");
    expect(loadSession()?.tokens).toBeNull();
  });

  it("clearSession drops the persisted metadata and this tab's pair", () => {
    saveSession(sess(UID, T1));
    clearSession();
    expect(localStorage.getItem("andvari.session")).toBeNull();
    expect(sessionStorage.getItem(TAB_TOKENS_KEY)).toBeNull();
    expect(loadSession()).toBeNull();
  });
});

/** Another tab overwrote the metadata (a different account signed in there). */
function saveSessionMetaOnly(s: Session): void {
  localStorage.setItem("andvari.session", JSON.stringify(s));
}

describe("A14 F5 — a duplicated tab never shares a rotating refresh token", () => {
  // Chrome's and Firefox's "Duplicate tab" copy sessionStorage. Two tabs spending one single-use
  // refresh token trip the server's reuse heuristic, which revokes the whole device. Each tab holds
  // a Web Lock named after its own tab id; a copy cannot take the original's and drops its pair.
  it("a reload (the lock is free again) keeps the pair", async () => {
    saveSession(sess(UID, T1));
    const locks = (navigator as unknown as { locks: ReturnType<typeof fakeLocks> }).locks;
    locks.held.clear(); // the previous document is gone, and its lock with it
    resetTabClaim();
    await claimTabTokens({ waitMs: 20 });
    expect(loadSession()?.tokens).toEqual(T1);
  });

  it("a duplicate (the original still holds the lock) drops the copied pair and signs in on its own", async () => {
    saveSession(sess(UID, T1)); // the original tab claimed its id's lock here
    resetTabClaim(); // ...and this module now plays the duplicate, with a copy of its sessionStorage
    await claimTabTokens({ waitMs: 20 });
    expect(loadSession()?.tokens).toBeNull();
    expect(sessionStorage.getItem(TAB_TOKENS_KEY)).toBeNull();
    // Its own later sign-in gets a fresh tab id, so it never contends with the original again.
    saveSession(sess(UID, T2));
    expect(loadSession()?.tokens).toEqual(T2);
  });

  it("a browser with Web Locks but no AbortSignal.timeout never waits forever for the original's lock", async () => {
    saveSession(sess(UID, T1));
    resetTabClaim();
    vi.stubGlobal("AbortSignal", class {}); // no static timeout()
    await claimTabTokens({ waitMs: 20 }); // resolves at once: an `ifAvailable` request, not an unbounded wait
    expect(loadSession()?.tokens).toBeNull();
  });
});

// ---- wiring: App and Welcome cannot render in node, so the call sites are pinned ----

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const appTsx = readFileSync(here("./App.tsx"), "utf8");
const welcomeTsx = readFileSync(here("./Welcome.tsx"), "utf8");
const vaultTsx = readFileSync(here("./Vault.tsx"), "utf8");

describe("A14 F5 — lock revokes and drops a per-tab pair; unlock is then a full sign-in", () => {
  const lockPerTab = appTsx.slice(appTsx.indexOf("const lockPerTab = useCallback"), appTsx.indexOf("const lockLocal = useCallback"));

  it("the lock path branches on the offline copy: ON keeps today's behaviour, OFF goes per-tab", () => {
    const lockLocal = appTsx.slice(appTsx.indexOf("const lockLocal = useCallback"), appTsx.indexOf("const lock = useCallback"));
    expect(lockLocal).toContain("if (meta && !tokensKeptAcrossLock(meta.userId))");
    // A14's "keeps no token once locked" holds at the server too, so the lock logs its pair out again
    // (forgetting it only left a refresh token valid for 30 days). Locking one tab therefore also ends the account's
    // other tabs in this browser, until the server can end one session by its own refresh token.
    expect(lockLocal).toContain("void lockPerTab(notice, meta, true);");
    const onIdle = appTsx.slice(appTsx.indexOf("const onIdle = useCallback"), appTsx.indexOf("const lockWarning = useAutoLock("));
    expect(onIdle).toContain('if (p.kind === "unlock" && p.session.tokens) void lockPerTab(notice, p.session, true);');
    // Only the hand-over to another tab (it turned the offline copy off and holds this pair now) forgets without revoking.
    expect([...appTsx.matchAll(/lockPerTab\([^;]*, false\);/g)].map((m) => m[0])).toEqual(['lockPerTab("The offline copy was turned off in another tab — sign in again.", v.meta, false);']);
  });

  it("per-tab lock: usage flushed first (H33), then revoked while the pair is still held, then dropped", () => {
    // The order itself is behaviour-tested on tabsession.lockTabTokens (tabsession.test.ts); this pins that the
    // lock hands it the Vault's flush and lands on the token-less unlock card.
    expect(lockPerTab.length).toBeGreaterThan(0);
    expect(lockPerTab).toContain("lockTabTokens(clientRef.current, { flush: usageFlushRef.current, flushWaitMs: LOCK_USAGE_FLUSH_WAIT_MS, revoke })");
    expect(lockPerTab).toContain("clearTabTokens()");
    expect(lockPerTab).toContain("session: { ...meta, tokens: null }");
  });

  it("the Vault registers its usage flush so the lock can await it", () => {
    expect(vaultTsx).toContain("registerUsageFlush?.(() => usage.flush());");
    expect(appTsx).toContain("registerUsageFlush={(fn) => {");
  });

  it("a session with no tokens boots to the unlock card, which runs the normal sign-in, TOTP included", () => {
    // Every held session lands on the unlock card; with the offline copy on, one without tokens is one the server
    // ended (design §4.4, its card is tested in session-end.test.ts).
    expect(appTsx).toContain('setPhase(session !== null ? { kind: "unlock", session } : { kind: "welcome" });');
    const unlock = welcomeTsx.slice(welcomeTsx.indexOf("function Unlock("), welcomeTsx.indexOf("// ---- Sign up"));
    // Spec 01 §7: the same sign-in is where the unlock card goes when the server's keys could not be compared here.
    expect(unlock.indexOf("if (endedByServer(session)) {")).toBeLessThan(unlock.indexOf("if (!session.tokens || signInInstead) {"));
    expect(unlock).toContain("if (!session.tokens || signInInstead) {");
    expect(unlock).toContain("<SignIn ctx={ctx} pin={pin} cardNotice={cardNotice} onReady={onReady} onForget={onForget} lockedEmail={session.email} />");
    const signIn = welcomeTsx.slice(welcomeTsx.indexOf("function SignIn("), welcomeTsx.indexOf("// ---- Unlock a session"));
    expect(signIn).toContain("useState(lockedEmail ?? initialEmail ?? \"\")");
    expect(signIn).toContain("disabled={!!lockedEmail || needTotp}");
    // The two-step code is asked without asking for the password again.
    // (It keeps the typed password for that step only: after any refusal the field is emptied.)
    expect(signIn).toContain('case "totp_required":\n          keepPassword = true;\n          setNeedTotp(true);');
  });

  it("boot claims this tab's slot and migrates a legacy pair before reading the session", () => {
    const boot = appTsx.slice(appTsx.indexOf("await initSodium();"), appTsx.indexOf("const client = makeClient(session, baseUrl);"));
    expect(boot.indexOf("await claimTabTokens();")).toBeGreaterThan(-1);
    expect(boot.indexOf("migrateLegacySessionTokens();")).toBeGreaterThan(boot.indexOf("await migrateCacheConsentOnce("));
    expect(boot.indexOf("const session = loadSession();")).toBeGreaterThan(boot.indexOf("migrateLegacySessionTokens();"));
  });

  it("a tab that rode the shared pair locks without revoking when another tab turns the offline copy off", () => {
    const listener = appTsx.slice(appTsx.indexOf("const onStorage = (e: StorageEvent) => {"), appTsx.indexOf('window.addEventListener("storage", onStorage);'));
    expect(listener).toContain("void lockPerTab(\"The offline copy was turned off in another tab — sign in again.\", v.meta, false);");
  });
});
