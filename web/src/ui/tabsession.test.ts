import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiClient, type Tokens } from "../api/client";
import { clearSession, lockRevokeUnconfirmed, loadSession, makeClient, recordLockRevoke, resetTabClaim, saveSession, type Session } from "./session";
import {
  abandonSignIn,
  adoptSharedPair,
  dropOnSignOutElsewhere,
  idleTimerUserId,
  lockTabTokens,
  pendingSignInBinding,
  revokeForSignOut,
  storageVerdict,
} from "./tabsession";

/**
 * Security review 2026-10, A14 review 1 (W1–W5, W7, We): the per-tab token rules App applies on a
 * browser without the offline copy, driven here as functions of a real ApiClient (App has no DOM
 * test harness; its wiring is pinned at the end).
 */

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const appTsx = readFileSync(here("./App.tsx"), "utf8");
const welcomeTsx = readFileSync(here("./Welcome.tsx"), "utf8");

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

const jsonResp = (status: number, body: unknown): Response =>
  ({ ok: status >= 200 && status < 300, status, statusText: String(status), json: async () => body, text: async () => JSON.stringify(body) }) as unknown as Response;

/** A fake server: logout answers [logoutStatus] and records the bearer it saw (null = unauthenticated). */
function server(opts: { logoutStatus?: number } = {}) {
  const seen = { logouts: [] as (string | null)[], refreshes: 0 };
  vi.stubGlobal("fetch", async (url: string | URL, init?: RequestInit) => {
    const u = String(url);
    const auth = (init?.headers as Record<string, string> | undefined)?.["Authorization"] ?? null;
    if (u.endsWith("/api/v1/auth/logout")) {
      seen.logouts.push(auth);
      return jsonResp(opts.logoutStatus ?? 204, {});
    }
    if (u.endsWith("/api/v1/auth/refresh")) {
      seen.refreshes++;
      return jsonResp(401, { error: "unauthorized" });
    }
    return jsonResp(404, {});
  });
  return seen;
}

const PAIR: Tokens = { accessToken: "acc-1", refreshToken: "ref-1" };
const SHARED: Tokens = { accessToken: "acc-s", refreshToken: "ref-s" };
const UID = "11111111-1111-4111-8111-111111111111";
const meta = (userId: string, tokens: Tokens | null): Session => ({ baseUrl: "", userId, personalVaultId: "pv", email: "m@example.com", isAdmin: false, tokens });

beforeEach(() => {
  vi.stubGlobal("localStorage", fakeStorage());
  vi.stubGlobal("sessionStorage", fakeStorage());
  vi.stubGlobal("navigator", {});
  resetTabClaim();
});
afterEach(() => vi.unstubAllGlobals());

describe("W1 — a sign-out with no pair never POSTs unauthenticated; the lock's own revoke result is what counts", () => {
  it("the lock revokes while the pair is held, then drops it, and hands back the revoke result", async () => {
    const seen = server();
    const client = new ApiClient("", PAIR);
    let settled = false;
    const { revoked } = await lockTabTokens(client, { flush: null, flushWaitMs: 10, revoke: true });
    void revoked?.then(() => (settled = true));
    expect(client.getTokens()).toBeNull();
    expect(revoked).not.toBeNull();
    expect(settled, "the lock does not wait for the revocation").toBe(false);
    expect(await revoked).toBe(true);
    expect(seen.logouts).toEqual(["Bearer acc-1"]);
  });

  it("a sign-out after that lock reuses its result — no second, unauthenticated POST, no false alarm", async () => {
    const seen = server();
    const client = new ApiClient("", PAIR);
    const { revoked: atLock } = await lockTabTokens(client, { flush: null, flushWaitMs: 10, revoke: true });
    expect(await revokeForSignOut(client, atLock)).toBe(true);
    expect(seen.logouts).toEqual(["Bearer acc-1"]);
  });

  it("a lock-time revoke the server did NOT confirm is what the sign-out reports", async () => {
    server({ logoutStatus: 500 });
    const client = new ApiClient("", PAIR);
    const { revoked: atLock } = await lockTabTokens(client, { flush: null, flushWaitMs: 10, revoke: true });
    expect(await atLock).toBe(false);
    expect(await revokeForSignOut(client, atLock)).toBe(false);
  });

  it("a fresh tab that never held a pair has nothing of its own to revoke: no POST, nothing to report", async () => {
    const seen = server();
    expect(await revokeForSignOut(new ApiClient("", null), null)).toBe(true);
    expect(seen.logouts).toEqual([]);
  });

  it("a pair still held is revoked at sign-out as before", async () => {
    const seen = server();
    expect(await revokeForSignOut(new ApiClient("", PAIR), null)).toBe(true);
    expect(seen.logouts).toEqual(["Bearer acc-1"]);
  });
});

describe("W-b (A14 review 3) — the lock's revoke result outlives a reload, in the tab's sessionStorage", () => {
  it("a lock-time revoke the server did not confirm is still reported after a reload (a new App, no in-memory record)", async () => {
    server({ logoutStatus: 500 });
    const client = new ApiClient("", PAIR);
    recordLockRevoke(UID, "pending"); // App records it as it locks
    const { revoked: atLock } = await lockTabTokens(client, { flush: null, flushWaitMs: 10, revoke: true });
    recordLockRevoke(UID, (await atLock) ? "confirmed" : "unconfirmed"); // ...and the answer when it lands
    // The reload: a fresh client with no pair and no in-memory lock record; only sessionStorage remains.
    resetTabClaim();
    const seen = server();
    expect(await revokeForSignOut(new ApiClient("", null), null, lockRevokeUnconfirmed(UID))).toBe(false);
    expect(seen.logouts, "still nothing POSTed unauthenticated").toEqual([]);
  });

  it("a reload before the server answered counts as unconfirmed: the answer can never arrive", async () => {
    recordLockRevoke(UID, "pending");
    expect(lockRevokeUnconfirmed(UID)).toBe(true);
    expect(await revokeForSignOut(new ApiClient("", null), null, lockRevokeUnconfirmed(UID))).toBe(false);
  });

  it("a confirmed lock-time revoke, another account's record, or none at all reports confirmed", async () => {
    recordLockRevoke(UID, "unconfirmed");
    recordLockRevoke(UID, "confirmed");
    expect(lockRevokeUnconfirmed(UID)).toBe(false);
    recordLockRevoke("22222222-2222-4222-8222-222222222222", "unconfirmed");
    expect(lockRevokeUnconfirmed(UID), "another account's lock is not this sign-out's").toBe(false);
    expect(lockRevokeUnconfirmed(null)).toBe(false);
    expect(await revokeForSignOut(new ApiClient("", null), null, lockRevokeUnconfirmed(UID))).toBe(true);
  });

  it("the record lives in sessionStorage, never in localStorage, and a sign-out's clearSession removes it", () => {
    recordLockRevoke(UID, "unconfirmed");
    expect(sessionStorage.length).toBe(1);
    expect(localStorage.length).toBe(0);
    clearSession();
    expect(lockRevokeUnconfirmed(UID)).toBe(false);
  });

  it("App records the lock's revoke in the tab, reads it at sign-out, and drops it at unlock", () => {
    const lockPerTab = appTsx.slice(appTsx.indexOf("const lockPerTab = useCallback"), appTsx.indexOf("const lockLocal = useCallback"));
    expect(lockPerTab).toContain('recordLockRevoke(meta.userId, "pending");');
    expect(lockPerTab).toContain('recordLockRevoke(meta.userId, ok ? "confirmed" : "unconfirmed");');
    expect(lockPerTab.indexOf("if (lockRevokeRef.current !== revoked) return;")).toBeLessThan(lockPerTab.indexOf('recordLockRevoke(meta.userId, ok ?'));
    const signOut = appTsx.slice(appTsx.indexOf("const signOut = useCallback"), appTsx.indexOf("const lockChannelRef = "));
    expect(signOut).toContain("revokeForSignOut(clientRef.current, lockRevokeRef.current, lockRevokeUnconfirmed(uid))");
    const onUnlocked = appTsx.slice(appTsx.indexOf("const onUnlocked = "), appTsx.indexOf("const signOut = useCallback"));
    expect(onUnlocked).toContain("clearLockRevoke();");
  });
});

describe("W7 — a lock never leaves the pair behind, even when a storage write throws", () => {
  it("a throwing onTokens (a full or disabled localStorage) still leaves the client without the pair", async () => {
    server();
    const client = new ApiClient("", PAIR, () => {
      throw new DOMException("quota", "QuotaExceededError");
    });
    await expect(lockTabTokens(client, { flush: null, flushWaitMs: 10, revoke: true })).resolves.toBeTruthy();
    expect(client.getTokens()).toBeNull();
  });

  it("a flush that hangs is bounded and one that throws is ignored", async () => {
    server();
    const hang = new ApiClient("", PAIR);
    await lockTabTokens(hang, { flush: () => new Promise(() => {}), flushWaitMs: 5, revoke: false });
    expect(hang.getTokens()).toBeNull();
    const boom = new ApiClient("", PAIR);
    await lockTabTokens(boom, { flush: async () => Promise.reject(new Error("x")), flushWaitMs: 5, revoke: false });
    expect(boom.getTokens()).toBeNull();
  });

  it("saveSession's storage write is guarded: a throwing localStorage does not throw out of it", () => {
    vi.stubGlobal("localStorage", { ...fakeStorage(), setItem: () => { throw new DOMException("quota", "QuotaExceededError"); } } as Storage);
    expect(() => saveSession(meta(UID, PAIR))).not.toThrow();
  });

  it("App's per-tab lock changes the phase in a finally", () => {
    const lockPerTab = appTsx.slice(appTsx.indexOf("const lockPerTab = useCallback"), appTsx.indexOf("const lockLocal = useCallback"));
    const fin = lockPerTab.indexOf("} finally {");
    expect(fin).toBeGreaterThan(-1);
    expect(lockPerTab.indexOf("setPhase(", fin)).toBeGreaterThan(fin);
    expect(lockPerTab.indexOf("clearTabTokens()", fin)).toBeGreaterThan(fin);
  });
});

describe("W4 + We — the storage listener's verdicts", () => {
  const ctx = (o: Partial<Parameters<typeof storageVerdict>[1]> = {}) => ({
    activeUserId: UID,
    have: PAIR,
    after: null,
    keptAcrossLock: () => false,
    ...o,
  });
  const ev = (oldValue: Session | null, newValue: Session | null) => ({
    key: "andvari.session",
    oldValue: oldValue ? JSON.stringify(oldValue) : null,
    newValue: newValue ? JSON.stringify(newValue) : null,
  });

  it("W4: a sign-out in another tab, without the offline copy, revokes this tab's own pair before dropping it", async () => {
    const v = storageVerdict(ev(meta(UID, null), null), ctx());
    expect(v).toEqual({ kind: "signedOutElsewhere", revokeOwn: true });
    const seen = server();
    const client = new ApiClient("", PAIR);
    const r = dropOnSignOutElsewhere(client, true);
    expect(client.getTokens()).toBeNull();
    expect(await r).toBe(true);
    expect(seen.logouts).toEqual(["Bearer acc-1"]);
  });

  it("W4: with the offline copy the pair was the shared one the other tab revoked: drop it, revoke nothing", async () => {
    expect(storageVerdict(ev(meta(UID, SHARED), null), ctx({ keptAcrossLock: () => true }))).toEqual({ kind: "signedOutElsewhere", revokeOwn: false });
    const seen = server();
    const client = new ApiClient("", SHARED);
    expect(dropOnSignOutElsewhere(client, false)).toBeNull();
    expect(client.getTokens()).toBeNull();
    expect(seen.logouts).toEqual([]);
  });

  it("another tab turned the offline copy OFF and took the shared pair this tab rode: lock without revoking", () => {
    const after = meta(UID, null);
    const v = storageVerdict(ev(meta(UID, SHARED), after), ctx({ have: SHARED, after }));
    expect(v).toEqual({ kind: "lockWithoutRevoke", meta: after });
  });

  it("We: another tab turned the offline copy ON: this tab's OWN pair is revoked before the shared one is adopted", async () => {
    const after = meta(UID, SHARED);
    const v = storageVerdict(ev(meta(UID, null), after), ctx({ have: PAIR, after, keptAcrossLock: () => true }));
    expect(v).toEqual({ kind: "adopt", tokens: SHARED, revokeOwnFirst: true });
    const seen = server();
    const client = new ApiClient("", PAIR);
    const r = adoptSharedPair(client, SHARED, true);
    expect(client.getTokens()).toEqual(SHARED);
    expect(await r).toBe(true);
    expect(seen.logouts, "the revocation used this tab's own pair, captured before the adoption").toEqual(["Bearer acc-1"]);
  });

  it("a rotation of the SHARED pair by another tab is adopted with no revocation (it would end the shared session)", () => {
    const after = meta(UID, { accessToken: "acc-s2", refreshToken: "ref-s2" });
    const v = storageVerdict(ev(meta(UID, SHARED), after), ctx({ have: SHARED, after, keptAcrossLock: () => true }));
    expect(v).toEqual({ kind: "adopt", tokens: after.tokens, revokeOwnFirst: false });
  });

  it("another account's session is never grafted into this tab, and unrelated keys are ignored", () => {
    const after = meta("22222222-2222-4222-8222-222222222222", SHARED);
    expect(storageVerdict(ev(meta(UID, null), after), ctx({ after, keptAcrossLock: () => true }))).toEqual({ kind: "ignore" });
    expect(storageVerdict({ key: "andvari.other", oldValue: null, newValue: null }, ctx())).toEqual({ kind: "ignore" });
  });

  it("App's listener applies exactly these verdicts", () => {
    const listener = appTsx.slice(appTsx.indexOf("const onStorage = (e: StorageEvent) => {"), appTsx.indexOf('window.addEventListener("storage", onStorage);'));
    expect(listener).toContain("storageVerdict(");
    expect(listener).toContain("dropOnSignOutElsewhere(clientRef.current, v.revokeOwn)");
    expect(listener).toContain("adoptSharedPair(clientRef.current, v.tokens, v.revokeOwnFirst)");
    expect(listener).toContain('void lockPerTab("The offline copy was turned off in another tab — sign in again.", v.meta, false);');
  });
});

describe("W5 — an unlock card that still holds this tab's pair has an idle lock", () => {
  it("the timer runs for an open vault, and for a token-holding unlock card on a per-tab browser only", () => {
    const perTab = () => false;
    const kept = () => true;
    expect(idleTimerUserId(UID, null, perTab)).toBe(UID);
    expect(idleTimerUserId(null, meta(UID, PAIR), perTab)).toBe(UID);
    expect(idleTimerUserId(null, meta(UID, null), perTab)).toBeNull();
    expect(idleTimerUserId(null, meta(UID, PAIR), kept)).toBeNull();
    expect(idleTimerUserId(null, null, perTab)).toBeNull();
  });

  it("App arms the policy idle timer for it and runs the per-tab lock when it fires", () => {
    expect(appTsx).toContain("const idleUserId = idleTimerUserId(vaultUserId, phase.kind === \"unlock\" ? phase.session : null, tokensKeptAcrossLock);");
    expect(appTsx).toContain("resolveAutoLockSeconds(fetchedAutoLock, readPersistedAutoLockSeconds(idleUserId)).seconds");
    const onIdle = appTsx.slice(appTsx.indexOf("const onIdle = useCallback"), appTsx.indexOf("const lockWarning = useAutoLock("));
    expect(onIdle).toContain('if (p.kind === "unlock" && p.session.tokens) void lockPerTab(notice, p.session, true);');
    expect(appTsx).toContain("const lockWarning = useAutoLock(autoLockSeconds, onIdle);");
  });
});

describe("W3 — the caller's saveSession is the only writer of a fresh login pair", () => {
  const X = UID;
  const Y = "22222222-2222-4222-8222-222222222222";
  const ySession = {
    userId: Y, deviceId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", accessToken: "y-acc", refreshToken: "y-ref", isAdmin: false,
    accountKeys: { kdfSalt: "s", kdfParams: { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 }, wrappedUvk: "w", encryptedIdentitySeed: "e", identityPub: "p", escrowFingerprint: "f" },
  };
  const everywhere = () => {
    let all = "";
    for (const s of [localStorage, sessionStorage]) for (let i = 0; i < s.length; i++) all += s.getItem(s.key(i)!) ?? "";
    return all;
  };

  it("Y signing in on X's Welcome writes nothing under X's metadata, even when the sign-in then fails or the pair rotates", async () => {
    localStorage.setItem(`andvari.cacheOptIn.${X}`, "1"); // X keeps the offline copy: the shared localStorage slot is the graft target
    saveSession(meta(X, null)); // X's token-less session: the tab boots to Welcome bound to X
    const client = makeClient(loadSession(), "");
    let rotated = 0;
    vi.stubGlobal("fetch", async (url: string | URL) => {
      const u = String(url);
      if (u.endsWith("/api/v1/auth/login")) return jsonResp(200, ySession);
      if (u.endsWith("/api/v1/auth/refresh")) return jsonResp(200, { accessToken: `y-acc${++rotated}`, refreshToken: `y-ref${rotated}` });
      if (u.endsWith("/api/v1/account/keys")) return rotated === 0 ? jsonResp(401, { error: "unauthorized" }) : jsonResp(200, {});
      return jsonResp(404, {});
    });
    const s = await client.login("y@example.com", "auth", "test");
    expect(s.userId).toBe(Y);
    expect(client.getTokens()?.refreshToken).toBe("y-ref");
    expect(loadSession(), "login() persisted nothing: X's metadata is untouched").toEqual(meta(X, null));
    expect(everywhere()).not.toContain("y-ref");

    // A14 review 3 (W-a): until Account.unlock has checked the keys the login came with, Welcome binds the client to a
    // placeholder no account has - a rotation is written nowhere. Then it binds the account that signed in; a rotation
    // before its saveSession (the first sync) is still not written under X.
    client.boundUserId = pendingSignInBinding();
    await client.accountKeys();
    expect(rotated).toBe(1);
    expect(everywhere()).not.toContain("y-ref");
    client.boundUserId = s.userId; // unlock succeeded
    await client.accountKeys();
    expect(everywhere()).not.toContain("y-ref");
    expect(loadSession()?.userId).toBe(X);

    // Welcome's saveSession — the ONLY writer — records Y with the CURRENT pair; later rotations follow Y.
    saveSession({ ...meta(Y, client.getTokens()), email: "y@example.com" });
    expect(loadSession()?.userId).toBe(Y);
    expect(loadSession()?.tokens?.refreshToken).toBe("y-ref1");
  });

  it("W-a: before unlock checks it, the login's userId is no binding - even when it names the persisted account", async () => {
    // A server that answers with X's userId for a login that is not X's: until Account.unlock has checked the keys, the
    // client must not treat X's persisted session as its own (no rotation written into it, no persisted pair adopted).
    localStorage.setItem(`andvari.cacheOptIn.${X}`, "1");
    saveSession(meta(X, { accessToken: "x-acc", refreshToken: "x-ref" }));
    const client = makeClient(null, "");
    vi.stubGlobal("fetch", async (url: string | URL) => {
      const u = String(url);
      if (u.endsWith("/api/v1/auth/login")) return jsonResp(200, { ...ySession, userId: X });
      if (u.endsWith("/api/v1/auth/refresh")) return jsonResp(200, { accessToken: "y-acc9", refreshToken: "y-ref9" });
      if (u.endsWith("/api/v1/account/keys")) return jsonResp(401, { error: "unauthorized" });
      return jsonResp(404, {});
    });
    const s = await client.login("y@example.com", "auth", "test");
    client.boundUserId = pendingSignInBinding();
    expect(client.boundUserId).not.toBe(s.userId);
    expect(client.boundUserId, "a fresh placeholder each time").not.toBe(pendingSignInBinding());
    await client.accountKeys().catch(() => {});
    expect(loadSession()?.tokens?.refreshToken, "X's persisted pair is neither replaced nor adopted").toBe("x-ref");
  });

  it("a sign-in that fails after login() revokes the pair it got and drops it, writing nothing", async () => {
    localStorage.setItem(`andvari.cacheOptIn.${X}`, "1");
    saveSession(meta(X, { accessToken: "x-acc", refreshToken: "x-ref" })); // another tab's live shared pair for X
    const client = makeClient(null, "");
    const seen = { logouts: [] as (string | null)[] };
    vi.stubGlobal("fetch", async (url: string | URL, init?: RequestInit) => {
      const u = String(url);
      if (u.endsWith("/api/v1/auth/login")) return jsonResp(200, { ...ySession, userId: X });
      if (u.endsWith("/api/v1/auth/logout")) {
        seen.logouts.push((init?.headers as Record<string, string> | undefined)?.["Authorization"] ?? null);
        return jsonResp(204, {});
      }
      return jsonResp(404, {});
    });
    await client.login("y@example.com", "auth", "test");
    client.boundUserId = X; // even after unlock had bound it, a later failure must not write under X
    expect(await abandonSignIn(client)).toBe(true);
    expect(seen.logouts).toEqual(["Bearer y-acc"]);
    expect(client.getTokens()).toBeNull();
    expect(loadSession()?.tokens?.refreshToken, "the persisted session is untouched").toBe("x-ref");
    expect(abandonSignIn(client), "nothing held, nothing to revoke").toBeNull();
  });

  it("login() fires no onTokens; register's pair is installed without persisting either", async () => {
    const onTokens = vi.fn();
    const client = new ApiClient("", null, onTokens);
    vi.stubGlobal("fetch", async () => jsonResp(200, ySession));
    await client.login("y@example.com", "auth", "test");
    expect(onTokens).not.toHaveBeenCalled();
    client.useSessionTokens({ accessToken: "r-acc", refreshToken: "r-ref" });
    expect(onTokens).not.toHaveBeenCalled();
    expect(client.getTokens()?.refreshToken).toBe("r-ref");
  });

  it("Welcome binds the client and saves the CURRENT pair, for both sign-in and register", () => {
    const signIn = welcomeTsx.slice(welcomeTsx.indexOf("function SignIn("), welcomeTsx.indexOf("const ADMIN_PIN_PENDING"));
    // W-a: a placeholder between login() and Account.unlock; the server's userId only after unlock succeeded.
    const login = signIn.indexOf("client.login(email, authKey, deviceName()");
    const pending = signIn.indexOf("client.boundUserId = pendingSignInBinding();");
    const unlock = signIn.indexOf("await Account.unlock(s.userId");
    const bind = signIn.indexOf("client.boundUserId = s.userId;");
    expect(login).toBeGreaterThan(0);
    expect(pending).toBeGreaterThan(login);
    expect(unlock).toBeGreaterThan(pending);
    expect(bind).toBeGreaterThan(unlock);
    // The pre-existing leak: a sign-in that fails after login() revokes and drops the pair it got.
    expect(signIn).toContain("if (signedIn && !saved) void abandonSignIn(client);");
    expect(signIn).toContain("tokens: client.getTokens(),");
    expect(welcomeTsx).toContain("client.useSessionTokens({ accessToken: s.accessToken, refreshToken: s.refreshToken });");
    expect(welcomeTsx).not.toContain("client.setTokens({ accessToken: s.accessToken, refreshToken: s.refreshToken });");
  });
});

describe("W1 wiring in App", () => {
  it("the lock records its revoke result and surfaces a refusal; sign-out uses revokeForSignOut with it", () => {
    const lockPerTab = appTsx.slice(appTsx.indexOf("const lockPerTab = useCallback"), appTsx.indexOf("const lockLocal = useCallback"));
    expect(lockPerTab).toContain("const { revoked } = await lockTabTokens(");
    expect(lockPerTab).toContain("lockRevokeRef.current = revoked;");
    expect(lockPerTab).toContain("LOCK_REVOKE_UNCONFIRMED");
    const signOut = appTsx.slice(appTsx.indexOf("const signOut = useCallback"), appTsx.indexOf("const lockChannelRef = "));
    expect(signOut).toContain('kind === "user" ? await revokeForSignOut(clientRef.current, lockRevokeRef.current, lockRevokeUnconfirmed(uid)) : true');
  });
});
