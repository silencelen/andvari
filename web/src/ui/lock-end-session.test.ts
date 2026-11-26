import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiClient, type Tokens } from "../api/client";
import { lockTabTokens } from "./tabsession";

/**
 * With the server's narrower call (spec 03 §2, index row 93): on a browser without the offline copy a lock
 * ends exactly its own tab's session, by its own refresh token, and nothing else. The fake server below keeps sessions
 * the way spec 03 §2 says the real one does: one session per (refresh token, access token) pair, sessions grouped by
 * the browser's device row; a refresh rotates into a new session; `end-session` ends the session of a live token and,
 * for a consumed token, every session of its device row (the reuse signal); the logout ends every session of the
 * device row.
 */

type Sess = { device: string; access: string; refresh: string; live: boolean; consumed: boolean };

function fakeServer() {
  const sessions: Sess[] = [];
  const requests: { path: string; auth: string | null; body: unknown }[] = [];
  let n = 0;
  /** A refresh answer held back until the test releases it (a refresh "on its way"). */
  let holdRefresh: Promise<void> | null = null;
  const mint = (device: string): Tokens => {
    n++;
    const s: Sess = { device, access: `acc-${n}`, refresh: `ref-${n}`, live: true, consumed: false };
    sessions.push(s);
    return { accessToken: s.access, refreshToken: s.refresh };
  };
  const resp = (status: number, body: unknown = {}) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  vi.stubGlobal("fetch", async (url: string | URL, init?: RequestInit) => {
    const path = new URL(String(url), "http://srv.invalid").pathname;
    const auth = (init?.headers as Record<string, string> | undefined)?.["Authorization"] ?? null;
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : null;
    requests.push({ path, auth, body });
    const byAccess = auth ? sessions.find((s) => `Bearer ${s.access}` === auth && s.live) : undefined;
    if (path === "/api/v1/auth/refresh") {
      if (holdRefresh) await holdRefresh;
      const s = sessions.find((x) => x.refresh === body?.refreshToken);
      if (!s || !s.live) return resp(401, { error: "session_revoked" });
      if (s.consumed) {
        for (const x of sessions) if (x.device === s.device) x.live = false;
        return resp(401, { error: "refresh_reuse" });
      }
      s.consumed = true;
      s.live = false;
      return resp(200, mint(s.device));
    }
    if (path === "/api/v1/auth/end-session") {
      const s = sessions.find((x) => x.refresh === body?.refreshToken);
      if (s?.consumed) {
        for (const x of sessions) if (x.device === s.device) x.live = false;
      } else if (s) {
        s.live = false;
      }
      return resp(200, { ok: true });
    }
    if (path === "/api/v1/auth/logout") {
      if (!byAccess) return resp(401, { error: "unauthorized" });
      for (const x of sessions) if (x.device === byAccess.device) x.live = false;
      return resp(204);
    }
    if (!byAccess) return resp(401, { error: "unauthorized" });
    return resp(200, {});
  });
  return {
    requests,
    mint,
    /** Expire an access token (the session stays; its refresh token still refreshes). */
    expireAccess(t: Tokens) {
      const s = sessions.find((x) => x.access === t.accessToken)!;
      s.access = `${s.access}-expired`;
    },
    hold(): () => void {
      let release!: () => void;
      holdRefresh = new Promise<void>((r) => (release = r));
      return () => {
        holdRefresh = null;
        release();
      };
    },
    liveFor: (device: string) => sessions.filter((s) => s.device === device && s.live).map((s) => s.refresh),
  };
}

const lockOpts = { flush: null, flushWaitMs: 10, revoke: true } as const;

beforeEach(() => vi.stubGlobal("navigator", {}));
afterEach(() => vi.unstubAllGlobals());

describe("a lock without the offline copy ends its own session, and only that (spec 03 §2 end-session)", () => {
  it("the request made at a lock: one end-session with the tab's refresh token, no bearer, no logout; the pair is gone", async () => {
    const srv = fakeServer();
    const tab = new ApiClient("", srv.mint("browser"));
    const cut = vi.spyOn(tab, "cutLiveTraffic");
    const { revoked } = await lockTabTokens(tab, lockOpts);
    expect(tab.getTokens()).toBeNull();
    expect(cut, "the tab's events socket is closed at the lock").toHaveBeenCalled();
    expect(await revoked).toBe(true);
    expect(srv.requests).toEqual([{ path: "/api/v1/auth/end-session", auth: null, body: { refreshToken: "ref-1" } }]);
    expect(srv.liveFor("browser")).toEqual([]);
  });

  it("the other tab of the same account in the same browser stays signed in: its tokens still work and still refresh", async () => {
    const srv = fakeServer();
    const tab1 = new ApiClient("", srv.mint("browser"));
    const tab2Pair = srv.mint("browser");
    const tab2 = new ApiClient("", tab2Pair);
    const { revoked } = await lockTabTokens(tab1, lockOpts);
    expect(await revoked).toBe(true);
    expect(srv.liveFor("browser"), "only tab 1's session ended").toEqual(["ref-2"]);
    await expect(tab2.accountKeys()).resolves.toBeDefined();
    srv.expireAccess(tab2Pair);
    await expect(tab2.accountKeys(), "tab 2 refreshes on its own token").resolves.toBeDefined();
    expect(tab2.getTokens()?.refreshToken).toBe("ref-3");
    expect(srv.requests.filter((r) => r.path === "/api/v1/auth/logout")).toEqual([]);
  });

  it("a refresh racing the lock: the spent token is never sent, and the session the refresh brings back is ended", async () => {
    const srv = fakeServer();
    const pair = srv.mint("browser");
    const tab1 = new ApiClient("", pair);
    const tab2 = new ApiClient("", srv.mint("browser"));
    srv.expireAccess(pair);
    const release = srv.hold();
    const call = tab1.accountKeys().catch(() => null); // 401, then a refresh that is held on its way
    await vi.waitFor(() => expect(srv.requests.some((r) => r.path === "/api/v1/auth/refresh")).toBe(true));
    const { revoked } = await lockTabTokens(tab1, lockOpts);
    expect(tab1.getTokens()).toBeNull();
    expect(srv.requests.filter((r) => r.path === "/api/v1/auth/end-session"), "nothing is sent while the refresh is on its way").toEqual([]);
    release();
    expect(await revoked).toBe(true);
    await call;
    const ends = srv.requests.filter((r) => r.path === "/api/v1/auth/end-session").map((r) => r.body);
    expect(ends, "the refresh's answer, not the spent token").toEqual([{ refreshToken: "ref-3" }]);
    expect(tab1.getTokens(), "the lock is not undone by the answer").toBeNull();
    expect(srv.liveFor("browser"), "no live token of tab 1 is left, and tab 2 is untouched").toEqual(["ref-2"]);
    await expect(tab2.accountKeys()).resolves.toBeDefined();
  });

  it("a refresh still waiting for another tab's refresh lock never spends the token, so the lock ends the token itself", async () => {
    const srv = fakeServer();
    const pair = srv.mint("browser");
    let grant!: () => void;
    const granted = new Promise<void>((r) => (grant = r));
    vi.stubGlobal("navigator", {
      locks: { request: async (_n: string, _o: unknown, cb: () => Promise<boolean>) => (await granted, cb()) },
    });
    const tab = new ApiClient("", pair);
    srv.expireAccess(pair);
    const call = tab.accountKeys().catch(() => null);
    await vi.waitFor(() => expect(srv.requests.length).toBe(1)); // the 401
    const { revoked } = await lockTabTokens(tab, lockOpts);
    grant();
    expect(await revoked).toBe(true);
    await call;
    expect(srv.requests.filter((r) => r.path !== "/api/v1/account/keys").map((r) => [r.path, r.body])).toEqual([
      ["/api/v1/auth/end-session", { refreshToken: "ref-1" }],
    ]);
    expect(srv.liveFor("browser")).toEqual([]);
  });

  it("a rotated pair that lands after the pair was replaced is ended too: nobody holds it", async () => {
    const srv = fakeServer();
    const pair = srv.mint("browser");
    const tab = new ApiClient("", pair);
    srv.expireAccess(pair);
    const release = srv.hold();
    const call = tab.accountKeys().catch(() => null);
    await vi.waitFor(() => expect(srv.requests.some((r) => r.path === "/api/v1/auth/refresh")).toBe(true));
    tab.setTokens(null);
    release();
    await call;
    await vi.waitFor(() => expect(srv.requests.some((r) => r.path === "/api/v1/auth/end-session")).toBe(true));
    expect(srv.liveFor("browser")).toEqual([]);
  });
});
