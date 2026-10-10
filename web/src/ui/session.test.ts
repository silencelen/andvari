import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LOGOUT_TIMEOUT_MS, type Tokens } from "../api/client";
import { loadSession, makeClient, revokeSessionBestEffort, saveSession, type Session } from "./session";

/**
 * SAME-USER token guards in makeClient (shared family browser): the persisted session
 * can come to belong to a DIFFERENT account than the one a long-lived tab was opened
 * for (user X's frozen tab wakes after user Y signed in elsewhere). X's client must
 * neither ADOPT Y's persisted pair during a refresh nor WRITE X's rotations into Y's
 * persisted session — either would splice two accounts' credentials together.
 */

/** Map-backed localStorage for the node test environment. */
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

const sess = (userId: string, tokens: Tokens): Session => ({
  baseUrl: "",
  userId,
  personalVaultId: "pv",
  email: `${userId}@example.com`,
  isAdmin: false,
  tokens,
});

const SYNC_BODY = { rev: 1, full: true, vaults: [], grants: [], items: [], removedGrants: [] };

const jsonResp = (status: number, body: unknown): Response =>
  ({
    ok: status >= 200 && status < 300,
    status,
    statusText: String(status),
    json: async () => body,
    text: async () => JSON.stringify(body),
  }) as unknown as Response;

describe("makeClient same-user token guards", () => {
  beforeEach(() => {
    vi.stubGlobal("localStorage", fakeStorage());
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("does NOT adopt a different user's persisted pair — rotates its own token instead", async () => {
    // X's tab: client created while X's session was the persisted one.
    const xTokens: Tokens = { accessToken: "xa0", refreshToken: "xr0" };
    saveSession(sess("user-x", xTokens));
    const client = makeClient(loadSession(), "http://server");
    // Then Y signed in from another tab: the persisted session is now Y's.
    const yTokens: Tokens = { accessToken: "ya9", refreshToken: "yr9" };
    saveSession(sess("user-y", yTokens));

    let refreshedWith: string | null = null;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL, init?: RequestInit) => {
        if (String(url).endsWith("/api/v1/auth/refresh")) {
          refreshedWith = (JSON.parse(String(init?.body)) as { refreshToken: string }).refreshToken;
          return jsonResp(200, { accessToken: "xa1", refreshToken: "xr1" });
        }
        const auth = (init?.headers as Record<string, string>)["Authorization"];
        return auth === "Bearer xa1" ? jsonResp(200, SYNC_BODY) : jsonResp(401, { error: "unauthorized" });
      }),
    );

    // X's access token expires → refresh. It must fall through to a REAL rotation
    // with X's own refresh token, not graft Y's pair into X's live client.
    await client.sync(0);
    expect(refreshedWith).toBe("xr0");
    expect(client.getTokens()).toEqual({ accessToken: "xa1", refreshToken: "xr1" });

    // …and X's rotation was NOT written over Y's persisted session either.
    expect(loadSession()?.userId).toBe("user-y");
    expect(loadSession()?.tokens).toEqual(yTokens);
  });

  it("adopts a pair a SAME-user tab already rotated (no rotation POST)", async () => {
    const xTokens: Tokens = { accessToken: "xa0", refreshToken: "xr0" };
    saveSession(sess("user-x", xTokens));
    const client = makeClient(loadSession(), "http://server");
    // Another tab of the SAME user rotated and persisted the new pair.
    saveSession(sess("user-x", { accessToken: "xa5", refreshToken: "xr5" }));

    let refreshPosts = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL, init?: RequestInit) => {
        if (String(url).endsWith("/api/v1/auth/refresh")) {
          refreshPosts++;
          return jsonResp(401, { error: "refresh_reuse" }); // adopting means we never get here
        }
        const auth = (init?.headers as Record<string, string>)["Authorization"];
        return auth === "Bearer xa5" ? jsonResp(200, SYNC_BODY) : jsonResp(401, { error: "unauthorized" });
      }),
    );

    await client.sync(0);
    expect(refreshPosts).toBe(0); // adopted instead of spending the consumed xr0
    expect(client.getTokens()).toEqual({ accessToken: "xa5", refreshToken: "xr5" });
  });

  it("a client created without a session (fresh sign-in) never adopts persisted tokens", async () => {
    // The sign-in form's client predates any session of its own; whatever pair is
    // persisted belongs to someone else's flow — rotation must use its OWN token.
    const client = makeClient(null, "http://server");
    client.setTokens({ accessToken: "fa0", refreshToken: "fr0" }); // as login() would
    saveSession(sess("user-y", { accessToken: "ya9", refreshToken: "yr9" }));

    let refreshedWith: string | null = null;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL, init?: RequestInit) => {
        if (String(url).endsWith("/api/v1/auth/refresh")) {
          refreshedWith = (JSON.parse(String(init?.body)) as { refreshToken: string }).refreshToken;
          return jsonResp(200, { accessToken: "fa1", refreshToken: "fr1" });
        }
        const auth = (init?.headers as Record<string, string>)["Authorization"];
        return auth === "Bearer fa1" ? jsonResp(200, SYNC_BODY) : jsonResp(401, { error: "unauthorized" });
      }),
    );

    await client.sync(0);
    expect(refreshedWith).toBe("fr0");
  });
});

/**
 * bug-web--0 (spec 03): USER sign-out must revoke the device session server-side — the web's
 * three sign-out paths route it through revokeSessionBestEffort BEFORE their local teardown.
 * Best-effort + bounded: the POST fires with the held credential, but a refusing, unreachable,
 * or HUNG server never blocks the wipe (the natives' 5 s logout timeout, mirrored).
 */
describe("revokeSessionBestEffort — sign-out revocation", () => {
  beforeEach(() => {
    vi.stubGlobal("localStorage", fakeStorage());
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("POSTs /auth/logout with the held access token and drops the client's pair", async () => {
    saveSession(sess("user-x", { accessToken: "xa0", refreshToken: "xr0" }));
    const client = makeClient(loadSession(), "http://server");
    let logoutAuth: string | null = null;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL, init?: RequestInit) => {
        if (String(url).endsWith("/api/v1/auth/logout")) {
          logoutAuth = (init?.headers as Record<string, string>)["Authorization"] ?? null;
          return jsonResp(200, {});
        }
        return jsonResp(404, { error: "not_found" });
      }),
    );
    await expect(revokeSessionBestEffort(client)).resolves.toBe(true);
    expect(logoutAuth).toBe("Bearer xa0"); // the revocation actually fired, as this device
    // The POST does NOT clear the pair — dropping it is the sign-out path's own next line
    // (App.signOut, Welcome's two teardowns). See the late-resolve test below for why.
    expect(client.getTokens()).not.toBeNull();
  });

  it("the revocation POST carries an abort signal, so the bound cancels it", async () => {
    saveSession(sess("user-x", { accessToken: "xa0", refreshToken: "xr0" }));
    const client = makeClient(loadSession(), "http://server");
    let signal: AbortSignal | null | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string | URL, init?: RequestInit) => {
        signal = init?.signal;
        return jsonResp(200, {});
      }),
    );
    await revokeSessionBestEffort(client);
    // Without one, abandoning the 5 s race leaves the request running indefinitely.
    expect(signal).toBeInstanceOf(AbortSignal);
  });

  /**
   * Security review 2026-10 (web sign-out): a 401 on the logout POST does NOT mean the session is
   * dead server-side — access tokens expire after 1 h while the refresh token lives 30 days. The
   * old "no refresh-retry on 401" premise left a copied refresh token alive after the member
   * signed out of any tab that had sat locked past the hour. Logout now spends the refresh token
   * it captured, ONCE, and revokes with the fresh access token — without adopting the new pair
   * (the caller is about to drop it; persisting it would resurrect the session).
   */
  it("an EXPIRED access token: logout refreshes once with the held refresh token, then revokes", async () => {
    saveSession(sess("user-x", { accessToken: "xa0", refreshToken: "xr0" }));
    const client = makeClient(loadSession(), "http://server");
    const calls: { path: string; auth: string | null; body: string | null }[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL, init?: RequestInit) => {
        const path = new URL(String(url)).pathname;
        const auth = (init?.headers as Record<string, string>)["Authorization"] ?? null;
        calls.push({ path, auth, body: (init?.body as string | undefined) ?? null });
        if (path === "/api/v1/auth/refresh") return jsonResp(200, { accessToken: "na1", refreshToken: "nr1" });
        if (path === "/api/v1/auth/logout") return auth === "Bearer na1" ? jsonResp(200, {}) : jsonResp(401, { error: "unauthorized" });
        return jsonResp(404, { error: "not_found" });
      }),
    );
    await expect(revokeSessionBestEffort(client)).resolves.toBe(true);
    expect(calls.map((c) => c.path)).toEqual(["/api/v1/auth/logout", "/api/v1/auth/refresh", "/api/v1/auth/logout"]);
    expect(JSON.parse(calls[1]!.body!)).toEqual({ refreshToken: "xr0" });
    expect(calls[2]!.auth).toBe("Bearer na1");
    // The rotated pair is spent on the revocation only — never adopted or persisted.
    expect(client.getTokens()).toEqual({ accessToken: "xa0", refreshToken: "xr0" });
    expect(loadSession()?.tokens).toEqual({ accessToken: "xa0", refreshToken: "xr0" });
  });

  it("every request of the expired-token revocation rides the ONE logout abort clock", async () => {
    saveSession(sess("user-x", { accessToken: "xa0", refreshToken: "xr0" }));
    const client = makeClient(loadSession(), "http://server");
    const signals: (AbortSignal | null | undefined)[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL, init?: RequestInit) => {
        signals.push(init?.signal);
        if (String(url).endsWith("/api/v1/auth/refresh")) return jsonResp(200, { accessToken: "na1", refreshToken: "nr1" });
        return signals.length === 1 ? jsonResp(401, { error: "unauthorized" }) : jsonResp(200, {});
      }),
    );
    await revokeSessionBestEffort(client);
    expect(signals).toHaveLength(3);
    expect(signals[0]).toBeInstanceOf(AbortSignal);
    expect(new Set(signals).size).toBe(1);
  });

  it("a refused refresh (dead pair, or the break-glass origin) stops there and reports not revoked", async () => {
    saveSession(sess("user-x", { accessToken: "xa0", refreshToken: "xr0" }));
    const client = makeClient(loadSession(), "http://server");
    const paths: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL) => {
        paths.push(new URL(String(url)).pathname);
        return url.toString().endsWith("/refresh") ? jsonResp(403, { error: "public_refresh_disabled" }) : jsonResp(401, { error: "unauthorized" });
      }),
    );
    await expect(revokeSessionBestEffort(client)).resolves.toBe(false);
    expect(paths).toEqual(["/api/v1/auth/logout", "/api/v1/auth/refresh"]);
    expect(client.getTokens()).toEqual({ accessToken: "xa0", refreshToken: "xr0" }); // the caller drops it, not logout()
  });

  it("a logout abandoned at the bound never clears a LATER session's tokens", async () => {
    vi.useFakeTimers();
    saveSession(sess("user-x", { accessToken: "xa0", refreshToken: "xr0" }));
    const client = makeClient(loadSession(), "http://server");
    let land: ((r: Response) => void) | null = null;
    vi.stubGlobal("fetch", vi.fn(() => new Promise<Response>((resolve) => { land = resolve; })));

    const p = revokeSessionBestEffort(client);
    client.setTokens(null); // the sign-out's own teardown, right after the revocation is issued
    await vi.advanceTimersByTimeAsync(LOGOUT_TIMEOUT_MS);
    await p; // race abandoned — the sign-out completed and the user signed back in:
    client.setTokens({ accessToken: "ya0", refreshToken: "yr0" });

    land!(jsonResp(200, {})); // …and only NOW the abandoned revocation resolves
    await vi.advanceTimersByTimeAsync(0);
    // It must not touch the new session. A `.finally(() => setTokens(null))` on logout()
    // signed the user straight back out here, one request behind.
    expect(client.getTokens()).toEqual({ accessToken: "ya0", refreshToken: "yr0" });
  });

  it("resolves instead of rejecting when the server is unreachable — the wipe must proceed", async () => {
    saveSession(sess("user-x", { accessToken: "xa0", refreshToken: "xr0" }));
    const client = makeClient(loadSession(), "http://server");
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new TypeError("Failed to fetch"))));
    await expect(revokeSessionBestEffort(client)).resolves.toBe(false);
  });

  it("a HUNG logout is abandoned at the 5 s bound — never a wedged sign-out", async () => {
    vi.useFakeTimers();
    saveSession(sess("user-x", { accessToken: "xa0", refreshToken: "xr0" }));
    const client = makeClient(loadSession(), "http://server");
    vi.stubGlobal("fetch", vi.fn(() => new Promise<never>(() => {}))); // black hole
    let settled = false;
    const p = revokeSessionBestEffort(client).then(() => {
      settled = true;
    });
    await vi.advanceTimersByTimeAsync(4_999);
    expect(settled).toBe(false); // still waiting on the server inside the bound
    await vi.advanceTimersByTimeAsync(1);
    await p;
    expect(settled).toBe(true);
  });

  it("a null client (no tab client yet) is a no-op", async () => {
    await expect(revokeSessionBestEffort(null)).resolves.toBe(false);
  });
});
