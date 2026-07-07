import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiClient, ApiError, type Tokens } from "./client";

/**
 * F25 — the refresh token is SINGLE-USE and rotating, and the server's reuse heuristic
 * revokes the whole device (`refresh_reuse`). These tests drive ApiClient against a
 * stateful fake of that server (mocked fetch, same pattern as client.events.test.ts)
 * and assert the client can never be maneuvered into replaying a consumed token:
 * concurrent 401s share ONE in-flight rotation, a pair already rotated by another tab
 * is ADOPTED via readPersistedTokens instead of spent, and the rotation runs inside
 * the `andvari-refresh` Web Lock where the API exists.
 */

/** What the client holds at test start: a valid refresh token, an EXPIRED access token. */
const STALE: Tokens = { accessToken: "a-stale", refreshToken: "r0" };

const SYNC_BODY = { rev: 1, full: true, vaults: [], grants: [], items: [], removedGrants: [] };

const jsonResp = (status: number, body: unknown): Response =>
  ({
    ok: status >= 200 && status < 300,
    status,
    statusText: String(status),
    json: async () => body,
    text: async () => JSON.stringify(body),
  }) as unknown as Response;

const flush = async () => {
  for (let i = 0; i < 25; i++) await Promise.resolve();
};

/**
 * Stateful fake of the server's rotating-refresh scheme. `reuseDetected` flips — and
 * the device is "revoked" — the moment ANY request replays a non-current refresh
 * token: the exact catastrophe F25 exists to prevent, so every test asserts it stayed
 * false. `beforeRotate` lets a test hold the rotation open to prove concurrency.
 */
function fakeAuthServer(current: Tokens, opts: { beforeRotate?: () => Promise<void> } = {}) {
  const state = {
    current: { ...current },
    rotations: 0,
    refreshPosts: 0,
    reuseDetected: false,
    dataAuths: [] as string[],
  };
  const fetchImpl = async (url: string | URL, init?: RequestInit): Promise<Response> => {
    const u = String(url);
    if (u.endsWith("/api/v1/auth/refresh")) {
      state.refreshPosts++;
      const body = JSON.parse(String(init?.body)) as { refreshToken: string };
      if (body.refreshToken !== state.current.refreshToken) {
        state.reuseDetected = true; // server heuristic: replayed token → device revoked
        return jsonResp(401, { error: "refresh_reuse", message: "device revoked" });
      }
      await opts.beforeRotate?.();
      state.rotations++;
      state.current = { accessToken: `a${state.rotations}`, refreshToken: `r${state.rotations}` };
      return jsonResp(200, state.current);
    }
    const auth = (init?.headers as Record<string, string>)["Authorization"] ?? "";
    state.dataAuths.push(auth);
    return auth === `Bearer ${state.current.accessToken}`
      ? jsonResp(200, u.includes("/api/v1/sync") ? SYNC_BODY : {})
      : jsonResp(401, { error: "unauthorized", message: "expired" });
  };
  return { state, fetchImpl };
}

describe("ApiClient single-flight token refresh (F25)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("two concurrent 401s spend the refresh token exactly once (no refresh_reuse)", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const server = fakeAuthServer({ accessToken: "a0", refreshToken: "r0" }, { beforeRotate: () => gate });
    vi.stubGlobal("fetch", vi.fn(server.fetchImpl));
    const onTokens = vi.fn();
    const client = new ApiClient("http://server", { ...STALE }, onTokens);

    // A WS-bell sync racing a user save at access expiry: both 401 concurrently.
    const both = Promise.all([client.accountKeys(), client.sync(0)]);
    await flush();
    // Both callers are parked on the ONE in-flight rotation.
    expect(server.state.refreshPosts).toBe(1);
    release();
    await both;

    expect(server.state.refreshPosts).toBe(1); // never a second POST
    expect(server.state.rotations).toBe(1);
    expect(server.state.reuseDetected).toBe(false); // the device would have been revoked
    // Both first attempts used the stale token; both retries the rotated one.
    expect(server.state.dataAuths.filter((a) => a === "Bearer a-stale")).toHaveLength(2);
    expect(server.state.dataAuths.filter((a) => a === "Bearer a1")).toHaveLength(2);
    expect(onTokens).toHaveBeenCalledTimes(1);
    expect(client.getTokens()).toEqual({ accessToken: "a1", refreshToken: "r1" });
  });

  it("sequential expiries rotate again — the in-flight handle is released after settling", async () => {
    const server = fakeAuthServer({ accessToken: "a0", refreshToken: "r0" });
    vi.stubGlobal("fetch", vi.fn(server.fetchImpl));
    const client = new ApiClient("http://server", { ...STALE });

    await client.sync(0); // 401 → rotation 1 → retry ok
    expect(server.state.rotations).toBe(1);

    // An hour later the next access token has expired too.
    server.state.current = { ...server.state.current, accessToken: "a1-expired-server-side" };
    await client.sync(0); // 401 → rotation 2 (spends r1, which is still current)
    expect(server.state.rotations).toBe(2);
    expect(server.state.reuseDetected).toBe(false);
  });

  it("adopts a pair another tab already rotated instead of replaying the spent token", async () => {
    // Tab A already rotated r0→r1 and persisted the new pair; OUR in-memory copy still
    // holds r0 — which the server now treats as CONSUMED. POSTing it would revoke the
    // device; the re-read inside the refresh path must adopt tab A's pair instead.
    const persisted: Tokens = { accessToken: "a1", refreshToken: "r1" };
    const server = fakeAuthServer(persisted);
    vi.stubGlobal("fetch", vi.fn(server.fetchImpl));
    const onTokens = vi.fn();
    const client = new ApiClient("http://server", { ...STALE }, onTokens, () => ({ ...persisted }));

    await client.sync(0);

    expect(server.state.refreshPosts).toBe(0); // no rotation POST at all
    expect(server.state.reuseDetected).toBe(false);
    expect(onTokens).toHaveBeenCalledWith(persisted); // adopted, and surfaced to the persistence hook
    expect(client.getTokens()).toEqual(persisted);
    expect(server.state.dataAuths.at(-1)).toBe("Bearer a1"); // retried with the adopted access token
  });

  it("runs the rotation inside the andvari-refresh web lock, re-reading persisted tokens INSIDE it", async () => {
    const events: string[] = [];
    const server = fakeAuthServer({ accessToken: "a0", refreshToken: "r0" });
    vi.stubGlobal("fetch", vi.fn(server.fetchImpl));
    vi.stubGlobal("navigator", {
      locks: {
        request: vi.fn(async (name: string, cb: (lock: unknown) => Promise<boolean>) => {
          events.push(`lock:${name}`);
          const out = await cb(null);
          events.push("unlock");
          return out;
        }),
      },
    });
    const client = new ApiClient("http://server", { ...STALE }, () => {}, () => {
      events.push("read-persisted");
      return null; // nothing newer persisted → proceed to rotate
    });

    await client.sync(0);

    expect(events).toEqual(["lock:andvari-refresh", "read-persisted", "unlock"]);
    expect(server.state.rotations).toBe(1);
    expect(server.state.reuseDetected).toBe(false);
  });

  it("a refresh the server refuses clears the pair and surfaces the 401", async () => {
    // Device revoked server-side: every token is dead. The client must give up (no
    // retry loop), drop the pair, and let the caller's 401 path take over.
    const server = fakeAuthServer({ accessToken: "aX", refreshToken: "rX" }); // client's r0 is not current → refused
    vi.stubGlobal("fetch", vi.fn(server.fetchImpl));
    const onTokens = vi.fn();
    const client = new ApiClient("http://server", { ...STALE }, onTokens);

    const err = await client.sync(0).catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(401);
    expect(client.getTokens()).toBeNull();
    expect(onTokens).toHaveBeenCalledWith(null);
  });

  it("a transport failure during refresh keeps the pair (transient — retry later succeeds)", async () => {
    const server = fakeAuthServer({ accessToken: "a0", refreshToken: "r0" });
    let refreshNetDown = true;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL, init?: RequestInit) => {
        if (String(url).endsWith("/api/v1/auth/refresh") && refreshNetDown) throw new TypeError("network down");
        return server.fetchImpl(url, init);
      }),
    );
    const client = new ApiClient("http://server", { ...STALE });

    // The VPN blipped exactly at rotation time: the caller sees the failure, but the
    // still-valid pair must NOT be dropped — it is the only way back in.
    await expect(client.sync(0)).rejects.toThrow(/network down/);
    expect(client.getTokens()).toEqual(STALE);

    refreshNetDown = false;
    await client.sync(0); // the in-flight handle was released; this rotation succeeds
    expect(server.state.rotations).toBe(1);
    expect(client.getTokens()).toEqual({ accessToken: "a1", refreshToken: "r1" });
  });

  it("(sanity) the fake server does revoke on an actual replay", async () => {
    // Guards the guard: prove the fixture detects the catastrophe the client avoids.
    const server = fakeAuthServer({ accessToken: "a0", refreshToken: "r-current" });
    const replayed = await server.fetchImpl("http://server/api/v1/auth/refresh", {
      method: "POST",
      body: JSON.stringify({ refreshToken: "r-consumed" }),
    });
    expect(replayed.status).toBe(401);
    expect(server.state.reuseDetected).toBe(true);
    expect(((await replayed.json()) as { error: string }).error).toBe("refresh_reuse");
  });
});
