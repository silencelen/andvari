import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Tokens } from "../api/client";
import { loadSession, makeClient, saveSession, type Session } from "./session";

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
