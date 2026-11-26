import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiClient, END_SESSION_RETRY_MAX_S } from "../api/client";
import { lockTabTokens } from "./tabsession";

/**
 * Anyone behind the same address can spend the server's per-address limit on
 * `end-session`, so a lock's call is answered 429. The tab drops its pair at once, as before; the call it made keeps the
 * refresh token it read and tries once more after the wait the server names (Retry-After), so the session still ends.
 * A wait not named, or longer than END_SESSION_RETRY_MAX_S, is not waited for: the lock resolves "not confirmed", which
 * the unlock card says (App: LOCK_REVOKE_UNCONFIRMED). On the code before, the first 429 was the answer.
 */

const PAIR = { accessToken: "acc-1", refreshToken: "ref-1" };

function server(answers: Array<{ status: number; retryAfter?: string }>) {
  const posts: unknown[] = [];
  vi.stubGlobal("fetch", async (url: string | URL, init?: RequestInit) => {
    if (!String(url).endsWith("/api/v1/auth/end-session")) throw new Error(`unexpected ${String(url)}`);
    posts.push(JSON.parse(String(init?.body)));
    const a = answers.shift() ?? { status: 500 };
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (a.retryAfter !== undefined) headers["Retry-After"] = a.retryAfter;
    return new Response(JSON.stringify(a.status === 200 ? { ok: true } : { error: "rate_limited" }), { status: a.status, headers });
  });
  return posts;
}

const lockOpts = { flush: null, flushWaitMs: 0, revoke: true };

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("the lock's end-session, refused for the moment", () => {
  it("is tried once more after the server's wait, with the same token, while the tab has already dropped its pair", async () => {
    vi.useFakeTimers();
    const posts = server([{ status: 429, retryAfter: "2" }, { status: 200 }]);
    const tab = new ApiClient("", PAIR);
    const { revoked } = await lockTabTokens(tab, lockOpts);
    expect(tab.getTokens()).toBeNull(); // the pair is gone from the tab at once
    let settled: boolean | null = null;
    void revoked!.then((v) => (settled = v));
    await vi.advanceTimersByTimeAsync(1_900);
    expect([posts.length, settled]).toEqual([1, null]); // waiting out the server's wait
    await vi.advanceTimersByTimeAsync(200);
    expect(await revoked).toBe(true);
    expect(posts).toEqual([{ refreshToken: "ref-1" }, { refreshToken: "ref-1" }]);
  });

  it("only once: a second refusal is the answer, \"not confirmed\"", async () => {
    vi.useFakeTimers();
    const posts = server([{ status: 429, retryAfter: "1" }, { status: 429, retryAfter: "1" }]);
    const { revoked } = await lockTabTokens(new ApiClient("", PAIR), lockOpts);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(await revoked).toBe(false);
    expect(posts).toHaveLength(2);
  });

  it("a wait not named, unreadable or longer than the bound is not waited for", async () => {
    for (const retryAfter of [undefined, "soon", String(END_SESSION_RETRY_MAX_S + 1), "-3"]) {
      const posts = server([{ status: 429, ...(retryAfter !== undefined ? { retryAfter } : {}) }, { status: 200 }]);
      const { revoked } = await lockTabTokens(new ApiClient("", PAIR), lockOpts);
      expect(await revoked, String(retryAfter)).toBe(false);
      expect(posts, String(retryAfter)).toHaveLength(1);
    }
  });

  it("any other refusal is not tried again", async () => {
    const posts = server([{ status: 401 }, { status: 200 }]);
    const { revoked } = await lockTabTokens(new ApiClient("", PAIR), lockOpts);
    expect(await revoked).toBe(false);
    expect(posts).toHaveLength(1);
  });
});
