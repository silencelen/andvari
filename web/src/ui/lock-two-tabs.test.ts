import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiClient } from "../api/client";
import { revokeSessionBestEffort } from "./session";

/**
 * Found in the browser walk (two tabs, no offline copy): locking tab 1 locks tab 2 too, and both log the browser's device
 * row out. The second logout finds the session already ended (its access and refresh tokens both 401), and tab 1 then
 * said "The server didn't confirm it ended this tab's session", a false alarm. A refresh refused with 401 is the
 * server saying the session is ended: the revoke is confirmed. Any other answer stays unconfirmed.
 */
describe("a lock's logout that finds the session already ended is confirmed", () => {
  afterEach(() => vi.unstubAllGlobals());

  const withAnswers = (logout: number, refresh: number) => {
    const seen: string[] = [];
    vi.stubGlobal("fetch", async (url: string) => {
      const path = new URL(url).pathname;
      seen.push(path);
      return new Response("{}", { status: path.endsWith("/logout") ? logout : refresh, headers: { "Content-Type": "application/json" } });
    });
    const client = new ApiClient("https://vault.example.org");
    client.setTokens({ accessToken: "a", refreshToken: "r" });
    return { client, seen };
  };

  it("logout 401 then refresh 401: confirmed", async () => {
    const { client, seen } = withAnswers(401, 401);
    expect(await revokeSessionBestEffort(client)).toBe(true);
    expect(seen).toEqual(["/api/v1/auth/logout", "/api/v1/auth/refresh"]);
  });

  it("logout 401 then refresh 503 or 429: not confirmed", async () => {
    expect(await revokeSessionBestEffort(withAnswers(401, 503).client)).toBe(false);
    expect(await revokeSessionBestEffort(withAnswers(401, 429).client)).toBe(false);
  });
});
