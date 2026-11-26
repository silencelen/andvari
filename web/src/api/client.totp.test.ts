import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiClient } from "./client";

/**
 * The two-factor card's confirm step on the REST client. Setting two-step sign-in up is not on this client any more: it
 * is WireApi.totpSetup, always with the password proof (vault/twostep-setup.test.ts).
 */
describe("ApiClient two-factor routes", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("confirm resolves on the server's plain-text ok (the old client parsed it as JSON and threw after a success)", async () => {
    const bodies: (string | undefined)[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string | URL, init?: RequestInit) => {
        bodies.push(init?.body as string | undefined);
        return new Response("ok", { status: 200, headers: { "Content-Type": "text/plain" } });
      }),
    );
    await expect(new ApiClient("http://server", { accessToken: "a", refreshToken: "r" }).totpConfirm("123456")).resolves.toBeUndefined();
    expect(JSON.parse(bodies[0]!)).toEqual({ code: "123456" });
  });

  it("offers no setup without the proof", () => {
    expect("totpSetup" in ApiClient.prototype).toBe(false);
  });
});
