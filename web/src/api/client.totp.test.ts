import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiClient } from "./client";

/**
 * Security review 2026-10 (server F4, client half): POST /account/totp/setup takes an optional
 * `{ currentAuthKey }` — the password proof a FIRST enrollment needs outside the server's
 * fresh-login window (spec 03 §2). The bare call keeps its no-body wire shape.
 */
const jsonResp = (body: unknown): Response =>
  ({ ok: true, status: 200, statusText: "200", json: async () => body, text: async () => JSON.stringify(body) }) as unknown as Response;

function stub(): { bodies: (string | undefined)[] } {
  const bodies: (string | undefined)[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url: string | URL, init?: RequestInit) => {
      bodies.push(init?.body as string | undefined);
      return jsonResp({ secretBase32: "S", otpauthUri: "otpauth://totp/x" });
    }),
  );
  return { bodies };
}

describe("ApiClient.totpSetup — the first-enrollment password proof", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("sends currentAuthKey when given one", async () => {
    const { bodies } = stub();
    await new ApiClient("http://server", { accessToken: "a", refreshToken: "r" }).totpSetup("AUTHKEY");
    expect(JSON.parse(bodies[0]!)).toEqual({ currentAuthKey: "AUTHKEY" });
  });

  it("keeps the fielded no-body shape without one", async () => {
    const { bodies } = stub();
    await new ApiClient("http://server", { accessToken: "a", refreshToken: "r" }).totpSetup();
    expect(bodies[0]).toBeUndefined();
  });
});
