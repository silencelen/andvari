import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiClient, ApiError } from "./client";

/**
 * Audit H34: `putUsage` must REJECT on a non-2xx. It used to ride raw(), which resolves with the
 * error Response, so a refused ledger write (400 `bad_usage_blob`, 413, 5xx, an uncurable 401)
 * looked exactly like a landed one and UsageTracker.flush()'s re-arm catch was unreachable for
 * every server refusal — the window's uses were dropped with no signal. The extension (json())
 * and core (`if (!resp.status.isSuccess()) throw`) already threw; this pins web to the same
 * contract at the client seam, where the tracker's duck-typed tests cannot see it.
 */

const resp = (status: number, body: unknown): Response =>
  ({
    ok: status >= 200 && status < 300,
    status,
    statusText: String(status),
    json: async () => body,
    text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
  }) as unknown as Response;

function stub(status: number, body: unknown): { calls: { method: string; path: string; body: unknown }[] } {
  const calls: { method: string; path: string; body: unknown }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string | URL, init?: RequestInit) => {
      calls.push({ method: init?.method ?? "GET", path: String(url).replace("http://server", ""), body: init?.body ? JSON.parse(String(init.body)) : undefined });
      return resp(status, body);
    }),
  );
  return { calls };
}

const client = () => new ApiClient("http://server", { accessToken: "a", refreshToken: "r" });

describe("ApiClient.putUsage (spec 03 §3 — audit H34)", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("PUT /usage carries { sealedUsage } and resolves on 200", async () => {
    const { calls } = stub(200, "ok");
    await expect(client().putUsage("c2VhbGVk")).resolves.toBe("ok");
    expect(calls[0]).toMatchObject({ method: "PUT", path: "/api/v1/usage", body: { sealedUsage: "c2VhbGVk" } });
  });

  it("REJECTS a refused write with the server's code, so the tracker re-arms instead of dropping the uses", async () => {
    stub(400, { error: "bad_usage_blob", message: "ledger too large" });
    const err = await client().putUsage("c2VhbGVk").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).code).toBe("bad_usage_blob");
  });

  it("REJECTS a 5xx the same way — a transient blip must not read as a landed flush", async () => {
    stub(503, { error: "unavailable", message: "try later" });
    await expect(client().putUsage("c2VhbGVk")).rejects.toBeInstanceOf(ApiError);
  });
});
