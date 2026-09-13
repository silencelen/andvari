import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiClient } from "./client";

/**
 * H24 (audit 2026-09-13) + PRC-1: `POST /admin/recovery` must carry the recovery-cli bundle
 * BYTE-FOR-BYTE. The CLI serializes the server's own RecoveryUpload type (pretty-printed, key
 * order and whitespace its own); re-serializing on the client once turned `tempKdfParams` into
 * a JSON string and 400'd the last step of the household's only path back from a forgotten
 * master password. So the wire pin here is on the RAW body string, not a parsed shape.
 */
describe("ApiClient.adminRecovery", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("POSTs the bundle text verbatim as application/json with the bearer, and returns the server's 'ok'", async () => {
    const calls: { method?: string; url: string; headers: Record<string, string>; body: unknown }[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL, init?: RequestInit) => {
        calls.push({ method: init?.method, url: String(url), headers: init?.headers as Record<string, string>, body: init?.body });
        return { ok: true, status: 200, statusText: "OK", text: async () => "ok", json: async () => ({}) } as unknown as Response;
      }),
    );
    const client = new ApiClient("http://server", { accessToken: "a", refreshToken: "r" });
    // Deliberately NOT the shape JSON.stringify(JSON.parse(x)) would produce: pretty-printed,
    // with a trailing newline exactly as the CLI's File.writeText emits it.
    const text = '{\n  "userId": "u1",\n  "tempKdfParams": {\n    "v": 1\n  }\n}\n';
    const r = await client.adminRecovery(text);
    expect(r).toBe("ok");
    expect(calls).toHaveLength(1);
    expect(calls[0]!.method).toBe("POST");
    expect(calls[0]!.url).toBe("http://server/api/v1/admin/recovery");
    expect(calls[0]!.headers["Content-Type"]).toBe("application/json");
    expect(calls[0]!.headers["Authorization"]).toBe("Bearer a");
    expect(calls[0]!.body, "the bytes on the wire are the CLI's bytes").toBe(text);
  });

  it("surfaces the server's refusal codes as ApiError (no_such_user, kdf_too_weak, bad_request) for the panel to name", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ ok: false, status: 400, statusText: "Bad Request", json: async () => ({ error: "no_such_user", message: "x" }), text: async () => "" }) as unknown as Response),
    );
    const client = new ApiClient("http://server", { accessToken: "a", refreshToken: "r" });
    await expect(client.adminRecovery("{}")).rejects.toMatchObject({ status: 400, code: "no_such_user" });
  });
});
