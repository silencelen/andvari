import { afterEach, describe, expect, it, vi } from "vitest";
import { ACCOUNT_DELETE_TIMEOUT_MS, AccountDeleteBlockedError, AccountDeleteUnknownError, ApiError, ApiClient } from "./client";

/**
 * Account deletion on the wire (spec 03 §13): `GET /account/delete/preview` with its served ids held to the grammar (A10),
 * and `POST /account/delete` — the exact body, the 409 refusal surfaced WITH its blockers, every other refusal of the
 * server's as the usual ApiError, and the replies that prove nothing — a transport failure (left to the caller), any 5xx,
 * anything that is not the server's JSON — as an unknown outcome (the request is not idempotent and may have committed).
 */

const V1 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const V2 = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

const resp = (status: number, body: unknown): Response =>
  ({
    ok: status >= 200 && status < 300,
    status,
    statusText: String(status),
    json: async () => body,
    text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
  }) as unknown as Response;

function stub(...answers: Response[]): { calls: { url: string; method?: string; body?: string; auth?: string }[] } {
  const calls: { url: string; method?: string; body?: string; auth?: string }[] = [];
  let i = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string | URL, init?: RequestInit) => {
      calls.push({ url: String(url), method: init?.method, body: init?.body as string | undefined, auth: (init?.headers as Record<string, string> | undefined)?.Authorization });
      return answers[Math.min(i++, answers.length - 1)]!;
    }),
  );
  return { calls };
}

const client = () => new ApiClient("http://server", { accessToken: "a", refreshToken: "r" });

describe("ApiClient.accountDeletePreview", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("GETs the preview and keeps well-formed ids", async () => {
    const { calls } = stub(resp(200, { blockers: [{ kind: "shared_vault", vaultId: V1, others: 2 }], deletedVaults: [V2], leftVaults: [], totpRequired: true }));
    const p = await client().accountDeletePreview();
    expect(calls[0]).toMatchObject({ url: "http://server/api/v1/account/delete/preview", method: "GET", auth: "Bearer a" });
    expect(p).toEqual({ blockers: [{ kind: "shared_vault", vaultId: V1, others: 2 }], deletedVaults: [V2], leftVaults: [], totpRequired: true });
  });

  it("drops a malformed consequence id but KEEPS a blocker whose id is malformed — a refusal never shrinks", async () => {
    stub(resp(200, { blockers: [{ kind: "shared_vault", vaultId: "../admin", others: 1 }], deletedVaults: [V1, "not-a-uuid"], leftVaults: ["x\ny"], totpRequired: false }));
    const c = client();
    const refused: string[] = [];
    c.onRefusedIds = (_endpoint, r) => refused.push(...r.map((x) => x.field));
    const p = await c.accountDeletePreview();
    expect(p.blockers).toEqual([{ kind: "shared_vault", vaultId: null, others: 1 }]);
    expect(p.deletedVaults).toEqual([V1]);
    expect(p.leftVaults).toEqual([]);
    expect(refused.sort()).toEqual(["blockers.vaultId", "deletedVaults", "leftVaults"]);
  });
});

describe("ApiClient.deleteAccount", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("POSTs exactly { confirmEmail, currentAuthKey, totp? } and returns deletedAt", async () => {
    const { calls } = stub(resp(200, { deletedAt: 1_800_000_000_000 }));
    const r = await client().deleteAccount({ confirmEmail: "me@x.com", currentAuthKey: "KEY", totp: "123456" });
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({ url: "http://server/api/v1/account/delete", method: "POST" });
    expect(JSON.parse(calls[0]!.body!)).toEqual({ confirmEmail: "me@x.com", currentAuthKey: "KEY", totp: "123456" });
    expect(r.deletedAt).toBe(1_800_000_000_000);
  });

  it("a 409 account_delete_blocked throws AccountDeleteBlockedError carrying the blockers", async () => {
    stub(resp(409, { error: "account_delete_blocked", message: "account deletion is blocked", blockers: [{ kind: "shared_vault", vaultId: V1, others: 1 }, { kind: "last_admin", others: 3 }] }));
    const e = await client().deleteAccount({ confirmEmail: "me@x.com", currentAuthKey: "KEY" }).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(AccountDeleteBlockedError);
    expect(e).toBeInstanceOf(ApiError);
    expect((e as AccountDeleteBlockedError).code).toBe("account_delete_blocked");
    expect((e as AccountDeleteBlockedError).blockers).toEqual([{ kind: "shared_vault", vaultId: V1, others: 1 }, { kind: "last_admin", vaultId: null, others: 3 }]);
  });

  it("a malformed blocker row becomes an unknown blocker, and a refusal with none is still a refusal", async () => {
    stub(resp(409, { error: "account_delete_blocked", message: "m", blockers: [42, { kind: 7 }] }));
    const e = (await client().deleteAccount({ confirmEmail: "me@x.com", currentAuthKey: "KEY" }).catch((x: unknown) => x)) as AccountDeleteBlockedError;
    expect(e.blockers).toEqual([{ kind: "unknown", vaultId: null, others: 0 }, { kind: "unknown", vaultId: null, others: 0 }]);
    stub(resp(409, { error: "account_delete_blocked", message: "m" }));
    const empty = (await client().deleteAccount({ confirmEmail: "me@x.com", currentAuthKey: "KEY" }).catch((x: unknown) => x)) as AccountDeleteBlockedError;
    expect(empty).toBeInstanceOf(AccountDeleteBlockedError);
    expect(empty.blockers).toEqual([]);
  });

  it("any other 409 is a plain ApiError", async () => {
    stub(resp(409, { error: "something_else", message: "m" }));
    const e = await client().deleteAccount({ confirmEmail: "me@x.com", currentAuthKey: "KEY" }).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(ApiError);
    expect(e).not.toBeInstanceOf(AccountDeleteBlockedError);
    expect((e as ApiError).code).toBe("something_else");
  });

  it("a wrong proof is a 403 reauth_failed: surfaced as-is, with no token refresh", async () => {
    const { calls } = stub(resp(403, { error: "reauth_failed", message: "forbidden" }));
    const e = (await client().deleteAccount({ confirmEmail: "me@x.com", currentAuthKey: "WRONG" }).catch((x: unknown) => x)) as ApiError;
    expect(e.status).toBe(403);
    expect(e.code).toBe("reauth_failed");
    expect(calls, "nothing was refreshed or re-sent").toHaveLength(1);
  });

  it("a transport failure propagates untouched — the caller reports the outcome as unknown", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("Failed to fetch"); }));
    await expect(client().deleteAccount({ confirmEmail: "me@x.com", currentAuthKey: "KEY" })).rejects.toBeInstanceOf(TypeError);
  });

  it("any 5xx is an UNKNOWN outcome — a proxy's page or the server's own JSON alike (it may have failed after its commit)", async () => {
    for (const [status, body] of [[502, "<html>Bad gateway</html>"], [504, ""], [524, "A timeout occurred"], [500, { error: "internal", message: "internal error" }]] as const) {
      stub(resp(status, body));
      const e = await client().deleteAccount({ confirmEmail: "me@x.com", currentAuthKey: "KEY" }).catch((x: unknown) => x);
      expect(e, `HTTP ${status}`).toBeInstanceOf(AccountDeleteUnknownError);
      expect(e).not.toBeInstanceOf(ApiError);
      expect((e as AccountDeleteUnknownError).status).toBe(status);
    }
  });

  it("a hung request ends at its deadline as an UNKNOWN outcome (status 0) — nothing waits on it for ever", async () => {
    const hung = vi.fn((_url: string | URL, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal?.reason ?? new DOMException("aborted", "AbortError")));
      }),
    );
    vi.stubGlobal("fetch", hung);
    const c = client();
    c.deleteTimeoutMs = 25;
    const t0 = Date.now();
    const e = await c.deleteAccount({ confirmEmail: "me@x.com", currentAuthKey: "KEY" }).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(AccountDeleteUnknownError);
    expect((e as AccountDeleteUnknownError).status).toBe(0);
    expect(Date.now() - t0).toBeLessThan(5_000);
    expect(hung.mock.calls[0]![1]?.signal, "the POST carries the deadline").toBeDefined();
    expect(client().deleteTimeoutMs, "a minute by default").toBe(ACCOUNT_DELETE_TIMEOUT_MS);
    expect(ACCOUNT_DELETE_TIMEOUT_MS).toBe(60_000);
  });

  it("a reply that is not the server's JSON is UNKNOWN, whatever its status", async () => {
    for (const [status, body] of [[200, "<html>ok</html>"], [200, { something: "else" }], [403, "<html>blocked by a firewall</html>"], [403, { message: "Forbidden" }], [409, "conflict"], [400, [1, 2]]] as const) {
      stub(resp(status, body));
      const e = await client().deleteAccount({ confirmEmail: "me@x.com", currentAuthKey: "KEY" }).catch((x: unknown) => x);
      expect(e, `HTTP ${status} ${JSON.stringify(body)}`).toBeInstanceOf(AccountDeleteUnknownError);
    }
  });
});
