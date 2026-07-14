// AndvariApi engine tests (node --test, chrome-free — the manifest version is injected via the
// constructor and fetch is global/mockable). Covers the E1-2 header, the E1-9/AM1 refresh state
// machine, the AM6 single-flight, and the E1-3 ApiError parse. api.ts type-strips under node
// because it has no runtime imports (KdfParams is an `import type`) and no parameter properties.
import { strict as assert } from "node:assert";
import { afterEach, test } from "node:test";
import { AndvariApi, ApiError } from "./api.ts";

// A minimal Response stand-in. `json`-mode bodies parse; `text`-mode bodies make .json() throw
// (a non-JSON error body — the http_<status>/statusText fallback path).
function jsonResp(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: `HTTP ${status}`,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}
function textResp(status: number, body: string): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: `HTTP ${status}`,
    json: async () => {
      throw new SyntaxError("not json");
    },
    text: async () => body,
  } as unknown as Response;
}

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

const OK_SYNC = { rev: 0, vaults: [], grants: [], items: [] };

test("E1-2: sends X-Andvari-Client: extension/<version> on a json call AND the refresh POST", async () => {
  const calls: { url: string; headers: Record<string, string> }[] = [];
  let syncSeen = 0;
  globalThis.fetch = (async (url: string, init: { headers: Record<string, string> }) => {
    calls.push({ url, headers: init.headers });
    if (url.includes("/sync")) return ++syncSeen === 1 ? jsonResp(401, { error: "expired" }) : jsonResp(200, OK_SYNC);
    if (url.includes("/refresh")) return jsonResp(200, { accessToken: "a2", refreshToken: "r2" });
    throw new Error("unexpected " + url);
  }) as unknown as typeof fetch;

  const api = new AndvariApi("https://x", "1.2.3");
  api.setTokens("a1", "r1");
  await api.sync(0); // 401 → refresh → retry, so both header sites are exercised
  const syncCall = calls.find((c) => c.url.includes("/sync"))!;
  const refreshCall = calls.find((c) => c.url.includes("/refresh"))!;
  assert.equal(syncCall.headers["X-Andvari-Client"], "extension/1.2.3");
  assert.equal(refreshCall.headers["X-Andvari-Client"], "extension/1.2.3");
});

test("constructor default: no clientVersion → extension/0.0.0", async () => {
  let seen = "";
  globalThis.fetch = (async (_url: string, init: { headers: Record<string, string> }) => {
    seen = init.headers["X-Andvari-Client"];
    return jsonResp(200, { serverTime: 1 });
  }) as unknown as typeof fetch;
  await new AndvariApi("https://x").clientPolicy();
  assert.equal(seen, "extension/0.0.0");
});

test("E1-9: 401 → ONE rotation → retry with the fresh access token; onTokensChanged fired", async () => {
  const changes: { access: string | null; refresh: string | null }[] = [];
  let sawFreshAccess = false;
  globalThis.fetch = (async (url: string, init: { headers: Record<string, string> }) => {
    if (url.includes("/sync")) {
      if (init.headers["authorization"] === "Bearer a2") {
        sawFreshAccess = true;
        return jsonResp(200, OK_SYNC);
      }
      return jsonResp(401, { error: "expired" });
    }
    if (url.includes("/refresh")) return jsonResp(200, { accessToken: "a2", refreshToken: "r2" });
    throw new Error("unexpected " + url);
  }) as unknown as typeof fetch;

  const api = new AndvariApi("https://x", "1.2.3");
  api.onTokensChanged = () => void changes.push(api.getTokens());
  api.setTokens("a1", "r1");
  await api.sync(0);
  assert.ok(sawFreshAccess, "the retry used the rotated access token");
  assert.deepEqual(changes.at(-1), { access: "a2", refresh: "r2" });
});

test("AM1: consume-persist ordering — onTokensChanged sees refresh===null BEFORE the refresh POST", async () => {
  const observed: (string | null)[] = [];
  let refreshStarted = false;
  const api = new AndvariApi("https://x", "1.2.3");
  api.onTokensChanged = () => void observed.push(api.getTokens().refresh);
  globalThis.fetch = (async (url: string) => {
    if (url.includes("/sync")) return refreshStarted ? jsonResp(200, OK_SYNC) : jsonResp(401, { error: "expired" });
    if (url.includes("/refresh")) {
      refreshStarted = true;
      assert.deepEqual(observed, [null], "the consumed (refresh:null) state was persisted before the POST");
      return jsonResp(200, { accessToken: "a2", refreshToken: "r2" });
    }
    throw new Error("unexpected " + url);
  }) as unknown as typeof fetch;
  api.setTokens("a1", "r1");
  await api.sync(0);
  assert.deepEqual(observed, [null, "r2"], "then the success set fires with the new refresh token");
});

test("AM6: two concurrent 401s produce exactly ONE refresh POST (single-flight)", async () => {
  let refreshPosts = 0;
  let syncCalls = 0;
  globalThis.fetch = (async (url: string) => {
    if (url.includes("/sync")) {
      syncCalls++;
      return syncCalls <= 2 ? jsonResp(401, { error: "expired" }) : jsonResp(200, OK_SYNC);
    }
    if (url.includes("/refresh")) {
      refreshPosts++;
      await new Promise((r) => setTimeout(r, 10)); // stay in-flight while the 2nd 401 lands
      return jsonResp(200, { accessToken: "a2", refreshToken: "r2" });
    }
    throw new Error("unexpected " + url);
  }) as unknown as typeof fetch;
  const api = new AndvariApi("https://x", "1.2.3");
  api.setTokens("a1", "r1");
  await Promise.all([api.sync(0), api.sync(0)]);
  assert.equal(refreshPosts, 1, "the single-use refresh token was spent exactly once");
});

test("E1-9: refresh 503 → refresh token RESTORED + notified; a later refresh reuses the SAME token", async () => {
  const changes: (string | null)[] = [];
  const refreshBodies: string[] = [];
  let failNext = true;
  const api = new AndvariApi("https://x", "1.2.3");
  api.onTokensChanged = () => void changes.push(api.getTokens().refresh);
  globalThis.fetch = (async (url: string, init: { headers: Record<string, string>; body: string }) => {
    if (url.includes("/sync")) return init.headers["authorization"] === "Bearer a2" ? jsonResp(200, OK_SYNC) : jsonResp(401, { error: "expired" });
    if (url.includes("/refresh")) {
      refreshBodies.push(JSON.parse(init.body).refreshToken);
      if (failNext) {
        failNext = false;
        return jsonResp(503, { error: "unavailable" });
      }
      return jsonResp(200, { accessToken: "a2", refreshToken: "r2" });
    }
    throw new Error("unexpected " + url);
  }) as unknown as typeof fetch;
  api.setTokens("a1", "r1");
  await assert.rejects(api.sync(0), (e: unknown) => e instanceof ApiError && e.status === 401);
  assert.equal(api.getTokens().refresh, "r1", "the transient failure restored the refresh token");
  assert.ok(changes.includes("r1"), "onTokensChanged fired on the restore");
  await api.sync(0); // now the refresh succeeds using the restored token
  assert.deepEqual(refreshBodies, ["r1", "r1"], "the later refresh reused the same, still-valid token");
});

test("E1-9: refresh network throw → refresh token restored + notified", async () => {
  const changes: (string | null)[] = [];
  const api = new AndvariApi("https://x", "1.2.3");
  api.onTokensChanged = () => void changes.push(api.getTokens().refresh);
  globalThis.fetch = (async (url: string) => {
    if (url.includes("/sync")) return jsonResp(401, { error: "expired" });
    if (url.includes("/refresh")) throw new TypeError("Failed to fetch");
    throw new Error("unexpected " + url);
  }) as unknown as typeof fetch;
  api.setTokens("a1", "r1");
  await assert.rejects(api.sync(0));
  assert.equal(api.getTokens().refresh, "r1");
  assert.ok(changes.includes("r1"));
});

test("E1-9: refresh 401 → BOTH tokens cleared + notified (definitive death)", async () => {
  const changes: { access: string | null; refresh: string | null }[] = [];
  const api = new AndvariApi("https://x", "1.2.3");
  api.onTokensChanged = () => void changes.push(api.getTokens());
  globalThis.fetch = (async (url: string) => {
    if (url.includes("/sync")) return jsonResp(401, { error: "expired" });
    if (url.includes("/refresh")) return jsonResp(401, { error: "invalid_grant" });
    throw new Error("unexpected " + url);
  }) as unknown as typeof fetch;
  api.setTokens("a1", "r1");
  await assert.rejects(api.sync(0));
  assert.deepEqual(api.getTokens(), { access: null, refresh: null });
  assert.deepEqual(changes.at(-1), { access: null, refresh: null });
});

test("eventsTicket: POSTs /api/v1/events/ticket with the Bearer + client headers; returns the body", async () => {
  let seen: { url: string; method: string; headers: Record<string, string> } | undefined;
  globalThis.fetch = (async (url: string, init: { method: string; headers: Record<string, string> }) => {
    seen = { url, method: init.method, headers: init.headers };
    return jsonResp(200, { ticket: "tick-1", expiresInSeconds: 30 });
  }) as unknown as typeof fetch;
  const api = new AndvariApi("https://x", "1.2.3");
  api.setTokens("a1", "r1");
  const t = await api.eventsTicket();
  assert.deepEqual(t, { ticket: "tick-1", expiresInSeconds: 30 });
  assert.equal(seen!.url, "https://x/api/v1/events/ticket");
  assert.equal(seen!.method, "POST");
  assert.equal(seen!.headers["authorization"], "Bearer a1");
  assert.equal(seen!.headers["X-Andvari-Client"], "extension/1.2.3");
});

test("E1-3: ApiError parses the server {error, message} body", async () => {
  const api = new AndvariApi("https://x", "1.2.3");
  globalThis.fetch = (async () => jsonResp(401, { error: "invalid_credentials", message: "authentication failed" })) as unknown as typeof fetch;
  await assert.rejects(
    api.login("e", "k"),
    (e: unknown) => e instanceof ApiError && e.status === 401 && e.code === "invalid_credentials" && e.message === "authentication failed",
  );
});

test("E1-3: non-JSON error body falls back to http_<status> + statusText", async () => {
  const api = new AndvariApi("https://x", "1.2.3");
  globalThis.fetch = (async () => textResp(502, "<html>bad gateway</html>")) as unknown as typeof fetch;
  await assert.rejects(
    api.clientPolicy(),
    (e: unknown) => e instanceof ApiError && e.status === 502 && e.code === "http_502" && e.message === "HTTP 502",
  );
});

test("E1-2/E1-3: body code upgrade_required fires onUpgradeRequired AND still throws the ApiError", async () => {
  const api = new AndvariApi("https://x", "1.2.3");
  let fired = 0;
  api.onUpgradeRequired = () => void fired++;
  globalThis.fetch = (async () => jsonResp(426, { error: "upgrade_required", message: "min extension 0.11.0" })) as unknown as typeof fetch;
  await assert.rejects(api.sync(0), (e: unknown) => e instanceof ApiError && e.status === 426 && e.code === "upgrade_required");
  assert.equal(fired, 1);
});
