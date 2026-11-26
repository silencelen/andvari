// What the extension's own client does with a refresh whose answer never came (spec 03 §2, the refresh's grace). The
// server takes a refresh token once; for sixty seconds from that moment it answers a repeat with the same pair, and any
// other repeat reads as a stolen token (every session of the device ends, a theft is recorded). So the extension, as the
// shared code and the web client do, tries such a token once more within fifty seconds of its first sending and never
// again; past that it sends nothing, ends the session as its own end and keeps the token for the next sign-in's name.
// Each test is one of the sequences an independent check ran against the web client (its points A to D), asked of the
// extension's client, and the worker's death in mid-request.
import { strict as assert } from "node:assert";
import { afterEach, test } from "node:test";
import { AndvariApi, ApiError, RefreshUnansweredError, SessionNotConfirmedError } from "./api.ts";

const realFetch = globalThis.fetch;
const realNow = Date.now;
afterEach(() => {
  globalThis.fetch = realFetch;
  Date.now = realNow;
});

type Fate = "ok" | "lost" | "page401" | "page502" | "unreadable200" | "env503" | "codeOnly401" | "gw504errorOnly";

/** The server's rule (as the web's tests keep it), behind a road whose answers can be lost or replaced by a page. */
function server(fates: Fate[]) {
  const s = { now: 1_000_000, current: "r0", n: 0, grace: new Map<string, { pair: { accessToken: string; refreshToken: string }; at: number }>(), refreshes: [] as string[], logouts: 0, reuse: 0, revoked: false };
  const json = (status: number, b: unknown) => new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });
  globalThis.fetch = (async (url: string | URL, init?: RequestInit) => {
    const u = String(url);
    if (u.endsWith("/api/v1/auth/refresh")) {
      const token = (JSON.parse(String(init?.body)) as { refreshToken: string }).refreshToken;
      s.refreshes.push(token);
      const fate = fates.shift() ?? "ok";
      if (fate === "page401") return new Response("<html>401 Authorization Required</html>", { status: 401 });
      if (fate === "env503") return json(503, { error: "unavailable", message: "busy" });
      if (fate === "codeOnly401") return json(401, { error: "refresh_reuse" }); // a body with a code and no message
      let answer: Response;
      if (s.revoked) answer = json(401, { error: "refresh_reuse", message: "reuse" });
      else if (token === s.current) {
        s.n++;
        const pair = { accessToken: `a${s.n}`, refreshToken: `r${s.n}` };
        s.grace.set(token, { pair, at: s.now });
        s.current = pair.refreshToken;
        answer = json(200, pair);
      } else {
        const g = s.grace.get(token);
        if (g && s.now - g.at <= 60_000) answer = json(200, g.pair);
        else {
          s.reuse++;
          s.revoked = true;
          answer = json(401, { error: "refresh_reuse", message: "reuse" });
        }
      }
      if (fate === "lost") throw new TypeError("Failed to fetch");
      if (fate === "page502") return new Response("<html>502 Bad Gateway</html>", { status: 502 });
      // A gateway's answer with a code alone, after the server took the token.
      if (fate === "gw504errorOnly") return json(504, { error: "upstream timed out" });
      if (fate === "unreadable200") return new Response("<html>Welcome</html>", { status: 200 });
      return answer;
    }
    if (u.endsWith("/api/v1/auth/logout")) {
      s.logouts++;
      return json(401, { error: "unauthorized", message: "expired" });
    }
    const auth = ((init?.headers as Record<string, string>) ?? {})["authorization"] ?? "";
    if (!s.revoked && auth === `Bearer a${s.n}` && s.n > 0) return json(200, { sealedUsage: null, updatedAt: 0 });
    return json(401, { error: "unauthorized", message: "expired" });
  }) as typeof fetch;
  return s;
}

const at = (s: { now: number }, ms: number) => {
  s.now = ms;
  Date.now = () => ms;
};

function client() {
  const api = new AndvariApi("http://server", "1.0.0");
  api.setTokens("a-old", "r0");
  const ends: string[] = [];
  api.onRefreshRefused = (why) => ends.push(why);
  const persisted: { access: string | null; refresh: string | null }[] = [];
  api.onTokensChanged = () => {
    persisted.push(api.getTokens());
  };
  return { api, ends, persisted, use: () => api.getUsage().then(() => "ok" as const, (e: unknown) => e) };
}

test("A: a lost answer is tried once more inside fifty seconds and answered by the server's grace; never a third", async () => {
  const s = server(["lost", "ok"]);
  const c = client();
  at(s, 1_000_000);
  const e = await c.use();
  assert.ok(e instanceof RefreshUnansweredError, "a renewal with no answer, not the request's 401");
  at(s, 1_030_000);
  assert.equal(await c.use(), "ok");
  assert.deepEqual(s.refreshes, ["r0", "r0"]);
  assert.equal(s.reuse, 0);
  assert.deepEqual(c.ends, []);
});

test("A and D: past fifty seconds nothing is sent; the session ends here as not confirmed, once, and the token is kept", async () => {
  const s = server(["lost", "lost", "ok"]);
  const c = client();
  at(s, 1_000_000);
  await c.use();
  at(s, 1_070_000);
  const e = await c.use();
  assert.ok(e instanceof SessionNotConfirmedError);
  assert.ok(!(e instanceof ApiError && e.status === 401), "never said as the server's 401");
  for (let i = 0; i < 3; i++) await c.use();
  assert.deepEqual(s.refreshes, ["r0"], "nothing sent again");
  assert.equal(s.reuse, 0);
  assert.deepEqual(c.ends, ["not_confirmed"], "exactly one end, the extension's own");
  assert.equal(c.api.keptUnconfirmed, "r0");
  assert.deepEqual(c.api.getTokens(), { access: null, refresh: null });
});

test("A: the one more try is the last, even inside the minute", async () => {
  const s = server(["lost", "lost", "ok"]);
  const c = client();
  at(s, 1_000_000);
  await c.use();
  at(s, 1_005_000);
  await c.use();
  at(s, 1_010_000);
  await c.use();
  assert.deepEqual(s.refreshes, ["r0", "r0"]);
  assert.deepEqual(c.ends, ["not_confirmed"]);
});

test("the worker that dies in mid-request earns no extra try: nothing kept holds the token", async () => {
  const s = server(["lost", "ok"]);
  const c = client();
  at(s, 1_000_000);
  await c.use();
  assert.ok(c.persisted.every((p) => p.refresh === null), "no snapshot ever held the marked token");
  // A new worker, from what was kept.
  const kept = c.api.getTokens();
  const next = new AndvariApi("http://server", "1.0.0");
  next.setTokens(kept.access, kept.refresh);
  at(s, 1_010_000);
  await next.getUsage().catch(() => null);
  assert.deepEqual(s.refreshes, ["r0"]);
});

test("B: a sign-out while the mark stands spends nothing; the quick unlock's refresh neither", async () => {
  const s = server(["lost"]);
  const c = client();
  at(s, 1_000_000);
  await c.use();
  at(s, 1_090_000);
  assert.equal(await c.api.logout(), false, "not confirmed");
  assert.equal(await c.api.forceRefresh(), "transient");
  assert.deepEqual(s.refreshes, ["r0"]);
  assert.equal(s.reuse, 0);
  assert.equal(c.api.keptUnconfirmed, "r0");
});

for (const fate of ["page401", "page502", "unreadable200"] as const) {
  test(`C: ${fate} is not the server's answer: no end, the mark stands, and the one more try goes`, async () => {
    const s = server([fate, "ok"]);
    const c = client();
    at(s, 1_000_000);
    const e = await c.use();
    assert.ok(e instanceof RefreshUnansweredError);
    assert.deepEqual(c.ends, [], "not said as the server's end");
    at(s, 1_010_000);
    assert.equal(await c.use(), "ok");
    assert.deepEqual(s.refreshes, ["r0", "r0"]);
    assert.equal(s.reuse, 0);
  });
}

test("C: the server's own answer for the moment clears the mark after a first try, not after the one more", async () => {
  const s = server(["env503", "ok"]);
  const c = client();
  at(s, 1_000_000);
  await c.use();
  at(s, 1_200_000);
  assert.equal(await c.use(), "ok", "cleared: a later first try");

  const s2 = server(["lost", "env503", "ok"]);
  const c2 = client();
  at(s2, 1_000_000);
  await c2.use();
  at(s2, 1_005_000);
  await c2.use();
  at(s2, 1_010_000);
  await c2.use();
  assert.deepEqual(s2.refreshes, ["r0", "r0"], "the first try is still unanswered: no third");
  assert.deepEqual(c2.ends, ["not_confirmed"]);
});

test("an answer with an error code and no message is not the server's own: no end, and the one more try goes", async () => {
  const s = server(["codeOnly401", "ok"]);
  const c = client();
  at(s, 1_000_000);
  const e = await c.use();
  assert.ok(e instanceof RefreshUnansweredError, "not said as the server's refusal");
  assert.deepEqual(c.ends, []);
  at(s, 1_030_000);
  assert.equal(await c.use(), "ok");
  assert.deepEqual(s.refreshes, ["r0", "r0"]);
  assert.equal(s.reuse, 0);
  assert.deepEqual(c.ends, []);
});

test("a gateway's 504 with a code alone, after the server took the token: never sent again past the window, no theft", async () => {
  const s = server(["gw504errorOnly"]);
  const c = client();
  at(s, 1_000_000);
  const e = await c.use();
  assert.ok(e instanceof RefreshUnansweredError, "not the server's answer for the moment");
  at(s, 1_070_000);
  assert.ok((await c.use()) instanceof SessionNotConfirmedError);
  assert.deepEqual(s.refreshes, ["r0"], "the token is not sent again at +70 s");
  assert.equal(s.reuse, 0, "no theft recorded");
  assert.deepEqual(c.ends, ["not_confirmed"]);
  assert.equal(c.api.keptUnconfirmed, "r0");
});

test("the server's own refusal still ends the session as the server's", async () => {
  const s = server(["ok"]);
  s.revoked = true;
  const c = client();
  at(s, 1_000_000);
  await c.use();
  assert.deepEqual(c.ends, ["refused"]);
  assert.equal(c.api.keptUnconfirmed, null);
});
