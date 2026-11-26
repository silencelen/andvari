// node --test. A worker that starts with a kept pair whose refresh token is missing: a renewal was on the wire when the
// browser stopped the worker (its refresh token was consumed, and that consume persisted, before the request went), and
// its answer never reached any worker. Before, every request then failed with the server's 401 and nothing was said until
// a lock. Now its first refusal ends the session as the end this browser could not confirm, once, and nothing is sent.
// Driven through the real background.ts, and the client alone.
import { strict as assert } from "node:assert";
import { afterEach, test } from "node:test";
import { AndvariApi, ApiError, SessionNotConfirmedError } from "./api.ts";
import { signedInWorld } from "./testing/bgharness.ts";

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

const json = (status: number, b: unknown) => new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });

test("the client: a pair restored with no refresh token reads its first refusal as the end that could not be confirmed, once", async () => {
  const sent: string[] = [];
  globalThis.fetch = (async (url: string | URL) => {
    sent.push(String(url).replace("http://server", ""));
    return json(401, { error: "unauthorized", message: "expired" });
  }) as typeof fetch;
  const api = new AndvariApi("http://server", "1.0.0");
  api.setTokens("a-old", null); // as the worker restores a snapshot written while a renewal was out
  const ends: string[] = [];
  api.onRefreshRefused = (why) => ends.push(why);
  const e = await api.getUsage().then(() => "ok", (x: unknown) => x);
  assert.ok(e instanceof SessionNotConfirmedError, `the end this browser could not confirm, not the request's 401: ${String(e)}`);
  assert.ok(!(e instanceof ApiError && e.status === 401));
  assert.deepEqual(ends, ["not_confirmed"]);
  assert.ok(!sent.some((p) => p.includes("/auth/refresh")), "no refresh is sent");
  assert.deepEqual(api.getTokens(), { access: null, refresh: null });
  await api.getUsage().catch(() => null);
  assert.deepEqual(ends, ["not_confirmed"], "said once");
});

test("the worker: stopped while a renewal was out, it starts again and its first refusal says the end could not be confirmed", async () => {
  const { world, server, w } = await signedInWorld();
  // The access token has expired at the server; the renewal never answers (the browser stops the worker meanwhile).
  server.override = (_m: string, path: string) =>
    path === "/api/v1/auth/refresh"
      ? new Promise<Response>(() => {})
      : path.startsWith("/api/v1/sync")
        ? json(401, { error: "unauthorized", message: "expired" })
        : null;
  void w.alarm("resync");
  for (let i = 0; i < 300 && !world.log.some((l: { path: string }) => l.path === "/api/v1/auth/refresh"); i++) await new Promise((r) => setTimeout(r, 10));
  const refreshes = () => world.log.filter((l: { path: string }) => l.path === "/api/v1/auth/refresh").length;
  assert.equal(refreshes(), 1, "the renewal is on the wire");
  const w2 = await world.start();
  assert.equal((await w2.popup({ type: "status" })).unlocked, true, "the session came back with the worker");
  await w2.alarm("resync");
  const st = await w2.popup({ type: "status" });
  assert.equal(st.serverEnded, true, "the session ended");
  assert.equal(st.serverEndedUnconfirmed, true, "as the end this browser could not confirm, never as the server's");
  assert.equal(refreshes(), 1, "nothing was sent again");
});
