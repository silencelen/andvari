// serverswitch seam tests (node --test; type-stripped natively, Node 22.18+). These drive the REAL
// origin-switch + purge logic background.ts delegates to — not a mirror. The §4.1 test builds a real
// AndvariApi and a header-capturing fetch, so removing the token-clear-on-switch (installing the old
// token-holding api instead of a fresh one) makes it fail; the purge tests fail if the popup-only
// sender guard is removed. api.ts / serverurl.ts type-strip under node (no chrome runtime imports).
//
// Why a seam and not a full background.test.ts harness (review 2026-07-16, FIX 3 option ii): background.ts
// is NOT importable under `node --test` — it uses extensionless relative imports (`from "./api"`, which
// node's ESM resolver can't resolve to ./api.ts) AND runs top-level chrome side effects at module load
// (chrome.runtime.onMessage/onStartup/storage.onChanged listeners, chrome.storage.session.setAccessLevel,
// indexedDB.open, `new WebSocket` via ensureSocket, alarms). So the enforcement is extracted into these
// chrome-free leaves that background delegates to, and driven here with a real AndvariApi. Irreducible
// residual: background.applyServerChange passing the real makeApi/installApi (a thin wiring line) is not
// itself node-driven — but makeApi is `new AndvariApi(url,…)` (structural) and api.test.ts pins that a
// fresh AndvariApi is tokenless, so the token-clear property is guarded end-to-end across the two suites.
import { strict as assert } from "node:assert";
import { afterEach, test } from "node:test";
import { AndvariApi } from "./api.ts";
import { originKeyFor } from "./serverurl.ts";
import { applyServerSwitch, purgeServerDataFor } from "./serverswitch.ts";

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

const OK_SYNC = { rev: 0, vaults: [], grants: [], items: [] };
function jsonResp(status: number, body: unknown): Response {
  return { ok: status >= 200 && status < 300, status, statusText: `HTTP ${status}`, json: async () => body, text: async () => JSON.stringify(body) } as unknown as Response;
}

// ---- FIX 3a: §4.1 rule 1 / B1-5 — no Authorization crosses a server switch (the SHIPPED wiring) ----

test("§4.1/B1-5: a server switch installs a FRESH api for the new origin — no Authorization crosses", async () => {
  const seen: { url: string; auth: string | undefined }[] = [];
  globalThis.fetch = (async (url: string, init: { headers: Record<string, string> }) => {
    seen.push({ url, auth: init.headers["authorization"] });
    return jsonResp(200, OK_SYNC);
  }) as unknown as typeof fetch;

  // The OLD origin's api, authenticated — exactly what background holds while unlocked.
  const oldApi = new AndvariApi("https://old.example", "1.0.0");
  oldApi.setTokens("access-OLD", "refresh-OLD");
  await oldApi.sync(0);
  assert.equal(seen.at(-1)!.auth, "Bearer access-OLD", "sanity: the old api does send its token");

  // Drive the REAL switch core with a real makeApi factory (new AndvariApi) + a call-order log.
  const order: string[] = [];
  let installed: AndvariApi | null = null;
  await applyServerSwitch<AndvariApi>({
    nextUrl: "https://new.example",
    currentUrl: "https://old.example",
    hasSession: true,
    bumpRedeemGen: () => order.push("bumpRedeemGen"),
    lock: async () => void order.push("lock"),
    makeApi: (url) => {
      order.push("makeApi");
      return new AndvariApi(url, "1.0.0");
    },
    installApi: (a) => {
      order.push("installApi");
      installed = a;
    },
    setOrigin: () => order.push("setOrigin"),
    registerAutofill: async () => void order.push("registerAutofill"),
  });

  // Order IS the enforcement: lock under the OLD origin BEFORE swapping the api (the armed stash lands
  // in the old namespace), then adopt the new origin, mint a fresh api, install it, re-register autofill.
  assert.deepEqual(order, ["bumpRedeemGen", "lock", "setOrigin", "makeApi", "installApi", "registerAutofill"]);
  assert.ok(installed !== null && installed !== oldApi, "a BRAND-NEW instance, not the token-holding old one");
  assert.deepEqual(installed!.getTokens(), { access: null, refresh: null }, "the fresh api holds no tokens");

  // End-to-end: the installed api talks to the NEW origin with NO Authorization header.
  await installed!.sync(0);
  const newCall = seen.at(-1)!;
  assert.ok(newCall.url.startsWith("https://new.example"));
  assert.equal(newCall.auth, undefined, "no Authorization header may cross the origin change");
  for (const c of seen) if (c.url.startsWith("https://new.example")) assert.notEqual(c.auth, "Bearer access-OLD");
});

test("§4.1: an unchanged origin is a full no-op (no redeemGen bump, no lock, no api swap)", async () => {
  const order: string[] = [];
  await applyServerSwitch<AndvariApi>({
    nextUrl: "https://same.example",
    currentUrl: "https://same.example",
    hasSession: true,
    bumpRedeemGen: () => order.push("bumpRedeemGen"),
    lock: async () => void order.push("lock"),
    makeApi: (u) => new AndvariApi(u, "1.0.0"),
    installApi: () => order.push("installApi"),
    setOrigin: () => order.push("setOrigin"),
    registerAutofill: async () => void order.push("registerAutofill"),
  });
  assert.deepEqual(order, [], "same origin → nothing happens");
});

test("§4.1: with NO live session the switch skips the lock but still swaps to a fresh, tokenless api", async () => {
  const order: string[] = [];
  let installed: AndvariApi | null = null;
  await applyServerSwitch<AndvariApi>({
    nextUrl: "https://new.example",
    currentUrl: "https://old.example",
    hasSession: false,
    bumpRedeemGen: () => order.push("bumpRedeemGen"),
    lock: async () => void order.push("lock"),
    makeApi: (u) => new AndvariApi(u, "1.0.0"),
    installApi: (a) => {
      installed = a;
    },
    setOrigin: () => {},
    registerAutofill: async () => {},
  });
  assert.ok(!order.includes("lock"), "no live session → no lock (nothing to stash)");
  assert.deepEqual(installed!.getTokens(), { access: null, refresh: null });
});

// ---- FIX 1: purgeServerData extension-page-only sender guard (the SHIPPED handler core) ----
// 0.17.0: the caller's trust boolean is now URL-derived (extension-origin sender URL ⇒ trusted),
// NOT `sender.tab !== undefined` — the options page (options_ui open_in_tab) HAS a tab, so the old
// tab-based derivation refused the only legitimate caller (2026-07-18 review Finding 2).

test("purgeServerData — an UNTRUSTED (content-script/page) sender is REFUSED and purges nothing", async () => {
  const purged: string[] = [];
  const r = await purgeServerDataFor("https://self.example", /* untrustedSender */ true, async (k) => void purged.push(k));
  assert.deepEqual(r, { ok: false }, "a page/content sender never reaches the destructive per-origin wipe");
  assert.deepEqual(purged, [], "no origin namespace was wiped");
});

test("purgeServerData — a trusted extension-page sender purges the CANONICAL origin's namespace", async () => {
  const purged: string[] = [];
  const r = await purgeServerDataFor("HTTPS://Self.Example/", /* untrustedSender */ false, async (k) => void purged.push(k));
  assert.deepEqual(r, { ok: true });
  assert.deepEqual(purged, [originKeyFor("https://self.example")], "canonicalized first, then purged by originKey");
});

test("purgeServerData — a non-origin string is a no-op (ok:false), never a throw or a wipe", async () => {
  const purged: string[] = [];
  const r = await purgeServerDataFor("not a url", false, async (k) => void purged.push(k));
  assert.deepEqual(r, { ok: false });
  assert.deepEqual(purged, []);
});
