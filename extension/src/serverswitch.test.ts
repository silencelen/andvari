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
import { applyServerSwitch, purgeOriginRecords, purgeServerDataFor } from "./serverswitch.ts";
import type { KvArea } from "./trustedkv.ts";

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

// ---- A15: "Remove data for this server" removes ALL of that origin's records, in every store ----
// The options copy promises "this browser's PIN / quick-unlock and cached state for that server" is removed. Before A15
// the purge removed a fixed key list and missed the per-user records (`itemHomes:<userId>`, `personalWrap:<userId>`,
// `personalChange:<userId>`); since A15 those live in the trusted store (IndexedDB), which the purge must clear too.

function mapArea(entries: Record<string, unknown>): KvArea & { map: Map<string, unknown> } {
  const map = new Map(Object.entries(entries));
  return {
    map,
    async get(keys) {
      const list = keys === null ? [...map.keys()] : typeof keys === "string" ? [keys] : [...keys];
      return Object.fromEntries(list.filter((k) => map.has(k)).map((k) => [k, map.get(k)]));
    },
    async set(items) {
      for (const [k, v] of Object.entries(items)) map.set(k, v);
    },
    async remove(keys) {
      for (const k of typeof keys === "string" ? [keys] : keys) map.delete(k);
    },
  };
}

test("A15 purge: every per-origin record goes — per-user homes/wrap/change included — in the trusted store, local and session", async () => {
  const A = originKeyFor("https://self.example");
  const B = originKeyFor("https://other.example");
  const U1 = "11111111-1111-4111-8111-111111111111";
  const U2 = "55555555-5555-4555-8555-555555555555";
  const perOrigin = (ok: string) => ({
    [`ns.${ok}.itemHomes:${U1}`]: {},
    [`ns.${ok}.itemHomes:${U2}`]: {},
    [`ns.${ok}.personalWrap:${U1}`]: {},
    [`ns.${ok}.personalChange:${U1}`]: {},
    [`ns.${ok}.quBioCred`]: {},
    [`ns.${ok}.quOfferDismissed`]: true,
    [`ns.${ok}.updateInfo`]: {},
    [`ns.${ok}.updateAcceptedSeq`]: 3,
  });
  const global = { serverUrl: "https://self.example", lastEmail: "me@example.org", a15Migrated: true };
  const trusted = mapArea({ ...perOrigin(A), ...perOrigin(B), ...global });
  const local = mapArea({ ...perOrigin(A), ...perOrigin(B) }); // pre-A15 leftovers (or planted later)
  const session = mapArea({ [`ns.${A}.quickUnlock`]: {}, [`ns.${A}.knownLogins`]: {}, [`ns.${A}.updateCheckedAt`]: 1, [`ns.${B}.quickUnlock`]: {} });
  await purgeOriginRecords(A, [trusted, local, session]);
  for (const [name, a] of [["trusted", trusted], ["local", local], ["session", session]] as const) {
    for (const k of a.map.keys()) assert.ok(!k.startsWith(`ns.${A}.`), `${name} still holds ${k}`);
  }
  // Another origin's records and the global ones are untouched.
  assert.deepEqual([...trusted.map.keys()].sort(), [...Object.keys(perOrigin(B)), ...Object.keys(global)].sort());
  assert.deepEqual([...local.map.keys()].sort(), Object.keys(perOrigin(B)).sort());
  assert.deepEqual([...session.map.keys()], [`ns.${B}.quickUnlock`]);
});

test("A15 purge: one store failing does not stop the others; a malformed origin key purges nothing", async () => {
  const A = originKeyFor("https://self.example");
  const broken: KvArea = {
    get: async () => Promise.reject(new Error("IndexedDB unavailable")),
    set: async () => {},
    remove: async () => {},
  };
  const local = mapArea({ [`ns.${A}.itemHomes:u`]: {} });
  await purgeOriginRecords(A, [broken, local]);
  assert.equal(local.map.size, 0, "the next store is still purged");
  const keep = mapArea({ [`ns.${A}.itemHomes:u`]: {}, "ns..x": 1, serverUrl: "x" });
  for (const bad of ["", "XYZ", A.toUpperCase(), `${A}0`, "../"]) await purgeOriginRecords(bad, [keep]);
  assert.equal(keep.map.size, 3, "only a 16-hex origin key ever names a namespace");
});
