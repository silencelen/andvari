// Runs under Node's built-in runner (node --test); type-stripped natively (Node 22.18+).
// Excluded from tsc (tsconfig `exclude`) because it imports node:test, which the extension's
// chrome-only lib set does not type. `npm test` in extension/ runs this.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import {
  canonicalizeServerUrl,
  DEFAULT_SERVER_URL,
  getServerUrl,
  middleTruncateOrigin,
  nsKey,
  originKeyFor,
  originMatchPattern,
  SERVER_URL_KEY,
  setServerUrl,
  type ServerUrlArea,
} from "./serverurl.ts";

// A Map-backed chrome.storage.local stand-in (the module takes the area structurally).
function fakeArea(initial: Record<string, unknown> = {}): ServerUrlArea & { map: Map<string, unknown>; gets: number; sets: number } {
  const map = new Map(Object.entries(initial));
  return {
    map,
    gets: 0,
    sets: 0,
    async get(key: string) {
      this.gets++;
      return map.has(key) ? { [key]: map.get(key) } : {};
    },
    async set(items: Record<string, unknown>) {
      this.sets++;
      for (const [k, v] of Object.entries(items)) map.set(k, v);
    },
  };
}

test("DEFAULT_SERVER_URL is the reference instance — no tailnet host baked anywhere (§5.5 gate)", () => {
  assert.equal(DEFAULT_SERVER_URL, "https://andvari.monahanhosting.com");
  assert.ok(!DEFAULT_SERVER_URL.includes("ts.net"));
  assert.equal(canonicalizeServerUrl(DEFAULT_SERVER_URL), DEFAULT_SERVER_URL); // the default IS canonical
});

test("canonicalizeServerUrl — normalizes to lowercase scheme://host[:non-default port]", () => {
  assert.equal(canonicalizeServerUrl("https://example.org"), "https://example.org");
  assert.equal(canonicalizeServerUrl("HTTPS://EXAMPLE.ORG"), "https://example.org"); // case
  assert.equal(canonicalizeServerUrl("https://example.org/"), "https://example.org"); // bare trailing slash
  assert.equal(canonicalizeServerUrl("  https://example.org  "), "https://example.org"); // whitespace
  assert.equal(canonicalizeServerUrl("https://example.org:443"), "https://example.org"); // default port strips
  assert.equal(canonicalizeServerUrl("http://example.org:80"), "http://example.org");
  assert.equal(canonicalizeServerUrl("https://example.org:8443"), "https://example.org:8443"); // non-default kept
  assert.equal(canonicalizeServerUrl("http://192.168.2.122:8080"), "http://192.168.2.122:8080"); // LAN self-host
  assert.equal(canonicalizeServerUrl("https://пример.рф"), "https://xn--e1afmkfd.xn--p1ai"); // IDN → punycode
  assert.equal(canonicalizeServerUrl("https://[::1]:8443"), "https://[::1]:8443"); // IPv6 literal
  assert.equal(canonicalizeServerUrl("https://[0:0:0:0:0:0:0:1]"), "https://[::1]"); // IPv6 canonical form
});

test("canonicalizeServerUrl — rejects everything that is not a plain http(s) origin", () => {
  const bad = [
    "", //                                     empty
    "   ", //                                  whitespace only
    "example.org", //                          no scheme (the wave-3 options page pre-normalizes)
    "https://example.org/vault", //            path — a pasted page URL, not an origin
    "https://example.org/?q=1", //             query
    "https://example.org/#recover", //         fragment
    "https://user:pw@example.org", //          userinfo
    "javascript:alert(1)", //                  scheme safety (enroll-link rule)
    "file:///etc/passwd",
    "data:text/html,x",
    "ftp://example.org",
    "ws://example.org", //                     ws derives FROM the http origin, never stored
    "https://exa mple.org", //                 unparseable host
    "https://example.org:99999", //            port out of range
    "https://my_host", //                      underscore — outside the enroll-link host grammar
    "https://example.org.", //                 trailing-dot label
  ];
  for (const input of bad) assert.equal(canonicalizeServerUrl(input), null, `should reject: ${JSON.stringify(input)}`);
});

test("getServerUrl — storage.local.serverUrl ?? DEFAULT (§5.1), re-canonicalized on read", async () => {
  assert.equal(await getServerUrl(fakeArea()), DEFAULT_SERVER_URL); // absent → default
  assert.equal(await getServerUrl(fakeArea({ [SERVER_URL_KEY]: "https://self.example:8443" })), "https://self.example:8443");
  // A hand-edited/legacy value resolves to the same canonical form (same originKey namespace)…
  assert.equal(await getServerUrl(fakeArea({ [SERVER_URL_KEY]: "HTTPS://Self.Example:8443/" })), "https://self.example:8443");
  // …and garbage falls back to the default rather than poisoning consumers.
  assert.equal(await getServerUrl(fakeArea({ [SERVER_URL_KEY]: "not a url" })), DEFAULT_SERVER_URL);
  assert.equal(await getServerUrl(fakeArea({ [SERVER_URL_KEY]: 42 })), DEFAULT_SERVER_URL);
  assert.equal(await getServerUrl(null), DEFAULT_SERVER_URL); // no storage at all (non-extension context)
  const throwing = { get: async () => Promise.reject(new Error("wedged")), set: async () => {} };
  assert.equal(await getServerUrl(throwing), DEFAULT_SERVER_URL); // storage failure → fail-safe default
});

test("setServerUrl — canonicalizes before persisting; an invalid input throws and never writes", async () => {
  const area = fakeArea();
  assert.equal(await setServerUrl("HTTPS://Self.Example:8443/", area), "https://self.example:8443");
  assert.equal(area.map.get(SERVER_URL_KEY), "https://self.example:8443"); // stored value is ALWAYS canonical
  await assert.rejects(() => setServerUrl("javascript:alert(1)", area), /not a valid server origin/);
  await assert.rejects(() => setServerUrl("https://example.org/vault", area), /not a valid server origin/);
  assert.equal(area.map.get(SERVER_URL_KEY), "https://self.example:8443"); // rejected inputs left no write
  assert.equal(area.sets, 1);
});

test("server choice lives in storage.local ONLY — storage.sync is never touched (§5.1, binding)", async () => {
  // The per-device trust rationale: a synced serverUrl would let one phished device repoint every
  // synced browser. Pin the plumbing: with BOTH areas present, only local sees traffic.
  const local = fakeArea();
  const sync = fakeArea({ [SERVER_URL_KEY]: "https://evil.example" }); // even a planted sync value is never read
  const g = globalThis as { chrome?: unknown };
  const prior = g.chrome;
  g.chrome = { storage: { local, sync } };
  try {
    assert.equal(await getServerUrl(), DEFAULT_SERVER_URL); // default args resolve chrome.storage.local
    await setServerUrl("https://self.example"); // default-arg path → chrome.storage.local

  } finally {
    g.chrome = prior;
  }
  assert.equal(local.map.get(SERVER_URL_KEY), "https://self.example");
  assert.ok(local.gets >= 1 && local.sets === 1);
  assert.equal(sync.gets + sync.sets, 0, "storage.sync must never be touched");
  assert.equal(sync.map.get(SERVER_URL_KEY), "https://evil.example"); // untouched, unread
});

test("originKeyFor — hex(sha256(canonical origin)).take(16), the native scheme (§4.2)", () => {
  // Pinned vectors (sha256sum-verified): a scheme change (length, hash, casing) must break here first.
  assert.equal(originKeyFor("https://andvari.monahanhosting.com"), "e1fd6516bf573c7f");
  assert.equal(originKeyFor("https://example.org"), "50d7a905e3046b88");
  assert.match(originKeyFor("https://self.example"), /^[0-9a-f]{16}$/); // fixed-width lowercase hex
  // Scheme, host and port are ALL identity: distinct origins get distinct namespaces.
  assert.notEqual(originKeyFor("https://a.example"), originKeyFor("http://a.example"));
  assert.notEqual(originKeyFor("https://a.example"), originKeyFor("https://a.example:8443"));
  assert.equal(originKeyFor("https://a.example"), originKeyFor("https://a.example")); // deterministic
});

test("nsKey — ns.<originKey>.<key>, collision-free across origins (fixed-width key)", () => {
  const a = originKeyFor("https://a.example");
  const b = originKeyFor("https://b.example");
  assert.equal(nsKey(a, "quickUnlock"), `ns.${a}.quickUnlock`);
  assert.notEqual(nsKey(a, "quickUnlock"), nsKey(b, "quickUnlock"));
  // Fixed-width originKey ⇒ one origin's namespace can never be a prefix of another's.
  assert.ok(!nsKey(a, "x").startsWith(`ns.${b}.`));
});

test("namespacing round-trip — A→B→A preserves A's material; wipes stay origin-scoped (B2-7)", () => {
  // The storage layer as background.ts drives it: every per-origin read/write goes through
  // nsKey(currentOriginKey, ...); a switch ONLY changes currentOriginKey. Simulate the exact flow.
  const store = new Map<string, unknown>();
  const A = originKeyFor("https://a.example");
  const B = originKeyFor("https://b.example:8443");

  // Pointed at A: quick-unlock enrolled + armed, offer dismissed.
  let current = A;
  const put = (k: string, v: unknown): void => void store.set(nsKey(current, k), v);
  const get = (k: string): unknown => store.get(nsKey(current, k));
  put("quickUnlock", { userId: "user-a", blob: "blob-a", lockedTokens: { access: "tok-a", refresh: "r-a" } });
  put("quOfferDismissed", true);

  // Switch A→B (§4.1): the switch changes the namespace key and touches NOTHING under A.
  current = B;
  assert.equal(get("quickUnlock"), undefined, "B starts empty — no cross-namespace read");
  put("quickUnlock", { userId: "user-b", blob: "blob-b", lockedTokens: null });

  // B's own policy-forbid / explicit remove wipes ONLY ns.<B>.* (purgeOriginNamespace semantics).
  for (const k of [...store.keys()]) if (k.startsWith(`ns.${B}.`)) store.delete(k);
  assert.equal(get("quickUnlock"), undefined);

  // Back to A: PIN material + offer flag are exactly as left — the round trip lost nothing.
  current = A;
  assert.deepEqual(get("quickUnlock"), { userId: "user-a", blob: "blob-a", lockedTokens: { access: "tok-a", refresh: "r-a" } });
  assert.equal(get("quOfferDismissed"), true);
});

test("middleTruncateOrigin — popup header display: short passes through, long elides the MIDDLE", () => {
  // Within budget → unchanged (the common reference/self-host case).
  assert.equal(middleTruncateOrigin("https://andvari.monahanhosting.com"), "https://andvari.monahanhosting.com");
  assert.equal(middleTruncateOrigin("https://self.example"), "https://self.example");
  // Over budget → head + ellipsis + tail, both ends preserved (scheme start AND final labels visible).
  const long = "https://vault.some-really-long-subdomain.internal.example.com:8443";
  const out = middleTruncateOrigin(long, 34);
  assert.ok(out.length <= 34, `truncated to <=34 chars, got ${out.length}`);
  assert.ok(out.includes("…"), "uses a single-char ellipsis");
  assert.ok(out.startsWith("https://vault"), "keeps the scheme + host start");
  assert.ok(out.endsWith(":8443"), "keeps the tail (final labels + port)");
  assert.ok(!out.includes("......"), "the ellipsis is U+2026, never dots that could read as labels");
  // Exactly at the budget → unchanged (boundary).
  const exact = "https://abcdefghijklmnopqrst.example"; // 35 chars
  assert.equal(middleTruncateOrigin(exact, exact.length), exact);
  assert.equal(middleTruncateOrigin(exact, exact.length - 1).length, exact.length - 1);
});

test("originMatchPattern — vault-exclusion patterns (B2-5): ports dropped, IPv6 fails closed", () => {
  assert.equal(originMatchPattern(DEFAULT_SERVER_URL), "https://andvari.monahanhosting.com/*");
  // Match patterns cannot carry a port — the host pattern matches EVERY port (over-excludes, safe).
  assert.equal(originMatchPattern("https://self.example:8443"), "https://self.example/*");
  assert.equal(originMatchPattern("http://192.168.2.122:8080"), "http://192.168.2.122/*");
  // A bracketed IPv6 literal has no valid pattern form → null → caller must NOT register autofill.
  assert.equal(originMatchPattern("https://[::1]:8443"), null);
  assert.equal(originMatchPattern("not-an-origin"), null);
});
