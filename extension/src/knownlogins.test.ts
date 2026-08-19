// node --test. Pins the known-logins digest (the locked save-prompt check, owner decision
// 2026-08-18): the derivation carries NO password material, the pair key is the same authority
// notion as autofill/duplicates (eTLD+1, unresolvable hosts as themselves), and the re-offer
// verdict orders TTL-expiry above everything (plaintext never outlives its bound). The storage
// wiring (KLKEY rebuild/retention/wipe) lives in background.ts, shaped by these leaves.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import {
  LOCKED_PENDING_TTL_MS,
  REOFFER_MIN_GAP_MS,
  buildKnownLoginDigests,
  knownLoginDigest,
  reofferDecision,
  siteKeyOfHost,
} from "./knownlogins.ts";
import type { PslResolve } from "./urimatch.ts";

// A hand-rolled PSL stand-in (the RESOLVE_UNKNOWN idiom): *.example/*.com resolve to their last
// two labels; bare "com" is a public suffix; everything else (localhost, IPs) is unknown.
const resolve: PslResolve = (host) => {
  if (host === "com" || host === "example") return { kind: "public-suffix" };
  const parts = host.split(".");
  if (parts.length >= 2 && (parts.at(-1) === "com" || parts.at(-1) === "example")) {
    return { kind: "registrable", domain: parts.slice(-2).join(".") };
  }
  return { kind: "unknown" };
};

const key = new Uint8Array(16).fill(7);
const otherKey = new Uint8Array(16).fill(8);

test("digest: deterministic, 16-byte truncation, key-dependent", () => {
  const a = knownLoginDigest(key, "login.com", "user");
  assert.equal(a, knownLoginDigest(key, "login.com", "user"));
  assert.equal(Buffer.from(a, "base64").length, 16);
  assert.notEqual(a, knownLoginDigest(otherKey, "login.com", "user"));
});

test("digest: username normalizes (trim + lowercase) — display strings never split a pair", () => {
  assert.equal(knownLoginDigest(key, "login.com", "  Alice@X.com "), knownLoginDigest(key, "login.com", "alice@x.com"));
});

test("digest: the NUL separator keeps (site, user) pairs unforgeable across the boundary", () => {
  assert.notEqual(knownLoginDigest(key, "a", "b c"), knownLoginDigest(key, "a b", "c"));
});

test("site key: the autofill/duplicates authority — eTLD+1; www/port/case collapse", () => {
  assert.equal(siteKeyOfHost("URL.Login.com", resolve), "login.com");
  assert.equal(siteKeyOfHost("www.login.com:8080", resolve), "login.com");
  assert.equal(siteKeyOfHost("login.com", resolve), "login.com");
});

test("site key: unresolvable hosts key as themselves; garbage keys as nothing", () => {
  assert.equal(siteKeyOfHost("192.168.7.50", resolve), "192.168.7.50");
  assert.equal(siteKeyOfHost("localhost", resolve), "localhost");
  assert.equal(siteKeyOfHost("", resolve), null);
});

test("build: logins only, one digest per (site,user) pair, every uri, app uris skipped", () => {
  const items = [
    { doc: { type: "login", login: { username: "user", uris: ["https://url.login.com/a", "login.com/b"] } } }, // same pair twice → 1
    { doc: { type: "login", login: { username: "user", uris: ["other.com"] } } },
    { doc: { type: "login", login: { username: "user", uris: ["androidapp://com.example.app"] } } }, // app → skipped
    { doc: { type: "login", login: { username: "user" } } }, // no uris → nothing
    { doc: { type: "note" } }, // not a login
  ];
  const digests = buildKnownLoginDigests(key, items, resolve);
  assert.equal(digests.length, 2);
  assert.ok(digests.includes(knownLoginDigest(key, "login.com", "user")));
  assert.ok(digests.includes(knownLoginDigest(key, "other.com", "user")));
});

test("reoffer: TTL expiry outranks everything — even a quiet pending, even an unlocked vault", () => {
  const old = { lockedAt: 0, quiet: true };
  assert.equal(reofferDecision(old, LOCKED_PENDING_TTL_MS + 1, false), "expired");
  assert.equal(reofferDecision(old, LOCKED_PENDING_TTL_MS + 1, true), "expired");
  assert.equal(reofferDecision({ lockedAt: 0 }, LOCKED_PENDING_TTL_MS, false), "offer"); // at the bound, not past it
});

test("reoffer: unlocked offers; quiet stays quiet for its whole locked life", () => {
  assert.equal(reofferDecision({ lockedAt: 5 }, 10, true), "offer");
  assert.equal(reofferDecision({ lockedAt: 5, quiet: true, offeredAt: 0 }, REOFFER_MIN_GAP_MS * 2, false), "quiet");
});

test("reoffer: locked re-offers throttle to one per gap", () => {
  assert.equal(reofferDecision({ lockedAt: 5, offeredAt: 5 }, REOFFER_MIN_GAP_MS, false), "throttled");
  assert.equal(reofferDecision({ lockedAt: 5, offeredAt: 5 }, 5 + REOFFER_MIN_GAP_MS, false), "offer");
  assert.equal(reofferDecision({}, 1, false), "offer"); // never offered → immediate
});
