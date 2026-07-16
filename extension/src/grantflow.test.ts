// Options-page grant-flow tests (node --test, chrome-free — the permissions surface is injected).
// Covers the §5.1/D2 decision table: both grants requested in ONE gesture; a broad-dismissed degrades
// to autofill-off (never a switch-fail); a per-origin-dismissed changes nothing; plus the Firefox
// first-run route decision.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import {
  BROAD_ORIGIN_PATTERN,
  decideGrant,
  type PermissionsSurface,
  requestServerGrants,
  shouldRouteToOptions,
} from "./grantflow.ts";

/** A chrome.permissions stand-in. `grantOn` is the SET the user ends up granting from the combined
 *  request (models the post-gesture state contains() reads back — the source of truth): "all" grants
 *  every requested pattern, "none" grants nothing, or an explicit subset. `preGranted` seeds
 *  already-held permissions. contains() models that a granted broad `https` host pattern COVERS any
 *  https pattern (Chrome/Firefox broad-pattern semantics). */
function fakePerms(opts: { grantOn?: "all" | "none" | string[]; preGranted?: string[]; throwOnRequest?: boolean } = {}): PermissionsSurface & {
  requests: string[][];
  granted: Set<string>;
} {
  const granted = new Set(opts.preGranted ?? []);
  const requests: string[][] = [];
  const has = (pattern: string): boolean =>
    granted.has(pattern) || (granted.has(BROAD_ORIGIN_PATTERN) && pattern.startsWith("https://"));
  return {
    requests,
    granted,
    async request({ origins }) {
      if (opts.throwOnRequest) throw new Error("origin not in optional_host_permissions");
      requests.push(origins);
      const decision = opts.grantOn ?? "all";
      if (decision === "none") return false;
      const toGrant = decision === "all" ? origins : decision;
      for (const o of toGrant) granted.add(o);
      return toGrant.length === origins.length;
    },
    async contains({ origins }) {
      return origins.every(has);
    },
  };
}

test("BROAD_ORIGIN_PATTERN is https://*/* — the autofill grant, http excluded by design", () => {
  assert.equal(BROAD_ORIGIN_PATTERN, "https://*/*");
});

test("decideGrant — the pure §5.1/D2 table", () => {
  // Per-origin missing dominates: no fetch grant ⇒ never commit, even if broad is somehow held.
  assert.deepEqual(decideGrant(false, false), { commit: false, autofill: false, reason: "declined" });
  assert.deepEqual(decideGrant(false, true), { commit: false, autofill: false, reason: "declined" });
  // Per-origin held, broad missing ⇒ COMMIT the switch, autofill stays off (the graceful degrade).
  assert.deepEqual(decideGrant(true, false), { commit: true, autofill: false, reason: "autofill-declined" });
  // Both held ⇒ full success.
  assert.deepEqual(decideGrant(true, true), { commit: true, autofill: true, reason: "granted" });
});

test("requestServerGrants — BOTH grants ride ONE request (same user gesture)", async () => {
  const perms = fakePerms({ grantOn: "all" });
  const decision = await requestServerGrants("https://self.example/*", perms);
  assert.equal(perms.requests.length, 1, "exactly one permissions.request — a second would break the gesture");
  assert.deepEqual(perms.requests[0], ["https://self.example/*", "https://*/*"], "per-origin + broad requested together");
  assert.deepEqual(decision, { commit: true, autofill: true, reason: "granted" });
});

test("requestServerGrants — broad dismissed ⇒ switch still commits, autofill off (degrade, not fail)", async () => {
  // The gesture leaves only the per-origin fetch grant held (broad declined / not held).
  const perms = fakePerms({ grantOn: ["https://self.example/*"] });
  const decision = await requestServerGrants("https://self.example/*", perms);
  assert.equal(decision.commit, true, "the server switch must NOT fail on a broad-only decline");
  assert.equal(decision.autofill, false);
  assert.equal(decision.reason, "autofill-declined");
});

test("requestServerGrants — per-origin dismissed ⇒ no change at all", async () => {
  const perms = fakePerms({ grantOn: "none" });
  const decision = await requestServerGrants("https://self.example/*", perms);
  assert.equal(perms.requests.length, 1, "the gesture was attempted");
  assert.deepEqual(decision, { commit: false, autofill: false, reason: "declined" });
  assert.equal(perms.granted.size, 0, "nothing was granted");
});

test("requestServerGrants — a pre-granted broad covers a new https origin (returning user)", async () => {
  // Broad already held (a prior self-host); switching to another https origin needs no new prompt to
  // fetch AND autofill is already live. contains() resolves both from the broad grant.
  const perms = fakePerms({ preGranted: [BROAD_ORIGIN_PATTERN], grantOn: "none" });
  const decision = await requestServerGrants("https://other.example/*", perms);
  assert.deepEqual(decision, { commit: true, autofill: true, reason: "granted" });
});

test("requestServerGrants — invalid origin (null pattern) makes no request and changes nothing", async () => {
  const perms = fakePerms();
  const decision = await requestServerGrants(null, perms);
  assert.deepEqual(decision, { commit: false, autofill: false, reason: "invalid-origin" });
  assert.equal(perms.requests.length, 0, "a null pattern must never reach permissions.request");
});

test("requestServerGrants — a throwing request (LAN-http outside optional perms) degrades to no-change", async () => {
  const perms = fakePerms({ throwOnRequest: true });
  const decision = await requestServerGrants("http://192.168.1.9/*", perms);
  assert.equal(decision.commit, false, "an ungrantable origin leaves the current server in place");
  assert.equal(decision.reason, "declined");
});

test("requestServerGrants — no permissions API ⇒ no-change (fail safe)", async () => {
  const decision = await requestServerGrants("https://self.example/*", null);
  assert.deepEqual(decision, { commit: false, autofill: false, reason: "declined" });
});

test("shouldRouteToOptions — only a definite missing grant routes (null/unknown never false-alarms)", () => {
  assert.equal(shouldRouteToOptions(false), true); //  detected missing ⇒ route to options (Firefox first run)
  assert.equal(shouldRouteToOptions(true), false); //  granted ⇒ stay
  assert.equal(shouldRouteToOptions(null), false); //  undetectable ⇒ never route (no false alarm)
});
