// node --test. Security review 2026-10, branch A15: the one-time move of the extension's trust state out of
// chrome.storage.local into the trusted store (the extension origin's IndexedDB, trustedkv.ts).
//
// The rule the migration must not break is the bug being fixed: a pre-A15 storage.local value may already have been
// PLANTED by a content script, so nothing content-reachable becomes trusted, canonical, pinned or adopted on the way
// in. The server choice is never adopted (a non-default one waits for the Trust Gate again); the update channel's
// anti-rollback seq restarts at the MIN_SEQ floor; a pending personal change is dropped (the next unlock re-stages it);
// item homes and the personal wrap move under their strict decoders (the same trust they had in storage.local); the
// migration flag lives in the trusted store only.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { DEFAULT_SERVER_URL, getServerUrl, originKeyFor, SERVER_URL_KEY } from "./serverurl.ts";
import { TrustedStoreUnavailable, type KvArea } from "./trustedkv.ts";
import { A15_MIGRATED_KEY, LAST_EMAIL_KEY, LEGACY_SERVER_KEY, migrateTrustState, rememberableEmail } from "./trustmigrate.ts";

const OK = originKeyFor(DEFAULT_SERVER_URL);
const OK2 = originKeyFor("https://self.example");
const U1 = "11111111-1111-4111-8111-111111111111";
const V1 = "22222222-2222-4222-8222-222222222222";
const I1 = "33333333-3333-4333-8333-333333333333";
const I2 = "44444444-4444-4444-8444-444444444444";
const ns = (ok: string, k: string) => `ns.${ok}.${k}`;

type Fake = KvArea & { map: Map<string, unknown>; writes: number };
function area(initial: Record<string, unknown> = {}, opts: { failGet?: boolean; failSet?: boolean; lossy?: boolean } = {}): Fake {
  const map = new Map(Object.entries(structuredClone(initial)));
  const self: Fake = {
    map,
    writes: 0,
    async get(keys) {
      if (opts.failGet) throw new TrustedStoreUnavailable("IndexedDB is not available here");
      const list = keys === null ? [...map.keys()] : typeof keys === "string" ? [keys] : [...keys];
      const out: Record<string, unknown> = {};
      for (const k of list) if (map.has(k)) out[k] = structuredClone(map.get(k));
      return out;
    },
    async set(items) {
      if (opts.failSet) throw new TrustedStoreUnavailable("quota");
      self.writes++;
      // `lossy` models a store that acknowledges a write it did not keep (the verify step must catch it).
      for (const [k, v] of Object.entries(items)) if (!(opts.lossy && k !== A15_MIGRATED_KEY)) map.set(k, structuredClone(v));
    },
    async remove(keys) {
      for (const k of typeof keys === "string" ? [keys] : keys) map.delete(k);
    },
  };
  return self;
}

/** A pre-A15 storage.local as a real install leaves it, plus everything a content script could have planted. */
function preA15Local(serverUrl: string) {
  return {
    [SERVER_URL_KEY]: serverUrl,
    lastEmail: "me@example.org",
    nsAdoptedOnce: true,
    [ns(OK2, `itemHomes:${U1}`)]: { [I1]: V1, "not-a-uuid": V1, [I2]: "also-not" },
    [ns(OK2, `personalWrap:${U1}`)]: { vaultId: V1, wrappedVk: "c2VhbGVk" },
    [ns(OK2, `personalChange:${U1}`)]: { vaultId: V1, wrappedVk: "c2VhbGVk", currentVaultId: "" },
    [ns(OK2, "quBioCred")]: { credentialId: "Y3JlZA", prfSalt: "c2FsdA", userId: U1 },
    [ns(OK2, "quOfferDismissed")]: true,
    [ns(OK, "updateInfo")]: { latest: "99.0.0", chromeUrl: "https://evil.example/x.zip", firefoxUrl: null },
    [ns(OK, "updateAcceptedSeq")]: 2_000_000_000,
    [ns(OK, "updateCheckedAt")]: Date.now(),
    [ns(OK, "updateChannelQuiet")]: { reason: "unverified" },
    someOtherExtensionLikeKey: "left alone",
  };
}

test("a planted NON-default serverUrl is never adopted: the worker stays on the default until the Trust Gate", async () => {
  const legacy = area(preA15Local("https://evil.example"));
  const trusted = area();
  const r = await migrateTrustState(legacy, trusted);
  assert.equal(r.kind, "migrated");
  assert.equal(trusted.map.has(SERVER_URL_KEY), false, "the server choice is NOT written");
  assert.equal(await getServerUrl(trusted), DEFAULT_SERVER_URL, "the worker dials the default");
  // Kept only as a display-only suggestion the options page offers for re-confirmation through the gate.
  assert.equal(trusted.map.get(LEGACY_SERVER_KEY), "https://evil.example");
  assert.equal(r.kind === "migrated" && r.legacyServer, "https://evil.example");
});

test("a legacy value is canonicalized before it is even suggested; the default or garbage suggests nothing", async () => {
  for (const [stored, suggested] of [
    ["HTTPS://Self.Example:8443/", "https://self.example:8443"],
    [DEFAULT_SERVER_URL, undefined],
    [`${DEFAULT_SERVER_URL}/`, undefined],
    ["javascript:alert(1)", undefined],
    ["https://self.example/vault", undefined],
    [42, undefined],
  ] as const) {
    const trusted = area();
    await migrateTrustState(area({ [SERVER_URL_KEY]: stored }), trusted);
    assert.equal(trusted.map.get(LEGACY_SERVER_KEY), suggested, JSON.stringify(stored));
    assert.equal(trusted.map.has(SERVER_URL_KEY), false);
  }
});

test("a server the user already chose in the trusted store is never shadowed by a legacy suggestion", async () => {
  const trusted = area({ [SERVER_URL_KEY]: "https://mine.example" });
  await migrateTrustState(area({ [SERVER_URL_KEY]: "https://evil.example" }), trusted);
  assert.equal(trusted.map.get(SERVER_URL_KEY), "https://mine.example");
  assert.equal(trusted.map.has(LEGACY_SERVER_KEY), false);
});

test("the update channel is NOT migrated: no offer, no seq (restarts at the MIN_SEQ floor), no throttle, no quiet", async () => {
  const trusted = area();
  await migrateTrustState(area(preA15Local(DEFAULT_SERVER_URL)), trusted);
  for (const k of ["updateInfo", "updateAcceptedSeq", "updateCheckedAt", "updateChannelQuiet"]) {
    assert.equal(trusted.map.has(ns(OK, k)), false, `${k} must not move`);
  }
});

test("item homes and the personal wrap move under their strict decoders; the pending change is dropped", async () => {
  const trusted = area();
  await migrateTrustState(area(preA15Local(DEFAULT_SERVER_URL)), trusted);
  assert.deepEqual(trusted.map.get(ns(OK2, `itemHomes:${U1}`)), { [I1]: V1 }, "only well-formed pairs move");
  assert.deepEqual(trusted.map.get(ns(OK2, `personalWrap:${U1}`)), { vaultId: V1, wrappedVk: "c2VhbGVk" });
  assert.equal(trusted.map.has(ns(OK2, `personalChange:${U1}`)), false, "the next unlock re-stages a pending change");
  // The conveniences move too (closing the email read on Firefox): shape-checked, nothing more.
  assert.equal(trusted.map.get(LAST_EMAIL_KEY), "me@example.org");
  assert.deepEqual(trusted.map.get(ns(OK2, "quBioCred")), { credentialId: "Y3JlZA", prfSalt: "c2FsdA", userId: U1 });
  assert.equal(trusted.map.get(ns(OK2, "quOfferDismissed")), true);
  // Malformed records are dropped, never carried: a homes map with no valid pair, a wrap with an extra field,
  // a bio record for a non-UUID user, a non-true dismissed flag, a userId suffix that is not a UUID.
  const t2 = area();
  await migrateTrustState(
    area({
      [ns(OK2, `itemHomes:${U1}`)]: { x: "y" },
      [ns(OK2, `personalWrap:${U1}`)]: { vaultId: V1, wrappedVk: "c2VhbGVk", extra: 1 },
      [ns(OK2, "quBioCred")]: { credentialId: "Y3JlZA", prfSalt: "c2FsdA", userId: "../../x" },
      [ns(OK2, "quOfferDismissed")]: "yes",
      [ns(OK2, "itemHomes:not-a-uuid")]: { [I1]: V1 },
      lastEmail: "a\nb@example.org",
    }),
    t2,
  );
  assert.deepEqual([...t2.map.keys()], [A15_MIGRATED_KEY], "nothing malformed reached the trusted store");
});

test("after a verified migration every old key is deleted from storage.local; foreign keys are left alone", async () => {
  const legacy = area(preA15Local("https://evil.example"));
  await migrateTrustState(legacy, area());
  assert.deepEqual([...legacy.map.keys()], ["someOtherExtensionLikeKey"]);
});

test("the migration flag lives in the trusted store: a storage.local flag (planted or not) neither skips nor re-runs it", async () => {
  // A planted flag in storage.local does not skip the migration…
  const trusted = area();
  const legacy = area({ ...preA15Local(DEFAULT_SERVER_URL), [A15_MIGRATED_KEY]: true });
  const r = await migrateTrustState(legacy, trusted);
  assert.equal(r.kind, "migrated");
  assert.equal(trusted.map.get(A15_MIGRATED_KEY), true);
  assert.equal(legacy.map.has(A15_MIGRATED_KEY), false, "and the flag is never written to storage.local");
  // …and once the trusted flag is set, values planted in storage.local later are never read again.
  const replanted = area({ [SERVER_URL_KEY]: "https://evil.example", [ns(OK2, `itemHomes:${U1}`)]: { [I2]: V1 } });
  const again = await migrateTrustState(replanted, trusted);
  assert.equal(again.kind, "already");
  assert.equal(trusted.map.has(LEGACY_SERVER_KEY), false);
  assert.deepEqual(trusted.map.get(ns(OK2, `itemHomes:${U1}`)), { [I1]: V1 }, "the migrated homes stand");
  assert.equal(replanted.map.size, 2, "storage.local is not even read");
});

test("trusted store unavailable: nothing is read from or deleted in storage.local, no flag, and the default stands", async () => {
  const legacy = area(preA15Local("https://evil.example"));
  const trusted = area({}, { failGet: true, failSet: true });
  const r = await migrateTrustState(legacy, trusted);
  assert.equal(r.kind, "unavailable");
  assert.equal(legacy.map.size, Object.keys(preA15Local("x")).length, "storage.local untouched (retried once IndexedDB works)");
  assert.equal(await getServerUrl(trusted), DEFAULT_SERVER_URL);
});

test("a write the store did not keep fails verification: no flag, storage.local kept, retried next start", async () => {
  const legacy = area(preA15Local(DEFAULT_SERVER_URL));
  const lossy = area({}, { lossy: true });
  const r = await migrateTrustState(legacy, lossy);
  assert.equal(r.kind, "failed");
  assert.equal(lossy.map.has(A15_MIGRATED_KEY), false);
  assert.equal(legacy.map.size, Object.keys(preA15Local("x")).length, "nothing deleted before the copy verified");
  // A retry on a working store completes, and never overwrites what is already there.
  const trusted = area({ [ns(OK2, `itemHomes:${U1}`)]: { [I2]: V1 } });
  assert.equal((await migrateTrustState(legacy, trusted)).kind, "migrated");
  assert.deepEqual(trusted.map.get(ns(OK2, `itemHomes:${U1}`)), { [I2]: V1 }, "the trusted store's own record wins");
});

test("rememberableEmail: a short single-line string, or nothing", () => {
  assert.equal(rememberableEmail("me@example.org"), "me@example.org");
  assert.equal(rememberableEmail(""), null);
  assert.equal(rememberableEmail("a\u0000b"), null);
  assert.equal(rememberableEmail("a\u2028b"), null);
  assert.equal(rememberableEmail("x".repeat(321)), null);
  assert.equal(rememberableEmail(7), null);
});
