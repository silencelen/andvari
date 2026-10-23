// node --test. Security review 2026-10, A15 review F2 (LOW): the one-time migration reran whenever the trusted store
// lacked its flag, not only on the upgrade it exists for. Two probe-confirmed triggers: the store was unavailable at the
// upgrade and became available later (Firefox's "Never remember history" turned off), or the store lost its data while
// storage.local kept its own. Whatever a content script had written to storage.local in the meantime then moved into
// the trusted store (a planted server suggestion, homes, an older wrap, an email, a credential id).
//
// The rule now: storage.local is read only when the BROWSER attested an upgrade from a pre-A15 build
// (`runtime.onInstalled`, reason "update", previousVersion no newer than the last pre-A15 release), and that is
// recorded as "owed" in the trusted store before anything is read. Every other flagless start sets the flag without
// reading. These tests use only exports that existed before the fix (plus the owed key's literal name), so they run —
// and fail — against the pre-fix module too.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { originKeyFor, SERVER_URL_KEY } from "./serverurl.ts";
import { TrustedStoreUnavailable, type KvArea } from "./trustedkv.ts";
import { A15_MIGRATED_KEY, LEGACY_SERVER_KEY, migrateTrustState } from "./trustmigrate.ts";

const OWED = "a15MigrationOwed";
const OK2 = originKeyFor("https://self.example");
const U1 = "11111111-1111-4111-8111-111111111111";
const V1 = "22222222-2222-4222-8222-222222222222";
const I1 = "33333333-3333-4333-8333-333333333333";
const ns = (ok: string, k: string) => `ns.${ok}.${k}`;

type Sig = { reason: string; previousVersion?: string } | null;
// The pre-fix function takes two arguments; calling it with a third is how this file runs against it unchanged.
const migrate = migrateTrustState as unknown as (legacy: KvArea, trusted: KvArea, awaitInstall: () => Promise<Sig>) => Promise<{ kind: string }>;
const signal = (s: Sig) => async () => s;

type Spy = KvArea & { map: Map<string, unknown>; reads: number; sets: Record<string, unknown>[]; onRead?: () => void };
function area(initial: Record<string, unknown> = {}, opts: { fail?: boolean; timedOut?: boolean; failSetOf?: string } = {}): Spy {
  const map = new Map(Object.entries(structuredClone(initial)));
  const self: Spy = {
    map,
    reads: 0,
    sets: [],
    async get(keys) {
      if (opts.fail) throw new TrustedStoreUnavailable("IndexedDB is not available here", opts.timedOut === true);
      self.reads++;
      self.onRead?.();
      const list = keys === null ? [...map.keys()] : typeof keys === "string" ? [keys] : [...keys];
      const out: Record<string, unknown> = {};
      for (const k of list) if (map.has(k)) out[k] = structuredClone(map.get(k));
      return out;
    },
    async set(items) {
      if (opts.fail) throw new TrustedStoreUnavailable("IndexedDB is not available here", opts.timedOut === true);
      if (opts.failSetOf !== undefined && opts.failSetOf in items) throw new TrustedStoreUnavailable("quota");
      self.sets.push(structuredClone(items));
      for (const [k, v] of Object.entries(items)) map.set(k, structuredClone(v));
    },
    async remove(keys) {
      for (const k of typeof keys === "string" ? [keys] : keys) map.delete(k);
    },
  };
  return self;
}

/** What a content script could have left in storage.local after the upgrade: every value here is a plant. */
const planted = () => ({
  [SERVER_URL_KEY]: "https://evil.example",
  lastEmail: "attacker@example.org",
  [ns(OK2, `itemHomes:${U1}`)]: { [I1]: V1 },
  [ns(OK2, `personalWrap:${U1}`)]: { vaultId: V1, wrappedVk: "b2xkZXI" },
  [ns(OK2, "quBioCred")]: { credentialId: "cGxhbnQ", prfSalt: "c2FsdA", userId: U1 },
});

test("F2: a flagless start with NO install event sets the flag without reading storage.local", async () => {
  const legacy = area(planted());
  const trusted = area();
  const r = await migrate(legacy, trusted, signal(null));
  assert.equal(legacy.reads, 0, "storage.local is never read");
  assert.equal(trusted.map.get(A15_MIGRATED_KEY), true, "the flag is set, so no later start migrates either");
  for (const k of [LEGACY_SERVER_KEY, "lastEmail", ns(OK2, `itemHomes:${U1}`), ns(OK2, `personalWrap:${U1}`), ns(OK2, "quBioCred")]) {
    assert.equal(trusted.map.has(k), false, `${k} was not moved`);
  }
  assert.equal(r.kind, "skipped");
  assert.equal(legacy.map.size, Object.keys(planted()).length, "and nothing is deleted there either (never read, never trusted)");
});

test("F2: a fresh install, an update from an A15 build and a browser update read nothing", async () => {
  for (const sig of [
    { reason: "install" },
    { reason: "update", previousVersion: "0.28.2" },
    { reason: "update", previousVersion: "0.29.0" },
    { reason: "update", previousVersion: "1.0" },
    { reason: "chrome_update" },
    { reason: "browser_update" },
    { reason: "shared_module_update" },
  ]) {
    const legacy = area(planted());
    const trusted = area();
    await migrate(legacy, trusted, signal(sig));
    assert.equal(legacy.reads, 0, `${JSON.stringify(sig)}: storage.local not read`);
    assert.equal(trusted.map.get(A15_MIGRATED_KEY), true, `${JSON.stringify(sig)}: flag set`);
    assert.equal(trusted.map.has(LEGACY_SERVER_KEY), false);
  }
});

test("F2: an update whose previous version is missing or malformed attests nothing", async () => {
  for (const previousVersion of [undefined, "", "0.28", "garbage", "0.28.1-beta", "0.28.1.0.0", " ", "-1.0.0"]) {
    const legacy = area(planted());
    const trusted = area();
    await migrate(legacy, trusted, signal({ reason: "update", previousVersion: previousVersion as string }));
    // "0.28" is a well-formed pre-A15 version (0.28.0): the only one of these that does attest.
    if (previousVersion === "0.28") assert.equal(legacy.reads, 1, "0.28 = 0.28.0, older than 0.28.1: attested");
    else assert.equal(legacy.reads, 0, `previousVersion ${JSON.stringify(previousVersion)}: storage.local not read`);
  }
});

test("F2: the browser's report of an update from a pre-A15 build records 'owed' BEFORE storage.local is read, then migrates", async () => {
  for (const previousVersion of ["0.28.1", "0.28.0", "0.27.0", "0.16.3"]) {
    const legacy = area({ [SERVER_URL_KEY]: "https://self.example", lastEmail: "me@example.org" });
    const trusted = area();
    let owedAtRead: unknown = "not read";
    legacy.onRead = () => (owedAtRead = trusted.map.get(OWED));
    const r = await migrate(legacy, trusted, signal({ reason: "update", previousVersion }));
    assert.equal(owedAtRead, true, `${previousVersion}: owed was recorded in the trusted store before the read`);
    assert.equal(r.kind, "migrated");
    assert.equal(trusted.map.get(LEGACY_SERVER_KEY), "https://self.example", "kept as a pending suggestion (never the choice)");
    assert.equal(trusted.map.has(SERVER_URL_KEY), false);
    assert.equal(trusted.map.get(A15_MIGRATED_KEY), true);
    assert.notEqual(trusted.map.get(OWED), true, "no longer owed");
    // The flag and the owed mark change in ONE write: no start can see "done" while still owed, or the reverse.
    const last = trusted.sets[trusted.sets.length - 1]!;
    assert.deepEqual(Object.keys(last).sort(), [A15_MIGRATED_KEY, OWED].sort());
  }
});

test("F2: an owed migration that did not complete finishes at the next start, which needs no install event", async () => {
  const legacy = area({ [SERVER_URL_KEY]: "https://self.example" });
  const trusted = area({}, { failSetOf: LEGACY_SERVER_KEY }); // the copy cannot be written this time
  const r1 = await migrate(legacy, trusted, signal({ reason: "update", previousVersion: "0.28.1" }));
  assert.equal(r1.kind, "failed");
  assert.equal(trusted.map.get(OWED), true, "still owed");
  assert.notEqual(trusted.map.get(A15_MIGRATED_KEY), true);
  // Next start: no install event this time (the update was the previous start's), yet the migration is owed.
  const healthy = area(Object.fromEntries(trusted.map));
  const r2 = await migrate(legacy, healthy, signal(null));
  assert.equal(r2.kind, "migrated");
  assert.equal(healthy.map.get(LEGACY_SERVER_KEY), "https://self.example");
  assert.equal(healthy.map.get(A15_MIGRATED_KEY), true);
});

test("F2: no trusted store at the attested upgrade — nothing is read then, and a later flagless start reads nothing either", async () => {
  const legacy = area({ [SERVER_URL_KEY]: "https://self.example" });
  const none = area({}, { fail: true });
  const r1 = await migrate(legacy, none, signal({ reason: "update", previousVersion: "0.28.1" }));
  assert.equal(r1.kind, "unavailable");
  assert.equal(legacy.reads, 0, "nowhere to record 'owed', so nothing is read for trust");
  // While the store stayed unavailable a content script planted more; then the store came back (FF setting turned off).
  for (const [k, v] of Object.entries(planted())) legacy.map.set(k, v);
  const back = area();
  const r2 = await migrate(legacy, back, signal(null));
  assert.equal(r2.kind, "skipped");
  assert.equal(legacy.reads, 0, "the store's return is not an upgrade: storage.local is not read");
  assert.equal(back.map.has(LEGACY_SERVER_KEY), false, "no planted suggestion");
  assert.equal(back.map.get(A15_MIGRATED_KEY), true);
});

test("F2: a store that lost its data while storage.local kept a plant does not re-migrate", async () => {
  // A15 ran before (flag set), then the trusted store's data went; storage.local has a fresh plant.
  const legacy = area(planted());
  const wiped = area();
  await migrate(legacy, wiped, signal(null));
  assert.equal(legacy.reads, 0);
  assert.equal(wiped.map.has(LEGACY_SERVER_KEY), false);
  assert.equal(wiped.map.has(ns(OK2, `personalWrap:${U1}`)), false, "an older wrap a page planted does not become the cache");
});

test("F2: an 'owed' mark planted in storage.local means nothing", async () => {
  const legacy = area({ ...planted(), [OWED]: true, [A15_MIGRATED_KEY]: false });
  const trusted = area();
  await migrate(legacy, trusted, signal(null));
  assert.equal(legacy.reads, 0);
  assert.equal(trusted.map.has(LEGACY_SERVER_KEY), false);
});

test("F2: once migrated, a later attested-looking event with the flag set and nothing owed reads nothing", async () => {
  const legacy = area(planted());
  const trusted = area({ [A15_MIGRATED_KEY]: true });
  let asked = 0;
  const r = await migrate(legacy, trusted, async () => {
    asked++;
    return { reason: "update", previousVersion: "0.28.1" };
  });
  assert.equal(r.kind, "already");
  assert.equal(asked, 0, "the steady state does not even wait for the install event");
  assert.equal(legacy.reads, 0);
});

test("F2: attestsPreA15Upgrade is the browser report check, and LAST_PRE_A15_VERSION is the newest release without A15", async () => {
  const mod = (await import("./trustmigrate.ts")) as Record<string, unknown>;
  const attests = mod.attestsPreA15Upgrade as ((s: Sig) => boolean) | undefined;
  assert.equal(typeof attests, "function", "trustmigrate.ts exports attestsPreA15Upgrade");
  assert.equal(mod.LAST_PRE_A15_VERSION, "0.28.1");
  assert.equal(attests!({ reason: "update", previousVersion: "0.28.1" }), true);
  assert.equal(attests!({ reason: "update", previousVersion: "0.9.9" }), true);
  assert.equal(attests!({ reason: "update", previousVersion: "0.28.1.1" }), false);
  assert.equal(attests!({ reason: "update", previousVersion: "0.28.2" }), false);
  assert.equal(attests!({ reason: "install", previousVersion: "0.28.1" }), false);
  assert.equal(attests!(null), false);
  assert.equal(attests!({ reason: "update" }), false);
});
