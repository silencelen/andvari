// node --test. Security review 2026-10, the A16 review (2026-10-23) R3: one failure path of the A15 review's F2 fix
// brought back F1's harm. At the browser-attested pre-A15 upgrade the "owed" write threw or timed out, so that worker
// life was `unsettled` with nothing recorded; the next start had no flag, no owed mark and no install event, so the
// migration was `skipped`, the flag set without reading — and the worker dialed the DEFAULT, unblocked, while
// storage.local still named the self-hoster's server: the next sign-in went to the reference instance.
//
// Now a start that skips the migration writes, with the flag, a mark that it did so unread, and while that mark stands
// storage.local's `serverUrl` is read ONLY to block (decline-only, as with no store): a planted value is a denial of
// service, never a repoint. (The in-life retry of the owed write is the worker's: background.pins.test.ts.) These tests
// use only exports that existed before the fix, so against the pre-fix modules they fail.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { DEFAULT_SERVER_URL, SERVER_URL_KEY } from "./serverurl.ts";
import { forgetPendingServer, loadServerState } from "./serverstate.ts";
import { TrustedStoreUnavailable, type KvArea } from "./trustedkv.ts";
import { A15_MIGRATED_KEY, LEGACY_SERVER_KEY, migrateTrustState } from "./trustmigrate.ts";

const SELF = "https://vault.selfhost.example";
const MARK = "a15UnattestedServer";

function area(init: Record<string, unknown> = {}, opts: { failSetOnce?: boolean; timeOutSetOnce?: boolean } = {}) {
  const data = new Map(Object.entries(init));
  let failSet = !!opts.failSetOnce;
  let timeOutSet = !!opts.timeOutSetOnce;
  const reads: string[] = [];
  const kl = (k: string | readonly string[]) => (typeof k === "string" ? [k] : [...k]);
  const a: KvArea = {
    async get(keys) {
      const list = keys === null ? [...data.keys()] : kl(keys);
      reads.push(...(keys === null ? ["*"] : list));
      const o: Record<string, unknown> = {};
      for (const k of list) if (data.has(k)) o[k] = data.get(k);
      return o;
    },
    async set(items) {
      if (failSet) {
        failSet = false;
        throw new TrustedStoreUnavailable("put failed");
      }
      if (timeOutSet) {
        timeOutSet = false;
        throw new TrustedStoreUnavailable("a transaction took too long", true);
      }
      for (const [k, v] of Object.entries(items)) data.set(k, v);
    },
    async remove(keys) {
      for (const k of kl(keys)) data.delete(k);
    },
  };
  return { a, data, reads };
}

const upgrade = async () => ({ reason: "update", previousVersion: "0.28.1" });
const none = async () => null;

for (const how of ["throws", "times out"] as const) {
  test(`R3: the attested start's "owed" write ${how}; the next start (no flag, no event) blocks instead of dialing the default`, async () => {
    const legacy = area({ [SERVER_URL_KEY]: SELF });
    const trusted = area({}, how === "throws" ? { failSetOnce: true } : { timeOutSetOnce: true });
    const o1 = await migrateTrustState(legacy.a, trusted.a, upgrade);
    const s1 = await loadServerState(o1, trusted.a, legacy.a);
    assert.deepEqual(s1.block, { kind: "unsettled" }, "the attested start itself: unsettled, nothing dialed");
    // The worker life ended before the owed write was retried: the next start has nothing to go on.
    const o2 = await migrateTrustState(legacy.a, trusted.a, none);
    assert.equal(o2.kind, "skipped");
    const s2 = await loadServerState(o2, trusted.a, legacy.a);
    assert.equal(s2.url, DEFAULT_SERVER_URL, "never adopted");
    assert.deepEqual(s2.block, { kind: "confirm", origin: SELF, keepable: false }, "blocked: decline-only, never offered for connecting");
    assert.equal(trusted.data.has(LEGACY_SERVER_KEY), false, "storage.local's value did not become a suggestion either");
    // …and so does every start after it, until the user decides.
    const o3 = await migrateTrustState(legacy.a, trusted.a, none);
    assert.equal(o3.kind, "already");
    assert.deepEqual((await loadServerState(o3, trusted.a, legacy.a)).block, { kind: "confirm", origin: SELF, keepable: false });
  });
}

test("R3: 'Not mine' lifts it for good: storage.local's value and the mark both go", async () => {
  const legacy = area({ [SERVER_URL_KEY]: SELF });
  const trusted = area();
  const o = await migrateTrustState(legacy.a, trusted.a, none);
  const st = await loadServerState(o, trusted.a, legacy.a);
  assert.ok(st.block);
  assert.equal(await forgetPendingServer(st.block, trusted.a, legacy.a), true);
  assert.equal(legacy.data.has(SERVER_URL_KEY), false);
  assert.equal(trusted.data.has(MARK), false);
  // A value planted in storage.local after that is never read again: the mark is gone, every start is "already".
  legacy.data.set(SERVER_URL_KEY, "https://evil.example");
  const later = await migrateTrustState(legacy.a, trusted.a, none);
  assert.equal((await loadServerState(later, trusted.a, legacy.a)).block, null);
});

test("R3: a server chosen through the gate lifts it, and the mark goes with the choice", async () => {
  const legacy = area({ [SERVER_URL_KEY]: SELF });
  const trusted = area();
  await loadServerState(await migrateTrustState(legacy.a, trusted.a, none), trusted.a, legacy.a);
  trusted.data.set(SERVER_URL_KEY, SELF); // setServerUrl after the Trust Gate's Connect
  const st = await loadServerState({ kind: "already" }, trusted.a, legacy.a);
  assert.deepEqual(st, { url: SELF, trustedStore: true, block: null });
  assert.equal(trusted.data.has(MARK), false);
});

test("R3: a fresh install, or storage.local naming the default or nothing, blocks nothing (and leaves no mark)", async () => {
  for (const v of [undefined, DEFAULT_SERVER_URL, "nonsense"]) {
    const legacy = area(v === undefined ? {} : { [SERVER_URL_KEY]: v });
    const trusted = area();
    const o = await migrateTrustState(legacy.a, trusted.a, async () => ({ reason: "install" }));
    assert.equal(o.kind, "skipped");
    assert.equal((await loadServerState(o, trusted.a, legacy.a)).block, null, String(v));
    assert.equal(trusted.data.get(A15_MIGRATED_KEY), true);
    assert.equal(trusted.data.has(MARK), false, "the mark is cleared once storage.local names no other server");
    assert.deepEqual((await loadServerState({ kind: "already" }, trusted.a, legacy.a)).block, null);
  }
});

test("R3: storage.local is read only for its serverUrl, and only while the mark stands", async () => {
  const legacy = area({ [SERVER_URL_KEY]: SELF, lastEmail: "a@example.org" });
  const trusted = area();
  await loadServerState(await migrateTrustState(legacy.a, trusted.a, none), trusted.a, legacy.a);
  assert.deepEqual(legacy.reads, [SERVER_URL_KEY], "the one key, nothing else");
  // A completed migration (the flag, no mark): storage.local is not consulted at all.
  const plain = area({ [SERVER_URL_KEY]: SELF });
  await loadServerState({ kind: "already" }, area({ [A15_MIGRATED_KEY]: true }).a, plain.a);
  assert.deepEqual(plain.reads, []);
});
