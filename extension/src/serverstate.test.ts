// node --test. Security review 2026-10, A15 review F1 (MEDIUM): after the A15 update a self-hoster's previous server is
// not adopted (it sat in storage.local, which a content script could write) — and until F1 the worker dialed the
// default in the meantime, with nothing stopping a sign-in. storage.session is cleared by the update, so the user
// signed in again with the email prefilled, and the reference instance, which answers an unknown email with a
// deterministic fake salt, received the email and an authKey derived from the master password under a salt it chose.
// The update channel polled it, the open-vault / forgot / must-change buttons opened it, and the self-host vault lost
// its autofill exclusion. Under Firefox's "Never remember history" there was not even the suggestion.
//
// serverstate.ts is the rule: while a server is pending, the worker dials NO server, the default included.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { DEFAULT_SERVER_URL, originMatchPattern, SERVER_URL_KEY } from "./serverurl.ts";
import { autofillExcludeMatches, DIAL_TYPES, dialRefusal, forgetPendingServer, loadServerState, type ServerBlock } from "./serverstate.ts";
import { SENDER_CLASS } from "./sendergate.ts";
import { TrustedStoreUnavailable, type KvArea } from "./trustedkv.ts";
import { LEGACY_SERVER_KEY, type MigrationOutcome } from "./trustmigrate.ts";

type Fake = KvArea & { map: Map<string, unknown>; reads: string[]; removed: string[] };
function area(initial: Record<string, unknown> = {}, opts: { fail?: boolean } = {}): Fake {
  const map = new Map(Object.entries(initial));
  const self: Fake = {
    map,
    reads: [],
    removed: [],
    async get(keys) {
      if (opts.fail) throw new TrustedStoreUnavailable("no IndexedDB");
      const list = keys === null ? [...map.keys()] : typeof keys === "string" ? [keys] : [...keys];
      self.reads.push(...(keys === null ? ["*"] : list));
      const out: Record<string, unknown> = {};
      for (const k of list) if (map.has(k)) out[k] = map.get(k);
      return out;
    },
    async set() {
      throw new Error("loadServerState / forgetPendingServer never write a store");
    },
    async remove(keys) {
      if (opts.fail) throw new TrustedStoreUnavailable("no IndexedDB");
      for (const k of typeof keys === "string" ? [keys] : keys) {
        self.removed.push(k);
        map.delete(k);
      }
    },
  };
  return self;
}

const migrated = (legacyServer: string | null): MigrationOutcome => ({ kind: "migrated", legacyServer, moved: [], removed: 0 });
const CONFIRM: ServerBlock = { kind: "confirm", origin: "https://self.example", keepable: true };
const UNSETTLED: ServerBlock = { kind: "unsettled" };

test("F1: while a server is pending, every sign-in lane and the connection test are refused with confirm_server", () => {
  assert.deepEqual([...DIAL_TYPES].sort(), ["ping", "unlock", "unlockTotp", "unlockWithBio", "unlockWithPin"]);
  for (const block of [CONFIRM, { ...CONFIRM, keepable: false }, UNSETTLED]) {
    for (const type of DIAL_TYPES) {
      assert.deepEqual(dialRefusal(type, block), { ok: false, code: "confirm_server" }, `${type} under ${block.kind}`);
    }
  }
  // With no block nothing is held.
  for (const type of DIAL_TYPES) assert.equal(dialRefusal(type, null), null);
});

test("F1: what stays open while a server is pending: the pages' own reads, the way out, locking — nothing that dials", () => {
  for (const type of Object.keys(SENDER_CLASS)) {
    if ((DIAL_TYPES as readonly string[]).includes(type)) continue;
    assert.equal(dialRefusal(type, CONFIRM), null, `${type} is not a dial`);
  }
  // The way out must stay open: the gate's commit, "Not mine", and what the pages render from.
  for (const type of ["setServerUrl", "forgetLegacyServer", "serverInfo", "status", "lock", "signOut", "purgeServerData"]) {
    assert.ok(type in SENDER_CLASS, `${type} is a real message type`);
    assert.equal(dialRefusal(type, CONFIRM), null);
  }
});

test("F1: a migrated previous server is a pending confirm — the worker's url stays the default but is not dialed", async () => {
  const trusted = area({ [LEGACY_SERVER_KEY]: "https://self.example" });
  const st = await loadServerState(migrated("https://self.example"), trusted, area());
  assert.equal(st.url, DEFAULT_SERVER_URL);
  assert.deepEqual(st.block, { kind: "confirm", origin: "https://self.example", keepable: true });
  assert.equal(st.trustedStore, true);
});

test("F1: the pending state survives restarts (it is read from the trusted store), until confirmed or declined", async () => {
  const trusted = area({ a15Migrated: true, [LEGACY_SERVER_KEY]: "https://self.example" });
  assert.deepEqual((await loadServerState({ kind: "already" }, trusted, area())).block, CONFIRM);
  // A server chosen through the gate since: no block, and a stray suggestion beside it is removed.
  const chosen = area({ [SERVER_URL_KEY]: "https://mine.example", [LEGACY_SERVER_KEY]: "https://self.example" });
  const st = await loadServerState({ kind: "already" }, chosen, area());
  assert.equal(st.url, "https://mine.example");
  assert.equal(st.block, null);
  assert.equal(chosen.map.has(LEGACY_SERVER_KEY), false);
  // Nothing pending, nothing chosen: the default, unblocked (a user who was always on the default).
  assert.deepEqual(await loadServerState({ kind: "already" }, area(), area()), { url: DEFAULT_SERVER_URL, trustedStore: true, block: null });
  // A suggestion equal to the default or not a plain origin is no pending server.
  for (const bad of [DEFAULT_SERVER_URL, "javascript:alert(1)", "https://x.example/path", 7]) {
    assert.equal((await loadServerState({ kind: "already" }, area({ [LEGACY_SERVER_KEY]: bad }), area())).block, null, String(bad));
  }
});

test("F1: no trusted store (Firefox 'Never remember history') — storage.local's serverUrl is read ONLY to block", async () => {
  const legacy = area({ [SERVER_URL_KEY]: "HTTPS://Self.Example/" });
  const st = await loadServerState({ kind: "unavailable", timedOut: false }, area({}, { fail: true }), legacy);
  assert.equal(st.url, DEFAULT_SERVER_URL, "never adopted");
  assert.equal(st.trustedStore, false);
  assert.deepEqual(st.block, { kind: "confirm", origin: "https://self.example", keepable: false }, "a block that cannot be confirmed here");
  assert.deepEqual(legacy.reads, [SERVER_URL_KEY], "only that one key is read, nothing else in storage.local");
  // The default, nothing, or garbage there: the default is in effect, unblocked (the only server this mode can keep).
  for (const v of [undefined, DEFAULT_SERVER_URL, "nonsense", { url: "https://self.example" }]) {
    const l = area(v === undefined ? {} : { [SERVER_URL_KEY]: v });
    assert.equal((await loadServerState({ kind: "unavailable", timedOut: false }, area({}, { fail: true }), l)).block, null, JSON.stringify(v));
  }
  // storage.local unreadable too: nothing names another server.
  assert.equal((await loadServerState({ kind: "unavailable", timedOut: false }, area({}, { fail: true }), area({}, { fail: true }))).block, null);
});

test("F1: a store that timed out, or an owed migration that failed, is 'unsettled' — the server is unknown, nothing dials", async () => {
  const legacy = area({ [SERVER_URL_KEY]: "https://self.example" });
  const t = await loadServerState({ kind: "unavailable", timedOut: true }, area({}, { fail: true }), legacy);
  assert.deepEqual(t.block, UNSETTLED);
  assert.deepEqual(legacy.reads, [], "a timed-out store is not the no-store mode: storage.local is not consulted");
  assert.deepEqual((await loadServerState({ kind: "failed" }, area(), legacy)).block, UNSETTLED);
  // The store answered the migration but not the server read right after.
  assert.deepEqual((await loadServerState({ kind: "already" }, area({}, { fail: true }), legacy)).block, UNSETTLED);
});

test("F1: 'Not mine' drops the pending origin where it is kept; an unsettled block cannot be dismissed", async () => {
  const trusted = area({ [LEGACY_SERVER_KEY]: "https://self.example" });
  const legacy = area({ [SERVER_URL_KEY]: "https://self.example" });
  assert.equal(await forgetPendingServer(CONFIRM, trusted, legacy), true);
  assert.deepEqual(trusted.removed, [LEGACY_SERVER_KEY]);
  assert.deepEqual(legacy.removed, [], "a keepable block lives in the trusted store only");
  const l2 = area({ [SERVER_URL_KEY]: "https://self.example" });
  assert.equal(await forgetPendingServer({ ...CONFIRM, keepable: false }, area({}, { fail: true }), l2), true);
  assert.deepEqual(l2.removed, [SERVER_URL_KEY], "no store: the old storage.local value goes (it was only ever read to block)");
  assert.equal(await forgetPendingServer(UNSETTLED, area(), area()), false);
  assert.equal(await forgetPendingServer(null, area(), area()), true);
  assert.equal(await forgetPendingServer(CONFIRM, area({}, { fail: true }), area()), false, "a removal that failed keeps the block");
});

test("F1: autofill stays out of the pending origin, and fails closed when it cannot be excluded or is unknown", () => {
  const self = originMatchPattern("https://self.example")!;
  const def = originMatchPattern(DEFAULT_SERVER_URL)!;
  assert.deepEqual(autofillExcludeMatches(DEFAULT_SERVER_URL, CONFIRM)?.sort(), [def, self].sort());
  assert.deepEqual(autofillExcludeMatches(DEFAULT_SERVER_URL, { ...CONFIRM, keepable: false })?.sort(), [def, self].sort());
  assert.deepEqual(autofillExcludeMatches(DEFAULT_SERVER_URL, null), [def]);
  assert.deepEqual(autofillExcludeMatches("https://mine.example", null)?.sort(), [def, originMatchPattern("https://mine.example")!].sort());
  assert.equal(autofillExcludeMatches(DEFAULT_SERVER_URL, { kind: "confirm", origin: "https://[::1]:8443", keepable: true }), null, "an IPv6 literal cannot be excluded: no autofill at all");
  assert.equal(autofillExcludeMatches(DEFAULT_SERVER_URL, UNSETTLED), null, "the user's vault origin is unknown: no autofill at all");
  assert.equal(autofillExcludeMatches("https://[::1]", null), null);
});
