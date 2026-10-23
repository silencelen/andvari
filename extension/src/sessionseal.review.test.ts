// node --test. Security review 2026-10, the A16 review (2026-10-23): R1 who decides that the sealing key is replaced,
// R2 the custody epoch's durability, R4 the lock's erase comes first. sessionseal.ts is driven against in-memory
// stand-ins for storage.session and the key store; the worker's wiring is pinned in background.pins.test.ts.
//
// Each test names the reviewer's probe it comes from (P1a, P1b, P2, P3). They are written so that they also run
// against the module before the fix: there, they fail (the old seal kept its key for any record of the sealed SHAPE,
// never retried a failed epoch write, and had no rotation or lock copy at all).
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { nsKey } from "./serverurl.ts";
import { SEAL_KEY_RECORD, SessionSeal, slotKey } from "./sessionseal.ts";
import type { KvArea } from "./trustedkv.ts";

const OK = "0123456789abcdef";
const OTHER = "fedcba9876543210";
const tick = (ms = 5) => new Promise((r) => setTimeout(r, ms));

/** storage.session stand-in: values cross it as JSON, every call is logged in order. */
function fakeSession(initial: Record<string, unknown> = {}) {
  const data = new Map<string, unknown>(Object.entries(initial).map(([k, v]) => [k, JSON.parse(JSON.stringify(v))]));
  const log: string[] = [];
  const kl = (k: string | readonly string[]) => (typeof k === "string" ? [k] : [...k]);
  const area: KvArea = {
    async get(keys) {
      log.push(`get ${keys === null ? "*" : kl(keys).join(",")}`);
      const o: Record<string, unknown> = {};
      for (const k of keys === null ? [...data.keys()] : kl(keys)) if (data.has(k)) o[k] = JSON.parse(JSON.stringify(data.get(k)));
      return o;
    },
    set(items) {
      log.push(`set ${Object.keys(items).join(",")}`);
      for (const [k, v] of Object.entries(items)) data.set(k, JSON.parse(JSON.stringify(v)));
      return Promise.resolve();
    },
    remove(keys) {
      log.push(`remove ${kl(keys).join(",")}`);
      for (const k of kl(keys)) data.delete(k);
      return Promise.resolve();
    },
  };
  return { area, data, log };
}

/** The key store stand-in (structured clone, like IndexedDB). Writes, or everything, can be made to fail or hang. */
function fakeKeys() {
  const data = new Map<string, unknown>();
  let failSets = false;
  let failAll = false;
  let hang: Promise<void> | null = null;
  let release: () => void = () => {};
  const gate = async (write: boolean) => {
    if (hang) await hang;
    if (failAll || (write && failSets)) throw new Error("the key store refused");
  };
  const area: KvArea = {
    async get(keys) {
      await gate(false);
      const o: Record<string, unknown> = {};
      for (const k of keys === null ? [...data.keys()] : typeof keys === "string" ? [keys] : keys) if (data.has(k)) o[k] = structuredClone(data.get(k));
      return o;
    },
    async set(items) {
      await gate(true);
      for (const [k, v] of Object.entries(items)) data.set(k, structuredClone(v));
    },
    async remove(keys) {
      await gate(true);
      for (const k of typeof keys === "string" ? [keys] : keys) data.delete(k);
    },
  };
  return {
    area,
    data,
    epoch: () => (data.get(SEAL_KEY_RECORD) as { epoch?: number } | undefined)?.epoch,
    key: () => (data.get(SEAL_KEY_RECORD) as { key?: CryptoKey } | undefined)?.key,
    failSets: (b: boolean) => (failSets = b),
    failAll: (b: boolean) => (failAll = b),
    hang: () => (hang = new Promise<void>((r) => (release = r))),
    release: () => {
      hang = null;
      release();
    },
  };
}

/** `lockErase()` answers `{erased, opened}` since the review; before, a promise. Either way: wait for the removal. */
async function erased(e: unknown): Promise<void> {
  const o = e as { erased?: Promise<void> } | Promise<void>;
  await ("erased" in (o as object) ? (o as { erased: Promise<void> }).erased : o);
}

const garbage = { v: 1, iv: "AAAA", ct: "AAAA" };

test("R1 / P1b: a planted record of the sealed SHAPE does not keep the key — a quick-unlock record from before never opens", async () => {
  const k = fakeKeys();
  const s1 = fakeSession();
  const a = new SessionSeal({ session: s1.area, keys: k.area });
  await a.ready;
  await a.set("quickUnlock", OK, { blob: "B", lockedTokens: { refresh: "rt" } });
  const quCopy = structuredClone(s1.data.get(nsKey(OK, "quickUnlock")));
  await erased(a.lockErase());
  await tick();
  const keyBefore = k.key();
  // The browser exited; whoever can write storage.session plants a sealed-shaped garbage record before the next start.
  const s2 = fakeSession({ [nsKey("f".repeat(16), "knownLogins")]: garbage });
  const b = new SessionSeal({ session: s2.area, keys: k.area });
  assert.equal(await b.ready, true);
  assert.notEqual(k.key(), keyBefore, "nothing opened under the stored key, so a fresh key replaced it");
  assert.equal(k.epoch(), 0, "a fresh key starts a fresh epoch");
  assert.equal(s2.data.size, 0, "the garbage was dropped");
  s2.data.set(nsKey(OK, "quickUnlock"), quCopy);
  assert.equal(await b.get("quickUnlock", OK), undefined, "the previous session's quick-unlock record never opens again");
});

test("R1: a record that really opens keeps the key (a worker restart in the same browser session); garbage beside it changes nothing", async () => {
  const k = fakeKeys();
  const s = fakeSession();
  const a = new SessionSeal({ session: s.area, keys: k.area });
  await a.ready;
  await a.set("knownLogins", OK, { key: "k", digests: [] });
  s.data.set(nsKey(OTHER, "quickUnlock"), garbage);
  const before = k.key();
  const b = new SessionSeal({ session: s.area, keys: k.area });
  assert.equal(await b.ready, true);
  assert.equal(k.key(), before, "kept");
  assert.deepEqual(await b.get("knownLogins", OK), { key: "k", digests: [] });
  assert.equal(await b.get("quickUnlock", OTHER), undefined, "the garbage reads absent (and is dropped)");
});

test("R1: the two global slots count only when they open for the CURRENT origin (asked of the worker, only when needed)", async () => {
  const k = fakeKeys();
  const s = fakeSession();
  const a = new SessionSeal({ session: s.area, keys: k.area });
  await a.ready;
  await a.set("session", OK, { access: "tok" });
  const before = k.key();
  let asked = 0;
  const kept = new SessionSeal({ session: s.area, keys: k.area, originKey: async () => (asked++, OK) });
  assert.equal(await kept.ready, true);
  assert.equal(asked, 1);
  assert.equal(k.key(), before, "the snapshot opens for the current origin: same browser session, key kept");
  assert.deepEqual(await kept.get("session", OK), { access: "tok" });
  // Another origin is current (or none is known): the snapshot proves nothing about this key.
  const other = new SessionSeal({ session: s.area, keys: k.area, originKey: async () => OTHER });
  assert.equal(await other.ready, true);
  assert.notEqual(k.key(), before, "replaced");
  assert.equal(s.data.has("session"), false, "and the unopenable snapshot dropped");
});

test("R1 / P1a: a browser-start report replaces the key — a copy of the previous browser session's snapshot never opens after it", async () => {
  const k = fakeKeys();
  const s1 = fakeSession();
  const a = new SessionSeal({ session: s1.area, keys: k.area });
  await a.ready;
  await a.set("session", OK, { access: "tok", refresh: "rt", vaultKeys: { v: "KEY" } });
  const copy = structuredClone(s1.data.get("session"));
  // The browser closed while unlocked (no lock: the epoch never advanced). The copy is put back before the next start's
  // first read: with no report, the seal's start rule cannot tell it from a worker restart (spec 05 A16(a) residual).
  const s2 = fakeSession({ session: copy, lockNotice: { kind: "idle", seconds: 60 } });
  const b = new SessionSeal({ session: s2.area, keys: k.area, originKey: async () => OK });
  assert.equal(await b.ready, true);
  assert.deepEqual(await b.get("session", OK), { access: "tok", refresh: "rt", vaultKeys: { v: "KEY" } }, "no report yet: it opens");
  const before = k.key();
  // runtime.onStartup / runtime.onInstalled: a browser-attested new session.
  assert.equal(await b.rotate(), true);
  assert.notEqual(k.key(), before, "a fresh key");
  assert.equal(k.epoch(), 0);
  assert.equal(s2.data.has("session"), false, "every sealed record dropped");
  assert.deepEqual(s2.data.get("lockNotice"), { kind: "idle", seconds: 60 }, "the plain inventory stays");
  s2.data.set("session", copy);
  assert.equal(await b.get("session", OK), undefined, "the copy never opens again");
  // …and a worker restart in this browser session does not bring the old key back.
  const c = new SessionSeal({ session: s2.area, keys: k.area, originKey: async () => OK });
  assert.equal(await c.ready, true);
  assert.equal(await c.get("session", OK), undefined);
});

test("R1: an operation issued before the report is dropped (a write) or absent (a read); one issued after uses the new key", async () => {
  const k = fakeKeys();
  const s = fakeSession();
  const a = new SessionSeal({ session: s.area, keys: k.area });
  await a.ready;
  await a.set("quickUnlock", OK, { n: 1 });
  k.hang(); // the key store is slow: the rotation is still deciding when the next calls come in
  const read = a.get("quickUnlock", OK);
  const write = a.set("knownLogins", OK, { n: 2 });
  const rotated = a.rotate();
  assert.equal(a.available(), null, "undecided while the key is replaced");
  const after = a.set("knownLogins", OK, { n: 3 });
  k.release();
  assert.equal(await rotated, true);
  assert.equal(await read, undefined, "a read issued before the report reads absent");
  assert.equal(await write, false, "a write issued before it is dropped");
  assert.equal(await after, true, "a write issued after it lands, under the new key");
  assert.deepEqual(await a.get("knownLogins", OK), { n: 3 });
  assert.equal(await a.get("quickUnlock", OK), undefined, "the record from before is gone");
  // A lock's copy taken before the report never opens either.
  await a.set("session", OK, { access: "tok" });
  const e = a.lockErase() as unknown as { opened(o: string): Promise<{ session?: unknown }> };
  await a.rotate();
  assert.deepEqual(await e.opened(OK), {}, "the lock's copy is absent once the key was replaced");
});

test("R1: a rotation whose new key the store refuses deletes the old key and persists nothing secret", async () => {
  const k = fakeKeys();
  const s = fakeSession();
  const a = new SessionSeal({ session: s.area, keys: k.area });
  await a.ready;
  await a.set("quickUnlock", OK, { n: 1 });
  k.failSets(true);
  assert.equal(await a.rotate(), false);
  assert.equal(a.available(), false);
  assert.equal(await a.set("quickUnlock", OK, { n: 2 }), false, "nothing is written without a key");
  assert.equal(s.data.has(nsKey(OK, "quickUnlock")), false);
  k.failSets(false);
  // The remove went through the same refusing store, so the old key may stand: the next start still drops what it
  // cannot open, and it cannot open the record from before (none is left).
  const b = new SessionSeal({ session: s.area, keys: k.area });
  assert.equal(await b.ready, true);
  assert.equal(await b.get("quickUnlock", OK), undefined);
});

test("R2 / P2: a failed epoch write is retried by the next operation; the next start does not open a copy from before the lock", async () => {
  const k = fakeKeys();
  const s = fakeSession();
  const a = new SessionSeal({ session: s.area, keys: k.area });
  await a.ready;
  await a.set("quickUnlock", OK, { armed: 1 }); // keeps the key across restarts
  await a.set("session", OK, { access: "tok" });
  const copy = structuredClone(s.data.get("session"));
  k.failSets(true);
  await erased(a.lockErase());
  await tick();
  assert.equal(k.epoch(), 0, "the store refused the new epoch");
  k.failSets(false);
  await a.set("knownLogins", OK, { n: 1 }); // any later operation retries it
  await tick();
  assert.equal(k.epoch(), 1, "retried, and written");
  s.data.set("session", copy);
  const b = new SessionSeal({ session: s.area, keys: k.area });
  await b.ready;
  assert.equal(await b.get("session", OK), undefined, "the pre-lock copy stays closed after the restart");
});

test("R2: the lock waits (bounded) for its epoch after the erase; a snapshot or tab record is held until its epoch is in the store", async () => {
  const k = fakeKeys();
  const s = fakeSession();
  const a = new SessionSeal({ session: s.area, keys: k.area });
  await a.ready;
  await a.set("quickUnlock", OK, { armed: 1 });
  await a.set("tabs", OK, { before: 1 });
  k.failSets(true);
  const e = a.lockErase() as unknown as { erased: Promise<void> };
  await e.erased;
  assert.equal(s.data.has("tabs"), false, "erased without waiting on the store");
  const t0 = Date.now();
  assert.equal(await a.lockDurable(60), false, "the store still refuses");
  assert.ok(Date.now() - t0 < 1000, "bounded");
  // Written under an epoch the store does not hold, the record would not open at the next start (and copies from
  // before the lock would): it is not written at all, and its slot stays empty.
  assert.equal(await a.set("tabs", OK, { pageKnown: 1 }), false);
  assert.equal(s.data.has("tabs"), false);
  // Records not bound to the epoch are written as before.
  assert.equal(await a.set("knownLogins", OK, { n: 1 }), true);
  k.failSets(false);
  assert.equal(await a.set("tabs", OK, { pageKnown: 2 }), true, "the epoch lands first, then the record");
  assert.equal(k.epoch(), 1);
  assert.equal(await a.lockDurable(60), true);
  const b = new SessionSeal({ session: s.area, keys: k.area });
  await b.ready;
  assert.deepEqual(await b.get("tabs", OK), { pageKnown: 2 }, "it opens after a restart");
});

test("R2: a lock before the key is known advances the epoch once it is — and the lock's bounded wait covers that write", async () => {
  const k = fakeKeys();
  const s = fakeSession();
  const a = new SessionSeal({ session: s.area, keys: k.area });
  await a.ready;
  await a.set("quickUnlock", OK, { armed: 1 });
  await a.set("session", OK, { access: "tok" });
  const copy = structuredClone(s.data.get("session"));
  k.hang();
  const b = new SessionSeal({ session: s.area, keys: k.area });
  const e = b.lockErase() as unknown as { erased: Promise<void> };
  await e.erased;
  const durable = b.lockDurable(2000);
  k.release();
  assert.equal(await durable, true);
  assert.equal(k.epoch(), 1);
  s.data.set("session", copy);
  const c = new SessionSeal({ session: s.area, keys: k.area });
  await c.ready;
  assert.equal(await c.get("session", OK), undefined);
});

test("R2 / P3: a lock in a worker life whose start could not reach the key store is recorded once the store answers in that life", async () => {
  const k = fakeKeys();
  const s = fakeSession();
  const a = new SessionSeal({ session: s.area, keys: k.area });
  await a.ready;
  await a.set("quickUnlock", OK, { armed: 1 });
  await a.set("session", OK, { access: "tok" });
  const copy = structuredClone(s.data.get("session"));
  // A worker restart; the key store does not answer this time.
  k.failAll(true);
  const b = new SessionSeal({ session: s.area, keys: k.area });
  assert.equal(await b.ready, false);
  await erased(b.lockErase());
  await tick();
  k.failAll(false);
  await b.set("knownLogins", OK, { n: 1 }); // a later operation in this life (nothing is written: no key here)
  await tick();
  assert.equal(k.epoch(), 1, "the lock was recorded against the stored key");
  s.data.set("session", copy);
  const c = new SessionSeal({ session: s.area, keys: k.area });
  await c.ready;
  assert.equal(await c.get("session", OK), undefined, "the pre-lock copy stays closed in the next life");
});

test("R4: the erase comes first — the lock's copy and the removal are dispatched in one step; the copy opens under the epoch it was sealed in", async () => {
  const k = fakeKeys();
  const s = fakeSession();
  const a = new SessionSeal({ session: s.area, keys: k.area });
  await a.ready;
  await a.set("session", OK, { access: "tok", origin: "o" });
  await a.set("tabs", OK, { "7": { topOrigin: "https://a.example", pending: { password: "pw" } } });
  const pre = structuredClone(s.data.get("session"));
  s.log.length = 0;
  const e = a.lockErase() as unknown as { erased: Promise<void>; opened(o: string): Promise<{ session?: unknown; tabs?: unknown }> };
  assert.deepEqual(s.log, ["get session,tabs", "remove session,tabs"], "copied, then removed — before any await");
  await e.erased;
  assert.equal(s.data.has("session"), false);
  const got = await e.opened(OK);
  assert.deepEqual(got.session, { access: "tok", origin: "o" }, "the arm can still see the pair the lock erased");
  assert.ok(got.tabs, "and the tab records, for their page-known half");
  assert.deepEqual(await e.opened(OTHER), { session: undefined, tabs: undefined }, "for its own origin only");
  // A read is not the lock's copy: put back, the snapshot from before the lock does not open.
  s.data.set("session", pre);
  assert.equal(await a.get("session", OK), undefined);
});

test("R4: a cold lock (the key store has not answered) erases at once; its copy opens once the key is known, under the old epoch", async () => {
  const k = fakeKeys();
  const s = fakeSession();
  const a = new SessionSeal({ session: s.area, keys: k.area });
  await a.ready;
  await a.set("knownLogins", OK, { n: 1 });
  await a.set("session", OK, { access: "cold-tok" });
  const copy = structuredClone(s.data.get("session"));
  k.hang();
  const cold = new SessionSeal({ session: s.area, keys: k.area });
  s.log.length = 0;
  const e = cold.lockErase() as unknown as { erased: Promise<void>; opened(o: string): Promise<{ session?: unknown }> };
  assert.deepEqual(s.log.slice(-2), ["get session,tabs", "remove session,tabs"], "the erase did not wait for the key");
  const done = await Promise.race([e.erased.then(() => "erased"), tick(200).then(() => "waited")]);
  assert.equal(done, "erased");
  const opened = e.opened(OK);
  k.release();
  assert.deepEqual((await opened).session, { access: "cold-tok" }, "decided after: the pair the arm needs");
  s.data.set("session", copy);
  assert.equal(await cold.get("session", OK), undefined, "while a put-back copy stays closed");
  assert.equal(await cold.lockDurable(500), true);
});
