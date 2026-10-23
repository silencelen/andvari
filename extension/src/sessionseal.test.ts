// node --test. Security review 2026-10, branch A16: every secret-bearing storage.session record is sealed.
//
// The worker keeps unlocked custody in storage.session on both engines (the session snapshot, the tab records with a
// pending save's password, the armed quick-unlock record with its live refresh token, the known-logins digest). That a
// content script cannot reach storage.session is not relied on any more: each such record is AES-GCM sealed under a
// non-extractable key kept in the extension origin's own IndexedDB (sessionseal.ts). These tests drive the leaf against
// in-memory stand-ins for storage.session and the key store; the worker's wiring is pinned in background.pins.test.ts
// and storagefence.test.ts.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { nsKey } from "./serverurl.ts";
import {
  classifySessionKey,
  isSealedRecord,
  plainSessionArea,
  PLAIN_KINDS,
  SEAL_DB_NAME,
  SEAL_KEY_RECORD,
  SEALED_KINDS,
  SessionSeal,
  slotKey,
  type SealKind,
} from "./sessionseal.ts";
import { quickUnlockCompartment } from "./storageaccess.ts";
import { idbKv, TRUSTED_DB_NAME, TrustedStoreUnavailable, type KvArea } from "./trustedkv.ts";

const OK_A = "0123456789abcdef";
const OK_B = "fedcba9876543210";

/** storage.session stand-in: values cross it as JSON (like the real area), every call is logged in order. */
function fakeSession(initial: Record<string, unknown> = {}) {
  const data = new Map<string, unknown>(Object.entries(initial).map(([k, v]) => [k, JSON.parse(JSON.stringify(v))]));
  const log: string[] = [];
  const keyList = (k: string | readonly string[]) => (typeof k === "string" ? [k] : [...k]);
  const area: KvArea = {
    async get(keys) {
      log.push(`get ${keys === null ? "*" : keyList(keys).join(",")}`);
      const out: Record<string, unknown> = {};
      for (const k of keys === null ? [...data.keys()] : keyList(keys)) if (data.has(k)) out[k] = JSON.parse(JSON.stringify(data.get(k)));
      return out;
    },
    set(items) {
      log.push(`set ${Object.keys(items).join(",")}`);
      for (const [k, v] of Object.entries(items)) data.set(k, JSON.parse(JSON.stringify(v)));
      return Promise.resolve();
    },
    remove(keys) {
      log.push(`remove ${keyList(keys).join(",")}`);
      for (const k of keyList(keys)) data.delete(k);
      return Promise.resolve();
    },
  };
  return { area, data, log };
}

/** The key store stand-in: structured clone, like IndexedDB (a CryptoKey survives it). `mode` refuses or hangs. */
function fakeKeys(mode: "ok" | "refuse" | "hang" = "ok") {
  const data = new Map<string, unknown>();
  let release: (() => void) | null = null;
  const gate = new Promise<void>((r) => (release = r));
  const wait = async () => {
    if (mode === "refuse") throw new TrustedStoreUnavailable("IndexedDB is not available here");
    if (mode === "hang") await gate;
  };
  const area: KvArea = {
    async get(keys) {
      await wait();
      const out: Record<string, unknown> = {};
      for (const k of keys === null ? [...data.keys()] : typeof keys === "string" ? [keys] : keys) if (data.has(k)) out[k] = structuredClone(data.get(k));
      return out;
    },
    async set(items) {
      await wait();
      for (const [k, v] of Object.entries(items)) data.set(k, structuredClone(v));
    },
    async remove(keys) {
      await wait();
      for (const k of typeof keys === "string" ? [keys] : keys) data.delete(k);
    },
  };
  return {
    area,
    data,
    release: () => {
      mode = "ok";
      release?.();
    },
  };
}

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));

/** A value carrying a marker, so "nothing of it is in storage" is checkable on the raw JSON. */
const secretValue = (kind: string) => ({ kind, access: `SECRET-MARKER-${kind}`, nested: { password: `pw-${kind}`, n: 7 } });

test("every secret-bearing kind is written sealed — {v:1, iv, ct} — and nothing of the value reaches storage.session", async () => {
  const s = fakeSession();
  const k = fakeKeys();
  const seal = new SessionSeal({ session: s.area, keys: k.area });
  assert.equal(await seal.ready, true);
  for (const kind of SEALED_KINDS) {
    assert.equal(await seal.set(kind, OK_A, secretValue(kind)), true, `${kind} persisted`);
    const raw = s.data.get(slotKey(kind, OK_A));
    assert.ok(isSealedRecord(raw), `${kind} is stored as a sealed record`);
    assert.deepEqual(Object.keys(raw as object).sort(), ["ct", "iv", "v"]);
    const json = JSON.stringify(raw);
    assert.ok(!json.includes("SECRET-MARKER") && !json.includes("pw-"), `${kind}: no plaintext in storage`);
    assert.deepEqual(await seal.get(kind, OK_A), secretValue(kind), `${kind} round-trips`);
  }
  // The slots are the worker's existing keys: two global ones, two under the origin's namespace.
  assert.equal(slotKey("session", OK_A), "session");
  assert.equal(slotKey("tabs", OK_A), "tabs");
  assert.equal(slotKey("quickUnlock", OK_A), nsKey(OK_A, "quickUnlock"));
  assert.equal(slotKey("knownLogins", OK_A), nsKey(OK_A, "knownLogins"));
  // The key is a non-extractable AES-GCM 256 key in its OWN database (not andvari-qu, not andvari-trusted).
  const rec = k.data.get(SEAL_KEY_RECORD) as { key: CryptoKey; epoch: number };
  assert.equal(rec.key.extractable, false);
  assert.deepEqual(rec.key.algorithm, { name: "AES-GCM", length: 256 });
  assert.notEqual(SEAL_DB_NAME, TRUSTED_DB_NAME);
  assert.notEqual(SEAL_DB_NAME, "andvari-qu");
});

test("the storage.session inventory: four sealed kinds, three plain ones, anything else is not this build's", () => {
  assert.deepEqual([...SEALED_KINDS].sort(), ["knownLogins", "quickUnlock", "session", "tabs"]);
  assert.deepEqual([...PLAIN_KINDS].sort(), ["lockNotice", "updateChannelQuiet", "updateCheckedAt"]);
  assert.deepEqual(classifySessionKey("session"), { cls: "sealed", kind: "session" });
  assert.deepEqual(classifySessionKey("tabs"), { cls: "sealed", kind: "tabs" });
  assert.deepEqual(classifySessionKey(nsKey(OK_A, "quickUnlock")), { cls: "sealed", kind: "quickUnlock" });
  assert.deepEqual(classifySessionKey(nsKey(OK_A, "knownLogins")), { cls: "sealed", kind: "knownLogins" });
  assert.deepEqual(classifySessionKey("lockNotice"), { cls: "plain", kind: "lockNotice" });
  assert.deepEqual(classifySessionKey(nsKey(OK_A, "updateCheckedAt")), { cls: "plain", kind: "updateCheckedAt" });
  assert.deepEqual(classifySessionKey(nsKey(OK_A, "updateChannelQuiet")), { cls: "plain", kind: "updateChannelQuiet" });
  for (const other of ["quickUnlock", "knownLogins", "ns.xyz.quickUnlock", nsKey(OK_A, "updateInfo"), "unknown", ""]) {
    assert.deepEqual(classifySessionKey(other), { cls: "other" }, other);
  }
});

test("a tampered, swapped or cross-slot record reads as absent — locked — and is dropped", async () => {
  const s = fakeSession();
  const seal = new SessionSeal({ session: s.area, keys: fakeKeys().area });
  await seal.ready;
  const put = async (kind: SealKind, ok: string, v: unknown) => {
    await seal.set(kind, ok, v);
    return structuredClone(s.data.get(slotKey(kind, ok))) as { v: 1; iv: string; ct: string };
  };
  const flip = (b64: string) => (b64[0] === "A" ? "B" : "A") + b64.slice(1);

  // Tampered ciphertext / iv.
  const q = await put("quickUnlock", OK_A, secretValue("q"));
  s.data.set(slotKey("quickUnlock", OK_A), { ...q, ct: flip(q.ct) });
  assert.equal(await seal.get("quickUnlock", OK_A), undefined, "tampered ct");
  assert.equal(s.data.has(slotKey("quickUnlock", OK_A)), false, "an unreadable record is dropped");
  s.data.set(slotKey("quickUnlock", OK_A), { ...q, iv: flip(q.iv) });
  assert.equal(await seal.get("quickUnlock", OK_A), undefined, "tampered iv");
  s.data.set(slotKey("quickUnlock", OK_A), { ...q, extra: 1 });
  assert.equal(await seal.get("quickUnlock", OK_A), undefined, "not exactly {v, iv, ct}");
  s.data.set(slotKey("quickUnlock", OK_A), { ...q, v: 2 });
  assert.equal(await seal.get("quickUnlock", OK_A), undefined, "unknown version");

  // Swapped into another record slot of the same origin, or into the same slot of another origin.
  const q2 = await put("quickUnlock", OK_A, secretValue("q2"));
  s.data.set(slotKey("knownLogins", OK_A), q2);
  assert.equal(await seal.get("knownLogins", OK_A), undefined, "a quick-unlock record replayed as the known-logins digest");
  s.data.set(slotKey("quickUnlock", OK_B), q2);
  assert.equal(await seal.get("quickUnlock", OK_B), undefined, "origin A's record replayed under origin B");
  assert.deepEqual(await seal.get("quickUnlock", OK_A), secretValue("q2"), "the original still reads in its own slot");

  // The global slots bind the origin too: a snapshot sealed under A does not open under B; tabs ≠ session.
  const snap = await put("session", OK_A, secretValue("snap"));
  assert.equal(await seal.get("session", OK_B), undefined, "a snapshot sealed for origin A, read for origin B");
  s.data.set("session", snap);
  const tabs = await put("tabs", OK_A, secretValue("tabs"));
  s.data.set("session", tabs);
  assert.equal(await seal.get("session", OK_A), undefined, "the tab records replayed as the session snapshot");

  // Sealed under another key (another browser session's) → absent.
  const os = fakeSession();
  const foreign = new SessionSeal({ session: os.area, keys: fakeKeys().area });
  await foreign.ready;
  await foreign.set("knownLogins", OK_A, secretValue("kl"));
  s.data.set(slotKey("knownLogins", OK_A), os.data.get(slotKey("knownLogins", OK_A)));
  assert.equal(await seal.get("knownLogins", OK_A), undefined, "sealed under a different key");
});

test("a copy of the session snapshot or the tab records taken before a lock never unseals after it, restart included", async () => {
  const s = fakeSession();
  const k = fakeKeys();
  const seal = new SessionSeal({ session: s.area, keys: k.area });
  await seal.ready;
  await seal.set("session", OK_A, secretValue("unlocked"));
  await seal.set("tabs", OK_A, secretValue("pending"));
  await seal.set("quickUnlock", OK_A, secretValue("armed"));
  const snapCopy = structuredClone(s.data.get("session"));
  const tabsCopy = structuredClone(s.data.get("tabs"));
  await seal.lockErase();
  assert.equal(s.data.has("session"), false, "the lock removed the snapshot");
  assert.equal(s.data.has("tabs"), false, "…and the tab records");
  s.data.set("session", snapCopy);
  s.data.set("tabs", tabsCopy);
  assert.equal(await seal.get("session", OK_A), undefined, "the pre-lock snapshot, put back, is absent");
  assert.equal(await seal.get("tabs", OK_A), undefined, "the pre-lock tab records, put back, are absent");
  // Records written after the lock read normally; the quick-unlock record is not lock-scoped (it survives a lock).
  await seal.set("tabs", OK_A, { kept: "page-known" });
  assert.deepEqual(await seal.get("tabs", OK_A), { kept: "page-known" });
  assert.deepEqual(await seal.get("quickUnlock", OK_A), secretValue("armed"));
  // A worker restart in the same browser session: the advanced epoch was kept with the key.
  await tick(5);
  s.data.set("session", snapCopy);
  const again = new SessionSeal({ session: s.area, keys: k.area });
  assert.equal(await again.ready, true);
  assert.equal(await again.get("session", OK_A), undefined, "still absent after a restart");
  assert.deepEqual(await again.get("tabs", OK_A), { kept: "page-known" }, "the post-lock records survive the restart");
  assert.deepEqual(await again.get("quickUnlock", OK_A), secretValue("armed"));
});

test("a plaintext record already in storage.session at start is dropped, never unsealed into trust", async () => {
  const plainSnap = { origin: "https://vault.example", access: "tok", refresh: "rt", vaultKeys: { v: "a2V5" }, items: [] };
  const s = fakeSession({
    session: plainSnap,
    tabs: { "7": { pending: { password: "hunter2" } } },
    [nsKey(OK_A, "quickUnlock")]: { v: 1, userId: "u", blob: { ct: "x" }, lockedTokens: { access: "a", refresh: "r" } },
    [nsKey(OK_A, "knownLogins")]: { key: "aGVsbG8", digests: [] },
    quickUnlock: { v: 1, userId: "u" }, // the pre-namespacing bare key
    somethingElse: 1,
    lockNotice: { kind: "idle", seconds: 900 },
    [nsKey(OK_A, "updateCheckedAt")]: 1234,
  });
  const seal = new SessionSeal({ session: s.area, keys: fakeKeys().area });
  assert.equal(await seal.ready, true);
  for (const k of ["session", "tabs", nsKey(OK_A, "quickUnlock"), nsKey(OK_A, "knownLogins"), "quickUnlock", "somethingElse"]) {
    assert.equal(s.data.has(k), false, `${k} dropped at start`);
  }
  assert.deepEqual(s.data.get("lockNotice"), { kind: "idle", seconds: 900 }, "plain inventory keys stay");
  assert.equal(s.data.get(nsKey(OK_A, "updateCheckedAt")), 1234);
  for (const kind of SEALED_KINDS) assert.equal(await seal.get(kind, OK_A), undefined, `${kind} absent`);
  // …and a plaintext value written into a sealed slot later (by anyone) is absent and dropped too.
  s.data.set("session", plainSnap);
  assert.equal(await seal.get("session", OK_A), undefined);
  assert.equal(s.data.has("session"), false);
});

test("the key belongs to the browser session: fresh when storage.session holds no sealed record, kept while one exists", async () => {
  const k = fakeKeys();
  // The previous browser session sealed a record, then advanced the epoch with a lock.
  const prev = fakeSession();
  const before = new SessionSeal({ session: prev.area, keys: k.area });
  await before.ready;
  await before.set("quickUnlock", OK_A, secretValue("last session"));
  const lastSessionRecord = structuredClone(prev.data.get(nsKey(OK_A, "quickUnlock")));
  await before.lockErase();
  await tick(5);
  assert.equal((k.data.get(SEAL_KEY_RECORD) as { epoch: number }).epoch, 1);
  // A browser restart (or a reload, or an update): storage.session is empty → a fresh key replaces the old one.
  const s = fakeSession();
  const first = new SessionSeal({ session: s.area, keys: k.area });
  assert.equal(await first.ready, true);
  assert.equal((k.data.get(SEAL_KEY_RECORD) as { epoch: number }).epoch, 0, "a new key starts a new epoch");
  s.data.set(nsKey(OK_A, "quickUnlock"), lastSessionRecord);
  assert.equal(await first.get("quickUnlock", OK_A), undefined, "the old key is gone: last session's record never opens");
  await first.set("quickUnlock", OK_A, secretValue("armed"));
  // A worker restart within the session: a sealed record exists → the same key is kept and the record opens.
  const second = new SessionSeal({ session: s.area, keys: k.area });
  assert.equal(await second.ready, true);
  assert.deepEqual(await second.get("quickUnlock", OK_A), secretValue("armed"));
  // Sealed records but the key is gone (site data cleared): they can never open — dropped, and a fresh key is made.
  k.data.clear();
  const third = new SessionSeal({ session: s.area, keys: k.area });
  assert.equal(await third.ready, true);
  assert.equal(s.data.has(nsKey(OK_A, "quickUnlock")), false, "unopenable records dropped");
  assert.ok(k.data.has(SEAL_KEY_RECORD), "a fresh key");
  // A key record that is not a non-extractable AES-GCM key is not used.
  await third.set("knownLogins", OK_A, { a: 1 });
  const weak = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  k.data.set(SEAL_KEY_RECORD, { key: weak, epoch: 0 });
  const fourth = new SessionSeal({ session: s.area, keys: k.area });
  assert.equal(await fourth.ready, true);
  assert.equal(await fourth.get("knownLogins", OK_A), undefined);
  assert.equal((k.data.get(SEAL_KEY_RECORD) as { key: CryptoKey }).key.extractable, false, "replaced by a non-extractable key");
});

test("no key store (no IndexedDB, refused, or no answer in time): nothing secret persists and quick unlock does not arm", async () => {
  const cases: [string, KvArea][] = [
    ["refused", fakeKeys("refuse").area],
    ["no IndexedDB", idbKv(() => undefined, SEAL_DB_NAME, { timeoutMs: 50 })],
    ["an open that never answers", idbKv(() => ({ open: () => ({}) as IDBOpenDBRequest }), SEAL_DB_NAME, { timeoutMs: 50 })],
  ];
  for (const [name, keys] of cases) {
    const s = fakeSession({ session: { stale: true } });
    const seal = new SessionSeal({ session: s.area, keys });
    const t0 = Date.now();
    assert.equal(await seal.ready, false, name);
    assert.ok(Date.now() - t0 < 2000, `${name}: settles within the store's bound`);
    assert.equal(seal.available(), false);
    for (const kind of SEALED_KINDS) {
      assert.equal(await seal.set(kind, OK_A, secretValue(kind)), false, `${name}: ${kind} not persisted`);
      assert.equal(s.data.has(slotKey(kind, OK_A)), false, `${name}: no ${kind} record at all`);
      assert.equal(await seal.get(kind, OK_A), undefined);
    }
    assert.ok(!JSON.stringify([...s.data.values()]).includes("SECRET-MARKER"), `${name}: nothing secret in storage.session`);
    // The quick-unlock compartment needs the key, whatever the access-level call said.
    assert.equal(quickUnlockCompartment({ sessionTrusted: true }, seal.available()), false, name);
  }
  assert.equal(quickUnlockCompartment({ sessionTrusted: true }, true), true, "key + the access level (or Firefox's absent API)");
  assert.equal(quickUnlockCompartment({ sessionTrusted: false }, true), false, "Chrome: a setAccessLevel that failed still blocks (the belt)");
  assert.equal(quickUnlockCompartment({ sessionTrusted: true }, null), false, "not settled yet");
});

test("the lock's erase never waits on IndexedDB: removed at once, and a write still waiting for the key never lands after it", async () => {
  const s = fakeSession({ session: { anything: 1 }, tabs: { anything: 2 } });
  const k = fakeKeys("hang");
  const seal = new SessionSeal({ session: s.area, keys: k.area });
  const pending = seal.set("session", OK_A, secretValue("written before the lock"));
  s.log.length = 0;
  const erased = seal.lockErase();
  assert.deepEqual(s.log, ["remove session,tabs"], "dispatched synchronously, before any await");
  const done = await Promise.race([erased.then(() => "erased"), tick(200).then(() => "waited")]);
  assert.equal(done, "erased", "the erase resolves while the key store still has not answered");
  assert.equal(s.data.has("session"), false);
  assert.equal(await Promise.race([seal.peek("tabs", OK_A), tick(200).then(() => "waited")]), undefined, "peek never waits for the key");
  // The key store answers late: the write issued before the lock is dropped, never resurrected.
  k.release();
  assert.equal(await seal.ready, true);
  assert.equal(await pending, false);
  assert.equal(s.data.has("session"), false, "no snapshot after the lock");
});

test("a write mid-encryption when the lock erases is dropped; writes land in call order; a later remove wins", async () => {
  const s = fakeSession();
  const seal = new SessionSeal({ session: s.area, keys: fakeKeys().area });
  await seal.ready;
  const w = seal.set("session", OK_A, secretValue("racing"));
  void seal.lockErase();
  assert.equal(await w, false);
  assert.equal(s.data.has("session"), false);

  const a = seal.set("quickUnlock", OK_A, { n: 1 });
  const b = seal.set("quickUnlock", OK_A, { n: 2 });
  assert.deepEqual([await a, await b], [true, true]);
  assert.deepEqual(await seal.get("quickUnlock", OK_A), { n: 2 }, "the last write wins");

  const c = seal.set("knownLogins", OK_A, { n: 3 });
  const r = seal.remove("knownLogins", OK_A);
  await Promise.all([c, r]);
  assert.equal(await seal.get("knownLogins", OK_A), undefined, "a remove after a write wins");
  await seal.set("knownLogins", OK_A, { n: 4 });
  assert.deepEqual(await seal.get("knownLogins", OK_A), { n: 4 }, "…and a write after a remove lands");

  // The value is captured when set() is called (as chrome.storage does): a later mutation is not written.
  const live = { n: 5 };
  const p = seal.set("tabs", OK_A, live);
  live.n = 6;
  await p;
  assert.deepEqual(await seal.get("tabs", OK_A), { n: 5 });
});

test("the plain area takes only the plain inventory: a sealed slot cannot be written, read or removed through it", async () => {
  const s = fakeSession();
  const plain = plainSessionArea(s.area);
  await plain.set({ lockNotice: { kind: "idle", seconds: 60 }, [nsKey(OK_A, "updateCheckedAt")]: 1, [nsKey(OK_A, "updateChannelQuiet")]: { reason: "stale" } });
  assert.deepEqual(await plain.get("lockNotice"), { lockNotice: { kind: "idle", seconds: 60 } });
  await plain.remove(nsKey(OK_A, "updateChannelQuiet"));
  for (const k of ["session", "tabs", nsKey(OK_A, "quickUnlock"), nsKey(OK_A, "knownLogins"), "quickUnlock", "other"]) {
    assert.throws(() => plain.set({ [k]: { x: 1 } }), /not in the plain session inventory/, `set ${k}`);
    assert.throws(() => plain.get(k), /not in the plain session inventory/, `get ${k}`);
    assert.throws(() => plain.remove(k), /not in the plain session inventory/, `remove ${k}`);
  }
  assert.throws(() => plain.get(null), /not in the plain session inventory/, "no bulk read through the plain area");
  assert.equal(s.data.has("session"), false);
});

test("the purge area lists storage.session and removes through the seal", async () => {
  const s = fakeSession();
  const seal = new SessionSeal({ session: s.area, keys: fakeKeys().area });
  await seal.ready;
  await seal.set("quickUnlock", OK_A, { a: 1 });
  await seal.set("quickUnlock", OK_B, { b: 1 });
  const purge = seal.purgeArea();
  assert.deepEqual(Object.keys(await purge.get(null)).sort(), [nsKey(OK_A, "quickUnlock"), nsKey(OK_B, "quickUnlock")].sort());
  await purge.remove([nsKey(OK_A, "quickUnlock")]);
  assert.equal(await seal.get("quickUnlock", OK_A), undefined);
  assert.deepEqual(await seal.get("quickUnlock", OK_B), { b: 1 }, "another origin's record stays");
  assert.throws(() => purge.set({ x: 1 }), /removes only/);
});
