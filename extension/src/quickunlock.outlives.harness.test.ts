// node --test. Quick unlock read line by line for work that outlives the session it began under
// (the class that found the critical fault in the shared Kotlin code). The real background.ts, driven through
// testing/bgharness.ts.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { Chain, connect, signedInWorld, type World } from "./testing/bgharness.ts";

const PIN = "Tq7#kw2pZ";
const tick = (ms = 5) => new Promise((r) => setTimeout(r, ms));

/** Holds the next KDF run (the PIN bench, a PIN derivation or a password derivation) until `release()`. */
function holdKdf(world: World) {
  let open: (() => void) | null = null;
  let hit = false;
  world.kdfHook = async () => {
    if (hit) return;
    hit = true;
    await new Promise<void>((r) => (open = r));
  };
  return {
    get hit() {
      return hit;
    },
    release() {
      world.kdfHook = null;
      open?.();
    },
  };
}

/** Every storage.session key that holds a quick-unlock record, and every co-key in IndexedDB. */
function quickUnlockResidue(world: World): string[] {
  const keys = [...world.session.keys()].filter((k) => k.includes("quickUnlock"));
  const coKeys = [...(world.idb.get("andvari-qu")?.get("cokey")?.keys() ?? [])].map((k) => `idb:${k}`);
  return [...keys, ...coKeys];
}

/** Holds the next read of a quick-unlock record in storage.session until `release()`: the read has taken the record as
 *  it stood, and hands it over only then (a wipe can land in between, as it can in a real worker). */
function holdNextRecordRead() {
  const area = (globalThis as unknown as { chrome: { storage: { session: { get: (keys: unknown) => Promise<Record<string, unknown>> } } } }).chrome.storage.session;
  const real = area.get;
  let hit = false;
  let open: () => void = () => {};
  const opened = new Promise<void>((r) => (open = r));
  area.get = async (keys: unknown) => {
    const names = typeof keys === "string" ? [keys] : Array.isArray(keys) ? (keys as string[]) : [];
    if (hit || !names.some((k) => k.endsWith(".quickUnlock"))) return real(keys);
    hit = true;
    const v = await real(keys);
    await opened;
    return v;
  };
  return {
    get hit() {
      return hit;
    },
    release() {
      area.get = real;
      open();
    },
  };
}

const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
type Srv = { override: unknown; handle: (m: string, p: string, b: unknown, h: unknown) => Promise<Response> };

/**
 * The fake server answers the refresh (it has no route of its own for it) with the account's usual pair, and holds every
 * request [hold] names until its gate is released, then answers it as usual. Gates are keyed by name.
 */
function redeemServer(server: Srv, hold: (method: string, path: string, auth: string | undefined) => string | null) {
  const gates = new Map<string, { hit: boolean; open: () => void; opened: Promise<void> }>();
  const gate = (name: string) => {
    let g = gates.get(name);
    if (!g) {
      let open!: () => void;
      const opened = new Promise<void>((r) => (open = r));
      g = { hit: false, open, opened };
      gates.set(name, g);
    }
    return g;
  };
  server.override = (method: string, path: string, body: unknown, headers: Record<string, string> | undefined) => {
    const name = hold(method, path, headers?.authorization);
    const held = name !== null && !gate(name).hit;
    if (method === "POST" && path === "/api/v1/auth/refresh") {
      const uid = String((body as { refreshToken: string }).refreshToken).replace(/^rt-/, "");
      const answer = () => json({ accessToken: `at-${uid}`, refreshToken: `rt-${uid}` });
      if (!held) return answer();
      gate(name).hit = true;
      return gate(name).opened.then(answer);
    }
    if (!held) return null;
    const g = gate(name);
    g.hit = true;
    return g.opened.then(() => {
      const o = server.override;
      server.override = null; // answered as usual (handle reads the override once, synchronously)
      const r = server.handle(method, path, body, headers);
      server.override = o;
      return r;
    });
  };
  return {
    async reached(name: string) {
      for (let i = 0; i < 400 && !gate(name).hit; i++) await tick();
      assert.ok(gate(name).hit, `${name} is on the wire`);
    },
    release: (name: string) => gate(name).open(),
  };
}

/** The bearer the worker's last sync carried. */
function lastSyncBearer(world: World): string | undefined {
  const syncs = world.log.filter((l: { method: string; path: string }) => l.method === "GET" && l.path.startsWith("/api/v1/sync"));
  return (syncs.at(-1) as { headers?: Record<string, string> } | undefined)?.headers?.authorization;
}

test("a PIN unlock that proves its PIN after a password sign-in began supersedes it: one session, on its own account's tokens", async () => {
  const { world, server, acct: alice, w } = await signedInWorld();
  const bob = server.addAccount({ email: "bob@example.com", password: "bob horse" });
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  await w.popup({ type: "lock" });
  assert.equal((await w.popup({ type: "status" })).quickUnlock.armed, true);
  const srv = redeemServer(server, (m, p, auth) =>
    m === "POST" && p === "/api/v1/auth/login" ? "bob-login" : m === "GET" && p.startsWith("/api/v1/sync") && auth === `Bearer at-${alice.userId}` ? "alice-sync" : null,
  );
  // On the master-password form, another account's sign-in starts (its login is slow to answer)…
  const bobUnlock = w.popup({ type: "unlock", email: bob.email, password: bob.password });
  await srv.reached("bob-login");
  // …and meanwhile the PIN is entered in another window; its sync is slow too.
  const aliceRedeem = w.popup({ type: "unlockWithPin", pin: PIN });
  await srv.reached("alice-sync");
  srv.release("bob-login");
  await bobUnlock;
  srv.release("alice-sync");
  assert.equal((await aliceRedeem).ok, true, "the PIN unlock completes");
  const st = await w.popup({ type: "status" });
  assert.deepEqual([st.unlocked, st.email], [true, alice.email]);
  await w.alarm("resync");
  assert.equal(lastSyncBearer(world), `Bearer at-${alice.userId}`, "the open session syncs on its own account's token, not the other sign-in's");
});

test("a PIN unlock given up while a password sign-in is in its sync leaves that sign-in its tokens", async () => {
  const { world, server, w } = await signedInWorld();
  const alice = server.accounts[0] as { userId: string };
  const bob = server.addAccount({ email: "bob@example.com", password: "bob horse" });
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  await w.popup({ type: "lock" });
  const srv = redeemServer(server, (m, p, auth) =>
    m === "GET" && p.startsWith("/api/v1/sync") ? (auth === `Bearer at-${alice.userId}` ? "alice-sync" : auth === `Bearer at-${bob.userId}` ? "bob-sync" : null) : null,
  );
  const aliceRedeem = w.popup({ type: "unlockWithPin", pin: PIN });
  await srv.reached("alice-sync");
  // The person gives up on the PIN and signs in with the master password (here as another account).
  const bobUnlock = w.popup({ type: "unlock", email: bob.email, password: bob.password });
  await srv.reached("bob-sync");
  srv.release("alice-sync");
  assert.deepEqual(await aliceRedeem, { ok: false, code: "aborted" }, "the PIN unlock gives way");
  srv.release("bob-sync");
  assert.equal((await bobUnlock).ok, true);
  const st = await w.popup({ type: "status" });
  assert.deepEqual([st.unlocked, st.email], [true, bob.email]);
  await w.alarm("resync");
  assert.equal(lastSyncBearer(world), `Bearer at-${bob.userId}`, "the sign-in's session kept its tokens");
});

test("a password sign-in from the locked-armed screen keeps no stashed token pair while unlocked", async () => {
  const { server, w, acct } = await signedInWorld();
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  await w.popup({ type: "lock" });
  assert.equal((await w.popup({ type: "status" })).quickUnlock.armed, true, "locked-armed: the stash holds the session's pair");
  // The person types the master password instead of the PIN: a new server session.
  assert.equal((await w.popup({ type: "unlock", email: acct.email, password: acct.password })).ok, true);
  const st = await w.popup({ type: "status" });
  assert.equal(st.unlocked, true);
  assert.equal(st.quickUnlock.enrolled, true, "the enrolment itself stays");
  assert.equal(st.quickUnlock.armed, false, "the previous session's pair is not kept in the record while unlocked");
  // The next lock stashes the pair in use then, and the PIN works.
  await w.popup({ type: "lock" });
  assert.equal((await w.popup({ type: "status" })).quickUnlock.armed, true);
  redeemServer(server, () => null);
  assert.equal((await w.popup({ type: "unlockWithPin", pin: PIN })).ok, true);
});

test("a PIN unlock whose refresh is answered after another account signed in leaves that sign-in its own tokens", async () => {
  const { world, server, acct: alice, w } = await signedInWorld();
  const bob = server.addAccount({ email: "bob@example.com", password: "bob horse" });
  bob.addItem(bob.personalVaultId, { type: "login", name: "bob's shop", login: { username: "bob", password: "bob-pw", uris: ["https://shop.example"] } });
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  await w.popup({ type: "lock" });
  const srv = redeemServer(server, (m, p) => (m === "POST" && p === "/api/v1/auth/refresh" ? "alice-refresh" : null));
  const aliceRedeem = w.popup({ type: "unlockWithPin", pin: PIN });
  await srv.reached("alice-refresh");
  // The PIN unlock is slow; the person gives up and signs in with a master password (here another account's).
  assert.equal((await w.popup({ type: "unlock", email: bob.email, password: bob.password })).ok, true);
  const before = await w.popup({ type: "status" });
  assert.deepEqual([before.unlocked, before.email, before.count], [true, bob.email, 1]);
  srv.release("alice-refresh");
  assert.deepEqual(await aliceRedeem, { ok: false, code: "aborted" }, "the PIN unlock gives way");
  await w.alarm("resync");
  const after = await w.popup({ type: "status" });
  assert.deepEqual([after.unlocked, after.email], [true, bob.email]);
  assert.equal(lastSyncBearer(world), `Bearer at-${bob.userId}`, `the sign-in's session syncs on its own token, not on ${alice.email}'s (list after: ${after.count})`);
});

test("a password sign-in in its sync, superseded by a PIN unlock that proved its PIN, leaves the PIN unlock its tokens", async () => {
  const { world, server, acct: alice, w } = await signedInWorld();
  const bob = server.addAccount({ email: "bob@example.com", password: "bob horse" });
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  await w.popup({ type: "lock" });
  const srv = redeemServer(server, (m, p, auth) =>
    m === "GET" && p.startsWith("/api/v1/sync") && auth === `Bearer at-${bob.userId}`
      ? "bob-sync"
      : m === "GET" && p === "/api/v1/account/keys" && auth === `Bearer at-${alice.userId}`
        ? "alice-keys"
        : null,
  );
  // A sign-in is in its sync...
  const bobUnlock = w.popup({ type: "unlock", email: bob.email, password: bob.password });
  await srv.reached("bob-sync");
  // ...when the PIN is entered in another window and proves itself; its account-keys read is slow.
  const aliceRedeem = w.popup({ type: "unlockWithPin", pin: PIN });
  await srv.reached("alice-keys");
  srv.release("bob-sync");
  const bobResult = await bobUnlock;
  srv.release("alice-keys");
  const aliceResult = await aliceRedeem;
  assert.deepEqual(bobResult, { ok: false, code: "aborted" }, "the earlier sign-in gives way to the later PIN unlock");
  assert.equal(aliceResult.ok, true, `the PIN unlock completes, got ${JSON.stringify(aliceResult)}`);
  const st = await w.popup({ type: "status" });
  assert.deepEqual([st.unlocked, st.email], [true, alice.email]);
  await w.alarm("resync");
  assert.equal(lastSyncBearer(world), `Bearer at-${alice.userId}`, "the PIN unlock's session kept its tokens");
});

test("a quick-unlock record switched off while a lock is arming it is not written back", async () => {
  const { world, w } = await signedInWorld();
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  const read = holdNextRecordRead();
  const locking = w.popup({ type: "lock" });
  for (let i = 0; i < 400 && !read.hit; i++) await tick();
  assert.ok(read.hit, "the lock's arm has read the record");
  // Quick unlock is switched off in another window while the arm holds the record it read.
  assert.deepEqual(await w.popup({ type: "disableQuickUnlock" }), { ok: true });
  read.release();
  await locking;
  for (let i = 0; i < 20; i++) await tick();
  assert.deepEqual(quickUnlockResidue(world), [], "no record is put back, and no co-key is left");
  const st = await w.popup({ type: "status" });
  assert.deepEqual([st.unlocked, st.quickUnlock.enrolled, st.quickUnlock.armed], [false, false, false]);
});

/**
 * A refresh that rotates like a real server's: each refresh token works once (a spent one is refused with 401) and the
 * answer is a new pair. `hold()` makes the next refresh wait, after it is on the wire, until `release()`.
 */
function rotatingRefresh(server: Srv & { origin: string }) {
  const spent = new Set<string>();
  let n = 0;
  let gate: { hit: boolean; opened: Promise<void>; open: () => void } | null = null;
  server.override = (method: string, path: string, body: unknown) => {
    if (method !== "POST" || path !== "/api/v1/auth/refresh") return null;
    const rt = String((body as { refreshToken: string }).refreshToken);
    const answer = () => {
      if (spent.has(rt) || !rt.startsWith("rt-")) return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: { "content-type": "application/json" } });
      spent.add(rt);
      const uid = rt.slice(3).replace(/~\d+$/, "");
      return json({ accessToken: `at-${uid}`, refreshToken: `rt-${uid}~${++n}` });
    };
    const g = gate;
    if (g === null || g.hit) return Promise.resolve(answer());
    g.hit = true;
    return g.opened.then(answer);
  };
  return {
    hold() {
      let open: () => void = () => {};
      const opened = new Promise<void>((r) => (open = r));
      gate = { hit: false, opened, open };
    },
    async reached() {
      for (let i = 0; i < 400 && !gate?.hit; i++) await tick();
      assert.ok(gate?.hit, `a refresh is on the wire at ${server.origin}`);
    },
    release: () => gate?.open(),
  };
}

/** Switch to [origin]: through the Trust Gate the first time, at once to a server already pinned. */
async function switchTo(w: Awaited<ReturnType<World["start"]>>, origin: string) {
  const r = await w.popup({ type: "chooseServer", choice: "own", origin });
  if (r?.gate) await connect(w, origin);
  else assert.equal(r?.ok, true, `switched to ${origin}`);
}

test("a server switch while a PIN unlock's refresh is on the wire leaves both servers' quick unlock working", async () => {
  const { world, server: a, acct: alice, w } = await signedInWorld();
  const A = a.origin;
  const B = "https://other.example";
  const b = world.serve(B, new Chain({ origin: B }));
  const bob = b.addAccount({ email: "bob@example.com", password: "bob horse" });
  const refreshA = rotatingRefresh(a);
  rotatingRefresh(b);
  // Quick unlock armed at both servers: A's record stays standing under A while B is used (§4.2, B2-7).
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  await w.popup({ type: "lock" });
  await switchTo(w, B);
  assert.equal((await w.popup({ type: "unlock", email: bob.email, password: bob.password })).ok, true);
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  await w.popup({ type: "lock" });
  await switchTo(w, A);
  assert.equal((await w.popup({ type: "status" })).quickUnlock.armed, true, "A is armed");
  // A PIN unlock at A; its refresh is slow to answer, and the person connects to B meanwhile.
  refreshA.hold();
  const redeem = w.popup({ type: "unlockWithPin", pin: PIN });
  await refreshA.reached();
  await switchTo(w, B);
  refreshA.release();
  assert.deepEqual(await redeem, { ok: false, code: "aborted" }, "the unlock at A gives way to the switch");
  const atB = await w.popup({ type: "status" });
  assert.deepEqual([atB.unlocked, atB.quickUnlock.armed], [false, true], "B's quick unlock is still armed");
  assert.equal((await w.popup({ type: "unlockWithPin", pin: PIN })).ok, true, "and opens B's vault");
  assert.equal((await w.popup({ type: "status" })).email, bob.email);
  // Back at A, the record holds the pair A's server answered with, not the one its refresh spent.
  await switchTo(w, A);
  assert.equal((await w.popup({ type: "status" })).quickUnlock.armed, true);
  assert.equal((await w.popup({ type: "unlockWithPin", pin: PIN })).ok, true, "A's quick unlock still works");
  assert.equal((await w.popup({ type: "status" })).email, alice.email);
});

/** Makes the next write of a quick-unlock record to storage.session fail (as a full or failing storage would). */
function failNextRecordWrite() {
  return failNextWriteOf((k) => k.endsWith(".quickUnlock"));
}

/** Makes the next write to storage.session of a key [which] accepts fail (as a full or failing storage would). */
function failNextWriteOf(which: (key: string) => boolean) {
  const area = (globalThis as unknown as { chrome: { storage: { session: { set: (items: Record<string, unknown>) => Promise<void> } } } }).chrome.storage.session;
  const real = area.set;
  let failed = false;
  area.set = async (items: Record<string, unknown>) => {
    if (failed || !Object.keys(items).some(which)) return real(items);
    failed = true;
    area.set = real;
    throw new Error("storage.session: quota exceeded");
  };
  return {
    get failed() {
      return failed;
    },
  };
}

test("a quick-unlock record that cannot be updated after the vault opened is said as that, and kept", async () => {
  const { world, server, acct, w } = await signedInWorld();
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  await w.popup({ type: "lock" });
  const srv = redeemServer(server, (m, p) => (m === "GET" && p.startsWith("/api/v1/sync") ? "sync" : null));
  const redeem = w.popup({ type: "unlockWithPin", pin: PIN });
  await srv.reached("sync");
  const write = failNextRecordWrite(); // the record's last write, after the vault is open, fails
  srv.release("sync");
  const r = await redeem;
  assert.ok(write.failed, "the record's write failed");
  assert.deepEqual(r, { ok: true, notice: "quick_unlock_not_updated" }, "the vault is open, and the popup is told the record was not updated");
  const st = await w.popup({ type: "status" });
  assert.deepEqual([st.unlocked, st.email], [true, acct.email]);
  assert.equal(quickUnlockResidue(world).length, 2, "the record and its co-key are not wiped while the vault is open");
  await w.popup({ type: "lock" });
  assert.equal((await w.popup({ type: "status" })).quickUnlock.armed, true, "the next lock arms it again");
});

test("a session snapshot that cannot be written after a PIN unlock opened the vault leaves it open and working", async () => {
  const { world, server, acct, w } = await signedInWorld({ setup: ({ server }) => void ((server as unknown as { ticketsOn: boolean }).ticketsOn = true) });
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  await w.popup({ type: "lock" });
  const socketsBefore = world.sockets.length;
  const srv = redeemServer(server, (m, p) => (m === "GET" && p.startsWith("/api/v1/sync") ? "sync" : null));
  const redeem = w.popup({ type: "unlockWithPin", pin: PIN });
  await srv.reached("sync");
  const write = failNextWriteOf((k) => k === "session"); // the snapshot's write, the first after the vault opens, fails
  srv.release("sync");
  const r = await redeem;
  assert.ok(write.failed, "the snapshot's write failed");
  assert.deepEqual(r, { ok: true, notice: "quick_unlock_not_updated" }, "the vault is open, and the popup is told quick unlock was not updated");
  const st = await w.popup({ type: "status" });
  assert.deepEqual([st.unlocked, st.email], [true, acct.email]);
  assert.equal(quickUnlockResidue(world).length, 2, "the record and its co-key are not wiped while the vault is open");
  for (let i = 0; i < 20; i++) await tick();
  assert.ok(world.sockets.length > socketsBefore, "the live updates are started");
  await w.popup({ type: "lock" });
  assert.equal((await w.popup({ type: "status" })).quickUnlock.armed, true, "the next lock arms it again");
  assert.equal((await w.popup({ type: "unlockWithPin", pin: PIN })).ok, true, "and the PIN opens the vault again");
});

test("a session snapshot that cannot be written after a password sign-in opened the vault leaves it open and says so", async () => {
  const { world, acct, w } = await signedInWorld({ signIn: false, setup: ({ server }) => void ((server as unknown as { ticketsOn: boolean }).ticketsOn = true) });
  const write = failNextWriteOf((k) => k === "session");
  const r = await w.popup({ type: "unlock", email: acct.email, password: acct.password });
  assert.ok(write.failed, "the snapshot's write failed");
  assert.deepEqual(r, { ok: true, notice: "session_not_saved" }, "the vault is open, and the popup is told the session was not saved");
  const st = await w.popup({ type: "status" });
  assert.deepEqual([st.unlocked, st.email], [true, acct.email]);
  for (let i = 0; i < 20; i++) await tick();
  assert.ok(world.sockets.length > 0, "the live updates are started");
});

test("a quick-unlock record a password sign-in cannot re-stamp is said, and the vault opens", async () => {
  const { server, acct, w } = await signedInWorld();
  rotatingRefresh(server);
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  await w.popup({ type: "lock" });
  const write = failNextRecordWrite(); // the sign-in's re-stamp of the record
  const r = await w.popup({ type: "unlock", email: acct.email, password: acct.password });
  assert.ok(write.failed, "the record's write failed");
  assert.deepEqual(r, { ok: true, notice: "quick_unlock_not_updated" });
  assert.equal((await w.popup({ type: "status" })).unlocked, true);
  await w.popup({ type: "lock" });
  assert.deepEqual(await w.popup({ type: "unlockWithPin", pin: PIN }), { ok: true }, "the next lock arms it, and the PIN opens the vault");
});

test("a lock that lands after a PIN unlock installed its session, before the record is updated, keeps the record armed", async () => {
  const { server, w } = await signedInWorld();
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  await w.popup({ type: "lock" });
  const srv = redeemServer(server, (m, p) => (m === "GET" && p.startsWith("/api/v1/sync") ? "sync" : null));
  const redeem = w.popup({ type: "unlockWithPin", pin: PIN });
  await srv.reached("sync");
  const read = holdNextRecordRead(); // the redeem's last read of the record, after the session is installed
  srv.release("sync");
  for (let i = 0; i < 400 && !read.hit; i++) await tick();
  assert.ok(read.hit, "the redeem has read the record to update it");
  await w.popup({ type: "lock" }); // the vault is locked meanwhile; the lock arms the record with the live pair
  read.release();
  assert.deepEqual(await redeem, { ok: false, code: "aborted" }, "the unlock says the vault is no longer open");
  const st = await w.popup({ type: "status" });
  assert.deepEqual([st.unlocked, st.quickUnlock.armed], [false, true], "the lock's arm stands");
  assert.equal((await w.popup({ type: "unlockWithPin", pin: PIN })).ok, true);
});

test("a lock that lands while a password sign-in fetches the policy keeps the quick-unlock record armed", async () => {
  const { server, acct, w } = await signedInWorld();
  rotatingRefresh(server);
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  await w.popup({ type: "lock" });
  const o = server.override as (m: string, p: string, b: unknown, h: unknown) => unknown;
  let hit = false;
  let open: () => void = () => {};
  const opened = new Promise<void>((r) => (open = r));
  server.override = (m: string, p: string, b: unknown, h: unknown) => {
    if (m === "GET" && p === "/api/v1/client-policy" && !hit) {
      hit = true;
      return opened.then(() => json({ serverTime: Date.now(), autoLockSeconds: 900, clipboardClearSeconds: 30 }));
    }
    return o(m, p, b, h);
  };
  const signingIn = w.popup({ type: "unlock", email: acct.email, password: acct.password });
  for (let i = 0; i < 400 && !hit; i++) await tick();
  assert.ok(hit, "the sign-in, its session installed, is fetching the policy");
  await w.popup({ type: "lock" });
  open();
  assert.deepEqual(await signingIn, { ok: false, code: "aborted" }, "the sign-in says the vault is no longer open");
  const st = await w.popup({ type: "status" });
  assert.deepEqual([st.unlocked, st.quickUnlock.armed], [false, true], "the lock's arm stands");
  assert.equal((await w.popup({ type: "unlockWithPin", pin: PIN })).ok, true);
});

for (const [label, trigger] of [
  ["the next sync", "resync"],
  ["the next token change", "rotation"],
] as const) {
  test(`the live pair left in a record whose last write failed is cleared at ${label}`, async () => {
    const { server, acct, w } = await signedInWorld();
    assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
    await w.popup({ type: "lock" });
    const srv = redeemServer(server, (m, p) => (m === "GET" && p.startsWith("/api/v1/sync") ? "sync" : null));
    const redeem = w.popup({ type: "unlockWithPin", pin: PIN });
    await srv.reached("sync");
    failNextRecordWrite(); // the redeem's record update fails: the record keeps the pair it stashed for the redeem
    srv.release("sync");
    assert.deepEqual(await redeem, { ok: true, notice: "quick_unlock_not_updated" });
    assert.equal((await w.popup({ type: "status" })).quickUnlock.armed, true, "the record still holds the live pair");
    const rot = rotatingRefresh(server as unknown as Srv & { origin: string });
    void rot;
    if (trigger === "rotation") {
      // The next sync is refused once, so the session's pair is refreshed, and then fails (so the sync itself clears
      // nothing: only the token change can).
      const o = server.override as (m: string, p: string, b: unknown, h: unknown) => unknown;
      let syncs = 0;
      server.override = (m: string, p: string, b: unknown, h: unknown) => {
        if (m === "GET" && p.startsWith("/api/v1/sync") && syncs < 2) {
          syncs++;
          return new Response(JSON.stringify({ error: syncs === 1 ? "unauthorized" : "unavailable" }), { status: syncs === 1 ? 401 : 503, headers: { "content-type": "application/json" } });
        }
        return o(m, p, b, h);
      };
    }
    await w.alarm("resync");
    for (let i = 0; i < 20; i++) await tick();
    const st = await w.popup({ type: "status" });
    assert.deepEqual([st.unlocked, st.email, st.quickUnlock.enrolled, st.quickUnlock.armed], [true, acct.email, true, false], "no pair is left in the record while the vault is open");
    await w.popup({ type: "lock" });
    assert.deepEqual(await w.popup({ type: "unlockWithPin", pin: PIN }), { ok: true }, "the next lock arms it with the pair in use");
  });
}

test("a server switch while an unlocked session's refresh is on the wire arms the old server's record with the pair the refresh answered", async () => {
  const { world, server: a, acct: alice, w } = await signedInWorld();
  const B = "https://other.example";
  world.serve(B, new Chain({ origin: B }));
  const refreshA = rotatingRefresh(a);
  await switchTo(w, B); // B is pinned once, so the switch below happens at once
  await switchTo(w, a.origin);
  assert.equal((await w.popup({ type: "unlock", email: alice.email, password: alice.password })).ok, true);
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  // The next sync is refused once, so the session's pair is refreshed; the refresh is slow to answer.
  const o = a.override as (m: string, p: string, b: unknown, h: unknown) => unknown;
  let refused = false;
  a.override = (m: string, p: string, b: unknown, h: unknown) => {
    if (m === "GET" && p.startsWith("/api/v1/sync") && !refused) {
      refused = true;
      return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: { "content-type": "application/json" } });
    }
    return o(m, p, b, h);
  };
  refreshA.hold();
  const syncing = w.alarm("resync");
  await refreshA.reached();
  // The person connects to B meanwhile: the switch locks the session at A first.
  const switching = w.popup({ type: "chooseServer", choice: "own", origin: B });
  for (let i = 0; i < 400 && world.session.has("session"); i++) await tick();
  assert.ok(!world.session.has("session"), "the lock has begun");
  for (let i = 0; i < 20; i++) await tick();
  refreshA.release();
  assert.equal((await switching)?.ok, true);
  await syncing;
  await switchTo(w, a.origin);
  assert.equal((await w.popup({ type: "status" })).quickUnlock.armed, true);
  assert.deepEqual(await w.popup({ type: "unlockWithPin", pin: PIN }), { ok: true }, "A's quick unlock works: its record holds the pair A's server answered");
  assert.equal((await w.popup({ type: "status" })).email, alice.email);
});

test("a sign-in that sets its own pair while a lock waits for a refresh keeps its pair, and the lock stashes nothing of it", async () => {
  const { world, server: a, acct: alice, w } = await signedInWorld();
  const bob = a.addAccount({ email: "bob@example.com", password: "bob horse" });
  const refreshA = rotatingRefresh(a);
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  const o = a.override as (m: string, p: string, b: unknown, h: unknown) => unknown;
  let refused = false;
  a.override = (m: string, p: string, b: unknown, h: unknown) => {
    if (m === "GET" && p.startsWith("/api/v1/sync") && !refused) {
      refused = true;
      return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: { "content-type": "application/json" } });
    }
    return o(m, p, b, h);
  };
  refreshA.hold();
  const syncing = w.alarm("resync");
  await refreshA.reached();
  const locking = w.popup({ type: "lock" }); // waits, bounded, for Alice's refresh
  for (let i = 0; i < 400 && world.session.has("session"); i++) await tick();
  // Bob signs in meanwhile, and his sign-in completes before Alice's refresh answers.
  assert.equal((await w.popup({ type: "unlock", email: bob.email, password: bob.password })).ok, true);
  refreshA.release();
  await locking;
  await syncing;
  const st = await w.popup({ type: "status" });
  assert.deepEqual([st.unlocked, st.email], [true, bob.email]);
  await w.alarm("resync");
  assert.equal(lastSyncBearer(world), `Bearer at-${bob.userId}`, "Bob's session still has its pair");
  void alice;
});

/** Every refresh token the worker sent to [origin]. */
function refreshesSent(world: World, origin: string): string[] {
  return world.log
    .filter((l: { origin: string; method: string; path: string }) => l.origin === origin && l.method === "POST" && l.path === "/api/v1/auth/refresh")
    .map((l: { body?: { refreshToken?: string } }) => String(l.body?.refreshToken));
}

test("a lock during another account's password sign-in does not arm the record with that account's pair", async () => {
  const { world, server, acct: alice, w } = await signedInWorld();
  rotatingRefresh(server);
  const bob = server.addAccount({ email: "bob@example.com", password: "bob horse" });
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  await w.popup({ type: "lock" });
  const o = server.override as (m: string, p: string, b: unknown, h: { authorization?: string } | undefined) => unknown;
  let hit = false;
  let open: () => void = () => {};
  const opened = new Promise<void>((r) => (open = r));
  server.override = (m: string, p: string, b: unknown, h: { authorization?: string } | undefined) => {
    if (m === "GET" && p.startsWith("/api/v1/sync") && h?.authorization === `Bearer at-${bob.userId}` && !hit) {
      hit = true;
      return opened.then(() => server.handle(m, p, b, h));
    }
    return o(m, p, b, h);
  };
  // Bob signs in on the master-password form; his pair is in the worker's client, no session yet…
  const bobSignIn = w.popup({ type: "unlock", email: bob.email, password: bob.password });
  for (let i = 0; i < 400 && !hit; i++) await tick();
  assert.ok(hit, "Bob's sign-in is in its sync");
  // …and a lock arrives then (the popup hides Lock while locked; this is the belt).
  await w.popup({ type: "lock" });
  server.override = o;
  open();
  await bobSignIn;
  const r = await w.popup({ type: "unlockWithPin", pin: PIN });
  assert.ok(!refreshesSent(world, server.origin).some((t) => t.startsWith(`rt-${bob.userId}`)), "Alice's PIN never spends Bob's refresh token");
  assert.notEqual(r.ok, true, "and opens nothing on Bob's tokens");
  assert.equal((await w.popup({ type: "status" })).email ?? null, null);
  void alice;
});

test("after a server switch, a PIN unlock still under way at the old server does not route the new server's tokens", async () => {
  const { world, server: a, w } = await signedInWorld();
  const A = a.origin;
  const B = "https://other.example";
  const b = world.serve(B, new Chain({ origin: B }));
  const bob = b.addAccount({ email: "bob@example.com", password: "bob horse" });
  const carol = b.addAccount({ email: "carol@example.com", password: "carol horse" });
  rotatingRefresh(b);
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  await w.popup({ type: "lock" });
  await switchTo(w, B);
  assert.equal((await w.popup({ type: "unlock", email: bob.email, password: bob.password })).ok, true);
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  await w.popup({ type: "lock" });
  await switchTo(w, A);
  // A PIN unlock at A, held in its sync…
  const srvA = redeemServer(a, (m, p) => (m === "GET" && p.startsWith("/api/v1/sync") ? "a-sync" : null));
  const redeemA = w.popup({ type: "unlockWithPin", pin: PIN });
  await srvA.reached("a-sync");
  // …while the person goes to B, where Carol signs in; her first sync is refused once, so her pair is refreshed.
  await switchTo(w, B);
  const rot = b.override as (m: string, p: string, body: unknown, h: { authorization?: string } | undefined) => unknown;
  let refused = false;
  let held = false;
  let open: () => void = () => {};
  const opened = new Promise<void>((r) => (open = r));
  b.override = (m: string, p: string, body: unknown, h: { authorization?: string } | undefined) => {
    if (m === "GET" && p.startsWith("/api/v1/sync") && h?.authorization === `Bearer at-${carol.userId}`) {
      if (!refused) {
        refused = true;
        return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: { "content-type": "application/json" } });
      }
      if (!held) {
        held = true;
        return opened.then(() => b.handle(m, p, body, h));
      }
    }
    return rot(m, p, body, h);
  };
  const carolSignIn = w.popup({ type: "unlock", email: carol.email, password: carol.password });
  for (let i = 0; i < 400 && !held; i++) await tick();
  assert.ok(held, "Carol's sign-in has refreshed its pair and is in its sync again");
  srvA.release("a-sync");
  assert.deepEqual(await redeemA, { ok: false, code: "aborted" });
  // Bob's quick unlock at B still holds Bob's pair, not Carol's.
  assert.deepEqual(await w.popup({ type: "unlockWithPin", pin: PIN }), { ok: true }, "Bob's PIN opens Bob's vault");
  assert.equal((await w.popup({ type: "status" })).email, bob.email);
  open();
  await carolSignIn;
});

test("a stale client's tokens reach its server's record only when that record is the same account's", async () => {
  const { world, server: a, acct: alice, w } = await signedInWorld();
  const A = a.origin;
  const B = "https://other.example";
  world.serve(B, new Chain({ origin: B }));
  const bob = a.addAccount({ email: "bob@example.com", password: "bob horse" });
  const refreshA = rotatingRefresh(a);
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  await w.popup({ type: "lock" });
  await switchTo(w, B);
  await switchTo(w, A);
  // Bob signs in at A; his first sync is refused, and the refresh of his pair is slow to answer…
  const rot = a.override as (m: string, p: string, body: unknown, h: { authorization?: string } | undefined) => unknown;
  let refused = false;
  a.override = (m: string, p: string, body: unknown, h: { authorization?: string } | undefined) => {
    if (m === "GET" && p.startsWith("/api/v1/sync") && h?.authorization === `Bearer at-${bob.userId}` && !refused) {
      refused = true;
      return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: { "content-type": "application/json" } });
    }
    return rot(m, p, body, h);
  };
  refreshA.hold();
  const bobSignIn = w.popup({ type: "unlock", email: bob.email, password: bob.password });
  await refreshA.reached();
  // …the person goes to B meanwhile, and the refresh answers after.
  await switchTo(w, B);
  refreshA.release();
  await bobSignIn;
  for (let i = 0; i < 20; i++) await tick();
  await switchTo(w, A);
  assert.equal((await w.popup({ type: "status" })).quickUnlock.armed, true);
  assert.deepEqual(await w.popup({ type: "unlockWithPin", pin: PIN }), { ok: true }, "Alice's record kept Alice's pair");
  assert.equal((await w.popup({ type: "status" })).email, alice.email);
});

/** Holds the next AES-GCM key the worker generates (the quick-unlock co-key) after it is made, until `release()`. */
function holdNextCoKey() {
  const subtle = globalThis.crypto.subtle as unknown as { generateKey: (...a: unknown[]) => Promise<unknown> };
  const real = subtle.generateKey.bind(subtle);
  let hit = false;
  let open: () => void = () => {};
  const opened = new Promise<void>((r) => (open = r));
  subtle.generateKey = async (...args: unknown[]) => {
    const k = await real(...args);
    if (hit || (args[0] as { name?: string })?.name !== "AES-GCM") return k;
    hit = true;
    await opened;
    return k;
  };
  return {
    get hit() {
      return hit;
    },
    release() {
      delete (subtle as { generateKey?: unknown }).generateKey;
      open();
    },
  };
}

test("an enrolment switched off between making its co-key and writing its record writes nothing", async () => {
  const { world, w } = await signedInWorld();
  const coKey = holdNextCoKey();
  const enrolling = w.popup({ type: "enrollQuickUnlock", pin: PIN });
  for (let i = 0; i < 400 && !coKey.hit; i++) await tick();
  assert.ok(coKey.hit, "the enrolment has made its co-key");
  assert.deepEqual(await w.popup({ type: "disableQuickUnlock" }), { ok: true });
  coKey.release();
  assert.deepEqual(await enrolling, { ok: false, code: "switched_off" }, "the enrolment says quick unlock was switched off meanwhile");
  for (let i = 0; i < 20; i++) await tick();
  assert.deepEqual(quickUnlockResidue(world), [], "no record and no co-key");
  const st = await w.popup({ type: "status" });
  assert.equal(st.quickUnlock.enrolled, false);
  await w.popup({ type: "lock" });
  assert.equal((await w.popup({ type: "status" })).quickUnlock.armed, false, "and the next lock arms nothing");
});

for (const [label, end] of [
  ["a sign-out", { type: "signOut" }],
  ["a lock", { type: "lock" }],
] as const) {
  test(`a PIN enrolment overtaken by ${label} writes no quick-unlock record for the session that ended`, async () => {
    const { world, w, acct } = await signedInWorld();
    const kdf = holdKdf(world);
    const enrolling = w.popup({ type: "enrollQuickUnlock", pin: PIN });
    for (let i = 0; i < 400 && !kdf.hit; i++) await tick();
    assert.ok(kdf.hit, "the enrolment is deriving");
    await w.popup(end);
    kdf.release();
    assert.deepEqual(await enrolling, { ok: false, code: "locked" }, "the enrolment says the vault is locked");
    const st = await w.popup({ type: "status" });
    assert.equal(st.unlocked, false);
    assert.deepEqual([st.quickUnlock.enrolled, st.quickUnlock.armed], [false, false], "no quick unlock after it");
    assert.deepEqual(quickUnlockResidue(world), [], "no record and no co-key left in storage");
    // The next password sign-in to the same account does not switch on a quick unlock nobody finished setting up.
    assert.equal((await w.popup({ type: "unlock", email: acct.email, password: acct.password })).ok, true);
    assert.equal((await w.popup({ type: "status" })).quickUnlock.enrolled, false);
  });
}
