// node --test. Quick unlock and the session it began under (release 0.30.0 port of the overhaul's fixes de5dfd21,
// aade6862, 02987f7e and aca13f82): a token stash, a late refresh answer, an enrolment and a redeem must not outlive or
// cross into another session. The real background.ts, driven through testing/bgharness.ts.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { signedInWorld, signIn, type World } from "./testing/bgharness.ts";

const PIN = "Tq7#kw2pZ";
const tick = (ms = 5) => new Promise((r) => setTimeout(r, ms));
const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });

type Srv = { override: unknown; hold: unknown };

/**
 * The fake server answers the refresh (it has no route of its own for it) with the account's usual pair, and holds every
 * request [hold] names until its gate is released, then answers it as usual. Gates are keyed by name; each holds once.
 */
function redeemServer(server: Srv, hold: (method: string, path: string, body: unknown, auth: string | undefined) => string | null) {
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
  server.override = (method: string, path: string, body: unknown) => {
    if (method === "POST" && path === "/api/v1/auth/refresh") {
      const uid = String((body as { refreshToken: string }).refreshToken).replace(/^rt-/, "");
      return json({ accessToken: `at-${uid}`, refreshToken: `rt-${uid}` });
    }
    return null;
  };
  server.hold = (method: string, path: string, body: unknown, headers: Record<string, string> | undefined) => {
    const name = hold(method, path, body, headers?.authorization);
    if (name === null || gate(name).hit) return null;
    const g = gate(name);
    g.hit = true;
    return g.opened;
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

// ---------------------------------------------------------------- 1. the stash after a password sign-in (de5dfd21)

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

// ---------------------------------------------------------------- 2. a late forced refresh (aade6862)

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
  await signIn(w, bob);
  const before = await w.popup({ type: "status" });
  assert.deepEqual([before.unlocked, before.email, before.count], [true, bob.email, 1]);
  srv.release("alice-refresh");
  assert.deepEqual(await aliceRedeem, { ok: false, code: "aborted" }, "the PIN unlock gives way");
  await w.alarm("resync");
  const after = await w.popup({ type: "status" });
  assert.deepEqual([after.unlocked, after.email], [true, bob.email]);
  assert.equal(lastSyncBearer(world), `Bearer at-${bob.userId}`, `the sign-in's session syncs on its own token, not on ${alice.email}'s (list after: ${after.count})`);
});

// ---------------------------------------------------------------- 3. an enrolment overtaken by its session's end (02987f7e)

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
    const r = await enrolling;
    const st = await w.popup({ type: "status" });
    assert.equal(st.unlocked, false);
    assert.deepEqual([st.quickUnlock.enrolled, st.quickUnlock.armed], [false, false], `no quick unlock after it (the enrolment answered ${JSON.stringify(r)})`);
    assert.deepEqual(quickUnlockResidue(world), [], "no record and no co-key left in storage");
    assert.deepEqual(r, { ok: false, code: "locked" }, "the enrolment says the vault is locked");
    // The next password sign-in to the same account does not switch on a quick unlock nobody finished setting up.
    assert.equal((await w.popup({ type: "unlock", email: acct.email, password: acct.password })).ok, true);
    assert.equal((await w.popup({ type: "status" })).quickUnlock.enrolled, false);
  });
}

// ---------------------------------------------------------------- 4. a redeem and a password sign-in at once (aca13f82)

test("a PIN unlock that proves its PIN after a password sign-in began supersedes it: one session, on its own account's tokens", async () => {
  const { world, server, acct: alice, w } = await signedInWorld();
  const bob = server.addAccount({ email: "bob@example.com", password: "bob horse" });
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  await w.popup({ type: "lock" });
  assert.equal((await w.popup({ type: "status" })).quickUnlock.armed, true);
  const srv = redeemServer(server, (m, p, body, auth) =>
    m === "POST" && p === "/api/v1/auth/login" && (body as { email?: string }).email === bob.email
      ? "bob-login"
      : m === "GET" && p.startsWith("/api/v1/sync") && auth === `Bearer at-${alice.userId}`
        ? "alice-sync"
        : null,
  );
  // On the master-password form, another account's sign-in starts (its login is slow to answer)...
  const bobUnlock = w.popup({ type: "unlock", email: bob.email, password: bob.password });
  await srv.reached("bob-login");
  // ...and meanwhile the PIN is entered in another window; its sync is slow too.
  const aliceRedeem = w.popup({ type: "unlockWithPin", pin: PIN });
  await srv.reached("alice-sync");
  srv.release("bob-login");
  const bobResult = await bobUnlock;
  srv.release("alice-sync");
  assert.equal((await aliceRedeem).ok, true, "the PIN unlock completes");
  const st = await w.popup({ type: "status" });
  assert.deepEqual([st.unlocked, st.email], [true, alice.email]);
  await w.alarm("resync");
  assert.equal(lastSyncBearer(world), `Bearer at-${alice.userId}`, `the open session syncs on its own account's token, not the other sign-in's (that sign-in answered ${JSON.stringify(bobResult)})`);
});

test("a PIN unlock given up while a password sign-in is in its sync leaves that sign-in its tokens", async () => {
  const { world, server, acct: alice, w } = await signedInWorld();
  const bob = server.addAccount({ email: "bob@example.com", password: "bob horse" });
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  await w.popup({ type: "lock" });
  const srv = redeemServer(server, (m, p, _b, auth) =>
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

test("a password sign-in in its sync, superseded by a PIN unlock that proved its PIN, leaves the PIN unlock its tokens", async () => {
  const { world, server, acct: alice, w } = await signedInWorld();
  const bob = server.addAccount({ email: "bob@example.com", password: "bob horse" });
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  await w.popup({ type: "lock" });
  const srv = redeemServer(server, (m, p, _b, auth) =>
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
