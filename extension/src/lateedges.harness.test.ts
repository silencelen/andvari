// node --test. The edge cases of work that outlives a lock that were still open, through the real background.ts (testing/bgharness.ts).
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { Chain, connect, signedInWorld, type World } from "./testing/bgharness.ts";

const PIN = "Tq7#kw2pZ";
const tick = (ms = 5) => new Promise((r) => setTimeout(r, ms));
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
type Srv = { origin: string; override: unknown };

/** The server answers each refresh token once, with a new pair; `hold()` keeps the next refresh's answer until `release()`. */
function rotatingRefresh(server: Srv) {
  const spent = new Set<string>();
  let n = 0;
  let gate: { hit: boolean; opened: Promise<void>; open: () => void } | null = null;
  server.override = (method: string, path: string, body: unknown) => {
    if (method !== "POST" || path !== "/api/v1/auth/refresh") return null;
    const rt = String((body as { refreshToken: string }).refreshToken);
    const answer = () => {
      if (spent.has(rt) || !rt.startsWith("rt-")) return json({ error: "unauthorized" }, 401);
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

/** The next sync is refused once, so the session's pair is refreshed (through whatever override answers the refresh). */
function refuseNextSync(server: Srv) {
  const o = server.override as (m: string, p: string, b: unknown, h: unknown) => unknown;
  let refused = false;
  server.override = (m: string, p: string, b: unknown, h: unknown) => {
    if (m === "GET" && p.startsWith("/api/v1/sync") && !refused) {
      refused = true;
      return json({ error: "unauthorized" }, 401);
    }
    return o(m, p, b, h);
  };
}

test("2(a): a refresh slower than the lock's wait: the armed record follows the pair the server answered, and the PIN works", async () => {
  const { server, w } = await signedInWorld();
  const refresh = rotatingRefresh(server);
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  refuseNextSync(server);
  refresh.hold();
  const syncing = w.alarm("resync");
  await refresh.reached();
  await w.popup({ type: "lock" }); // waits for the refresh at most 1.5 s, then arms without it
  assert.equal((await w.popup({ type: "status" })).quickUnlock.armed, true);
  refresh.release();
  await syncing;
  await tick(50);
  assert.deepEqual(await w.popup({ type: "unlockWithPin", pin: PIN }), { ok: true }, "the record holds the answered pair, not the spent one");
});

test("2(a): a PIN unlock asked for while that slow refresh is still on the wire waits for its answer", async () => {
  const { server, w } = await signedInWorld();
  const refresh = rotatingRefresh(server);
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  refuseNextSync(server);
  refresh.hold();
  const syncing = w.alarm("resync");
  await refresh.reached();
  await w.popup({ type: "lock" });
  const unlocking = w.popup({ type: "unlockWithPin", pin: PIN });
  await tick(100);
  refresh.release();
  assert.deepEqual(await unlocking, { ok: true });
  await syncing;
  assert.equal((await w.popup({ type: "status" })).unlocked, true);
});

/** Holds the next KDF run (a PIN derivation) until `release()`. */
function holdKdf(world: World) {
  let open: (() => void) | null = null;
  let hit = false;
  world.kdfHook = async () => {
    if (hit) return;
    hit = true;
    await new Promise<void>((r) => (open = r));
  };
  return {
    async reached() {
      for (let i = 0; i < 400 && !hit; i++) await tick();
      assert.ok(hit, "the derivation is under way");
    },
    release() {
      world.kdfHook = null;
      open?.();
    },
  };
}

test("2(d): quick unlock switched off while its set-up derives (before the set-up's own wipe) stays off", async () => {
  const { world, w } = await signedInWorld();
  const kdf = holdKdf(world); // the set-up's first derivation (its bench)
  const enrolling = w.popup({ type: "enrollQuickUnlock", pin: PIN });
  await kdf.reached();
  assert.deepEqual(await w.popup({ type: "disableQuickUnlock" }), { ok: true }, "switched off in another window");
  kdf.release();
  assert.deepEqual(await enrolling, { ok: false, code: "switched_off" });
  const st = await w.popup({ type: "status" });
  assert.equal(st.quickUnlock.enrolled, false, "still off");
  assert.deepEqual([...(world.idb.get("andvari-qu")?.get("cokey")?.keys() ?? [])], [], "and no co-key is left");
  await w.popup({ type: "lock" });
  assert.equal((await w.popup({ type: "status" })).quickUnlock.armed, false, "nothing arms at the lock");
});

// ---- item 3: the release line's points, checked here ----

const SITE = "https://shop.example";
/** The FIRST push is answered only once `release()` is called. */
function holdPush(server: Srv) {
  let open: (() => void) | null = null;
  let hit = false;
  server.override = (method: string, path: string, body: unknown) => {
    if (hit || method !== "POST" || path !== "/api/v1/sync/push") return null;
    hit = true;
    return new Promise<void>((r) => (open = r)).then(() =>
      json({ rev: 9, results: (body as { mutations: { mutationId: string }[] }).mutations.map((m) => ({ mutationId: m.mutationId, status: "applied", newItemRev: 9 })) }),
    );
  };
  return {
    async reached() {
      for (let i = 0; i < 400 && !hit; i++) await tick();
      assert.ok(hit, "the save is on the wire");
    },
    release: () => open?.(),
  };
}

test("3(1): a Save answered after another account signed in says it landed in the account that was open, not 'saved' over the new one", async () => {
  const { world, server, w } = await signedInWorld();
  const bob = server.addAccount({ email: "bob@example.com", password: "bob horse" });
  world.tabs.set(4, { id: 4, url: `${SITE}/login`, active: true });
  assert.equal((await w.page({ type: "capturedCredential", username: "alice", password: "alice-shop-pw" }, 4, SITE)).ok, true);
  const push = holdPush(server);
  const saving = w.page({ type: "resolvePendingSave", action: "save" }, 4, SITE);
  await push.reached();
  await w.popup({ type: "signOut" });
  assert.equal((await w.popup({ type: "unlock", email: bob.email, password: bob.password })).ok, true);
  push.release();
  assert.deepEqual(await saving, { ok: true, otherAccount: true });
});

test("3(1): an approved save landing after another account signed in tells the page the same", async () => {
  const { world, server, acct, w } = await signedInWorld();
  const bob = server.addAccount({ email: "bob@example.com", password: "bob horse" });
  world.tabs.set(4, { id: 4, url: `${SITE}/login`, active: true });
  await w.popup({ type: "lock" });
  await w.page({ type: "capturedCredential", username: "alice", password: "alice-shop-pw" }, 4, SITE); // captured while locked
  assert.equal((await w.page({ type: "resolvePendingSave", action: "save" }, 4, SITE)).code, "locked", "the click is kept as approval");
  const push = holdPush(server);
  assert.equal((await w.popup({ type: "unlock", email: acct.email, password: acct.password })).ok, true); // the approval commits
  await push.reached();
  await w.popup({ type: "signOut" });
  assert.equal((await w.popup({ type: "unlock", email: bob.email, password: bob.password })).ok, true);
  push.release();
  for (let i = 0; i < 200 && !world.tabMessages.some((m: { msg: { type: string } }) => m.msg.type === "pendingSaveCommitted"); i++) await tick();
  const told = world.tabMessages.filter((m: { msg: { type: string } }) => m.msg.type === "pendingSaveCommitted").map((m: { msg: unknown }) => m.msg);
  assert.deepEqual(told, [{ type: "pendingSaveCommitted", otherAccount: true }]);
});

/** Switch to [origin]: through the Trust Gate the first time, at once to a server already pinned. */
async function switchTo(w: Awaited<ReturnType<World["start"]>>, origin: string) {
  const r = await w.popup({ type: "chooseServer", choice: "own", origin });
  if (r?.gate) await connect(w, origin);
  else assert.equal(r?.ok, true, `switched to ${origin}`);
}

test("2(b): a server switch during the PIN's derivation answers 'given up'; neither server's quick unlock is harmed", async () => {
  const { world, server: a, w } = await signedInWorld();
  const B = "https://other.example";
  const b = world.serve(B, new Chain({ origin: B }));
  const bob = b.addAccount({ email: "bob@example.com", password: "bob horse" });
  rotatingRefresh(a);
  rotatingRefresh(b);
  await switchTo(w, B); // B pinned once, so the switches below happen at once
  assert.equal((await w.popup({ type: "unlock", email: bob.email, password: bob.password })).ok, true);
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true, "B has quick unlock too");
  await w.popup({ type: "lock" });
  await switchTo(w, a.origin);
  assert.equal((await w.popup({ type: "unlock", email: "alice@example.com", password: "correct horse" })).ok, true);
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  await w.popup({ type: "lock" });
  const kdf = holdKdf(world);
  const unlocking = w.popup({ type: "unlockWithPin", pin: PIN });
  await kdf.reached();
  await switchTo(w, B);
  kdf.release();
  assert.deepEqual(await unlocking, { ok: false, code: "aborted" }, "given up, not an error");
  assert.equal((await w.popup({ type: "status" })).quickUnlock.armed, true, "B's record is not wiped");
  assert.deepEqual(await w.popup({ type: "unlockWithPin", pin: PIN }), { ok: true }, "and B's PIN opens B's vault");
  assert.equal((await w.popup({ type: "status" })).email, bob.email);
  await w.popup({ type: "lock" });
  await switchTo(w, a.origin);
  assert.equal((await w.popup({ type: "status" })).quickUnlock.armed, true, "the record is unharmed");
  assert.deepEqual(await w.popup({ type: "unlockWithPin", pin: PIN }), { ok: true });
});
