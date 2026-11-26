// node --test. The vault locks at its time, timer or no timer. Every chrome.alarms call was fired
// and forgotten, so a browser that refused the auto-lock alarm left the vault open for as long as it kept the session,
// and nothing said so. The lock's deadline is now kept with the session and checked at every way into the worker,
// before anything is served; past it the session is locked first, exactly as the alarm would have locked it. The real
// background.ts, driven through testing/bgharness.ts, with a browser whose alarms API refuses every alarm.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { passTime, signedInWorld } from "./testing/bgharness.ts";

const SITE = "https://shop.example";
const PIN = "Tq7#kw2pZ";
/** The harness server's policy locks after 900 s without use. */
const PAST = 16 * 60_000;
const BEFORE = 10 * 60_000;
const tick = (ms = 5) => new Promise((r) => setTimeout(r, ms));

async function refusingWorld() {
  const r = await signedInWorld({
    setup: ({ world, server, acct }) => {
      world.alarmRefusal = () => true; // the browser refuses every alarm, the auto-lock's included
      server.ticketsOn = true; // so the live socket is there to ring
      acct.addItem(acct.personalVaultId, { type: "login", name: "shop", login: { username: "alice", password: "shop-pw", uris: [SITE] } });
    },
  });
  r.world.tabs.set(4, { id: 4, url: `${SITE}/login`, active: true });
  return r;
}

const names = (r: { items?: { name: string }[] } | undefined) => (r?.items ?? []).map((i) => i.name);
const syncs = (world: { dialed: () => string[] }) => world.dialed().filter((d) => d.startsWith("GET /api/v1/sync")).length;

/** Locked the way the alarm locks: no session, the snapshot erased, the idle line above the unlock form. */
async function assertIdleLocked(w: { popup: (m: unknown) => Promise<any> }, world: { session: Map<string, unknown> }) {
  assert.equal(world.session.has("session"), false, "the session snapshot is erased");
  const st = await w.popup({ type: "status" });
  assert.equal(st.unlocked, false, "the vault is locked");
  assert.deepEqual(st.lockNotice, { kind: "idle", seconds: 900 }, "as the idle lock locks it");
}

test("a browser that refuses the auto-lock alarm: tried once more, the popup says so, and before the time everything works", async () => {
  const { world, w } = await refusingWorld();
  const st = await w.popup({ type: "status" }); // read once the alarm requests settled
  assert.equal(st.unlocked, true);
  assert.equal(st.timerNotice, "autolock", "the popup is told the timer could not be set");
  assert.equal(world.alarms.has("autolock"), false, "no alarm was set");
  assert.ok(world.alarmAsks.filter((n) => n === "autolock").length >= 2, "the refused alarm was asked for once more");
  passTime(BEFORE);
  assert.deepEqual(names(await w.popup({ type: "allItems" })), ["shop"], "the popup's list");
  assert.deepEqual(names({ items: (await w.page({ type: "matches", host: "shop.example" }, 4, SITE)).matches }), ["shop"], "the page's fill offer");
  const before = syncs(world);
  await w.alarm("resync");
  assert.equal(syncs(world), before + 1, "a sync");
  assert.equal((await w.popup({ type: "status" })).unlocked, true, "still open");
});

test("past the time, a popup message is answered locked: the session is gone first", async () => {
  const { world, w } = await refusingWorld();
  passTime(PAST);
  assert.deepEqual(names(await w.popup({ type: "allItems" })), [], "nothing is listed");
  await assertIdleLocked(w, world);
});

test("past the time, a page's fill request is answered locked", async () => {
  const { world, w } = await refusingWorld();
  passTime(PAST);
  assert.deepEqual((await w.page({ type: "matches", host: "shop.example" }, 4, SITE)).matches ?? [], [], "no login is offered");
  await assertIdleLocked(w, world);
});

test("past the time, a save is not written: the capture is taken as a locked one", async () => {
  const { world, server, w } = await refusingWorld();
  const pushes = server.pushes.length;
  passTime(PAST);
  const cap = await w.page({ type: "capturedCredential", username: "alice", password: "shop-new" }, 4, SITE);
  assert.equal(cap?.pending?.updatesItemId ?? null, null, "not offered as an update of a login it can read");
  await w.page({ type: "resolvePendingSave", action: "save" }, 4, SITE);
  assert.equal(server.pushes.length, pushes, "nothing was written");
  await assertIdleLocked(w, world);
});

test("past the time, the resync alarm locks instead of syncing", async () => {
  const { world, w } = await refusingWorld();
  const before = syncs(world);
  passTime(PAST);
  await w.alarm("resync");
  assert.equal(syncs(world), before, "no sync was asked for");
  await assertIdleLocked(w, world);
});

test("past the time, a live update (the socket's bell) locks instead of syncing", async () => {
  const { world, w } = await refusingWorld();
  for (let i = 0; i < 200 && world.sockets.length === 0; i++) await tick();
  const sock = world.sockets[0];
  assert.ok(sock, "the live socket is up");
  const before = syncs(world);
  passTime(PAST);
  sock.onmessage({ data: JSON.stringify({ type: "rev" }) });
  for (let i = 0; i < 200 && world.session.has("session"); i++) await tick();
  await tick(600); // past the bell's debounce
  assert.equal(syncs(world), before, "no sync was asked for");
  await assertIdleLocked(w, world);
});

test("past the time, the socket's revoked frame finds the vault locked, not an ended session left readable", async () => {
  const { world, w } = await refusingWorld();
  for (let i = 0; i < 200 && world.sockets.length === 0; i++) await tick();
  passTime(PAST);
  world.sockets[0].onmessage({ data: JSON.stringify({ type: "revoked" }) });
  for (let i = 0; i < 200 && world.session.has("session"); i++) await tick();
  await assertIdleLocked(w, world);
  assert.equal((await w.popup({ type: "status" })).serverEnded, false);
});

test("past the time, a new worker life restores nothing: the session is locked at start, and quick unlock armed as the alarm would", async () => {
  const { world, server, w } = await refusingWorld();
  // The fake server has no refresh route of its own: it answers a PIN unlock's refresh with the account's usual pair.
  server.override = (method: string, path: string, body: { refreshToken?: string } | undefined) =>
    method === "POST" && path === "/api/v1/auth/refresh"
      ? new Response(JSON.stringify({ accessToken: String(body?.refreshToken).replace(/^rt-/, "at-"), refreshToken: String(body?.refreshToken) }), { status: 200, headers: { "content-type": "application/json" } })
      : null;
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  passTime(PAST);
  const w2 = await world.start(); // the browser stopped the worker; the next event starts a new one
  assert.equal(world.session.has("session"), false, "the snapshot is erased at the start");
  assert.deepEqual(names(await w2.popup({ type: "allItems" })), []);
  const st = await w2.popup({ type: "status" });
  assert.equal(st.unlocked, false);
  assert.deepEqual(st.lockNotice, { kind: "idle", seconds: 900 });
  assert.equal(st.quickUnlock.armed, true, "the record is armed, as the alarm's lock arms it");
  assert.equal((await w2.popup({ type: "unlockWithPin", pin: PIN })).ok, true, "and the PIN opens the vault");
  assert.deepEqual(names(await w2.popup({ type: "allItems" })), ["shop"]);
});

test("use moves the time: a person active within the window keeps the vault open across worker lives", async () => {
  const { world, w } = await refusingWorld();
  passTime(BEFORE);
  await w.popup({ type: "allItems" }); // user activity re-arms the deadline
  passTime(BEFORE); // 20 min after the sign-in, 10 after the last use
  const w2 = await world.start();
  assert.deepEqual(names(await w2.popup({ type: "allItems" })), ["shop"], "still open in a new worker life");
  passTime(PAST);
  assert.deepEqual(names(await w2.popup({ type: "allItems" })), []);
  await assertIdleLocked(w2, world);
});

test("a browser that sets the alarms: the lock is set for its time, and no line shows", async () => {
  const { world, w } = await signedInWorld();
  const alarm = world.alarms.get("autolock") as { when?: number } | undefined;
  assert.ok(alarm?.when !== undefined && Math.abs(alarm.when - (Date.now() + 900_000)) < 5_000, "the alarm is set for the deadline");
  assert.ok(world.alarms.has("resync"));
  assert.equal((await w.popup({ type: "status" })).timerNotice, null);
});

test("a refused resync alarm is said too (with both refused, the first test shows the auto-lock line outranks it)", async () => {
  const { w } = await signedInWorld({ setup: ({ world }) => void (world.alarmRefusal = (n: string) => n === "resync") });
  assert.equal((await w.popup({ type: "status" })).timerNotice, "resync");
});
