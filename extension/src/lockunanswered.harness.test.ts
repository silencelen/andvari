// node --test. A lock that meets a refresh whose answer never came, then a quick unlock; and the notice of the end this
// browser could not confirm. Before: the lock armed the quick-unlock record with no refresh token (the client hides a
// marked one), the quick unlock's refresh then answered "revoked", and the sign-out's wipe ran ("Your session ended"),
// deleting what it held, from a refresh that only got no answer. Driven through the real background.ts.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import {
  QUICK_UNLOCK_NOT_CONFIRMED,
  sessionNotConfirmedNotice,
  SESSION_NOT_CONFIRMED_NOTICE,
  SESSION_NOT_CONFIRMED_NOTICE_UNSAVED_MANY,
  SESSION_NOT_CONFIRMED_NOTICE_UNSAVED_ONE,
  SESSION_NOT_CONFIRMED_NOTICE_UNSAVED_UNKNOWN,
} from "./errors.ts";
import { signedInWorld, type World } from "./testing/bgharness.ts";
import { drawPopup, lockedStatus, textOf } from "./testing/popupkit.ts";

const PIN = "Tq7#kw2pZ";
const SHOP = "https://shop.example";

function logins(world: World): { replacesRefreshToken?: string }[] {
  return world.log.filter((l: { method: string; path: string }) => l.method === "POST" && l.path === "/api/v1/auth/login").map((l: { body: never }) => l.body);
}

test("a lock while a refresh's mark stands, then a quick unlock: nothing sent, never revoked, no wipe; the not-confirmed end, the token kept", async () => {
  const { world, server, acct, w } = await signedInWorld();
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  // Every request is refused for its access token, and the refresh is answered by a gateway's page: no answer.
  server.override = (_m: string, path: string) =>
    path === "/api/v1/auth/refresh"
      ? new Response("<html>502 Bad Gateway</html>", { status: 502 })
      : path.startsWith("/api/v1/sync")
        ? new Response(JSON.stringify({ error: "unauthorized", message: "expired" }), { status: 401, headers: { "content-type": "application/json" } })
        : null;
  await w.alarm("resync"); // the first try: no answer, the mark stands
  assert.equal((await w.popup({ type: "status" })).serverEnded ?? false, false, "inside the window nothing has ended");
  await w.popup({ type: "lock" });
  await w.page({ type: "capturedCredential", username: "alice", password: "shop-pw" }, 4, SHOP);
  assert.equal((await w.popup({ type: "status" })).unsavedCaptures, 1);
  const from = world.log.length;
  const r = await w.popup({ type: "unlockWithPin", pin: PIN });
  assert.deepEqual({ ok: r.ok, code: r.code }, { ok: false, code: "not_confirmed" });
  assert.deepEqual(world.dialed().slice(from).filter((l: string) => /refresh|logout|end-session|sync|account/.test(l)), [], "nothing is sent");
  const st = await w.popup({ type: "status", takeLost: true });
  assert.equal(st.unsavedCaptures, 1, "no sign-out wipe: the capture made while locked stays");
  assert.equal(st.capturesLost ?? 0, 0);
  // The next sign-in names the token the lock kept, so that the server ends that chain as replaced.
  server.override = null;
  assert.equal((await w.popup({ type: "unlock", email: acct.email, password: acct.password })).ok, true);
  assert.equal(logins(world).at(-1)!.replacesRefreshToken, `rt-${acct.userId}`);
});

test("after that quick unlock the locked popup carries a standing mark of the end: at every render, after a worker restart, until the next sign-in", async () => {
  const { world, server, acct, w } = await signedInWorld();
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  server.override = (_m: string, path: string) =>
    path === "/api/v1/auth/refresh"
      ? new Response("<html>502 Bad Gateway</html>", { status: 502 })
      : path.startsWith("/api/v1/sync")
        ? new Response(JSON.stringify({ error: "unauthorized", message: "expired" }), { status: 401, headers: { "content-type": "application/json" } })
        : null;
  await w.alarm("resync");
  await w.popup({ type: "lock" });
  assert.equal((await w.popup({ type: "status" })).lockNotice, null, "a lock the person asked for says no reason");
  assert.equal((await w.popup({ type: "unlockWithPin", pin: PIN })).code, "not_confirmed");
  assert.deepEqual((await w.popup({ type: "status" })).lockNotice, { kind: "not_confirmed" });
  assert.deepEqual((await w.popup({ type: "status" })).lockNotice, { kind: "not_confirmed" }, "not taken by a read: it stands");
  const w2 = await world.start(); // a stopped worker, started again
  assert.deepEqual((await w2.popup({ type: "status" })).lockNotice, { kind: "not_confirmed" }, "kept at rest");
  server.override = null;
  assert.equal((await w2.popup({ type: "unlock", email: acct.email, password: acct.password })).ok, true);
  await w2.popup({ type: "lock" });
  assert.equal((await w2.popup({ type: "status" })).lockNotice, null, "the next sign-in clears it");
});

test("the locked popup says the standing mark at every opening, as the line of that quick unlock", async () => {
  for (let open = 0; open < 2; open++) {
    const p = await drawPopup((msg) => {
      if (msg.type === "serverInfo") return { url: "https://vault.example", trustedStore: true, block: null };
      if (msg.type === "status") return { ...lockedStatus, lockNotice: { kind: "not_confirmed" } };
      return undefined;
    });
    try {
      await p.settle(150);
      assert.deepEqual(p.errors, []);
      assert.ok(textOf(p.byId("msg")).includes(QUICK_UNLOCK_NOT_CONFIRMED), `opening ${open + 1}`);
    } finally {
      p.dispose();
    }
  }
});

test("the notice of the end this browser could not confirm says how many captures are not saved, as the server's end's does", () => {
  assert.equal(sessionNotConfirmedNotice(0), SESSION_NOT_CONFIRMED_NOTICE);
  assert.equal(sessionNotConfirmedNotice(1), SESSION_NOT_CONFIRMED_NOTICE_UNSAVED_ONE);
  assert.equal(sessionNotConfirmedNotice(3), SESSION_NOT_CONFIRMED_NOTICE_UNSAVED_MANY.replace("{0}", "3"));
  assert.equal(sessionNotConfirmedNotice(null), SESSION_NOT_CONFIRMED_NOTICE_UNSAVED_UNKNOWN);
  assert.equal(sessionNotConfirmedNotice(-1), SESSION_NOT_CONFIRMED_NOTICE_UNSAVED_UNKNOWN);
});
