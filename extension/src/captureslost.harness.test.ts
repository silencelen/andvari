// node --test. Design §4.4 (decided on 2026-11-17): a lock that nobody is there for deletes nothing a person has not
// been told about. The logins and cards this browser captured on pages and had not saved are deleted by the idle lock
// (a page's password is never kept past a lock) and by the full sign-out that follows a session the server ended for
// good; the popup now says how many the next time it opens, once, and only the number was kept. "Forget this server" on
// the options page asks twice over captures, or when it cannot tell, as the web app's does. Through the real
// background.ts (testing/bgharness.ts).
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import * as T from "./copy.ts";
import { fillApproved } from "./errors.ts";
import { passTime, signedInWorld } from "./testing/bgharness.ts";
import { capturesLostLine, COUNT_UNKNOWN, forgetUnsavedLine, unsavedArmStep } from "./unsavedarm.ts";

const SHOP = "https://shop.example";
const NEWS = "https://news.example";
const PIN = "Tq7#kw2pZ";
/** The harness server's policy locks after 900 s without use. */
const PAST = 16 * 60_000;

const json = (body: unknown, status: number) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

test("the idle lock deletes two captures: the popup's next render is told 2, once, and a read that does not take them leaves them", async () => {
  const { w } = await signedInWorld();
  await w.page({ type: "capturedCredential", username: "alice", password: "shop-pw" }, 4, SHOP);
  await w.page({ type: "capturedCredential", username: "bea", password: "news-pw" }, 5, NEWS);
  assert.equal((await w.popup({ type: "status" })).unsavedCaptures, 2);
  await w.alarm("autolock");
  const other = await w.popup({ type: "status" });
  assert.equal(other.unlocked, false, "the idle lock locked the vault");
  assert.equal(other.capturesLost, 0, "a read that does not take them (the options page's, a keep-alive) leaves them");
  assert.equal((await w.popup({ type: "status", takeLost: true })).capturesLost, 2, "the popup's render is told how many");
  assert.equal((await w.popup({ type: "status", takeLost: true })).capturesLost, 0, "once");
});

test("the idle lock a new worker life runs at its start (past the time) counts the captures the earlier life held", async () => {
  const { world, w } = await signedInWorld();
  await w.page({ type: "capturedCredential", username: "alice", password: "shop-pw" }, 4, SHOP);
  passTime(PAST);
  const w2 = await world.start(); // the browser stopped the worker; the next event starts a new one, past the lock's time
  const st = await w2.popup({ type: "status", takeLost: true });
  assert.equal(st.unlocked, false);
  assert.equal(st.capturesLost, 1);
});

test("a lock or sign-out the person asked for (with the count, first) records nothing to say afterwards", async () => {
  const { w } = await signedInWorld();
  await w.page({ type: "capturedCredential", username: "alice", password: "shop-pw" }, 4, SHOP);
  await w.popup({ type: "lock" });
  assert.equal((await w.popup({ type: "status", takeLost: true })).capturesLost, 0, "the manual Lock asked first");
  await w.page({ type: "capturedCredential", username: "alice", password: "shop-pw" }, 4, SHOP);
  await w.popup({ type: "signOut" });
  assert.equal((await w.popup({ type: "status", takeLost: true })).capturesLost, 0, "the popup's Sign out asked first");
});

test("an idle lock with nothing captured says nothing", async () => {
  const { w } = await signedInWorld();
  await w.alarm("autolock");
  assert.equal((await w.popup({ type: "status", takeLost: true })).capturesLost, 0);
});

test("the full sign-out after the server ended the session for good (a refused refresh at a PIN unlock) says the capture it deleted", async () => {
  const { server, w } = await signedInWorld({
    setup: ({ server }) => {
      // The fake server has no refresh route of its own: it answers a refresh with the account's usual pair.
      server.override = (method: string, path: string, body: { refreshToken?: string } | undefined) =>
        method === "POST" && path === "/api/v1/auth/refresh"
          ? json({ accessToken: String(body?.refreshToken).replace(/^rt-/, "at-"), refreshToken: String(body?.refreshToken) }, 200)
          : null;
    },
  });
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  await w.popup({ type: "lock" });
  assert.equal((await w.popup({ type: "status" })).quickUnlock.armed, true);
  // Captured while locked: kept, counted, and waiting for an unlock.
  await w.page({ type: "capturedCredential", username: "alice", password: "shop-pw" }, 4, SHOP);
  assert.equal((await w.popup({ type: "status" })).unsavedCaptures, 1);
  // The server ended the session elsewhere: its refresh is refused for good.
  server.override = (method: string, path: string) => (method === "POST" && path === "/api/v1/auth/refresh" ? json({ error: "unauthorized", message: "refused" }, 401) : null);
  const r = await w.popup({ type: "unlockWithPin", pin: PIN });
  assert.equal(r.ok, false);
  assert.equal(r.code, "revoked");
  const st = await w.popup({ type: "status", takeLost: true });
  assert.equal(st.unsavedCaptures, 0, "the full sign-out deleted it");
  assert.equal(st.capturesLost, 1, "and the popup is told");
});

test("the popup's line says how many and claims no way back; the popup takes it on its own render and keeps it while locked", () => {
  assert.equal(capturesLostLine(0), null);
  assert.equal(capturesLostLine(1), T.CAPTURES_LOST_ONE);
  assert.equal(capturesLostLine(3), fillApproved(T.CAPTURES_LOST_MANY, "3"));
  const popup = readFileSync(fileURLToPath(new URL("./popup.ts", import.meta.url)), "utf8");
  assert.ok(popup.includes('const s = await ask({ type: "status", takeLost: true });'), "the popup's render takes it");
  assert.equal(popup.match(/takeLost: true/g)?.length, 1, "and no other status read of the popup does");
  assert.ok(popup.includes('el("captures-lost").textContent = capturesLostShown ?? "";'), "in its own line, not the message an error uses");
  assert.ok(popup.includes("if (s?.unlocked) capturesLostShown = null;"), "gone once the vault is open");
  const html = readFileSync(fileURLToPath(new URL("../popup.html", import.meta.url)), "utf8");
  assert.ok(html.includes('<div id="captures-lost" class="must-change-strip grants-waiting" role="status" hidden></div>'));
});

test("Forget this server on the popup's own stop card and fork notice asks twice over captures, as the options page does", () => {
  const popup = readFileSync(fileURLToPath(new URL("./popup.ts", import.meta.url)), "utf8");
  const helper = popup.slice(popup.indexOf("async function forgetSecondClick("), popup.indexOf("function disarmForget("));
  assert.ok(helper.includes("const now = await popupCapturesNow();"), "the click reads the count");
  assert.ok(helper.includes("const step = unsavedArmStep(armed?.count ?? null, now, false);"), "and arms through the shared step");
  assert.ok(helper.includes("b.textContent = T.FORGET_CONFIRM;"));
  assert.ok(helper.includes('showMsg("info", forgetUnsavedLine(now) ?? "");'), "the count, or cannot tell, is said at the first click");
  assert.ok(popup.includes("return typeof s?.unsavedCaptures === \"number\" ? s.unsavedCaptures : COUNT_UNKNOWN;"), "no answer is cannot tell");
  for (const id of ["confirm-server-not-mine", "card-notice-follow"]) {
    const at = popup.indexOf(`el("${id}").addEventListener("click"`);
    assert.ok(at > -1, id);
    const handler = popup.slice(at, popup.indexOf("\n});", popup.indexOf('ask({ type: "forgetServer" })', at)));
    const arm = handler.indexOf("await forgetSecondClick(b)");
    assert.ok(arm > -1 && arm < handler.indexOf('ask({ type: "forgetServer" })'), `${id}: forgets only after the second click`);
  }
  // Leaving either button disarms it (the first click's own move of the focus to its line excepted).
  assert.ok(popup.includes('for (const id of ["card-notice-follow", "confirm-server-not-mine"]) {'));
  assert.match(popup, /b\.addEventListener\("blur", \(e: FocusEvent\) => \{\s*if \(e\.relatedTarget !== el\("msg"\)\) disarmForget\(b\);/);
});

test("Forget this server on the options page asks twice over captures and when it cannot tell, and once over none", () => {
  assert.equal(forgetUnsavedLine(0), null);
  assert.equal(forgetUnsavedLine(1), T.FORGET_UNSAVED_ONE);
  assert.equal(forgetUnsavedLine(2), fillApproved(T.FORGET_UNSAVED_MANY, "2"));
  assert.equal(forgetUnsavedLine(COUNT_UNKNOWN), T.FORGET_UNSAVED_UNKNOWN, "cannot tell is said, never as none");
  // None: the first click forgets. Captures, or cannot tell: the first click arms, the second forgets.
  assert.deepEqual(unsavedArmStep(null, 0, false), { act: true, armed: null });
  assert.deepEqual(unsavedArmStep(null, 2, false), { act: false, armed: 2 });
  assert.deepEqual(unsavedArmStep(2, 2, false), { act: true, armed: null });
  assert.deepEqual(unsavedArmStep(null, COUNT_UNKNOWN, false), { act: false, armed: COUNT_UNKNOWN });
  assert.deepEqual(unsavedArmStep(COUNT_UNKNOWN, COUNT_UNKNOWN, false), { act: true, armed: null });
  assert.deepEqual(unsavedArmStep(COUNT_UNKNOWN, 3, false), { act: false, armed: 3 }, "a count read at the second click arms again with it");
  const options = readFileSync(fileURLToPath(new URL("./options.ts", import.meta.url)), "utf8");
  const click = options.slice(options.indexOf('serverForget.addEventListener("click"'), options.indexOf('serverForget.addEventListener("blur"'));
  const arm = click.indexOf("const step = unsavedArmStep(forgetArmed, now, false);");
  assert.ok(arm > -1, "the click reads the count and arms through the shared step");
  assert.ok(click.indexOf('await send({ type: "forgetServer" })') > arm, "and forgets only after it");
  assert.ok(click.includes("serverForget.textContent = T.FORGET_CONFIRM;"));
  assert.ok(click.includes('serverForgetNote.textContent = forgetUnsavedLine(now) ?? "";'));
  assert.ok(options.includes("return typeof s?.unsavedCaptures === \"number\" ? s.unsavedCaptures : COUNT_UNKNOWN;"), "no answer is cannot tell");
});
