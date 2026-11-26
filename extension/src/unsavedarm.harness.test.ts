// node --test. Design §4.4 (decided on 2026-11-17): nothing this browser holds that was not sent is deleted without the
// person having been told how many. What the extension holds of that kind is what it captured on pages and has not saved
// (it keeps no queue of changes); the worker counts those for the popup, through the real background.ts
// (testing/bgharness.ts), and the popup's Sign out and Lock say the count on their first click (unsavedarm.ts).
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import * as T from "./copy.ts";
import { fillApproved } from "./errors.ts";
import { signedInWorld } from "./testing/bgharness.ts";
import { unsavedArmStep, unsavedCapturesLine } from "./unsavedarm.ts";

const SHOP = "https://shop.example";
const NEWS = "https://news.example";

test("the worker counts the logins captured on pages and not saved: a Save takes one off, and a lock deletes the rest", async () => {
  const { w } = await signedInWorld();
  assert.equal((await w.popup({ type: "status" })).unsavedCaptures, 0);
  await w.page({ type: "capturedCredential", username: "alice", password: "shop-pw" }, 4, SHOP);
  await w.page({ type: "capturedCredential", username: "bea", password: "news-pw" }, 5, NEWS);
  assert.equal((await w.popup({ type: "status" })).unsavedCaptures, 2, "two tabs hold a capture each");
  assert.equal((await w.page({ type: "resolvePendingSave", action: "save" }, 4, SHOP)).ok, true);
  assert.equal((await w.popup({ type: "status" })).unsavedCaptures, 1, "a saved capture is no longer at stake");
  // The lock deletes the other one (a page's password is not kept past a lock): that is why the popup asks first.
  await w.popup({ type: "lock" });
  assert.equal((await w.popup({ type: "status" })).unsavedCaptures, 0);
});

test("a sign-out deletes the captures too, including one made while locked", async () => {
  const { w } = await signedInWorld();
  await w.popup({ type: "lock" });
  await w.page({ type: "capturedCredential", username: "alice", password: "shop-pw" }, 4, SHOP);
  assert.equal((await w.popup({ type: "status" })).unsavedCaptures, 1, "a capture made while locked is counted while locked");
  await w.popup({ type: "signOut" });
  assert.equal((await w.popup({ type: "status" })).unsavedCaptures, 0);
});

test("Sign out asks once and Lock asks only over captures; neither acts on a first click over captures, and a moved count arms again", () => {
  // Sign out: always asked once, as before; the second click over the same count signs out.
  assert.deepEqual(unsavedArmStep(null, 0, true), { act: false, armed: 0 });
  assert.deepEqual(unsavedArmStep(0, 0, true), { act: true, armed: null });
  assert.deepEqual(unsavedArmStep(null, 2, true), { act: false, armed: 2 });
  assert.deepEqual(unsavedArmStep(2, 2, true), { act: true, armed: null });
  assert.deepEqual(unsavedArmStep(2, 3, true), { act: false, armed: 3 }, "a capture landed between the clicks");
  assert.deepEqual(unsavedArmStep(2, 0, true), { act: true, armed: null }, "everything was saved meanwhile");
  // Lock: one click with nothing at stake; two over captures.
  assert.deepEqual(unsavedArmStep(null, 0, false), { act: true, armed: null });
  assert.deepEqual(unsavedArmStep(null, 1, false), { act: false, armed: 1 });
  assert.deepEqual(unsavedArmStep(1, 1, false), { act: true, armed: null });
});

test("the line says how many, for the act it is about, and how to save them first only where saving is possible", () => {
  assert.equal(unsavedCapturesLine("signout", 0, true), null);
  assert.equal(unsavedCapturesLine("signout", 1, false), T.SIGN_OUT_UNSAVED_ONE);
  assert.equal(unsavedCapturesLine("signout", 3, true), `${fillApproved(T.SIGN_OUT_UNSAVED_MANY, "3")} ${T.UNSAVED_SAVE_FIRST}`);
  assert.equal(unsavedCapturesLine("lock", 1, true), `${T.LOCK_UNSAVED_ONE} ${T.UNSAVED_SAVE_FIRST}`);
  assert.equal(unsavedCapturesLine("lock", 2, false), fillApproved(T.LOCK_UNSAVED_MANY, "2"));
});

test("the popup's Sign out and Lock read the count at each click and go through the step", () => {
  const popup = readFileSync(fileURLToPath(new URL("./popup.ts", import.meta.url)), "utf8");
  const signOut = popup.slice(popup.indexOf('el("sign-out").addEventListener("click"'), popup.indexOf('el("sign-out").addEventListener("blur"'));
  assert.match(signOut, /const now = await unsavedNow\(\);\s*const step = unsavedArmStep\(signOutArmed, now\.count, true\);\s*if \(!step\.act\) \{/);
  assert.ok(signOut.indexOf("return;") < signOut.indexOf('ask({ type: "signOut" })'), "nothing is signed out on an arming click");
  const lock = popup.slice(popup.indexOf('el("lock").addEventListener("click"'), popup.indexOf('el("lock").addEventListener("blur"'));
  assert.match(lock, /const now = await unsavedNow\(\);\s*const step = unsavedArmStep\(lockArmed, now\.count, false\);\s*if \(!step\.act\) \{/);
  assert.ok(lock.indexOf("return;") < lock.indexOf('ask({ type: "lock" })'), "nothing is locked on an arming click");
});

test("the Lock button's word is the LOCK line's, set when the popup loads, not only after a first click was taken back", () => {
  const popup = readFileSync(fileURLToPath(new URL("./popup.ts", import.meta.url)), "utf8");
  const at = popup.indexOf('el("lock").addEventListener("click"');
  const before = popup.slice(popup.indexOf("let lockArmed: number | null = null;"), at);
  // Once in disarmLock, once at load (outside any function).
  assert.equal(before.match(/el\("lock"\)\.textContent = T\.LOCK;/g)?.length, 2);
  assert.match(before, /\n\}\n(?:\/\/[^\n]*\n)?el\("lock"\)\.textContent = T\.LOCK;\n/);
});
