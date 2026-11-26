// node --test. "Forget this server" in the popup, drawn (testing/popupkit.ts): with logins or cards caught and not saved,
// its first click says how many and its second forgets; that second step has the guard of "Forget the earlier account":
// it is taken only from a press (or a click with no press, as assistive technology sends it) begun a moment after the
// first click's line stood, never by two clicks in one turn, a double click or a held key; with none waiting it forgets
// at once, as before.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import * as T from "./copy.ts";
import { forgetUnsavedLine } from "./unsavedarm.ts";
import { drawPopup, lockedStatus, textOf, type Answer } from "./testing/popupkit.ts";

const ORIGIN = "https://vault.example";

/** A worker stopped at a fork of its server (the popup's stop card), with [unsaved] captures waiting. */
function forkedWorker(unsaved: number): Answer {
  return (msg) => {
    switch (msg.type) {
      case "serverInfo":
        return { url: ORIGIN, trustedStore: true, block: { kind: "fork", origin: ORIGIN } };
      case "status":
        return { ...lockedStatus, unsavedCaptures: unsaved };
      case "forgetServer":
        return { ok: true };
      default:
        return undefined;
    }
  };
}

const fire = (e: Record<string, unknown>, type: string, props: Record<string, unknown> = {}) => (e.fire as (t: string, p: Record<string, unknown>) => Promise<unknown>)(type, props);

async function stopCard(unsaved: number) {
  const p = await drawPopup(forkedWorker(unsaved));
  await p.settle(150);
  const b = p.byId("confirm-server-not-mine");
  assert.equal(b.hidden, false, "the stop card offers Forget this server");
  assert.equal(b.textContent, T.FORGET_THIS_SERVER);
  return { p, b, forgets: () => p.sent.filter((m) => m.type === "forgetServer").length };
}

test("two clicks in one turn, a double click or a held key never take the second step", async () => {
  const { p, b, forgets } = await stopCard(2);
  try {
    assert.deepEqual(p.errors, []);
    await Promise.all([fire(b, "click"), fire(b, "click")]);
    await p.settle(20);
    assert.equal(forgets(), 0, "two clicks in one turn");
    assert.equal(b.textContent, T.FORGET_CONFIRM, "the first step stands");
    assert.ok(textOf(p.byId("msg")).includes(forgetUnsavedLine(2)!), "and says the count");
    assert.equal(p.page.active, p.byId("msg"), "the first step moved the focus off the button, to its line");
    // A double click: a second press a tenth of a second later.
    p.clock.now += 100;
    await fire(b, "pointerdown");
    await fire(b, "click");
    await p.settle(20);
    assert.equal(forgets(), 0, "a double click");
    const said = textOf(p.byId("msg"));
    assert.ok(said.includes(T.FORGET_SERVER_READ_FIRST), "the popup says to read the line first");
    assert.ok(said.includes(forgetUnsavedLine(2)!), "and the line stays");
    // A held key: its repeats never start a press.
    p.clock.now += 2_000;
    await fire(b, "keydown", { key: "Enter", repeat: true });
    await fire(b, "click");
    await p.settle(20);
    assert.equal(forgets(), 0, "a held key");
    // A press begun after the line stood for a moment takes it.
    await fire(b, "pointerdown");
    await fire(b, "click");
    await p.settle(20);
    assert.equal(forgets(), 1, "a deliberate press");
  } finally {
    p.dispose();
  }
});

test("a click with no press, as assistive technology sends it: inside the second it is not taken; at five seconds it is", async () => {
  const { p, b, forgets } = await stopCard(1);
  try {
    await fire(b, "click"); // the first step
    await p.settle(20);
    const armed = p.clock.now;
    p.clock.now = armed + 500;
    await fire(b, "click");
    await p.settle(20);
    assert.equal(forgets(), 0, "a bare click inside the second");
    assert.ok(textOf(p.byId("msg")).includes(T.FORGET_SERVER_READ_FIRST));
    p.clock.now = armed + 5_000;
    await fire(b, "click");
    await p.settle(20);
    assert.equal(forgets(), 1, "a bare click at five seconds");
  } finally {
    p.dispose();
  }
});

test("with nothing waiting to be saved, one click forgets at once, as before", async () => {
  const { p, b, forgets } = await stopCard(0);
  try {
    await fire(b, "pointerdown");
    await fire(b, "click");
    await p.settle(20);
    assert.equal(forgets(), 1);
  } finally {
    p.dispose();
  }
});
