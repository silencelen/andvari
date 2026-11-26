// node --test. "Forget the earlier account on this device" in the popup, drawn: the desktop popup loaded against a
// stand-in DOM (testing/popupkit.ts) and pressed as a person presses it. The offer is drawn at the refusal on the
// password step and on the one-time-code step; its second step is taken only from a press that began after the
// confirmation stood on the screen for a moment, never by two clicks in one turn, a double click or a held key.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { FORGET_EARLIER_CONFIRM, FORGET_EARLIER_READ_FIRST, fillApproved } from "./errors.ts";
import { drawPopup, lockedStatus, textOf, type Answer } from "./testing/popupkit.ts";

const EMAIL = "alice@example.com";

/** A worker that refuses the sign-in (or its code step, with [viaCode]) as another account under a known address. */
function refusingWorker(viaCode: boolean): Answer {
  return (msg) => {
    switch (msg.type) {
      case "serverInfo":
        return { url: "https://vault.example", trustedStore: true, block: null };
      case "status":
        return { ...lockedStatus };
      case "unlock":
        return viaCode ? { ok: false, code: "totp_required" } : { ok: false, code: "remade_account" };
      case "unlockTotp":
        return { ok: false, code: "remade_account" };
      case "cancelTotp":
        return { ok: true };
      case "forgetEarlierAccount":
        return { ok: true };
      default:
        return undefined;
    }
  };
}

async function refusedPopup(viaCode: boolean) {
  const p = await drawPopup(refusingWorker(viaCode));
  await p.settle(150);
  p.byId("email").value = EMAIL;
  p.byId("password").value = "correct horse";
  await (p.byId("unlock").fire as (t: string) => Promise<unknown>)("click");
  await p.settle(30);
  if (viaCode) {
    p.byId("totp-code").value = "123456";
    await (p.byId("totp-verify").fire as (t: string) => Promise<unknown>)("click");
    await p.settle(30);
  }
  return p;
}

const fire = (e: Record<string, unknown>, type: string, props: Record<string, unknown> = {}) => (e.fire as (t: string, p: Record<string, unknown>) => Promise<unknown>)(type, props);
const forgets = (p: Awaited<ReturnType<typeof drawPopup>>) => p.sent.filter((m) => m.type === "forgetEarlierAccount").length;

for (const viaCode of [false, true]) {
  test(`the offer is drawn at the refusal on the ${viaCode ? "one-time-code" : "password"} step`, async () => {
    const p = await refusedPopup(viaCode);
    try {
      assert.deepEqual(p.errors, []);
      assert.equal(p.byId("forget-earlier").hidden, false, "the button is on the screen");
    } finally {
      p.dispose();
    }
  });
}

test("two clicks in one turn, a double click or a held key never take the second step", async () => {
  const p = await refusedPopup(false);
  try {
    const b = p.byId("forget-earlier");
    // Two clicks in one turn: the first shows the confirmation, the second is ignored.
    await Promise.all([fire(b, "click"), fire(b, "click")]);
    await p.settle(20);
    assert.equal(forgets(p), 0, "two clicks in one turn");
    assert.notEqual(p.page.active, b, "the first step moved the focus off the button");
    // A double click: two presses a tenth of a second apart, the second inside the moment.
    p.clock.now += 100;
    await fire(b, "pointerdown");
    await fire(b, "click");
    await p.settle(20);
    assert.equal(forgets(p), 0, "a double click");
    // A held key: its repeats never start a press.
    p.clock.now += 2_000;
    await fire(b, "keydown", { key: "Enter", repeat: true });
    await fire(b, "click");
    await p.settle(20);
    assert.equal(forgets(p), 0, "a held key");
    // A press begun after the confirmation stood for a moment takes it.
    await fire(b, "pointerdown");
    await fire(b, "click");
    await p.settle(20);
    assert.equal(forgets(p), 1, "a deliberate press");
  } finally {
    p.dispose();
  }
});

test("a click with no press, as assistive technology sends it: inside the second it is not taken and the popup says to read first; at five seconds it is taken", async () => {
  const p = await refusedPopup(false);
  try {
    const b = p.byId("forget-earlier");
    await fire(b, "click"); // the first step
    const armed = p.clock.now;
    p.clock.now = armed + 500;
    await fire(b, "click");
    await p.settle(20);
    assert.equal(forgets(p), 0, "a bare click inside the second");
    const said = textOf(p.byId("msg"));
    assert.ok(said.includes(FORGET_EARLIER_READ_FIRST), "the popup says to read the confirmation first");
    assert.ok(said.includes(fillApproved(FORGET_EARLIER_CONFIRM, EMAIL)), "and the confirmation stays");
    p.clock.now = armed + 5_000;
    await fire(b, "click");
    await p.settle(20);
    assert.equal(forgets(p), 1, "a bare click at five seconds");
  } finally {
    p.dispose();
  }
});

test("the worker is kept awake while the confirmation stands, and no longer once the step is taken", async () => {
  const p = await refusedPopup(false);
  try {
    const b = p.byId("forget-earlier");
    const awake = () => p.liveIntervals().filter((i) => i.ms !== undefined && i.ms <= 25_000 && i.ms >= 5_000);
    const before = awake().length;
    await fire(b, "click"); // the confirmation stands
    const pings = awake().slice(before);
    assert.equal(pings.length, 1, "one keepalive while the confirmation stands");
    const n = p.sent.length;
    pings[0]!.fn();
    await p.settle(10);
    assert.deepEqual(p.sent.slice(n).map((m) => m.type), ["status"], "a passive ping");
    p.clock.now += 2_000;
    await fire(b, "pointerdown");
    await fire(b, "click");
    await p.settle(20);
    assert.equal(forgets(p), 1);
    assert.equal(awake().length, before, "it ends with the step");
  } finally {
    p.dispose();
  }
});
