// node --test. A drawn walk of the popup (testing/popupkit.ts: popup.ts as the desktop bundle, against a stand-in DOM,
// pressed as a person presses it): the refusal of another account under a known address with its offer, the second
// confirmation, the notice after the forgetting and the one at the next sign-in; and the notice for an end this browser
// could not confirm, with logins caught and not saved: one, many, a number not known. Lines are named by their keys.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import {
  ACCOUNT_REMEMBERED,
  FORGET_EARLIER_CONFIRM,
  FORGET_EARLIER_CONFIRM_BUTTON,
  FORGET_EARLIER_DONE,
  FORGET_EARLIER_OFFER,
  fillApproved,
  sessionNotConfirmedNotice,
  unlockErrorMessage,
} from "./errors.ts";
import { drawPopup, lockedStatus, textOf, type Answer } from "./testing/popupkit.ts";

const EMAIL = "alice@example.com";
const fire = (e: Record<string, unknown>, type: string, props: Record<string, unknown> = {}) => (e.fire as (t: string, p: Record<string, unknown>) => Promise<unknown>)(type, props);

test("the walk of the way out: the refusal and its offer, the second confirmation, the notice after it, and the one at the next sign-in", async () => {
  let forgotten = false;
  const answer: Answer = (msg) => {
    switch (msg.type) {
      case "serverInfo":
        return { url: "https://vault.example", trustedStore: true, block: null };
      case "status":
        return { ...lockedStatus };
      case "unlock":
        return forgotten ? { ok: false, code: "aborted" } : { ok: false, code: "remade_account" };
      case "forgetEarlierAccount":
        forgotten = true;
        return { ok: true };
      default:
        return undefined;
    }
  };
  const p = await drawPopup(answer);
  try {
    await p.settle(150);
    p.byId("email").value = EMAIL;
    p.byId("password").value = "correct horse";
    await fire(p.byId("unlock"), "click");
    await p.settle(30);
    const msg = p.byId("msg");
    const refusal = unlockErrorMessage("remade_account", EMAIL);
    assert.ok(textOf(msg).includes(refusal.body), "the refusal for another account under a known address");
    const b = p.byId("forget-earlier");
    assert.equal(b.hidden, false);
    assert.equal(b.textContent, FORGET_EARLIER_OFFER, "its offer");
    await fire(b, "pointerdown");
    await fire(b, "click");
    assert.equal(textOf(msg), fillApproved(FORGET_EARLIER_CONFIRM, EMAIL), "the second confirmation, naming the address");
    assert.equal(b.textContent, FORGET_EARLIER_CONFIRM_BUTTON);
    assert.equal(p.page.active, msg, "the focus is on the confirmation, not on the button");
    p.clock.now += 1_500;
    await fire(b, "pointerdown");
    await fire(b, "click");
    await p.settle(30);
    assert.equal(textOf(msg), FORGET_EARLIER_DONE, "the notice after it");
    assert.equal(b.hidden, true, "the offer is gone");
    assert.deepEqual(p.errors, []);
  } finally {
    p.dispose();
  }
});

test("the notice at the first sign-in after the forgetting", async () => {
  const answer: Answer = (msg) => {
    switch (msg.type) {
      case "serverInfo":
        return { url: "https://vault.example", trustedStore: true, block: null };
      case "status":
        return { ...lockedStatus };
      case "unlock":
        return { ok: true, notice: "account_remembered" };
      default:
        return undefined;
    }
  };
  const p = await drawPopup(answer);
  try {
    await p.settle(150);
    p.byId("email").value = EMAIL;
    p.byId("password").value = "new horse";
    await fire(p.byId("unlock"), "click");
    await p.settle(60);
    assert.equal(textOf(p.byId("msg")), ACCOUNT_REMEMBERED);
  } finally {
    p.dispose();
  }
});

for (const [name, unsaved] of [["none", 0], ["one", 1], ["many", 4], ["a number not known", null]] as const) {
  test(`the notice for an end this browser could not confirm, with logins caught and not saved: ${name}`, async () => {
    const answer: Answer = (msg) => {
      switch (msg.type) {
        case "serverInfo":
          return { url: "https://vault.example", trustedStore: true, block: null };
        case "status":
          return { ...lockedStatus, unlocked: true, email: EMAIL, serverEnded: true, serverEndedUnconfirmed: true, ...(unsaved === null ? {} : { unsavedCaptures: unsaved }) };
        case "matches":
          return { locked: false, matches: [] };
        case "allItems":
          return { locked: false, items: [] };
        case "cardItems":
          return { locked: false, items: [] };
        case "cardFillOffers":
          return { fillable: false, origin: null, frames: [], pageFormOnly: false };
        default:
          return undefined;
      }
    };
    const p = await drawPopup(answer);
    try {
      await p.settle(200);
      assert.equal(p.byId("unlocked").hidden, false, "the copy stays readable");
      assert.equal(textOf(p.byId("msg")), sessionNotConfirmedNotice(unsaved));
      assert.equal(p.byId("qu-offer").hidden, true, "no quick unlock offered while it stands");
    } finally {
      p.dispose();
    }
  });
}
