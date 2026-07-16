// Runs under Node's built-in runner (node --test); type-stripped natively.
// Excluded from tsc (tsconfig `exclude`) — like updateverify.test.ts. `npm test` runs it.
//
// Pins the S3 card-classification rules (design 2026-07-10-extension-card-fill) at the PURE level:
// detect.ts's DOM entry points (findCardForms / findLoginForms) can't run here (no DOM), but the
// verdict logic is factored into pure functions (classifyCardField / demoteCsc / isCvvNameOrId)
// that take FieldSignals — the same shape core FieldClassifier vector-tests. Both misclassification
// directions ([A8]) and the capture/save gate ([A7]) are anchored here.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { classifyCardField, demoteCsc, isCvvNameOrId } from "./detect.ts";
import type { FieldSignal } from "./urimatch.ts";

const sig = (over: Partial<FieldSignal>): FieldSignal => ({ hints: [], htmlType: "text", htmlNameOrId: null, ...over });

/** Form-level verdict, mirroring buildLoginForm/buildCardForm's shared logic over FieldSignals:
 *  per-field kind, the cardnumber-anchor card-form test, the form-level CSC demotion, and the
 *  [A7] login-save-suppression gate. */
function formVerdict(fields: FieldSignal[]) {
  const cardKinds = fields.map(classifyCardField);
  const isCardForm = cardKinds.includes("cardnumber");
  const kinds = fields.map((f, i) => (isCardForm ? demoteCsc(cardKinds[i]!, f.htmlType ?? "", f.htmlNameOrId ?? "") : cardKinds[i]!));
  return { kinds, isCardForm, suppressLoginSave: isCardForm };
}

test("classifyCardField — name/id token runs → kinds (core CARD_NAME_KINDS parity)", () => {
  assert.equal(classifyCardField(sig({ htmlNameOrId: "cardnumber" })), "cardnumber");
  assert.equal(classifyCardField(sig({ htmlType: "tel", htmlNameOrId: "cardNumber" })), "cardnumber"); // tel is a fallback type
  assert.equal(classifyCardField(sig({ htmlType: "number", htmlNameOrId: "cardNum" })), "cardnumber");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "expiry" })), "cardexpiry");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "expMonth" })), "cardexpmonth"); // month/year win over generic exp
  assert.equal(classifyCardField(sig({ htmlNameOrId: "expYear" })), "cardexpyear");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "nameOnCard" })), "cardname");
  assert.equal(classifyCardField(sig({ htmlType: "number", htmlNameOrId: "cvv" })), "cardcvv");
});

test("classifyCardField — autocomplete card hints (post-fieldSignalOf mapping) → kinds", () => {
  // fieldSignalOf maps cc-number→cardnumber and cc-csc→creditcardsecuritycode; cc-exp* pass through.
  assert.equal(classifyCardField(sig({ hints: ["cardnumber"] })), "cardnumber");
  assert.equal(classifyCardField(sig({ hints: ["creditcardsecuritycode"], htmlType: "password" })), "cardcvv"); // negative login hint → none gap
  assert.equal(classifyCardField(sig({ hints: ["cc-exp"] })), "cardexpiry");
  assert.equal(classifyCardField(sig({ hints: ["cc-exp-month"] })), "cardexpmonth");
  assert.equal(classifyCardField(sig({ hints: ["cc-name"] })), "cardname");
});

test("classifyCardField — [A8] fires ONLY in the classify==none gap (login verdicts win)", () => {
  // A field the login classifier claims keeps its verdict — a card kind never outranks it.
  assert.equal(classifyCardField(sig({ htmlType: "password", htmlNameOrId: "cardPassword" })), null); // password type stays password
  assert.equal(classifyCardField(sig({ htmlType: "text", htmlNameOrId: "username" })), null); // NAME_POSITIVE_USER → username
  assert.equal(classifyCardField(sig({ htmlType: "email", htmlNameOrId: "email" })), null); // email → username
  // Name-keyword card fallback never fires from a password type (only the form-level CSC demotion may).
  assert.equal(classifyCardField(sig({ htmlType: "password", htmlNameOrId: "securityCode" })), null);
});

test("classifyCardField — [A8] hostile/edge inputs do not over-fire", () => {
  // A coupon field named like a code is NOT a card field (no card-name token run).
  assert.equal(classifyCardField(sig({ htmlNameOrId: "couponCode" })), null);
  // Cardholder name WITHOUT a PAN is a card-NAME kind but (see formVerdict) never a card FORM.
  assert.equal(classifyCardField(sig({ htmlNameOrId: "cardholder" })), "cardname");
});

test("[A7] a card form (cardnumber anchor) is EXCLUDED from the login save path — the 0.13.0 bug", () => {
  // The confirmed shipped bug: <input type=password name=securityCode> beside a text cardnumber
  // was offered as a login save (overwriting a stored merchant password with a CVV).
  const v = formVerdict([sig({ htmlType: "password", htmlNameOrId: "securityCode" }), sig({ htmlType: "text", htmlNameOrId: "cardnumber" })]);
  assert.equal(v.isCardForm, true);
  assert.equal(v.suppressLoginSave, true); // MUST NOT be offered as a login save
  assert.deepEqual(v.kinds, ["cardcvv", "cardnumber"]); // the password securityCode demoted to the CVV
});

test("[A7] a REAL password beside a card number is still a card form (whole-form save suppressed)", () => {
  const v = formVerdict([sig({ htmlType: "text", htmlNameOrId: "cardnumber" }), sig({ htmlType: "password", htmlNameOrId: "password" })]);
  assert.equal(v.suppressLoginSave, true);
  assert.deepEqual(v.kinds, ["cardnumber", null]); // the genuine password is NOT relabelled a CVV
});

test("[A8](a) a pure login form NEVER classifies as a card form", () => {
  const v = formVerdict([sig({ htmlType: "text", htmlNameOrId: "username" }), sig({ htmlType: "password", htmlNameOrId: "password" })]);
  assert.equal(v.isCardForm, false);
  assert.equal(v.suppressLoginSave, false);
  assert.deepEqual(v.kinds, [null, null]);
});

test("[A8] card kinds without a PAN anchor NEVER qualify a card form", () => {
  // Two generic expiry-ish fields + a name, but no card NUMBER → not a card form (core CardForm parity).
  const v = formVerdict([sig({ htmlNameOrId: "cardholder" }), sig({ htmlNameOrId: "expiry" })]);
  assert.equal(v.isCardForm, false);
  assert.equal(v.suppressLoginSave, false);
});

test("[A8](b) a full card form classifies every field to its card kind", () => {
  const v = formVerdict([
    sig({ htmlType: "text", htmlNameOrId: "cardnumber" }),
    sig({ htmlType: "text", htmlNameOrId: "nameOnCard" }),
    sig({ htmlType: "text", htmlNameOrId: "expiry" }),
    sig({ htmlType: "password", htmlNameOrId: "cvv" }),
  ]);
  assert.equal(v.isCardForm, true);
  assert.deepEqual(v.kinds, ["cardnumber", "cardname", "cardexpiry", "cardcvv"]);
});

test("isCvvNameOrId — [A7] broadened to full core CSC_DEMOTION parity", () => {
  // The tight 0.13.0 set stays true…
  assert.equal(isCvvNameOrId("cvv"), true);
  assert.equal(isCvvNameOrId("cvc2"), true);
  assert.equal(isCvvNameOrId("csc"), true);
  assert.equal(isCvvNameOrId("cardCvc"), true);
  // …and the graduating tokens are now recognised (this is what fixes the save-overwrite bug):
  assert.equal(isCvvNameOrId("securityCode"), true);
  assert.equal(isCvvNameOrId("cardVerificationValue"), true); // [card,verification,value] → "cardverification" run
  // Still never a substring / a real password / a plural:
  assert.equal(isCvvNameOrId("password"), false);
  assert.equal(isCvvNameOrId("mycvv"), false);
  assert.equal(isCvvNameOrId("securityCodes"), false);
  assert.equal(isCvvNameOrId(""), false);
});

test("demoteCsc — only a password-typed CSC-named field demotes; a non-card kind or non-password stays", () => {
  assert.equal(demoteCsc(null, "password", "securityCode"), "cardcvv");
  assert.equal(demoteCsc(null, "password", "password"), null); // real password not relabelled
  assert.equal(demoteCsc(null, "text", "cvv"), null); // a text CSC isn't demoted here (it classifies directly)
  assert.equal(demoteCsc("cardnumber", "password", "cvv"), "cardnumber"); // an existing kind is never overwritten
});
