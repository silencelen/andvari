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
import { classifyCardField, classifyCardSelect, demoteCsc, formlessGroups, isCvvNameOrId } from "./detect.ts";
import type { FieldSignal } from "./urimatch.ts";

const sig = (over: Partial<FieldSignal>): FieldSignal => ({ hints: [], htmlType: "text", htmlNameOrId: null, ...over });

/** Form-level verdict, mirroring buildLoginForm/buildCardForm's shared logic over FieldSignals:
 *  per-field kind, the cardnumber-anchor card-form test, the form-level CSC demotion, and the
 *  [A7] login-save-suppression gate. */
function formVerdict(fields: FieldSignal[]) {
  const cardKinds = fields.map((f) => classifyCardField(f));
  const isCardForm = cardKinds.includes("cardnumber");
  const kinds = fields.map((f, i) => (isCardForm ? demoteCsc(cardKinds[i]!, f.htmlType ?? "", f.htmlNameOrId ?? "", "") : cardKinds[i]!));
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
  assert.equal(demoteCsc(null, "password", "securityCode", ""), "cardcvv");
  assert.equal(demoteCsc(null, "password", "password", ""), null); // real password not relabelled
  assert.equal(demoteCsc(null, "text", "cvv", ""), null); // a text CSC isn't demoted here (it classifies directly)
  assert.equal(demoteCsc("cardnumber", "password", "cvv", ""), "cardnumber"); // an existing kind is never overwritten
});

test("demoteCsc — §8/F29 name and id checked INDEPENDENTLY (the `name || id` shadowing bug)", () => {
  // The shipped single `name || id` argument let a garbage name shadow a CVV id.
  assert.equal(demoteCsc(null, "password", "field_7", "cardCvc"), "cardcvv");
  assert.equal(demoteCsc(null, "password", "cardCvc", ""), "cardcvv");
  assert.equal(demoteCsc(null, "password", "field_7", "field_8"), null); // neither string reads CVV
  assert.equal(demoteCsc(null, "select-one", "cvv", "cvv"), null); // never a select
});

// ---- Tier 1 (design 2026-07-23-card-autofill-tier1): cardtype, gift guard, id retry, selects ----

test("classifyCardField — cardtype hint + name tokens (§2)", () => {
  assert.equal(classifyCardField(sig({ hints: ["cc-type"] })), "cardtype"); // normalizes to cctype
  assert.equal(classifyCardField(sig({ htmlNameOrId: "cardType" })), "cardtype");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "cc_type" })), "cardtype");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "ccBrand" })), "cardtype");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "cbtype" })), "cardtype");
});

test("classifyCardField — [T10] gift guard suppresses the token-path PAN verdict, per-string", () => {
  // name path: a gift-card number is NEVER a card-number anchor…
  assert.equal(classifyCardField(sig({ htmlNameOrId: "giftCardNumber" })), null);
  assert.equal(classifyCardField(sig({ htmlNameOrId: "loyaltyCardNo" })), null);
  assert.equal(classifyCardField(sig({ htmlNameOrId: "voucher_card_number" })), null);
  // …the id path suppresses off the id's OWN tokens (garbage name + gift id):
  assert.equal(classifyCardField(sig({ htmlNameOrId: "acct" }), "giftCardNumber"), null);
  // suppression is TERMINAL: a gift verdict on the name is a verdict — the id must not resurrect it.
  assert.equal(classifyCardField(sig({ htmlNameOrId: "giftCardNumber" }), "cardNumber"), null);
  // suppress-only: non-number kinds on a gifty string are untouched (anchor-only guard).
  assert.equal(classifyCardField(sig({ htmlNameOrId: "giftCardExpiry" })), "cardexpiry");
  // the autocomplete-hint path is NOT guarded — an explicit hint is the site's own claim.
  assert.equal(classifyCardField(sig({ hints: ["cardnumber"], htmlNameOrId: "giftCardNumber" })), "cardnumber");
});

test("classifyCardField — trailing-digit names classify HERE, not in core (deliberate divergence)", () => {
  // The ext tokenizer's letter↔digit boundary makes "cardNumber2" → [card,number,2] → the
  // whole-run "cardnumber" matches; core keeps digits glued ([card,number2] → NONE). Both sides
  // pin their OWN behavior (core: cardform.json "trailing digit stays glued") until the Tier-2
  // vocabulary lane aligns the tokenizers — see the tokens() doc comment in detect.ts.
  assert.equal(classifyCardField(sig({ htmlType: "tel", htmlNameOrId: "cardNumber2" })), "cardnumber");
});

test("classifyCardField — §8 htmlId retry, both misclassification directions", () => {
  // recovery: garbage name, classifiable id (incl. the EMPTY-name variant, where htmlNameOrId
  // already fell back to the id in fieldSignalOf — the retry is then a harmless re-run).
  assert.equal(classifyCardField(sig({ htmlNameOrId: "field_7" }), "cardNumber"), "cardnumber");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "input_2", htmlType: "tel" }), "expMonth"), "cardexpmonth");
  // direction 1: a login-classified field never card-classifies, whatever its id says.
  assert.equal(classifyCardField(sig({ htmlType: "password", htmlNameOrId: "password" }), "cardCvc"), null);
  assert.equal(classifyCardField(sig({ htmlNameOrId: "username" }), "cardNumber"), null);
  // direction 2: a name card verdict WINS — the id is not consulted after it.
  assert.equal(classifyCardField(sig({ htmlNameOrId: "expMonth" }), "expYear"), "cardexpmonth");
  // no signal on either string stays null.
  assert.equal(classifyCardField(sig({ htmlNameOrId: "field_7" }), "field_8"), null);
});

test("classifyCardSelect — restricted to select-meaningful kinds, hints first, id retry (§1/§8)", () => {
  assert.equal(classifyCardSelect("expMonth", null, []), "cardexpmonth");
  assert.equal(classifyCardSelect("expYear", null, []), "cardexpyear");
  assert.equal(classifyCardSelect("expiry", null, []), "cardexpiry");
  assert.equal(classifyCardSelect("cardType", null, []), "cardtype");
  assert.equal(classifyCardSelect(null, null, ["cc-exp-month"]), "cardexpmonth"); // hint path, normalized
  assert.equal(classifyCardSelect(null, null, ["cc-type"]), "cardtype");
  // §0: a select can never be a PAN/CVV/name field — those verdicts restrict to null…
  assert.equal(classifyCardSelect("cardNumber", null, []), null);
  assert.equal(classifyCardSelect("cvv", null, []), null);
  assert.equal(classifyCardSelect("nameOnCard", null, []), null);
  assert.equal(classifyCardSelect(null, null, ["cc-number"]), null); // …on the hint path too
  // id retry mirrors the input path.
  assert.equal(classifyCardSelect("field_3", "expYear", []), "cardexpyear");
  // a name card verdict (even one restricted away) stops the id retry.
  assert.equal(classifyCardSelect("cardNumber", "expYear", []), null);
  // no card signal at all → null.
  assert.equal(classifyCardSelect("country", null, []), null);
});

// ---- [T1] formless grouping: select-blind clustering + post-attach ----
// The pure suite has no DOM; formlessGroups is structural (parentElement climbs + `contains`),
// so minimal node stubs suffice. `instanceof HTMLInputElement` discharges against globals we
// install here — node has none, and detect.ts resolves the identifier at call time.
class StubNode {
  parent: StubNode | null = null;
  get parentElement(): StubNode | null {
    return this.parent;
  }
  contains(other: unknown): boolean {
    for (let n = other as StubNode | null; n; n = n.parent) if (n === this) return true;
    return false;
  }
  append(...kids: StubNode[]): void {
    for (const k of kids) k.parent = this;
  }
}
class StubInput extends StubNode {}
class StubSelect extends StubNode {}
(globalThis as any).HTMLInputElement = StubInput;
(globalThis as any).HTMLSelectElement = StubSelect;

const stubField = (input: StubNode, kind: string, cardKind: string | null = null) =>
  ({ input, kind, isNewPassword: false, textLike: false, cardKind }) as any;

test("[T1] formless clustering is select-blind: expiry selects + password CVV beside a PAN row stay ONE cluster", () => {
  // <div P> <div row1> <select expMonth> <select expYear> <input password cvv> </div>
  //         <div row2> <input text cardnumber> </div> </div>
  const root = new StubNode();
  const p = new StubNode();
  const row1 = new StubNode();
  const row2 = new StubNode();
  root.append(p);
  p.append(row1, row2);
  const selMonth = new StubSelect();
  const selYear = new StubSelect();
  const cvv = new StubInput();
  const pan = new StubInput();
  row1.append(selMonth, selYear, cvv);
  row2.append(pan);
  const groups = formlessGroups(
    [stubField(selMonth, "none", "cardexpmonth"), stubField(selYear, "none", "cardexpyear"), stubField(cvv, "password"), stubField(pan, "none", "cardnumber")] as any,
    root as any,
  );
  // Pre-[T1] regression shape: the CVV's climb stopped at row1 (the selects satisfied the
  // early-stop), splitting the PAN into a second group and killing the CVV fill + demotion.
  assert.equal(groups.length, 1);
  assert.equal(groups[0]!.container, p as any); // the climb passed row1 — only ONE input-backed field there
  assert.deepEqual(new Set(groups[0]!.fields.map((f: any) => f.input)), new Set([selMonth, selYear, cvv, pan]));
});

test("[T1] a select outside every formed group rides the root leftover group", () => {
  const root = new StubNode();
  const w1 = new StubNode();
  const w2 = new StubNode();
  root.append(w1, w2);
  const user = new StubInput();
  const pass = new StubInput();
  w1.append(user, pass);
  const stray = new StubSelect();
  w2.append(stray);
  const groups = formlessGroups([stubField(user, "username"), stubField(pass, "password"), stubField(stray, "none", "cardexpmonth")] as any, root as any);
  assert.equal(groups.length, 2);
  assert.equal(groups[0]!.container, w1 as any); // the login widget is untouched (bit-identity)
  assert.deepEqual(new Set(groups[0]!.fields.map((f: any) => f.input)), new Set([user, pass]));
  assert.equal(groups[1]!.container, root as any);
  assert.deepEqual(groups[1]!.fields.map((f: any) => f.input), [stray]);
});
