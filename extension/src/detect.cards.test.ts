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
import { bumpLabelGeneration, classifyCardField, classifyCardRadio, classifyCardSelect, demoteCsc, formlessGroups, isCvvNameOrId, labelSourcesOf, postalIsAmbiguous } from "./detect.ts";
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

test("classifyCardField — trailing-digit names classify on BOTH engines (tokenizer PARITY, [U9])", () => {
  // The letter↔digit boundary makes "cardNumber2" → [card,number,2] → the whole-run "cardnumber"
  // matches. Core's tokens() gained the same boundary at its two card call sites (Tier 2 §1.4);
  // the flipped cardform.json alignment case pins the core side (cardNumber2 → cc-number,
  // formKind card). Recorded residual seam: an anchorless lone `cvv2` PASSWORD still diverges
  // (core demotes field-locally; the extension only form-level via demoteCsc).
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

// ---- Tier 2 (design 2026-07-23-card-autofill-tier2 §1): vocabulary widening + label signals ----

test("§1.3 vocabulary widening — i18n + phrase tokens, group order load-bearing", () => {
  assert.equal(classifyCardField(sig({ htmlNameOrId: "kartennummer" })), "cardnumber");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "numeroTarjeta" })), "cardnumber");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "ccno" })), "cardnumber");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "validThru" })), "cardexpiry");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "dateExpiration" })), "cardexpiry");
  // [U10] mirror of the urimatch classifyCard vectors: the month/year groups are ORDERED before
  // the generic exp group, else "expiryYear"'s "expiry" run would land cardexpiry.
  assert.equal(classifyCardField(sig({ htmlNameOrId: "expiryYear" })), "cardexpyear");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "expiryMonth" })), "cardexpmonth");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "cryptogramme" })), "cardcvv");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "kartenpruefnummer" })), "cardcvv");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "titulaire" })), "cardname");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "cardHolderName" })), "cardname");
});

test("[U1] bare `creditcard` is the TRAILING group — composites keep their specific kinds", () => {
  // Mirrors the urimatch classifyCard vector set at the ext pure level (§9): without the trailing
  // placement, ~50 `credit_card_*` composites would collapse to PAN and mis-arm the split-PAN
  // pre-pass + richest-form counting.
  assert.equal(classifyCardField(sig({ htmlNameOrId: "credit_card" })), "cardnumber");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "creditCard" })), "cardnumber");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "credit_card_cvv" })), "cardcvv");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "credit_card_expiry" })), "cardexpiry");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "credit_card_type" })), "cardtype");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "credit_card_holder_name" })), "cardname");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "creditCardExpirationMonth" })), "cardexpmonth");
});

test("[U2]/[U3]/[U4] dropped tokens stay none — SSN/OTP/customer-id/session false positives", () => {
  assert.equal(classifyCardField(sig({ htmlNameOrId: "social_security_number" })), null);
  assert.equal(classifyCardField(sig({ htmlType: "tel", htmlNameOrId: "phone_verification_number" })), null);
  assert.equal(classifyCardField(sig({ htmlNameOrId: "c_id" })), null); // run-match makes cid == c+id
  assert.equal(classifyCardField(sig({ htmlNameOrId: "session_expires" })), null); // bare "expires" dropped
});

test("[W4] accented name/label classification folds at the cardKindFromTokens chokepoint (reds if the fold is removed)", () => {
  // "Prüfnummer" → fold → "pruefnummer" → the shipped cc-csc keyword matches. Un-folded, tokens()
  // treats ü as a separator ([pr, fnummer]) and never matches — so removing the fold reds these.
  assert.equal(classifyCardField(sig({ htmlNameOrId: "Prüfnummer" })), "cardcvv");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "Kartenprüfnummer" })), "cardcvv");
  // the label path folds per-source-string too: "Gültig bis" → gueltig+bis → gueltigbis (cc-exp).
  assert.equal(classifyCardField(sig({ htmlNameOrId: "field_1" }), null, ["Gültig bis"]), "cardexpiry");
  // id-retry path folds as well (garbage name, accented id).
  assert.equal(classifyCardField(sig({ htmlNameOrId: "field_7" }), "Prüfnummer"), "cardcvv");
});

test("§1.3 i18n gift suppressors — cadeau/geschenk/regalo kill the PAN anchor per-string", () => {
  assert.equal(classifyCardField(sig({ htmlNameOrId: "numeroCarteCadeau" })), null);
  assert.equal(classifyCardField(sig({ htmlNameOrId: "geschenk_kartennummer" })), null);
  assert.equal(classifyCardField(sig({ htmlNameOrId: "numero_tarjeta_regalo" })), null);
  // control: the same number tokens WITHOUT a suppressor anchor normally.
  assert.equal(classifyCardField(sig({ htmlNameOrId: "numeroCarte" })), "cardnumber");
});

test("[U5] label source strings classify PER-STRING — concatenation across sources is FORBIDDEN", () => {
  // aria-label "Rewards card" + placeholder "Number of points": neither string alone carries a
  // card run; a concatenated [rewards,card,number,of,points] would fabricate "cardnumber".
  assert.equal(classifyCardField(sig({ htmlNameOrId: "field_1" }), null, ["Rewards card", "Number of points"]), null);
  // label-only positives (no name/id signal at all):
  assert.equal(classifyCardField(sig({ htmlNameOrId: "field_1" }), null, ["Card number"]), "cardnumber");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "field_1" }), null, ["CVV"]), "cardcvv");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "field_1" }), null, ["Expiry date"]), "cardexpiry");
  // first verdict wins across the ordered sources (G3: the first label must be genuinely
  // verdict-less — "Postal code" now classifies cc-postal, covered by the G3 cardpostal suite below):
  assert.equal(classifyCardField(sig({ htmlNameOrId: "field_1" }), null, ["Billing address", "Card number"]), "cardnumber");
});

test("[U6] label bounds — a string over 60 chars or 8 tokens is IGNORED, not a verdict", () => {
  const at61 = "x".repeat(49) + " card number"; // 61 chars → ignored (help-sentence over-match)
  assert.equal(at61.length, 61);
  assert.equal(classifyCardField(sig({ htmlNameOrId: "field_1" }), null, [at61]), null);
  const at60 = "x".repeat(48) + " card number"; // 60 chars → still classified
  assert.equal(at60.length, 60);
  assert.equal(classifyCardField(sig({ htmlNameOrId: "field_1" }), null, [at60]), "cardnumber");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "field_1" }), null, ["one two three four five six seven card number"]), null); // 9 tokens
  assert.equal(classifyCardField(sig({ htmlNameOrId: "field_1" }), null, ["one two three four five six card number"]), "cardnumber"); // 8 tokens
  // an ignored string is NOT terminal — a later in-bounds source may still classify.
  assert.equal(classifyCardField(sig({ htmlNameOrId: "field_1" }), null, [at61, "Card number"]), "cardnumber");
});

test("[T10] gift guard on labels — per-string, terminal (name→id terminality parity)", () => {
  assert.equal(classifyCardField(sig({ htmlNameOrId: "field_1" }), null, ["Gift card number"]), null);
  // terminal: the first string positively identified a gift-card number — a later, cleaner
  // source must not resurrect the anchor.
  assert.equal(classifyCardField(sig({ htmlNameOrId: "field_1" }), null, ["Gift card number", "Card number"]), null);
  // suppress-only: non-anchor kinds on a gifty label are untouched.
  assert.equal(classifyCardField(sig({ htmlNameOrId: "field_1" }), null, ["Gift card expiry"]), "cardexpiry");
});

test("labels are the WEAKEST signal — name/id/hint verdicts always precede ([U5] order)", () => {
  assert.equal(classifyCardField(sig({ htmlNameOrId: "expMonth" }), null, ["Card number"]), "cardexpmonth"); // name beats label
  assert.equal(classifyCardField(sig({ htmlNameOrId: "field_1" }), "expYear", ["Card number"]), "cardexpyear"); // id beats label
  assert.equal(classifyCardField(sig({ hints: ["cardnumber"], htmlNameOrId: "field_1" }), null, ["CVV"]), "cardnumber"); // hint beats label
  // a gift verdict on the NAME is terminal — labels are never consulted after it.
  assert.equal(classifyCardField(sig({ htmlNameOrId: "giftCardNumber" }), null, ["Card number"]), null);
  // [U7] accepted + vectored label poisoning: a distant/attacker-authored same-origin label makes
  // an in-gap text field on a login page classify cardnumber (no cross-origin egress — fill still
  // requires the explicit popup pick). A choice, not an accident.
  assert.equal(classifyCardField(sig({ htmlType: "text", htmlNameOrId: "field_1" }), null, ["Card number"]), "cardnumber");
  // the login gap-gate still wins over any label: a password-typed field never label-classifies.
  assert.equal(classifyCardField(sig({ htmlType: "password", htmlNameOrId: "field_1" }), null, ["CVV"]), null);
});

test("classifyCardSelect — label param parity: weakest, per-string, kind-restricted (§1.1)", () => {
  assert.equal(classifyCardSelect("field_1", null, [], ["Expiry month"]), "cardexpmonth");
  assert.equal(classifyCardSelect("field_1", null, [], ["Card type"]), "cardtype");
  assert.equal(classifyCardSelect("field_1", null, [], ["Card number"]), null); // §0 restriction holds on labels too
  assert.equal(classifyCardSelect("cardNumber", null, [], ["Expiry month"]), null); // a name verdict stops the label pass
  assert.equal(classifyCardSelect("field_1", "expYear", [], ["Expiry month"]), "cardexpyear"); // id beats label
});

// ---- G3 (design 2026-07-23 §G3): CC_POSTAL — anchor-gated, shipping-suppressor, ambiguity ----

/** Anchored card-form verdict mirror of buildCardForm ([X3-A1]): per-field classifyCardField, and
 *  ONLY when a cardnumber anchor is present, demoteCsc + the [X3-A1](ii) ambiguity drop (>1
 *  surviving cardpostal → none). Returns null when there is NO anchor — a standalone postal is not
 *  a card form, so cardpostal never emerges (login grouping stays bit-identical). */
function cardFormKinds(fields: FieldSignal[]) {
  const cardKinds = fields.map((f) => classifyCardField(f));
  if (!cardKinds.includes("cardnumber")) return null; // no anchor → not a card form
  let kinds = fields.map((f, i) => demoteCsc(cardKinds[i]!, f.htmlType ?? "", f.htmlNameOrId ?? "", ""));
  // Share the PRODUCTION count predicate (buildCardForm's line uses the same postalIsAmbiguous) —
  // no hand-mirror of the >1 comparison the [X3-A1](ii) fail-close turns on.
  if (postalIsAmbiguous(kinds)) kinds = kinds.map((k) => (k === "cardpostal" ? null : k));
  return kinds;
}

test("[X3-A1] cc-postal per-field verdict: billing* + bare postalcode token runs classify cardpostal", () => {
  assert.equal(classifyCardField(sig({ htmlNameOrId: "billingZip" })), "cardpostal");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "billing_postal" })), "cardpostal");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "cardZip" })), "cardpostal");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "avsZip" })), "cardpostal");
  assert.equal(classifyCardField(sig({ htmlNameOrId: "postal_code" })), "cardpostal"); // [postal,code] whole-run = postalcode
  // a card-free state/coupon field carries no postal token run.
  assert.equal(classifyCardField(sig({ htmlNameOrId: "state" })), null);
  assert.equal(classifyCardField(sig({ htmlNameOrId: "couponCode" })), null);
});

test("[X3-A1] anchored form → billingZip is cardpostal; STANDALONE (no PAN anchor) → none (not a card form)", () => {
  assert.deepEqual(
    cardFormKinds([sig({ htmlType: "text", htmlNameOrId: "cardnumber" }), sig({ htmlType: "text", htmlNameOrId: "billingZip" })]),
    ["cardnumber", "cardpostal"],
  );
  // standalone: no cardnumber anchor → no card form → cardpostal never emerges (the pure per-field
  // verdict above is inert without an anchor; login grouping stays bit-identical).
  assert.equal(cardFormKinds([sig({ htmlType: "text", htmlNameOrId: "billingZip" })]), null);
});

test("[X3-A1](i) shipping-suppressor: a shipping* postal string suppresses to none (per-string, terminal)", () => {
  assert.equal(classifyCardField(sig({ htmlNameOrId: "shippingPostalCode" })), null); // cardpostal + "shipping" run → suppressed
  assert.equal(classifyCardField(sig({ htmlNameOrId: "recipientPostalCode" })), null); // "recipient" suppressor
  assert.equal(classifyCardField(sig({ htmlNameOrId: "livraison_postalcode" })), null); // i18n suppressor
  // control: the SAME postal token run WITHOUT a shipping token classifies normally.
  assert.equal(classifyCardField(sig({ htmlNameOrId: "billingPostalCode" })), "cardpostal");
  // suppression is terminal per-string: a shipping-postal NAME is not resurrected off a clean id.
  assert.equal(classifyCardField(sig({ htmlNameOrId: "shippingPostalCode" }), "billingZip"), null);
});

test("[X3-A1](ii) ambiguity: >1 surviving cardpostal on an anchored form → declare/fill NONE", () => {
  // two billing-postal fields both survive → fail-closed to none (never guess which is the card's).
  assert.deepEqual(
    cardFormKinds([
      sig({ htmlType: "text", htmlNameOrId: "cardnumber" }),
      sig({ htmlType: "text", htmlNameOrId: "billingZip" }),
      sig({ htmlType: "text", htmlNameOrId: "postalCode" }),
    ]),
    ["cardnumber", null, null],
  );
  // a billing + a SHIPPING postal is NOT ambiguous: the shipping one is suppressed PRE-count, so the
  // lone billing zip survives and fills.
  assert.deepEqual(
    cardFormKinds([
      sig({ htmlType: "text", htmlNameOrId: "cardnumber" }),
      sig({ htmlType: "text", htmlNameOrId: "billingZip" }),
      sig({ htmlType: "text", htmlNameOrId: "shippingPostalCode" }),
    ]),
    ["cardnumber", "cardpostal", null],
  );
});

test("[X3-A2] NO postal autofill hint — an autocomplete=postal-code is not cardpostal (name carries no postal token)", () => {
  assert.equal(classifyCardField(sig({ hints: ["postal-code"], htmlNameOrId: "field_1" })), null);
  // even on an anchored form the hinted-but-name-less field is a safe miss (accepted: the hint is
  // ambiguous billing-vs-shipping, so CC_POSTAL is name/id/label TOKEN-RUN only).
  assert.deepEqual(
    cardFormKinds([sig({ htmlType: "text", htmlNameOrId: "cardnumber" }), sig({ hints: ["postal-code"], htmlNameOrId: "field_1" })]),
    ["cardnumber", null],
  );
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

const stubField = (input: StubNode, kind: string, cardKind: string | null = null, textLike = false) =>
  ({ input, kind, isNewPassword: false, textLike, cardKind }) as any;

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
  // [W7] the text PAN is login-eligible (textLike true, as real collect() marks a text cardnumber),
  // so it stays in the clustering pool exactly as under the old instanceof partition. (The
  // tel-typed variant below covers the textLike=false path.)
  const groups = formlessGroups(
    [stubField(selMonth, "none", "cardexpmonth"), stubField(selYear, "none", "cardexpyear"), stubField(cvv, "password"), stubField(pan, "none", "cardnumber", true)] as any,
    root as any,
  );
  // Pre-[T1] regression shape: the CVV's climb stopped at row1 (the selects satisfied the
  // early-stop), splitting the PAN into a second group and killing the CVV fill + demotion.
  assert.equal(groups.length, 1);
  assert.equal(groups[0]!.container, p as any); // the climb passed row1 — only ONE input-backed field there
  assert.deepEqual(new Set(groups[0]!.fields.map((f: any) => f.input)), new Set([selMonth, selYear, cvv, pan]));
});

test("[W7] a TEL-typed PAN (textLike=false) still drives the password-CVV clustering (review-fold)", () => {
  // Same shape as the [T1] case but the PAN is type=tel — collect() admits it via cardKind alone
  // (kind none, textLike FALSE). The eligibility predicate must keep every NON-RADIO card input
  // in the clustering pool, or the CVV's climb stops a level low, the PAN is severed from the
  // cluster (no anchor → no demotion, no CVV fill) and the [A7] save-suppression loses its gate.
  const root = new StubNode();
  const p = new StubNode();
  const row1 = new StubNode();
  const row2 = new StubNode();
  root.append(p);
  p.append(row1, row2);
  const cvv = new StubInput();
  const pan = new StubInput();
  (pan as any).type = "tel";
  row1.append(cvv);
  row2.append(pan);
  const groups = formlessGroups([stubField(cvv, "password"), stubField(pan, "none", "cardnumber")] as any, root as any);
  assert.equal(groups.length, 1);
  assert.equal(groups[0]!.container, p as any); // ONE cluster — the tel PAN satisfied the early-stop at p
  assert.deepEqual(new Set(groups[0]!.fields.map((f: any) => f.input)), new Set([cvv, pan]));
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

// ---- V3 [W8]/[W7] radio card-type: cardtype-only classifier + login-inert grouping ----

test("[W8] classifyCardRadio — cardtype-only (name=cardType → cardtype; a month/year/shipping/rememberLogin radio → none)", () => {
  // both name directions + hint + id-retry yield cardtype…
  assert.equal(classifyCardRadio("cardType", null, []), "cardtype");
  assert.equal(classifyCardRadio("cc_type", null, []), "cardtype");
  assert.equal(classifyCardRadio("ccBrand", null, []), "cardtype");
  assert.equal(classifyCardRadio(null, null, ["cc-type"]), "cardtype"); // hint path (normalized)
  assert.equal(classifyCardRadio("field_1", "cardBrand", []), "cardtype"); // id retry
  assert.equal(classifyCardRadio("field_1", null, [], ["Card type"]), "cardtype"); // label path (weakest)
  // …but it is TIGHTER than the select set — a month/year radio must NOT classify (only cardtype rides).
  assert.equal(classifyCardRadio("cardMonth", null, []), null);
  assert.equal(classifyCardRadio("expiryYear", null, []), null);
  assert.equal(classifyCardRadio("field_1", null, [], ["Card number"]), null); // §0-style: not cardtype → none
  // NEVER the login classify(): a shipping / remember radio is inert (none), never username.
  assert.equal(classifyCardRadio("shipping", null, []), null);
  assert.equal(classifyCardRadio("rememberLogin", null, []), null);
  // a non-cardtype name verdict still stops the id/label retries (kind-restricted-away → null).
  assert.equal(classifyCardRadio("cardMonth", "cardType", []), null);
});

test("[W7] formlessGroups — a password beside a cardtype radio group groups byte-identically to today", () => {
  // <div w> <input password> <input radio cardtype> <input radio cardtype> </div>
  const root = new StubNode();
  const w = new StubNode();
  root.append(w);
  const pass = new StubInput();
  const r1 = new StubInput();
  const r2 = new StubInput();
  (r1 as any).type = "radio";
  (r2 as any).type = "radio";
  w.append(pass, r1, r2);
  // The radios are login-inert via the TYPE check (review-fold: card-classified non-radio inputs
  // stay eligible) — they do NOT drive the password's early-stop (which stays a singleton), then
  // attach post-hoc by container. Net grouping is byte-identical to the old instanceof partition.
  const groups = formlessGroups([stubField(pass, "password"), stubField(r1, "none", "cardtype"), stubField(r2, "none", "cardtype")] as any, root as any);
  assert.equal(groups.length, 1);
  assert.equal(groups[0]!.container, w as any);
  assert.deepEqual(new Set(groups[0]!.fields.map((f: any) => f.input)), new Set([pass, r1, r2]));
});

test("[X3-A3] formlessGroups — a cardpostal is login-inert: a login widget beside it groups bit-identically", () => {
  // <div w1> <input username> <input password> </div>  <div w2> <input text cardpostal> </div>
  const root = new StubNode();
  const w1 = new StubNode();
  const w2 = new StubNode();
  root.append(w1, w2);
  const user = new StubInput();
  const pass = new StubInput();
  w1.append(user, pass);
  const zip = new StubInput();
  w2.append(zip);
  // cardpostal is login-inert (excluded from the clustering pool like a select / cardtype radio),
  // so it can neither drive the password's early-stop nor pull into the login widget's cluster; it
  // rides the root leftover. The login widget groups byte-identically to a no-postal page.
  const groups = formlessGroups([stubField(user, "username"), stubField(pass, "password"), stubField(zip, "none", "cardpostal")] as any, root as any);
  assert.equal(groups.length, 2);
  assert.equal(groups[0]!.container, w1 as any);
  assert.deepEqual(new Set(groups[0]!.fields.map((f: any) => f.input)), new Set([user, pass]));
  assert.equal(groups[1]!.container, root as any);
  assert.deepEqual(groups[1]!.fields.map((f: any) => f.input), [zip]);
});

// ---- [U7] label source extraction: ordered sources + the per-generation cache ----
// labelSourcesOf is structural over the control's own surface (getAttribute / labels /
// getRootNode().getElementById / placeholder), so element stubs suffice — same convention as the
// [T1] suite above (StubInput discharges the `instanceof HTMLInputElement` placeholder gate).

test("[U7] labelSourcesOf — ordered sources: aria-label · el.labels · labelledby ids (one string per target) · placeholder", () => {
  const root = {
    getElementById: (id: string) => (id === "a" ? { textContent: "Expiry" } : id === "b" ? { textContent: "date" } : null),
  };
  const el = new StubInput() as any;
  el.getAttribute = (n: string) => (n === "aria-label" ? "Payment details" : n === "aria-labelledby" ? "a b missing" : null);
  el.labels = [{ textContent: "Card number" }];
  el.getRootNode = () => root;
  el.placeholder = "MM / YY";
  // each source stays a SEPARATE string ([U5]) — labelledby targets one string per id, listed order.
  assert.deepEqual(labelSourcesOf(el), ["Payment details", "Card number", "Expiry", "date", "MM / YY"]);
  // a select stub (not an HTMLInputElement) contributes no placeholder leg.
  const sel = new StubSelect() as any;
  sel.getAttribute = () => null;
  sel.labels = [{ textContent: "Expiry month" }];
  sel.getRootNode = () => root;
  assert.deepEqual(labelSourcesOf(sel), ["Expiry month"]);
});

test("[U6] labelSourcesOf — WeakMap cache holds within a sweep generation, invalidates on bump", () => {
  let reads = 0;
  const el = new StubInput() as any;
  el.getAttribute = (n: string) => (n === "aria-label" ? (reads++, "Card number") : null);
  el.labels = null;
  el.getRootNode = () => ({});
  el.placeholder = "";
  assert.deepEqual(labelSourcesOf(el), ["Card number"]);
  labelSourcesOf(el);
  assert.equal(reads, 1); // cached — a form-sized wrapping label costs once per tick, not per field visit
  bumpLabelGeneration(); // content.ts calls this on childList-bearing ticks ([U16] cadence)
  labelSourcesOf(el);
  assert.equal(reads, 2); // invalidated per sweep generation
});
