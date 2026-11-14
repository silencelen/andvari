// node --test. The card-release rule (owner decision 2026-11-14, round-11 review): card data goes only to a document
// whose origin, as the browser reports it for that frame, is a payment provider's card-entry origin, and only into a
// frame where the person chose a card field. A shop's top frame and its same-origin frames never receive it, whatever
// frames or fields their pages show; a frame is never filled because of where it sits; and no fill happens while two
// provider card frames in the tab ask for the same card detail.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { CHOICE_CHAIN_MS, CHOICE_TTL_MS, cardFillPlan, chosenCardFrame, chosenCardFrames, frameOriginOf, kindsOfferedTwice, mayReceiveCard, mayRedeem, pageCardFormsOnly, providerCardFrames, sameFrames, supersededChoices, type CardFrameRecord, type CardGrant } from "./cardrelease.ts";

const NOW = 1_800_000_000_000;
const SHOP = "https://shop.example";
const STRIPE = "https://js.stripe.com";
const BRAINTREE = "https://assets.braintreegateway.com";
const FULL = ["cardnumber", "cardexpiry", "cardcvv"] as const;

/** A frame's record: its origin, its card forms, the form holding the person's choice and when it was made, and its
 *  ancestor origins (directly in the shop's page by default). */
const rec = (origin: string, forms: string[][], anchor: number | null = null, at = NOW - 1_000, ancestors: string[] | null = [SHOP], shown?: boolean): CardFrameRecord =>
  ({ origin, forms: forms as CardFrameRecord["forms"], anchor, ...(anchor !== null ? { anchorAt: at } : {}), ancestors, ...(shown !== undefined ? { shown } : {}) });
/** The frame ids a plan fills, or why it fills none. */
const plan = (records: Record<number, CardFrameRecord>): number[] | string => {
  const p = cardFillPlan(records, NOW);
  return p.ok ? p.targets.map((t) => t.frameId) : p.reason;
};

test("the origin is the browser's: sender.origin, else the top frame's own URL; an opaque one is none", () => {
  assert.equal(frameOriginOf({ origin: STRIPE, url: "https://shop.example/", frameId: 3 }), STRIPE, "origin wins over url");
  assert.equal(frameOriginOf({ origin: "null", url: "https://js.stripe.com/x", frameId: 3 }), null, "a sandboxed document has no origin, whatever its URL");
  assert.equal(frameOriginOf({ origin: "", url: "https://js.stripe.com/x", frameId: 0 }), null);
  assert.equal(frameOriginOf({ url: "https://checkout.stripe.com/c/pay/x", frameId: 0 }), "https://checkout.stripe.com", "Safari: the top frame's own URL");
  // Round-12 review: a sandboxed sub-frame keeps its URL but has no origin, so a sub-frame's URL is never one.
  assert.equal(frameOriginOf({ url: "https://js.stripe.com/v3/elements-inner-card-0a.html", frameId: 3 }), null);
  assert.equal(frameOriginOf({ url: "https://js.stripe.com/v3/elements-inner-card-0a.html" }), null, "no frameId: no top frame");
  assert.equal(frameOriginOf({ url: "about:blank", frameId: 0 }), null);
  assert.equal(frameOriginOf({}), null);
});

test("a provider's frame with the person's choice in it fills", () => {
  const records = { 0: rec(SHOP, []), 3: rec(STRIPE, [[...FULL]], 0) };
  assert.deepEqual(providerCardFrames(records), [{ frameId: 3, origin: STRIPE }]);
  assert.deepEqual(chosenCardFrame(records, NOW), { frameId: 3, origin: STRIPE, kinds: [...FULL] });
  assert.deepEqual(cardFillPlan(records, NOW), { ok: true, targets: [{ frameId: 3, origin: STRIPE, kinds: [...FULL] }] });
  assert.ok(!pageCardFormsOnly(records));
  // The same frame with no choice in it fills nothing: the person taps the field first.
  assert.equal(plan({ 0: rec(SHOP, []), 3: rec(STRIPE, [[...FULL]]) }), "no_choice");
});

test("a provider's own top-level page (a hosted checkout) fills", () => {
  assert.deepEqual(plan({ 0: rec("https://checkout.stripe.com", [[...FULL]], 0) }), [0]);
});

test("a shop's top frame and its same-origin frames never receive a card, chosen or not", () => {
  const records = { 0: rec(SHOP, [[...FULL]], 0, NOW - 10), 2: rec(SHOP, [[...FULL]], 0, NOW - 5) };
  assert.deepEqual(providerCardFrames(records), []);
  assert.equal(chosenCardFrame(records, NOW), null, "a choice in the shop's document is never one");
  assert.equal(plan(records), "no_choice");
  assert.ok(pageCardFormsOnly(records), "the popup says why: the page takes the card itself");
  assert.ok(!mayReceiveCard(records[0]));
  // Even a grant minted for one (none is) could not be redeemed there.
  const grant: CardGrant = { itemId: "i", frameId: 0, origin: SHOP, kinds: [...FULL], sig: FULL.join(","), expiresMs: NOW + 30_000 };
  assert.ok(!mayRedeem(grant, "i", { frameId: 0, origin: SHOP }, NOW));
});

test("the round 5 to 10 attack pages are refused: their documents are the shop's (or opaque), never a provider's", () => {
  // Overlays, blends, closed roots, srcdoc and about:blank frames, a frame a script navigates, a form posted into a
  // frame, a hidden provider frame beside the shop's fields: whatever the page draws, its own fields are in documents
  // of the test site's origin, or of no origin at all, and the provider frames it shows hold none of the chosen fields.
  const site = "https://site.andvari-uitest.test:8443";
  for (const opaque of [frameOriginOf({ origin: "null" }), frameOriginOf({ url: "about:srcdoc" }), frameOriginOf({ url: "about:blank" })]) assert.equal(opaque, null);
  const records = { 0: rec(site, [[...FULL]], 0), 1: rec(site, [["cardnumber"]], 0), 4: rec(STRIPE, []) };
  assert.equal(chosenCardFrame(records, NOW), null);
  assert.deepEqual(providerCardFrames(records), [], "a provider frame with no card form of its own is no target either");
});

test("a split-field provider fills only the frames where the person chose a field: one tap in each, then one Fill", () => {
  const records = {
    0: rec(SHOP, []),
    1: rec(BRAINTREE, [["cardnumber"]], 0, NOW - 3_000), // tapped first
    2: rec(BRAINTREE, [["cardexpiry"]], 0, NOW - 2_000), // then the expiry
    3: rec(BRAINTREE, [["cardcvv"]]), // the security code was not tapped
  };
  const p = cardFillPlan(records, NOW);
  assert.ok(p.ok);
  assert.deepEqual(p.targets.map((t) => [t.frameId, t.kinds]), [[2, ["cardexpiry"]], [1, ["cardnumber"]]], "newest first; the untapped frame gets nothing");
  // A frame is never filled for where it sits: an untapped frame of the same provider, beside them, gets nothing either.
  assert.deepEqual(plan({ ...records, 3: rec(BRAINTREE, [["cardcvv"]], 0, NOW - 1_000) }), [3, 2, 1]);
});

test("more than one provider card frame offering a kind stops every fill, whatever its origin or where it sits", () => {
  // A script in the shop's page mounts its own provider element (its own merchant account) beside the real one, or an
  // invisible one over it: two frames ask for the card number, and nothing tells which is the box the person meant.
  const real = { 0: rec(SHOP, []), 3: rec(STRIPE, [[...FULL]], 0) };
  assert.deepEqual(kindsOfferedTwice(real), []);
  assert.equal(plan({ ...real, 9: rec(STRIPE, [["cardnumber"]]) }), "duplicate_kind", "an extra frame of the same provider, never chosen");
  assert.deepEqual(kindsOfferedTwice({ ...real, 9: rec(BRAINTREE, [["cardcvv"], ["cardpostal"]]) }), ["cardcvv"], "another provider counts too");
  assert.deepEqual(cardFillPlan({ ...real, 9: rec(BRAINTREE, [["cardcvv"]], 0, NOW) }, NOW), { ok: false, reason: "duplicate_kind", kinds: ["cardcvv"] });
  // A shop's own form, and a provider frame with no card form, do not count; nor does a kind twice in ONE frame (a
  // number split over four boxes, twin expiry boxes).
  assert.deepEqual(plan({ ...real, 1: rec(SHOP, [[...FULL]]), 4: rec(BRAINTREE, []) }), [3]);
  assert.deepEqual(plan({ 3: rec(STRIPE, [["cardnumber", "cardnumber", "cardnumber", "cardnumber", "cardexpiry", "cardexpiry", "cardcvv"]], 0) }), [3]);
});

test("a new choice of a kind lets go of the older choices of that kind in every other frame", () => {
  const records = {
    1: rec(BRAINTREE, [["cardnumber"]], 0, NOW - 5_000),
    2: rec(BRAINTREE, [["cardexpiry"]], 0, NOW - 4_000),
    3: rec(BRAINTREE, [["cardnumber", "cardcvv"]], 0, NOW - 3_000),
  };
  assert.deepEqual(supersededChoices(records, 3, ["cardnumber", "cardcvv"], NOW), [1], "the expiry choice stands");
  assert.deepEqual(supersededChoices(records, 2, ["cardexpiry"], NOW), []);
  // Should the worker not have heard of it yet, a newer choice still outranks an older one of the same kind.
  assert.deepEqual(chosenCardFrames(records, NOW).map((c) => c.frameId), [3, 2]);
});

test("the round-12 lure: fields typed into for something else never join a later fill", () => {
  // A saved-card checkout asks only for the security code, in a Stripe frame on the shop's page. A cross-origin rewards
  // widget mounts the attacker's own Stripe number and expiry elements ("Rewards number", "Valid thru"); the person
  // typed into them, and later taps the shop's code and presses Fill.
  const WIDGET = "https://rewards.example";
  const page = {
    1: rec(STRIPE, [["cardcvv"]], 0, NOW - 1_000), // the shop's code, tapped last
    5: rec(STRIPE, [["cardnumber"]], 0, NOW - 90_000, [WIDGET, SHOP]), // "Rewards number", inside the widget
    6: rec(STRIPE, [["cardexpiry"]], 0, NOW - 80_000, [WIDGET, SHOP]), // "Valid thru"
  };
  assert.deepEqual(plan(page), [1], "only the code: another chain of documents, and long before");
  // The same lures typed into just now still sit in another chain of documents.
  assert.deepEqual(plan({ ...page, 5: rec(STRIPE, [["cardnumber"]], 0, NOW - 3_000, [WIDGET, SHOP]), 6: rec(STRIPE, [["cardexpiry"]], 0, NOW - 2_000, [WIDGET, SHOP]) }), [1]);
  // Lures on the shop's own page (its own script: same chain) are dropped once more than 30 s older than the newer tap.
  assert.deepEqual(plan({ ...page, 5: rec(STRIPE, [["cardnumber"]], 0, NOW - 1_000 - CHOICE_CHAIN_MS - 1), 6: rec(STRIPE, [["cardexpiry"]], 0, NOW - 1_000 - CHOICE_CHAIN_MS - 2) }), [1]);
  // What stays: quick taps on the same page, which the popup names detail by detail before the Fill (the residual).
  assert.deepEqual(plan({ ...page, 5: rec(STRIPE, [["cardnumber"]], 0, NOW - 20_000), 6: rec(STRIPE, [["cardexpiry"]], 0, NOW - 10_000) }), [1, 6, 5]);
  // Each tap must be within 30 s of the next newer one kept: a gap ends the chain.
  assert.deepEqual(plan({ ...page, 6: rec(STRIPE, [["cardexpiry"]], 0, NOW - 10_000), 5: rec(STRIPE, [["cardnumber"]], 0, NOW - 10_000 - CHOICE_CHAIN_MS - 1) }), [1, 6]);
  // Another provider origin never joins, however quick.
  assert.deepEqual(plan({ 1: rec(STRIPE, [["cardcvv"]], 0, NOW - 1_000), 2: rec(BRAINTREE, [["cardnumber"]], 0, NOW - 2_000) }), [1]);
  // Where the browser lists no ancestors (Firefox), the time and origin rules still hold.
  assert.deepEqual(plan({ 1: rec(STRIPE, [["cardcvv"]], 0, NOW - 1_000, null), 5: rec(STRIPE, [["cardnumber"]], 0, NOW - 90_000, null) }), [1]);
  // A record from before the round (no list) never chains with one that has a list.
  assert.deepEqual(plan({ 1: rec(STRIPE, [["cardcvv"]], 0, NOW - 1_000), 5: rec(STRIPE, [["cardnumber"]], 0, NOW - 2_000, null) }), [1]);
});

test("a choice stands 2 minutes", () => {
  assert.equal(CHOICE_TTL_MS, 2 * 60 * 1000);
  assert.equal(chosenCardFrame({ 1: rec(STRIPE, [[...FULL]], 0, NOW - 2 * 60 * 1000 + 1) }, NOW)?.frameId, 1);
  assert.equal(chosenCardFrame({ 1: rec(STRIPE, [[...FULL]], 0, NOW - 2 * 60 * 1000 - 1) }, NOW), null);
});

test("a provider frame the page shows that has not reported refuses the fill, naming its origin", () => {
  // The top frame's content script sees a src naming a listed provider, and no frame of that origin reported (andvari may
  // not run there): its card kinds cannot be counted, so nothing is filled anywhere in the tab. The hint can only refuse.
  const records = { 3: rec(STRIPE, [[...FULL]], 0) };
  assert.deepEqual(cardFillPlan(records, NOW, "https://assets.braintreegateway.com"), { ok: false, reason: "unreported", origin: "https://assets.braintreegateway.com" });
  assert.deepEqual(cardFillPlan(records, NOW, null), { ok: true, targets: [{ frameId: 3, origin: STRIPE, kinds: [...FULL] }] });
});

test("a collapsed provider frame neither counts nor can be chosen", () => {
  // A second payment method, or a stored card's code beside the new-card form, collapsed to nothing.
  const records = { 3: rec(STRIPE, [[...FULL]], 0), 4: rec(STRIPE, [["cardcvv"]], 0, NOW - 500, [SHOP], false) };
  assert.deepEqual(kindsOfferedTwice(records), [], "the collapsed code frame does not count");
  assert.deepEqual(plan(records), [3], "and is not chosen, though it was tapped later");
  assert.ok(!mayReceiveCard(records[4]));
  assert.deepEqual(providerCardFrames({ 4: records[4] }), []);
  // Shown again, it counts again.
  assert.equal(plan({ ...records, 4: rec(STRIPE, [["cardcvv"]], 0, NOW - 500, [SHOP], true) }), "duplicate_kind");
});

test("a fill goes to exactly the frames, origins and card details the popup showed", () => {
  const n = ["cardnumber"] as CardFrameRecord["forms"][number];
  const e = ["cardexpiry"] as CardFrameRecord["forms"][number];
  const targets = [{ frameId: 2, origin: BRAINTREE, kinds: e }, { frameId: 1, origin: BRAINTREE, kinds: n }];
  assert.ok(sameFrames([{ frameId: 1, origin: BRAINTREE, kinds: n }, { frameId: 2, origin: BRAINTREE, kinds: e }], targets), "in any order");
  assert.ok(!sameFrames([{ frameId: 1, origin: BRAINTREE, kinds: n }], targets), "one missing");
  assert.ok(!sameFrames([...targets, { frameId: 3, origin: BRAINTREE, kinds: n }], targets), "one more");
  assert.ok(!sameFrames([{ frameId: 1, origin: BRAINTREE, kinds: n }, { frameId: 2, origin: STRIPE, kinds: e }], targets), "another origin");
  assert.ok(!sameFrames([{ frameId: 1, origin: BRAINTREE, kinds: n }, { frameId: 2, origin: BRAINTREE, kinds: ["cardexpiry", "cardcvv"] }], targets), "another detail than the popup named");
  assert.ok(!sameFrames([{ frameId: 1, origin: BRAINTREE, kinds: n }, { frameId: 1, origin: BRAINTREE, kinds: n }], targets), "the same twice");
  assert.ok(!sameFrames([{ frameId: 1, origin: BRAINTREE }, { frameId: 2, origin: BRAINTREE }], targets), "no details");
  assert.ok(!sameFrames(undefined, targets));
  assert.ok(!sameFrames([{ frameId: "1", origin: BRAINTREE, kinds: n }, { frameId: 2, origin: BRAINTREE, kinds: e }], targets));
  assert.ok(sameFrames([], []));
});

test("a provider frame nested under the shop's own same-origin frame fills where the person chose in it", () => {
  const adyen = "https://checkoutshopper-live.adyen.com";
  const records = { 0: rec(SHOP, []), 1: rec(SHOP, [["cardname"]]), 2: rec(adyen, [["cardnumber"]], 0), 3: rec(adyen, [["cardcvv"]], 0, NOW - 500) };
  assert.deepEqual(plan(records), [3, 2]);
});

test("a security code alone, in a provider's frame, is a fill of its own (saved-card re-authentication)", () => {
  const records = { 7: rec(STRIPE, [["cardcvv"]], 0) };
  assert.deepEqual(chosenCardFrame(records, NOW), { frameId: 7, origin: STRIPE, kinds: ["cardcvv"] });
});

test("a choice past its time is none; one never made is none", () => {
  assert.equal(chosenCardFrame({ 1: rec(STRIPE, [[...FULL]], 0, NOW - CHOICE_TTL_MS - 1) }, NOW), null, "expired");
  assert.equal(chosenCardFrame({ 1: rec(STRIPE, [[...FULL]], null) }, NOW), null, "no choice made");
  assert.equal(chosenCardFrame({ 1: rec(STRIPE, [[...FULL]], 3) }, NOW), null, "an anchor naming no form");
  assert.equal(chosenCardFrame({ 1: rec(STRIPE, [[...FULL]], 0, NOW + 120_000) }, NOW), null, "a time from the future");
});

test("each frame redeems its own grant only, at the origin it was minted for, before it expires", () => {
  const grant: CardGrant = { itemId: "card-1", frameId: 3, origin: STRIPE, kinds: ["cardnumber"], sig: "cardnumber", expiresMs: NOW + 30_000 };
  assert.ok(mayRedeem(grant, "card-1", { frameId: 3, origin: STRIPE }, NOW));
  assert.ok(!mayRedeem(grant, "card-1", { frameId: 3, url: "https://js.stripe.com/v3/x.html" }, NOW), "a sub-frame's URL is no origin (round-12 review)");
  assert.ok(mayRedeem({ ...grant, frameId: 0, origin: "https://checkout.stripe.com" }, "card-1", { frameId: 0, url: "https://checkout.stripe.com/c/pay/x" }, NOW), "Safari: the top frame's own URL");
  assert.ok(!mayRedeem(grant, "card-2", { frameId: 3, origin: STRIPE }, NOW), "another item");
  assert.ok(!mayRedeem(grant, "card-1", { frameId: 4, origin: STRIPE }, NOW), "another frame, even of the same provider");
  assert.ok(!mayRedeem(grant, "card-1", { frameId: 3, origin: SHOP }, NOW), "the frame navigated to the shop");
  assert.ok(!mayRedeem(grant, "card-1", { frameId: 3, origin: "null", url: "https://js.stripe.com/x" }, NOW), "sandboxed");
  assert.ok(!mayRedeem(grant, "card-1", { frameId: 3, origin: STRIPE }, NOW + 30_000), "expired");
  assert.ok(!mayRedeem(undefined, "card-1", { frameId: 3, origin: STRIPE }, NOW));
  assert.ok(!mayRedeem({ ...grant, origin: SHOP, frameId: 0 }, "card-1", { frameId: 0, origin: SHOP }, NOW), "a grant for a shop's document is refused at redemption too");
});
