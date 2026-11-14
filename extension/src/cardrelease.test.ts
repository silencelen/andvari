// node --test. The card-release rule (owner decision 2026-11-14): card data goes only to a document whose origin, as
// the browser reports it for that frame, is a payment provider's card-entry origin. A shop's top frame and its
// same-origin frames never receive it, whatever frames or fields their pages show; a provider that puts each field in
// a frame of its own is filled across the chosen frame's siblings (same origin, same ancestor origins), each with its
// own kinds, and not at all when two frames would take the same kind.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { CHOICE_TTL_MS, cardFillPlan, chosenCardFrame, frameOriginOf, mayReceiveCard, mayRedeem, pageCardFormsOnly, providerCardFrames, type CardFillPlan, type CardFrameRecord, type CardGrant } from "./cardrelease.ts";

const NOW = 1_800_000_000_000;
const SHOP = "https://shop.example";
const STRIPE = "https://js.stripe.com";
const BRAINTREE = "https://assets.braintreegateway.com";
const FULL = ["cardnumber", "cardexpiry", "cardcvv"] as const;

/** A frame's record; [ancestors]: its location.ancestorOrigins, nearest first (directly under the shop by default). */
const rec = (origin: string, forms: string[][], anchor: number | null = null, at = NOW - 1_000, ancestors: string[] | null = [SHOP]): CardFrameRecord =>
  ({ origin, forms: forms as CardFrameRecord["forms"], anchor, ...(anchor !== null ? { anchorAt: at } : {}), ancestors });
/** The frame ids a plan fills, or its refusal. */
const ids = (p: CardFillPlan): number[] | string => (p.ok ? p.targets.map((t) => t.frameId) : p.reason);

test("the origin is the browser's: sender.origin, else the frame's own URL; an opaque one is none", () => {
  assert.equal(frameOriginOf({ origin: STRIPE, url: "https://shop.example/" }), STRIPE, "origin wins over url");
  assert.equal(frameOriginOf({ origin: "null", url: "https://js.stripe.com/x" }), null, "a sandboxed document has no origin, whatever its URL");
  assert.equal(frameOriginOf({ origin: "", url: "https://js.stripe.com/x" }), null);
  assert.equal(frameOriginOf({ url: "https://js.stripe.com/v3/elements-inner-card.html" }), STRIPE, "Safari: the frame's own URL");
  assert.equal(frameOriginOf({ url: "about:blank" }), null);
  assert.equal(frameOriginOf({}), null);
});

test("a provider's frame with the person's choice in it fills", () => {
  const records = { 0: rec(SHOP, []), 3: rec(STRIPE, [[...FULL]], 0) };
  assert.deepEqual(providerCardFrames(records), [{ frameId: 3, origin: STRIPE }]);
  const chosen = chosenCardFrame(records, NOW);
  assert.deepEqual(chosen, { frameId: 3, origin: STRIPE, kinds: [...FULL] });
  assert.deepEqual(cardFillPlan(records, chosen!), { ok: true, targets: [{ frameId: 3, origin: STRIPE, kinds: [...FULL], chosen: true }] });
  assert.ok(!pageCardFormsOnly(records));
});

test("a provider's own top-level page (a hosted checkout) fills, with no siblings", () => {
  const hosted = "https://checkout.stripe.com";
  // Its own frames (a top-level page has no ancestors; theirs is the page) are not its siblings.
  const records = { 0: rec(hosted, [[...FULL]], 0, NOW - 1_000, []), 2: rec(hosted, [["cardpostal"]], null, NOW, [hosted]) };
  const chosen = chosenCardFrame(records, NOW);
  assert.equal(chosen?.frameId, 0);
  assert.deepEqual(ids(cardFillPlan(records, chosen!)), [0]);
});

test("a shop's top frame and its same-origin frames never receive a card, chosen or not", () => {
  const records = { 0: rec(SHOP, [[...FULL]], 0, NOW - 10), 2: rec(SHOP, [[...FULL]], 0, NOW - 5) };
  assert.deepEqual(providerCardFrames(records), []);
  assert.equal(chosenCardFrame(records, NOW), null, "a choice in the shop's document is never one");
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

test("a split-field provider fills the chosen frame's siblings: same origin, same ancestor origins, each its own kinds", () => {
  const AD = "https://ads.example";
  const records = {
    0: rec(SHOP, [], null, NOW, []),
    1: rec(BRAINTREE, [["cardnumber"]], 0), // Braintree's number, directly under the shop
    2: rec(BRAINTREE, [["cardexpiry"]]), // its expiry
    3: rec(BRAINTREE, [["cardcvv"]]), // its security code
    5: rec(AD, []), // an ad
    4: rec(BRAINTREE, [["cardpostal"]], null, NOW, [AD, SHOP]), // a Braintree frame inside the ad
    6: rec(STRIPE, [["cardname"]]), // another provider beside them
  };
  const chosen = chosenCardFrame(records, NOW)!;
  assert.equal(chosen.frameId, 1);
  const plan = cardFillPlan(records, chosen);
  assert.ok(plan.ok);
  assert.deepEqual(
    plan.targets.map((t) => [t.frameId, t.kinds, t.chosen]),
    [
      [1, ["cardnumber"], true],
      [2, ["cardexpiry"], false],
      [3, ["cardcvv"], false],
    ],
    "the ad's own Braintree frame (other ancestors) and the other provider (another origin) get nothing",
  );
  // A sibling holding two forms is ambiguous, and gets nothing.
  assert.deepEqual(ids(cardFillPlan({ ...records, 2: rec(BRAINTREE, [["cardexpiry"], ["cardname"]]) }, chosen)), [1, 3]);
});

test("where the browser lists no ancestors (Firefox), the chosen frame is filled alone: one field per Fill", () => {
  const records = {
    1: rec(BRAINTREE, [["cardnumber"]], 0, NOW - 1_000, null),
    2: rec(BRAINTREE, [["cardexpiry"]], null, NOW, null),
    3: rec(BRAINTREE, [["cardcvv"]], null, NOW, null),
  };
  assert.deepEqual(ids(cardFillPlan(records, chosenCardFrame(records, NOW)!)), [1]);
  // Nor is a frame with no list a sibling of one with a list.
  assert.deepEqual(ids(cardFillPlan({ ...records, 1: rec(BRAINTREE, [["cardnumber"]], 0) }, chosenCardFrame({ ...records, 1: rec(BRAINTREE, [["cardnumber"]], 0) }, NOW)!)), [1]);
});

test("a frame the page adds beside the provider's, taking a kind another frame takes, stops the whole fill", () => {
  // The shop's script embeds a frame of the same provider (its own merchant account) as one more sibling.
  const split = {
    1: rec(BRAINTREE, [["cardnumber"]], 0),
    2: rec(BRAINTREE, [["cardexpiry"]]),
    3: rec(BRAINTREE, [["cardcvv"]]),
    9: rec(BRAINTREE, [["cardnumber"]]),
  };
  const plan = cardFillPlan(split, chosenCardFrame(split, NOW)!);
  assert.deepEqual(plan, { ok: false, reason: "duplicate_kind", kinds: ["cardnumber"] });
  // Beside a provider's single card frame, an extra frame of that provider holding the security code alone.
  const single = { 3: rec(STRIPE, [[...FULL]], 0), 8: rec(STRIPE, [["cardcvv"]]) };
  assert.deepEqual(ids(cardFillPlan(single, chosenCardFrame(single, NOW)!)), "duplicate_kind");
  // The same kind twice inside ONE frame's form (a number split over four boxes, twin expiry boxes) is that form's own.
  const boxes = { 3: rec(STRIPE, [["cardnumber", "cardnumber", "cardnumber", "cardnumber", "cardexpiry", "cardcvv"]], 0) };
  assert.deepEqual(ids(cardFillPlan(boxes, chosenCardFrame(boxes, NOW)!)), [3]);
  // A frame nested elsewhere holding the same kind is no sibling, so it stops nothing.
  const elsewhere = { ...single, 8: rec(STRIPE, [["cardcvv"]], null, NOW, ["https://widget.example", SHOP]) };
  assert.deepEqual(ids(cardFillPlan(elsewhere, chosenCardFrame(elsewhere, NOW)!)), [3]);
});

test("a provider frame nested under the shop's own same-origin frame fills; its siblings share that nesting", () => {
  const adyen = "https://checkoutshopper-live.adyen.com";
  const inner = [SHOP, SHOP]; // inside the shop's checkout frame, inside the shop's page
  const records = {
    0: rec(SHOP, [], null, NOW, []),
    1: rec(SHOP, [["cardname"]]), // the shop's checkout frame (same origin): never a target
    2: rec(adyen, [["cardnumber"]], 0, NOW - 1_000, inner), // Adyen's number, inside it
    3: rec(adyen, [["cardcvv"]], null, NOW, inner), // Adyen's code, inside it
    4: rec(adyen, [["cardexpiry"]]), // an Adyen frame directly under the page: not a sibling
  };
  const chosen = chosenCardFrame(records, NOW)!;
  assert.equal(chosen.frameId, 2);
  assert.deepEqual(ids(cardFillPlan(records, chosen)), [2, 3]);
});

test("a security code alone, in a provider's frame, is a fill of its own (saved-card re-authentication)", () => {
  const records = { 7: rec(STRIPE, [["cardcvv"]], 0) };
  assert.deepEqual(chosenCardFrame(records, NOW), { frameId: 7, origin: STRIPE, kinds: ["cardcvv"] });
});

test("the newest choice in a provider's document wins; one past its time is none", () => {
  const records = { 1: rec(STRIPE, [[...FULL]], 0, NOW - 50_000), 2: rec(BRAINTREE, [["cardnumber"]], 0, NOW - 1_000), 3: rec(SHOP, [[...FULL]], 0, NOW - 10) };
  assert.equal(chosenCardFrame(records, NOW)?.frameId, 2, "the shop's newer choice is not one");
  assert.equal(chosenCardFrame({ 1: rec(STRIPE, [[...FULL]], 0, NOW - CHOICE_TTL_MS - 1) }, NOW), null, "expired");
  assert.equal(chosenCardFrame({ 1: rec(STRIPE, [[...FULL]], null) }, NOW), null, "no choice made");
  assert.equal(chosenCardFrame({ 1: rec(STRIPE, [[...FULL]], 3) }, NOW), null, "an anchor naming no form");
});

test("each frame redeems its own grant only, at the origin it was minted for, before it expires", () => {
  const grant: CardGrant = { itemId: "card-1", frameId: 3, origin: STRIPE, kinds: ["cardnumber"], sig: "cardnumber", expiresMs: NOW + 30_000 };
  assert.ok(mayRedeem(grant, "card-1", { frameId: 3, origin: STRIPE }, NOW));
  assert.ok(mayRedeem(grant, "card-1", { frameId: 3, url: "https://js.stripe.com/v3/x.html" }, NOW), "Safari: the frame's own URL");
  assert.ok(!mayRedeem(grant, "card-2", { frameId: 3, origin: STRIPE }, NOW), "another item");
  assert.ok(!mayRedeem(grant, "card-1", { frameId: 4, origin: STRIPE }, NOW), "another frame, even of the same provider");
  assert.ok(!mayRedeem(grant, "card-1", { frameId: 3, origin: SHOP }, NOW), "the frame navigated to the shop");
  assert.ok(!mayRedeem(grant, "card-1", { frameId: 3, origin: "null", url: "https://js.stripe.com/x" }, NOW), "sandboxed");
  assert.ok(!mayRedeem(grant, "card-1", { frameId: 3, origin: STRIPE }, NOW + 30_000), "expired");
  assert.ok(!mayRedeem(undefined, "card-1", { frameId: 3, origin: STRIPE }, NOW));
  assert.ok(!mayRedeem({ ...grant, origin: SHOP, frameId: 0 }, "card-1", { frameId: 0, origin: SHOP }, NOW), "a grant for a shop's document is refused at redemption too");
});
