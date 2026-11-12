// node --test. Round-5 review C1: a card number goes only into a field the person can see. A skimmer injects an
// invisible card form (opacity 0, visibility hidden, off-screen, 0x0, clipped or tucked under the payment provider's
// frame) into a checkout whose real fields are in that frame; the popup's Fill used to land in it. The rules are pure
// (detect.ts visibilityOf); the DOM probe that feeds them and the fill path's use of them are pinned below.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { MIN_FIELD_PX, visibilityOf, type VisibilityFacts } from "./detect.ts";

const shown = { display: "block", visibility: "visible", opacity: "1" };
const base: VisibilityFacts = {
  chain: [{ ...shown, display: "inline-block" }, shown, shown],
  rect: { left: 20, top: 300, width: 240, height: 36 },
  page: { scrollX: 0, scrollY: 0, width: 390, height: 2400 },
  viewport: null,
  hit: null,
};
const facts = (over: Partial<VisibilityFacts>): VisibilityFacts => ({ ...base, ...over });

test("an ordinary field is visible, on the page and on screen", () => {
  assert.equal(visibilityOf(base), "ok");
  assert.equal(visibilityOf(facts({ viewport: { width: 390, height: 844 }, hit: "self" })), "ok");
});

test("hidden by itself or by any ancestor", () => {
  assert.equal(visibilityOf(facts({ chain: [shown, { ...shown, display: "none" }] })), "hidden");
  assert.equal(visibilityOf(facts({ chain: [{ ...shown, visibility: "hidden" }, shown] })), "hidden");
  assert.equal(visibilityOf(facts({ chain: [{ ...shown, visibility: "collapse" }] })), "hidden");
  assert.equal(visibilityOf(facts({ chain: [] })), "hidden", "nothing read is nothing proven");
});

test("transparent: the opacity of the field and its ancestors combines, and an unreadable one counts as none", () => {
  assert.equal(visibilityOf(facts({ chain: [{ ...shown, opacity: "0" }] })), "transparent");
  assert.equal(visibilityOf(facts({ chain: [shown, { ...shown, opacity: "0.3" }, { ...shown, opacity: "0.3" }] })), "transparent", "0.09 is below the floor");
  assert.equal(visibilityOf(facts({ chain: [shown, { ...shown, opacity: "0.5" }] })), "ok");
  assert.equal(visibilityOf(facts({ chain: [{ ...shown, opacity: "" }] })), "transparent");
});

test("too small to use, or off the page", () => {
  assert.equal(visibilityOf(facts({ rect: { left: 20, top: 300, width: 0, height: 0 } })), "tiny");
  assert.equal(visibilityOf(facts({ rect: { left: 20, top: 300, width: 240, height: MIN_FIELD_PX - 1 } })), "tiny");
  assert.equal(visibilityOf(facts({ rect: { left: -9999, top: 300, width: 240, height: 36 } })), "offpage");
  assert.equal(visibilityOf(facts({ rect: { left: 20, top: -500, width: 240, height: 36 } })), "offpage");
  assert.equal(visibilityOf(facts({ rect: { left: 5000, top: 300, width: 240, height: 36 } })), "offpage");
  // Below the fold is still on the page: a long checkout is found before it is scrolled to.
  assert.equal(visibilityOf(facts({ rect: { left: 20, top: 1800, width: 240, height: 36 } })), "ok");
  // Scrolled: the box is in viewport coordinates, the page in document coordinates.
  assert.equal(visibilityOf(facts({ rect: { left: 20, top: -100, width: 240, height: 36 }, page: { ...base.page, scrollY: 600 } })), "ok");
});

test("at fill time the anchor must be on screen, and nothing may cover a field's centre", () => {
  const screen = { width: 390, height: 844 };
  assert.equal(visibilityOf(facts({ viewport: screen, rect: { left: 20, top: 900, width: 240, height: 36 } })), "offscreen");
  assert.equal(visibilityOf(facts({ viewport: screen, hit: "other" })), "covered", "a field tucked under the provider's frame");
  assert.equal(visibilityOf(facts({ hit: "other" })), "covered", "covered whether or not it is the anchor");
});

test("a select or a radio drawn through a proxy is held only to the rules a proxy cannot excuse", () => {
  assert.equal(visibilityOf(facts({ chain: [{ ...shown, opacity: "0" }], rect: { left: 20, top: 300, width: 1, height: 1 }, hit: "other" }), true), "ok");
  assert.equal(visibilityOf(facts({ chain: [{ ...shown, visibility: "hidden" }] }), true), "hidden");
  assert.equal(visibilityOf(facts({ rect: { left: -9999, top: 300, width: 240, height: 36 } }), true), "offpage");
  assert.equal(visibilityOf(facts({ viewport: { width: 390, height: 844 }, rect: { left: 20, top: 900, width: 240, height: 36 } }), true), "offscreen");
});

// ---- wiring: detection and fill use the rules (detect.ts and content.ts need a DOM, so these pin the source) ----

const detect = readFileSync(new URL("./detect.ts", import.meta.url), "utf-8");
const content = readFileSync(new URL("./content.ts", import.meta.url), "utf-8");

test("detection collects only fields that pass the page-time rules, for logins and cards alike", () => {
  assert.match(detect, /function isVisible\(el: HTMLElement\): boolean \{\s*return isRendered\(el\) && visibilityOf\(probeVisibility\(el, \{ onScreen: false, hitTest: false \}\), proxiedControl\(el\)\) === "ok";/);
  const collect = detect.slice(detect.indexOf("function collect(root: Document | ShadowRoot): Field[] {"));
  assert.ok(collect.includes("if (el.disabled || el.readOnly || !isVisible(el)) continue;"), "inputs (login and card)");
  assert.ok(collect.includes("if (el.disabled || !isVisible(el) || el.type !== \"select-one\") continue;"), "selects");
});

test("a card fill goes only into the form holding the focused field, and only if every field of it can be seen", () => {
  const fill = content.slice(content.indexOf("async function fillCardIntoForm("), content.indexOf("// ---- G2 save-card capture"));
  assert.ok(!content.includes("cardFormBySig"), "no more \"the first form with the grant's signature\"");
  const focus = fill.indexOf('if (anchor === null) return nothing("no_focus");');
  const before = fill.indexOf('if (cardFormNotVisible(form, anchor)) return nothing("not_visible");');
  const reveal = fill.indexOf('await safeSend({ type: "revealCardForFill", itemId })');
  const after = fill.indexOf('if (cardFormNotVisible(now, anchor)) return nothing("not_visible");');
  const write = fill.indexOf("return applyCardFill(now, r.fields);");
  assert.ok(focus > 0 && focus < before && before < reveal && reveal < after && after < write, "checked before the card is asked for and again before it is written");
  const check = content.slice(content.indexOf("function cardFormNotVisible("), content.indexOf("/** Drive cardfill.ts per field ref"));
  assert.match(check, /form\.fields\.some\(/, "one field that cannot be seen refuses the whole fill");
  assert.match(check, /probeVisibility\(f\.input, \{ onScreen: f\.input === anchor, hitTest: true \}\)/, "the anchor must be on screen, and every field is hit-tested");
  assert.match(content, /noteCardFocus\(t\);\s*maybeOpen\(t\);/, "the focus is noted on every trusted focusin");
});
