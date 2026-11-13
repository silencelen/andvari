// node --test. Round-5 review C1, round-6 review H1/M2: a card number goes only into a field the person can see, in
// the form of the field the person chose. A skimmer injects an invisible card form (opacity 0 or near it, a filter,
// a clip or mask, transparent text, 0x0, off-screen, or tucked under the payment provider's frame or an overlay that
// lets the pointer through) into a checkout whose real fields are in that frame; the popup's Fill used to land in it.
// The rules are pure (detect.ts visibilityOf and its helpers); the DOM probe that feeds them and the fill path's use
// of them are pinned below.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  clipLeavesWhole,
  colorAlpha,
  filterOpacity,
  MIN_FIELD_PX,
  MIN_OPACITY,
  paintsOver,
  proxiedControl,
  visibilityOf,
  type InkFacts,
  type PaintFacts,
  type VisibilityFacts,
} from "./detect.ts";

const shown = { display: "block", visibility: "visible", opacity: "1" };
const base: VisibilityFacts = {
  chain: [{ ...shown, display: "inline-block" }, shown, shown],
  ink: null,
  rect: { left: 20, top: 300, width: 240, height: 36 },
  page: { scrollX: 0, scrollY: 0, width: 390, height: 2400 },
  viewport: null,
  hit: null,
};
const facts = (over: Partial<VisibilityFacts>): VisibilityFacts => ({ ...base, ...over });
const ink: InkFacts = { color: "rgb(17, 17, 17)", textFill: "rgb(17, 17, 17)", background: "rgb(255, 255, 255)", backgroundImage: "none", fontSize: "16px" };
const fill = (f: VisibilityFacts): string => visibilityOf(f, false, MIN_OPACITY);

test("an ordinary field is visible, on the page and on screen", () => {
  assert.equal(visibilityOf(base), "ok");
  assert.equal(visibilityOf(facts({ viewport: { width: 390, height: 844 }, hit: "self" })), "ok");
  assert.equal(fill(facts({ ink, viewport: { width: 390, height: 844 }, hit: "self" })), "ok");
});

test("hidden by itself or by any ancestor", () => {
  assert.equal(visibilityOf(facts({ chain: [shown, { ...shown, display: "none" }] })), "hidden");
  assert.equal(visibilityOf(facts({ chain: [{ ...shown, visibility: "hidden" }, shown] })), "hidden");
  assert.equal(visibilityOf(facts({ chain: [{ ...shown, visibility: "collapse" }] })), "hidden");
  assert.equal(visibilityOf(facts({ chain: [] })), "hidden", "nothing read is nothing proven");
});

test("transparent: the opacity of the field and its ancestors combines, and an unreadable one counts as none", () => {
  assert.equal(visibilityOf(facts({ chain: [{ ...shown, opacity: "0" }] })), "transparent");
  assert.equal(visibilityOf(facts({ chain: [shown, { ...shown, opacity: "0.3" }, { ...shown, opacity: "0.3" }] })), "transparent", "0.09 is below the detection floor");
  assert.equal(visibilityOf(facts({ chain: [shown, { ...shown, opacity: "0.5" }] })), "ok", "detection collects it");
  assert.equal(visibilityOf(facts({ chain: [{ ...shown, opacity: "" }] })), "transparent");
});

test("a fill holds every field to near-full opacity, over every ancestor and any filter (round-6 H1)", () => {
  assert.ok(MIN_OPACITY >= 0.9);
  assert.equal(fill(facts({ chain: [shown, { ...shown, opacity: "0.5" }] })), "transparent");
  assert.equal(fill(facts({ chain: [{ ...shown, opacity: "0.95" }, { ...shown, opacity: "0.9" }] })), "transparent", "0.855 combined");
  assert.equal(fill(facts({ chain: [{ ...shown, opacity: "0.95" }, shown] })), "ok");
  assert.equal(fill(facts({ chain: [{ ...shown, filter: "opacity(0)" }] })), "transparent", "filter: opacity(0)");
  assert.equal(fill(facts({ chain: [shown, { ...shown, filter: "opacity(50%)" }] })), "transparent");
  assert.equal(fill(facts({ chain: [{ ...shown, filter: "blur(6px)" }] })), "filtered");
  assert.equal(fill(facts({ chain: [{ ...shown, filter: "brightness(0)" }] })), "filtered");
  assert.equal(fill(facts({ chain: [{ ...shown, filter: "contrast(0)" }] })), "filtered");
  assert.equal(fill(facts({ chain: [{ ...shown, filter: "invert(0.5)" }] })), "filtered");
  assert.equal(fill(facts({ chain: [{ ...shown, filter: 'url("#hide")' }] })), "filtered");
  assert.equal(fill(facts({ chain: [{ ...shown, filter: "drop-shadow(rgb(0, 0, 0) 0px 1px 2px) grayscale(1)" }] })), "ok");
});

test("filterOpacity reads a computed filter list", () => {
  assert.equal(filterOpacity(undefined), 1);
  assert.equal(filterOpacity("none"), 1);
  assert.equal(filterOpacity("opacity(0.5) opacity(50%)"), 0.25);
  assert.equal(filterOpacity("hue-rotate(90deg) saturate(2) sepia(0.2)"), 1);
  assert.equal(filterOpacity("blur(1px)"), 1, "a hairline blur leaves text readable");
  assert.equal(filterOpacity("blur(2px)"), null);
  assert.equal(filterOpacity("brightness(3)"), null, "washed out");
  assert.equal(filterOpacity("invert(1)"), 1, "inverted text is still text");
  assert.equal(filterOpacity("garbage"), null);
  assert.equal(filterOpacity("opacity(oops)"), null);
});

test("clipped or masked: by itself or by any ancestor; an inset that only rounds the corners is not a clip", () => {
  assert.equal(fill(facts({ chain: [{ ...shown, clipPath: "circle(2px at 50% 50%)" }] })), "clipped");
  assert.equal(fill(facts({ chain: [shown, { ...shown, clipPath: "inset(50%)" }] })), "clipped", "the visually-hidden pattern");
  assert.equal(fill(facts({ chain: [shown, { ...shown, clip: "rect(0px, 0px, 0px, 0px)" }] })), "clipped");
  assert.equal(fill(facts({ chain: [shown, { ...shown, mask: "linear-gradient(transparent, transparent)" }] })), "clipped");
  assert.equal(fill(facts({ chain: [{ ...shown, clipPath: "inset(0px round 8px)", clip: "auto", mask: "none" }] })), "ok");
  assert.equal(clipLeavesWhole("inset(2px 2px 2px 2px round 4px) border-box"), true);
  assert.equal(clipLeavesWhole("inset(10px)"), false);
  assert.equal(clipLeavesWhole("polygon(0 0, 1px 0, 1px 1px)"), false);
  assert.equal(clipLeavesWhole('url("#c")'), false);
});

test("what is typed must show: not transparent text on a transparent background, not text the colour of its background, not tiny text", () => {
  const f = (over: Partial<InkFacts>): string => fill(facts({ ink: { ...ink, ...over } }));
  assert.equal(f({}), "ok");
  assert.equal(f({ color: "rgba(0, 0, 0, 0)", textFill: "rgba(0, 0, 0, 0)", background: "rgba(0, 0, 0, 0)" }), "transparent");
  assert.equal(f({ color: "transparent", textFill: "transparent", background: "transparent" }), "transparent");
  assert.equal(f({ textFill: "rgba(0, 0, 0, 0)", background: "color(srgb 1 1 1 / 0)" }), "transparent", "-webkit-text-fill-color paints over color");
  assert.equal(f({ color: "rgba(0, 0, 0, 0)", textFill: "rgba(0, 0, 0, 0)" }), "ok", "transparent text on an opaque field: a masked input drawing its own overlay");
  assert.equal(f({ color: "rgb(255, 255, 255)", textFill: "rgb(255, 255, 255)", background: "rgb(254, 254, 254)" }), "unreadable");
  assert.equal(f({ fontSize: "0px" }), "unreadable");
  assert.equal(f({ fontSize: "5.5px" }), "unreadable");
  assert.equal(colorAlpha("rgba(10, 20, 30, 0.25)"), 0.25);
  assert.equal(colorAlpha("oklch(0.5 0.1 200 / 40%)"), 0.4);
  assert.equal(colorAlpha("rgb(1, 2, 3)"), 1);
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

test("at fill time every field must be on screen, and nothing may paint over its centre", () => {
  const screen = { width: 390, height: 844 };
  assert.equal(visibilityOf(facts({ viewport: screen, rect: { left: 20, top: 900, width: 240, height: 36 } })), "offscreen");
  assert.equal(visibilityOf(facts({ viewport: screen, hit: "other" })), "covered", "a field tucked under the provider's frame");
  assert.equal(visibilityOf(facts({ hit: "other" })), "covered", "covered whether or not it is the chosen field");
});

test("a cover is something that paints: an opaque background, an image, a backdrop filter, replaced content; a floating label or an empty overlay is not", () => {
  const p = (over: Partial<PaintFacts>): boolean =>
    paintsOver({ opacity: 1, background: "rgba(0, 0, 0, 0)", backgroundImage: "none", backdrop: "none", replaced: false, pseudo: [], ...over });
  assert.equal(p({}), false, "a transparent overlay (a toast layer, a floating label)");
  assert.equal(p({ background: "rgb(255, 255, 255)" }), true);
  assert.equal(p({ background: "rgba(0, 0, 0, 0.5)" }), true, "a modal's backdrop");
  assert.equal(p({ background: "rgba(0, 0, 0, 0.2)" }), false, "a faint tint leaves it readable");
  assert.equal(p({ background: "rgb(255, 255, 255)", opacity: 0.3 }), false);
  assert.equal(p({ backgroundImage: "linear-gradient(red, blue)" }), true);
  assert.equal(p({ backdrop: "blur(8px)" }), true);
  assert.equal(p({ replaced: true }), true, "an image or a frame over it");
  assert.equal(p({ pseudo: [{ background: "rgb(0, 0, 0)", backgroundImage: "none" }] }), true, "a ::before that paints over it");
});

test("only a radio is drawn through a proxy; a select is held to every rule (round-6 H1)", () => {
  assert.equal(visibilityOf(facts({ chain: [{ ...shown, opacity: "0" }], rect: { left: 20, top: 300, width: 1, height: 1 }, hit: "other" }), true), "ok");
  assert.equal(visibilityOf(facts({ chain: [{ ...shown, visibility: "hidden" }] }), true), "hidden");
  assert.equal(visibilityOf(facts({ rect: { left: -9999, top: 300, width: 240, height: 36 } }), true), "offpage");
  assert.equal(visibilityOf(facts({ viewport: { width: 390, height: 844 }, rect: { left: 20, top: 900, width: 240, height: 36 } }), true), "offscreen");
  const detect = readFileSync(new URL("./detect.ts", import.meta.url), "utf-8");
  assert.match(detect, /export function proxiedControl\(el: Element\): boolean \{\s*return el instanceof HTMLInputElement && el\.type === "radio";\s*\}/);
  assert.equal(typeof proxiedControl, "function");
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

test("only the person chooses the card field: a trusted press on it or a Tab onto it, with user activation", () => {
  const choose = content.slice(content.indexOf("function noteCardFocus("), content.indexOf("function deepActiveElement("));
  assert.match(choose, /lastPress\.target === t/, "the press landed on that very field");
  assert.match(choose, /if \(\(pressed \|\| tabbed\) && userActivated\(\) && cardFormForInput\(t\) !== null\) setCardFocus\(t\);/);
  assert.ok(!/cardFocus = t/.test(choose), "a focus alone never sets it");
  assert.match(content, /return ua\?\.isActive === true;/, "no activation API, no choice");
  assert.match(content, /for \(const type of \["pointerdown", "touchstart", "mousedown"\]\) document\.addEventListener\(type, notePress, \{ capture: true, passive: true \}\);/);
  assert.match(content, /e\.isTrusted && e\.key === "Tab" && !e\.altKey && !e\.ctrlKey && !e\.metaKey\) lastTab = performance\.now\(\);/);
  assert.match(content, /noteCardFocus\(t\);\s*maybeOpen\(t\);/, "looked at on every trusted focusin");
  assert.match(content, /noteCardFocus\(t \?\? null\); \/\/ a press on a card field that already had focus/, "and on a trusted click");
  // Let go when focus moves elsewhere in the page; kept when the page loses focus to the popup.
  assert.match(content, /if \(document\.hasFocus\(\) && deepActiveElement\(\) !== cardFocus\) setCardFocus\(null\);/);
  assert.match(content, /noteFocusLeft\(\); \/\/ H1/);
});

test("a card fill writes only the fields that can be seen, of the chosen field's form, and refuses when the chosen field or its frame cannot be", () => {
  const fill = content.slice(content.indexOf("async function fillCardIntoForm("), content.indexOf("// ---- G2 save-card capture"));
  assert.ok(!content.includes("cardFormBySig"), "no more \"the first form with the grant's signature\"");
  const focus = fill.indexOf('if (anchor === null) return nothing("no_focus");');
  const before = fill.indexOf('if (cardFieldsSeen(form, anchor) === null) return nothing("not_visible");');
  const reveal = fill.indexOf('await safeSend({ type: "revealCardForFill", itemId })');
  const after = fill.indexOf('if (seen === null) return nothing("not_visible");');
  const write = fill.indexOf("return applyCardFill(now, r.fields, seen);");
  assert.ok(focus > 0 && focus < before && before < reveal && reveal < after && after < write, "checked before the card is asked for and again before it is written");
  const seen = content.slice(content.indexOf("function cardFieldsSeen("), content.indexOf("function frameChainSeen("));
  assert.match(seen, /revealCovers\(scanScopes\(\), live\.map\(\(f\) => centre\(f\.input\)\), \(\) =>/, "covers that let the pointer through are hit-tested too");
  assert.match(seen, /probeVisibility\(f\.input, \{ onScreen: true, hitTest: true, fill: true, ignore: isOwnUiHost \}\), proxiedControl\(f\.input\), MIN_OPACITY\) === "ok"/, "every field: on screen, hit-tested, full rules");
  assert.match(seen, /if \(passing === null \|\| !passing\.some\(\(f\) => f\.input === anchor\)\) return null;/, "the chosen field must pass");
  assert.match(seen, /if \(!frameChainSeen\(centre\(anchor\)\)\) return null;/, "and the frame it is in");
  const chain = content.slice(content.indexOf("function frameChainSeen("), content.indexOf("/** Drive cardfill.ts per field ref"));
  assert.match(chain, /frame = win\.frameElement;/);
  assert.match(chain, /if \(frame === null \|\| parent === null/, "a frame element that cannot be reached fails");
  assert.match(chain, /visibilityOf\(\{ \.\.\.facts, ink: null, hit: whatShowsAt\(el, mapped\.x, mapped\.y\) \}, false, MIN_OPACITY\) === "ok"/);
  const apply = content.slice(content.indexOf("function applyCardFill("), content.indexOf("/** Popup-granted card fill"));
  assert.match(apply, /if \(!seen\.has\(input\)\) \{\s*unseen\(kind\);\s*continue;/, "a field that cannot be seen is never written");
  assert.match(apply, /if \(splitRan && panBoxes\.some\(\(b\) => !seen\.has\(b\)\)\) \{\s*unseen\("cardnumber"\);/, "a split number goes in whole or not at all");
  assert.match(apply, /if \(!seen\.has\(ref\.input\)\) \{\s*unseen\(ref\.kind\);/);
});

test("the Safari lane releases no card number or security code to an extension page", () => {
  const background = readFileSync(new URL("./background.ts", import.meta.url), "utf-8");
  const appLane = background.slice(background.indexOf('case "revealCardField": {'), background.indexOf('case "reveal":\n      return appVaultReveal(msg, sender);'));
  assert.match(appLane, /if \(msg\.field === "number" \|\| msg\.field === "cvv"\) return \{ ok: false, error: "not in this build" \}/);
  assert.ok(appLane.indexOf('msg.field === "number"') < appLane.indexOf("appVaultCard("), "refused before the app is asked");
});
