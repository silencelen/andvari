// node --test. Round-5 review C1, round-6 review H1/M2, round-7 review H1, round-8 review H and their regressions: a
// card number goes only into a field the person chose and can see, of the form that field is in, and never where a
// frame (any source, or none) lies over or under that field or its form (the frames rule, content.ts cardFillAgainst;
// paymentproviders.ts only names the provider in the explainer). The visibility rules are defence in depth for
// first-party card forms. The rules are pure (detect.ts visibilityOf and its helpers); the DOM probe that feeds them and
// the fill path's use of them are pinned below.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  boxContains,
  boxesOverlap,
  clipBox,
  colorAlpha,
  filterOpacity,
  maskAlphaAt,
  MIN_FIELD_PX,
  MIN_OPACITY,
  MIN_TEXT_ALPHA,
  paintsOver,
  samplePoints,
  unionBox,
  visibilityOf,
  type InkFacts,
  type PaintFacts,
  type VisibilityFacts,
} from "./detect.ts";
import { chooseAnchoredCardTarget } from "./messages.ts";

const shown = { display: "block", visibility: "visible", opacity: "1" };
const page = { left: 0, top: 0, width: 390, height: 2400 };
const base: VisibilityFacts = {
  chain: [{ ...shown, display: "inline-block" }, shown, shown],
  ink: null,
  rect: { left: 20, top: 300, width: 240, height: 36 },
  extents: [page],
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

test("a fill holds every field to near-full opacity, over every ancestor and any filter", () => {
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

test("any blend mode but normal refuses the fill: a near-black field lightened onto the page shows nothing (round-7 H1)", () => {
  assert.equal(fill(facts({ chain: [{ ...shown, blend: "lighten" }] })), "blended");
  assert.equal(fill(facts({ chain: [shown, { ...shown, blend: "multiply" }] })), "blended", "on an ancestor too");
  assert.equal(fill(facts({ chain: [{ ...shown, blend: "normal" }] })), "ok");
});

test("a mask hides a field only where it removes it: a fade at a panel's edge does not (round-7 regression 3)", () => {
  const panel = { left: 0, top: 0, width: 390, height: 800 };
  const fade = "linear-gradient(rgb(0, 0, 0) 80%, rgba(0, 0, 0, 0))";
  assert.equal(maskAlphaAt(fade, panel, 140, 300), 1, "the field sits in the opaque part");
  assert.ok(maskAlphaAt(fade, panel, 140, 760)! < 0.5, "and in the fade it is faint");
  assert.equal(maskAlphaAt("linear-gradient(rgba(0, 0, 0, 0), rgba(0, 0, 0, 0))", panel, 140, 300), 0, "a transparent mask hides everything");
  assert.equal(maskAlphaAt("linear-gradient(to right, rgb(0, 0, 0) 50%, rgba(0, 0, 0, 0) 50%)", panel, 300, 300), 0);
  assert.equal(maskAlphaAt("linear-gradient(90deg, rgb(0, 0, 0) 50%, rgba(0, 0, 0, 0) 50%)", panel, 100, 300), 1);
  assert.equal(maskAlphaAt('url("mask.svg")', panel, 140, 300), null, "an image is not told");
  assert.equal(maskAlphaAt("radial-gradient(rgb(0, 0, 0), rgba(0, 0, 0, 0))", panel, 140, 300), null);
  assert.equal(maskAlphaAt("none", panel, 140, 300), 1);
  const field = { left: 20, top: 300, width: 240, height: 36 };
  const masked = (mask: string): string => fill(facts({ rect: field, chain: [shown, { ...shown, mask, maskBox: panel }] }));
  assert.equal(masked(fade), "ok");
  assert.equal(masked("linear-gradient(rgba(0, 0, 0, 0), rgba(0, 0, 0, 0))"), "transparent");
  assert.equal(masked('url("mask.svg")'), "clipped");
  // A clip is judged by what it removes: the hit test's sample points (a clipped point is not the field's).
  assert.equal(fill(facts({ chain: [{ ...shown, display: "inline-block" }], hit: "other", viewport: { width: 390, height: 844 } })), "covered");
});

test("what is typed must show: text at least half opaque, not the background's colour, not tiny (round-7 H1)", () => {
  assert.equal(MIN_TEXT_ALPHA, 0.5);
  const f = (over: Partial<InkFacts>): string => fill(facts({ ink: { ...ink, ...over } }));
  assert.equal(f({}), "ok");
  // The review's overlay: transparent text over a transparent gradient, nothing to show what was filled.
  assert.equal(f({ color: "rgba(0, 0, 0, 0)", textFill: "rgba(0, 0, 0, 0)", background: "rgba(0, 0, 0, 0)", backgroundImage: "linear-gradient(rgba(0, 0, 0, 0), rgba(0, 0, 0, 0))" }), "unreadable");
  assert.equal(f({ color: "rgba(0, 0, 0, 0)", textFill: "rgba(0, 0, 0, 0)" }), "unreadable", "an opaque background no longer excuses invisible text");
  assert.equal(f({ textFill: "rgba(0, 0, 0, 0.4)" }), "unreadable", "-webkit-text-fill-color paints over color");
  assert.equal(f({ color: "rgba(17, 17, 17, 0.6)", textFill: "rgba(17, 17, 17, 0.6)" }), "ok");
  assert.equal(f({ color: "rgb(255, 255, 255)", textFill: "rgb(255, 255, 255)", background: "rgb(254, 254, 254)" }), "unreadable");
  assert.equal(f({ fontSize: "0px" }), "unreadable");
  assert.equal(f({ fontSize: "5.5px" }), "unreadable");
  assert.equal(colorAlpha("rgba(10, 20, 30, 0.25)"), 0.25);
  assert.equal(colorAlpha("oklch(0.5 0.1 200 / 40%)"), 0.4);
  assert.equal(colorAlpha("rgb(1, 2, 3)"), 1);
});

test("too small to use, or off the page; on the page means inside the page or the field's scrolling container", () => {
  assert.equal(visibilityOf(facts({ rect: { left: 20, top: 300, width: 0, height: 0 } })), "tiny");
  assert.equal(visibilityOf(facts({ rect: { left: 20, top: 300, width: 240, height: MIN_FIELD_PX - 1 } })), "tiny");
  assert.equal(visibilityOf(facts({ rect: { left: -9999, top: 300, width: 240, height: 36 } })), "offpage");
  assert.equal(visibilityOf(facts({ rect: { left: 20, top: -500, width: 240, height: 36 } })), "offpage");
  assert.equal(visibilityOf(facts({ rect: { left: 5000, top: 300, width: 240, height: 36 } })), "offpage");
  // Below the fold is still on the page: a long checkout is found before it is scrolled to.
  assert.equal(visibilityOf(facts({ rect: { left: 20, top: 1800, width: 240, height: 36 } })), "ok");
  // Scrolled: the box and the extents are both in viewport coordinates.
  assert.equal(visibilityOf(facts({ rect: { left: 20, top: -100, width: 240, height: 36 }, extents: [{ left: 0, top: -600, width: 390, height: 2400 }] })), "ok");
  // Round-6 M2: a field low in a scrolling modal is in that container's extent, though past the page's own height.
  const viewportPage = { left: 0, top: 0, width: 390, height: 844 };
  const modal = { left: 0, top: 40, width: 390, height: 3000 };
  assert.equal(visibilityOf(facts({ rect: { left: 20, top: 2600, width: 240, height: 36 }, extents: [viewportPage, modal] })), "ok");
  assert.equal(visibilityOf(facts({ rect: { left: 20, top: 3100, width: 240, height: 36 }, extents: [viewportPage, modal] })), "offpage");
  // Round-7 regression 1: a fixed login modal's field outside a smaller scroller is still on the page.
  const smallScroller = { left: 0, top: 600, width: 390, height: 200 };
  assert.equal(visibilityOf(facts({ rect: { left: 20, top: 100, width: 240, height: 36 }, extents: [viewportPage, smallScroller] })), "ok");
});

test("at fill time every field must be on screen, and nothing may paint over any of its sample points", () => {
  const screen = { width: 390, height: 844 };
  assert.equal(visibilityOf(facts({ viewport: screen, rect: { left: 20, top: 900, width: 240, height: 36 } })), "offscreen");
  assert.equal(visibilityOf(facts({ viewport: screen, hit: "other" })), "covered", "a field tucked under something");
  assert.equal(visibilityOf(facts({ hit: "other" })), "covered", "covered whether or not it is the chosen field");
  const points = samplePoints({ left: 0, top: 0, width: 200, height: 40 });
  assert.deepEqual(
    points,
    [{ x: 100, y: 20 }, { x: 50, y: 20 }, { x: 150, y: 20 }, { x: 100, y: 10 }, { x: 100, y: 30 }, { x: 50, y: 10 }, { x: 150, y: 10 }, { x: 50, y: 30 }, { x: 150, y: 30 }],
    "the centre, halfway to each side, and each corner inset by a quarter (round-8: a plus-shaped clip leaves the centre lines alone)",
  );
  assert.ok(points.filter((p) => p.x !== 100 && p.y !== 20).length === 4, "four points off both centre lines");
});

test("the frames rule's geometry: an area shared, a point inside, the boxes of a form, a frame's child clipped to it (round-8 H)", () => {
  const field = { left: 20, top: 300, width: 240, height: 36 };
  assert.ok(boxesOverlap(field, { left: 200, top: 320, width: 100, height: 100 }), "overlapping");
  assert.ok(!boxesOverlap(field, { left: 260, top: 300, width: 100, height: 36 }), "touching is not overlapping");
  assert.ok(!boxesOverlap(field, { left: 0, top: 0, width: 390, height: 0 }), "a box with no area (display: none) is never against anything");
  assert.ok(!boxesOverlap(field, { left: 0, top: 0, width: 390, height: 1 }), "a hidden controller frame across the top of the page is not against a form below it");
  assert.ok(boxContains(field, { x: 20, y: 300 }) && !boxContains(field, { x: 260, y: 300 }));
  assert.ok(!boxContains({ left: 0, top: 0, width: 0, height: 0 }, { x: 0, y: 0 }));
  assert.deepEqual(unionBox([field, { left: 20, top: 360, width: 110, height: 36 }, { left: 0, top: 0, width: 0, height: 0 }]), { left: 20, top: 300, width: 240, height: 96 }, "the form's box: its fields', empty ones aside");
  assert.equal(unionBox([{ left: 5, top: 5, width: 0, height: 10 }]), null);
  assert.deepEqual(clipBox({ left: 0, top: 0, width: 500, height: 500 }, field), field);
  assert.equal(clipBox({ left: 0, top: 0, width: 10, height: 10 }, field), null);
});

test("a cover is something that paints: an opaque background, an image, a backdrop filter, replaced content; a pseudo-element at its own opacity and size", () => {
  const p = (over: Partial<PaintFacts>): boolean =>
    paintsOver({ opacity: 1, background: "rgba(0, 0, 0, 0)", backgroundImage: "none", backdrop: "none", replaced: false, pseudo: [], ...over });
  assert.equal(p({}), false, "a transparent overlay (a toast layer)");
  assert.equal(p({ background: "rgb(255, 255, 255)" }), true);
  assert.equal(p({ background: "rgba(0, 0, 0, 0.5)" }), true, "a modal's backdrop");
  assert.equal(p({ background: "rgba(0, 0, 0, 0.2)" }), false, "a faint tint leaves it readable");
  assert.equal(p({ background: "rgb(255, 255, 255)", opacity: 0.3 }), false);
  assert.equal(p({ backgroundImage: "linear-gradient(red, blue)" }), true);
  assert.equal(p({ backdrop: "blur(8px)" }), true);
  assert.equal(p({ replaced: true }), true, "an image or a frame over it");
  assert.equal(p({ pseudo: [{ background: "rgb(0, 0, 0)", backgroundImage: "none" }] }), true, "a ::before that paints over it");
  // Round-7 regression 5: a filled text field's ripple (::before at opacity 0) and a hairline (::after, 1px high) are no cover.
  assert.equal(p({ pseudo: [{ background: "rgb(0, 0, 0)", backgroundImage: "none", opacity: "0" }] }), false);
  assert.equal(p({ pseudo: [{ background: "rgb(0, 0, 0)", backgroundImage: "none", width: "240px", height: "1px" }] }), false);
  assert.equal(p({ pseudo: [{ background: "rgb(0, 0, 0)", backgroundImage: "none", opacity: "1", width: "240px", height: "36px" }] }), true);
});

test("the grant follows the form holding the chosen field, in the frame that chose last (round-6 M2)", () => {
  const number = ["cardnumber", "cardexpiry", "cardcvv"] as const;
  const saved = ["cardcvv"] as const;
  // The frame's richest form is the new-card one; the person chose the saved card's security code.
  assert.deepEqual(chooseAnchoredCardTarget([{ frameId: 0, forms: [[...number], [...saved]], anchor: 1, anchorAt: 5 }]), { frameId: 0, kinds: ["cardcvv"] });
  // A sub-frame where the person chose wins over a top frame where nobody did.
  assert.deepEqual(chooseAnchoredCardTarget([{ frameId: 0, forms: [[...number]], anchor: null }, { frameId: 4, forms: [[...saved]], anchor: 0, anchorAt: 9 }]), { frameId: 4, kinds: ["cardcvv"] });
  // The latest choice wins.
  assert.deepEqual(chooseAnchoredCardTarget([{ frameId: 0, forms: [[...number]], anchor: 0, anchorAt: 9 }, { frameId: 4, forms: [[...saved]], anchor: 0, anchorAt: 5 }]), { frameId: 0, kinds: [...number] });
  // Nothing chosen, or an index out of range: no anchored target (the old chooser picks, and the frame says so).
  assert.equal(chooseAnchoredCardTarget([{ frameId: 0, forms: [[...number]] }]), null);
  assert.equal(chooseAnchoredCardTarget([{ frameId: 0, forms: [[...number]], anchor: 3, anchorAt: 1 }]), null);
  assert.equal(chooseAnchoredCardTarget([{ frameId: 0, forms: [[...number]], anchor: 0.5, anchorAt: 1 }]), null);
});

// ---- wiring: detection and fill use the rules (detect.ts and content.ts need a DOM, so these pin the source) ----

const detect = readFileSync(new URL("./detect.ts", import.meta.url), "utf-8");
const content = readFileSync(new URL("./content.ts", import.meta.url), "utf-8");
const background = readFileSync(new URL("./background.ts", import.meta.url), "utf-8");

test("detection collects only fields that pass the page-time rules; selects and radios drawn through a proxy are collected", () => {
  assert.match(detect, /function isVisible\(el: HTMLElement\): boolean \{\s*return isRendered\(el\) && visibilityOf\(probeVisibility\(el, \{ onScreen: false, hitTest: false \}\), proxiedAtDetection\(el\)\) === "ok";/);
  assert.match(detect, /export function proxiedAtDetection\(el: Element\): boolean \{\s*return el instanceof HTMLSelectElement \|\| \(el instanceof HTMLInputElement && el\.type === "radio"\);/);
  const collect = detect.slice(detect.indexOf("function collect(root: Document | ShadowRoot): Field[] {"));
  assert.ok(collect.includes("if (el.disabled || el.readOnly || !isVisible(el)) continue;"), "inputs (login and card)");
  assert.ok(collect.includes("if (el.disabled || !isVisible(el) || el.type !== \"select-one\") continue;"), "selects");
  // At fill time only a radio, or a select for the expiry or the brand, is excused (regression 2); never a number or code.
  assert.match(detect, /return el instanceof HTMLSelectElement && \(kind === "cardexpmonth" \|\| kind === "cardexpyear" \|\| kind === "cardtype"\);/);
  assert.ok(!detect.includes("revealCovers") && !detect.includes("MAX_COVER_SCAN"), "no global scan of the page (regression 7)");
});

test("the hit test looks at several points, and nothing but the field itself is excused at them (round-8 L)", () => {
  const shows = detect.slice(detect.indexOf("export function whatShowsAt("), detect.indexOf("export function probeVisibility("));
  assert.match(shows, /for \(const \{ x, y \} of points\)/);
  assert.match(shows, /if \(at === el \|\| el\.contains\(at\)\) \{\s*found = true;/);
  assert.match(shows, /if \(ignore\(at\)\) continue;\s*if \(paintsOver\(paintFactsOf\(at\)\)\) return "other";/, "only this extension's own UI is looked through");
  assert.ok(!detect.includes("isFieldPart"), "a label or a wrapper's part over a sample point is a cover like any other");
  assert.match(detect, /if \(node\.querySelectorAll\(CONTROLS\)\.length !== 1\) break;/, "a wrapper holds no other control");
});

test("only the person chooses the card field, and the choice is held to the fill rules (round-7 H1, M2-tab, regression 6)", () => {
  const choose = content.slice(content.indexOf("function chooseIfPersonPut("), content.indexOf("/** The innermost element focus is on"));
  assert.match(choose, /const onField = press !== null && press\.target === t && now - press\.at < CHOOSE_PRESS_MS;/, "a press on that very field");
  assert.match(choose, /const nearField = press !== null && press\.sameTask && target !== null && \(labels\.some\(\(l\) => l === target \|\| l\.contains\(target\)\) \|\| \(wrapper !== null && wrapper\.contains\(target\)\)\);/, "or on its label or wrapper, focusing it in the same task");
  assert.match(choose, /const tabbed = focus !== undefined && tab !== null && now - tab\.at < CHOOSE_TAB_MS && tab\.moves === focusMoves && from !== null && from === tab\.from;/, "a Tab from the field focused at keydown, nothing moved in between");
  // Round-8 L: whether the page prevented the Tab is read once the keydown is done, with focus still there and moved nowhere else.
  assert.match(choose, /setTimeout\(\(\) => \{\s*if \(tab\.event\.defaultPrevented \|\| focusMoves !== moves \|\| deepActiveElement\(\) !== t\) return;\s*chooseIfFits\(t\);\s*\}, 0\);/);
  assert.ok(choose.indexOf("tab.event.defaultPrevented") > choose.indexOf("setTimeout("), "never read while the keydown may still be dispatching");
  assert.match(choose, /const from = focus\?\.relatedTarget instanceof Element \? focus\.relatedTarget : null;/);
  assert.match(choose, /if \(onField \|\| nearField\) \{\s*chooseIfFits\(t\);/);
  const fits = content.slice(content.indexOf("function chooseIfFits("), content.indexOf("/** The innermost element focus is on"));
  assert.match(fits, /if \(filling \|\| !userActivated\(\)\) return;/);
  assert.match(fits, /if \(!chosenFieldSeen\(t\)\) return;/, "a field that cannot be seen is not chosen");
  assert.match(fits, /const against = cardFillAgainst\(t, form\);\s*if \(against !== null\) \{\s*refusedChoice = \{ field: t, host: against\.host \};\s*return;\s*\}\s*setCardFocus\(t\);/, "nor one a frame stands against (round-8 H)");
  assert.ok(!/cardFocus = t/.test(choose + fits), "a focus alone never sets it");
  assert.match(content, /return ua\?\.isActive === true;/, "no activation API, no choice");
  assert.match(content, /for \(const type of \["pointerdown", "touchstart", "mousedown", "click"\]\) document\.addEventListener\(type, notePress, \{ capture: true, passive: true \}\);/);
  assert.match(content, /setTimeout\(\(\) => \{\s*press\.sameTask = false;\s*\}, 0\);/, "the same task, and no longer");
  assert.match(content, /lastTab = \{ event: e, from: document\.activeElement, moves: focusMoves, at: performance\.now\(\) \};/);
  assert.match(content, /noteCardFocus\(t, e\);\s*maybeOpen\(t\);/, "every trusted focusin is looked at");
  assert.match(content, /try \{\s*chooseIfPersonPut\(t, focus\);\s*\} finally \{\s*if \(focus !== undefined\) focusMoves\+\+;\s*\}/, "and counted after it is looked at");
  // Let go when focus moves elsewhere in the page; kept when the page loses focus to the popup, and then measured
  // again once the blur has settled (round-8 M: a page's validation may move the form on blur).
  assert.match(content, /if \(!document\.hasFocus\(\)\) \{\s*remeasureAfterBlur\(\);\s*return;\s*\}\s*if \(deepActiveElement\(\) !== cardFocus\) setCardFocus\(null\);/);
  assert.match(content, /const BLUR_SETTLE_MS = \[150, 500\] as const;/);
  assert.match(content, /chosenAs = \{ place: contentPositionOf\(field\), digest: chosenAs\.digest \};/, "the place only; the styles stay those of the choice");
  // The place and styles at the choice; a fill refuses if either changed. No text colour (a blur check recolours it;
  // the fill checks the text's alpha anyway).
  assert.match(content, /chosenAs = \{ place: contentPositionOf\(next\), digest: styleDigest\(next\) \};/);
  assert.match(content, /return JSON\.stringify\(\[chain, f\.ink === null \? null : f\.ink\.fontSize\]\);/);
});

test("a card fill: never where a frame is against the chosen field or its form; only the chosen form's fields that can be seen", () => {
  const fill = content.slice(content.indexOf("async function fillCardIntoForm("), content.indexOf("// ---- G2 save-card capture"));
  assert.ok(!content.includes("cardFormBySig"), "no more \"the first form with the grant's signature\"");
  assert.ok(!content.includes("providerFramesHere") && !content.includes("providerFrameHost"), "no gate on a frame's src (round-8 H)");
  const focus = fill.indexOf('if (refusedChoice !== null && refusedChoice.field.isConnected) return framed(refusedChoice);');
  const closed = fill.indexOf('return nothing(cardFormsAllClosed() ? "closed_form" : "no_focus");');
  const frames = fill.indexOf("if (against !== null) return framed(against);");
  const changedBefore = fill.indexOf('if (before === "changed") return nothing("field_changed");');
  const before = fill.indexOf('if (before === null) return nothing("not_visible");');
  const reveal = fill.indexOf('await safeSend({ type: "revealCardForFill", itemId })');
  const framesAfter = fill.indexOf("if (againstLate !== null) return framed(againstLate);");
  const after = fill.indexOf('if (seen === null) return nothing("not_visible");');
  const write = fill.indexOf("return applyCardFill(now, r.fields, seen);");
  assert.ok(focus > 0 && focus < closed && closed < frames && frames < changedBefore && changedBefore < before && before < reveal && reveal < framesAfter && framesAfter < after && after < write, "checked before the card is asked for and again before it is written");
  assert.match(fill, /const against = cardFillAgainst\(anchor, form\);/);
  assert.match(fill, /const againstLate = cardFillAgainst\(anchor, now\);/, "the form of the fresh scan, after the round trip");
  // The rule: any frame element, any source or none, in every scope and child document this script can reach, against
  // the field's box, the form's box or the field's sample points; up the frame chain too; on Safari, any overlap.
  const against = content.slice(content.indexOf("function framesAgainst("), content.indexOf("/** Whether [t] passes the full fill rules"));
  assert.match(against, /const all = everyElement\(doc\);\s*if \(all === null\) return \{ host: null \};/, "a page too large to walk is refused, never half-walked");
  assert.match(against, /if \(el === exclude \|\| !FRAME_TAGS\.has\(el\.tagName\.toUpperCase\(\)\)\) continue;/);
  assert.match(against, /const hits = \(box: Box\): boolean => boxes\.some\(\(b\) => boxesOverlap\(box, b\)\) \|\| points\.some\(\(p\) => boxContains\(box, p\)\);/);
  assert.match(against, /for \(const inner of framesInside\(el, box\)\) if \(hits\(inner\.box\)\) return \{ host: frameHost\(inner\.el\) \};/, "and the frames of child documents it can read");
  assert.match(against, /for \(const at of doc\.elementsFromPoint\(x, y\)\) \{\s*if \(at !== exclude && FRAME_TAGS\.has\(at\.tagName\.toUpperCase\(\)\)\) return \{ host: frameHost\(at\) \};/, "and what lies under the sample points");
  assert.match(against, /const here = framesAgainst\(field\.ownerDocument, \[fieldBox, formBox\], points, null\);/);
  assert.match(against, /if \(__ANDVARI_TARGET__ === "safari"\) \{/);
  assert.match(against, /if \(el === field \|\| ancestors\.has\(el\) \|\| field\.contains\(el\) \|\| \(wrapper !== null && wrapper\.contains\(el\)\)\) continue;\s*if \(boxesOverlap\(boxOf\(el\.getBoundingClientRect\(\)\), fieldBox\)\) return \{ host: null \};/, "Safari: a closed root's host over the field");
  assert.match(against, /return framesUpChain\(fieldBox\);/);
  assert.match(against, /const against = framesAgainst\(parentDoc, \[mapped\], samplePoints\(mapped\), frame\);/, "in each parent, around this frame's place");
  const walk = content.slice(content.indexOf("function everyElement("), content.indexOf("function boxOf("));
  assert.match(walk, /if \(out\.length > FRAME_SCAN_MAX\) return false;/);
  assert.match(walk, /const sr = shadowRootOf\(el\);/, "every root it can open, not the scan's capped list");
  assert.ok(!walk.includes("shadowRoots") && !walk.includes("SHADOW_MAX_ROOTS"));
  const host = content.slice(content.indexOf("function frameHost("), content.indexOf("function framesInside("));
  assert.match(host, /return paymentProviderHost\(new URL\(src, el\.ownerDocument\.baseURI\)\.href\);/, "the list only names the provider");
  const seen = content.slice(content.indexOf("function cardFieldsSeen("), content.indexOf("function frameChainSeen("));
  assert.match(seen, /if \(!live\.some\(\(f\) => f\.input === anchor\) \|\| !chosenFieldSeen\(anchor\)\) return null;/, "the chosen field, full rules");
  assert.match(seen, /if \(moved \|\| styleDigest\(anchor\) !== chosenAs\.digest\) return "changed";/, "where and as it was at the choice");
  assert.match(seen, /visibilityOf\(probeVisibility\(f\.input, \{ onScreen: true, hitTest: true, fill: true, ignore: isOwnUiHost \}\), proxiedAtFill\(f\.input, f\.kind\), MIN_OPACITY\) === "ok"/, "every other field: on screen, hit-tested, full rules but the proxy's");
  assert.match(seen, /if \(!frameChainSeen\(\{ x: r\.left \+ r\.width \/ 2, y: r\.top \+ r\.height \/ 2 \}\)\) return null;/, "and the frame it is in");
  const chain = content.slice(content.indexOf("function frameChainSeen("), content.indexOf("function cardFormsAllClosed("));
  assert.match(chain, /frame = win\.frameElement;/);
  assert.match(chain, /if \(frame === null \|\| parent === null/, "a frame element that cannot be reached fails");
  assert.match(chain, /visibilityOf\(\{ \.\.\.facts, ink: null, hit: whatShowsAt\(el, \[mapped\]\) \}, false, MIN_OPACITY\) !== "ok"/);
  const apply = content.slice(content.indexOf("function applyCardFill("), content.indexOf("/** Popup-granted card fill"));
  assert.match(apply, /if \(!seen\.has\(input\)\) \{\s*unseen\(kind\);\s*continue;/, "a field that cannot be seen is never written");
  assert.match(apply, /if \(splitRan && panBoxes\.some\(\(b\) => !seen\.has\(b\)\)\) \{\s*unseen\("cardnumber"\);/, "a split number goes in whole or not at all");
  // No chip where no fill would go.
  assert.match(content, /if \(cardFillAgainst\(target, chipForm\) !== null\) return;/);
});

test("the worker: no gate on frames' sources; the grant from the chosen form; the explainer names a listed provider", () => {
  assert.ok(!background.includes("providerBlock") && !background.includes("providers"), "round-8 H: the worker never guesses from a frame's src");
  assert.match(background, /const target = chooseAnchoredCardTarget\(eligible\) \?\? chooseCardTarget\(eligible\);/);
  const info = background.slice(background.indexOf("async function cardFormInfo("), background.indexOf("function broadcastRescanCardForms("));
  assert.match(info, /const anchor = typeof a === "number" && Number\.isInteger\(a\) && a >= 0 && a < msg\.forms\.length \? a : null;/, "an index out of range is no choice");
  assert.match(info, /msg\.choseNow === true \|\| was\?\.anchor !== anchor \|\| was\.anchorAt === undefined \? Date\.now\(\) : was\.anchorAt/, "L7: every choice is stamped");
  const report = content.slice(content.indexOf("function reportCardForm("), content.indexOf("/** Bumped by every choice"));
  assert.match(report, /void safeSend\(\{ type: "cardFormInfo", forms, anchor, choseNow \}\);/);
});

test("the Safari lane releases no card number or security code to an extension page", () => {
  const appLane = background.slice(background.indexOf('case "revealCardField": {'), background.indexOf('case "reveal":\n      return appVaultReveal(msg, sender);'));
  assert.match(appLane, /if \(msg\.field === "number" \|\| msg\.field === "cvv"\) return \{ ok: false, error: "not in this build" \}/);
  assert.ok(appLane.indexOf('msg.field === "number"') < appLane.indexOf("appVaultCard("), "refused before the app is asked");
});
