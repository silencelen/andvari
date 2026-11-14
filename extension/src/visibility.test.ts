// node --test. The card-fill threat model (docs/design/2026-11-09-ios-app.md, "Card fill threat model"; owner decision
// 2026-11-14): a card goes only into a payment provider's card document, by the origin the browser reports for it
// (cardrelease.ts, cardproviders.ts, pinned in their own tests). Inside that document, the fill's visibility rules keep
// the box's own hidden fields out: only the field the person chose and can see, and only the fields of its form that
// pass. The rules are pure where they can be (detect.ts visibilityOf and its helpers); the DOM probe that feeds them and
// the fill path's use of them are pinned below, and so is the absence of the page-geometry rules they replaced.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  colorAlpha,
  filterOpacity,
  maskAlphaAt,
  MIN_FIELD_PX,
  MIN_OPACITY,
  MIN_TEXT_ALPHA,
  paintsOver,
  samplePoints,
  visibilityOf,
  type InkFacts,
  type PaintFacts,
  type VisibilityFacts,
} from "./detect.ts";

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
    [
      { x: 100, y: 20 },
      { x: 50, y: 20, offCentre: true },
      { x: 150, y: 20, offCentre: true },
      { x: 100, y: 10, offCentre: true },
      { x: 100, y: 30, offCentre: true },
      { x: 50, y: 10, offCentre: true },
      { x: 150, y: 10, offCentre: true },
      { x: 50, y: 30, offCentre: true },
      { x: 150, y: 30, offCentre: true },
    ],
    "the centre, halfway to each side, and each corner inset by a quarter (round-8: a plus-shaped clip leaves the centre lines alone)",
  );
  assert.ok(points.filter((p) => p.x !== 100 && p.y !== 20).length === 4, "four points off both centre lines");
  assert.equal(points.filter((p) => p.offCentre !== true).length, 1, "only the centre excuses nothing");
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

test("the hit test looks at nine points: the field itself at the centre; elsewhere a label, image or SVG icon too (round-9)", () => {
  const shows = detect.slice(detect.indexOf("export function whatShowsAt("), detect.indexOf("export function probeVisibility("));
  assert.match(shows, /for \(const \{ x, y, offCentre \} of points\)/);
  assert.match(shows, /if \(at === el \|\| el\.contains\(at\)\) \{\s*found = true;/);
  assert.match(shows, /if \(ignore\(at\) \|\| \(offCentre === true && excusedOffCentre\(at\)\)\) continue;\s*if \(paintsOver\(paintFactsOf\(at\)\)\) return "other";/, "this extension's own UI, and away from the centre a label, image or SVG icon");
  assert.ok(!detect.includes("isFieldPart"), "nothing else of a wrapper is excused");
  assert.match(detect, /if \(node\.querySelectorAll\(CONTROLS\)\.length !== 1\) break;/, "a wrapper holds no other control");
});

test("only the person chooses the card field, only in a provider's card document, held to the fill rules (round-7 H1, M2-tab, regression 6)", () => {
  assert.match(content, /const cardBox = isCardProviderOrigin\(location\.origin\);/);
  const choose = content.slice(content.indexOf("function chooseIfPersonPut("), content.indexOf("/** The innermost element focus is on"));
  assert.match(choose, /if \(filling \|\| !cardBox\) return;/, "a press in any other document never chooses a card field");
  assert.match(choose, /const onField = press !== null && press\.target === t && now - press\.at < CHOOSE_PRESS_MS;/, "a press on that very field");
  assert.match(choose, /const nearField = press !== null && press\.sameTask && target !== null && \(labels\.some\(\(l\) => l === target \|\| l\.contains\(target\)\) \|\| \(wrapper !== null && wrapper\.contains\(target\)\)\);/, "or on its label or wrapper, focusing it in the same task");
  assert.match(choose, /const tabbed = focus !== undefined && tab !== null && now - tab\.at < CHOOSE_TAB_MS && tab\.moves === focusMoves && from !== null && from === tab\.from;/, "a Tab from the field focused at keydown, nothing moved in between");
  // Round-8 L: whether the page prevented the Tab is read once the keydown is done, with focus still there and moved nowhere else.
  assert.match(choose, /setTimeout\(\(\) => \{\s*if \(tab\.event\.defaultPrevented \|\| focusMoves !== moves \|\| deepActiveElement\(\) !== t\) return;\s*chooseIfFits\(t\);\s*\}, 0\);/);
  assert.ok(choose.indexOf("tab.event.defaultPrevented") > choose.indexOf("setTimeout("), "never read while the keydown may still be dispatching");
  assert.match(choose, /if \(onField \|\| nearField\) \{\s*chooseIfFits\(t\);/);
  const fits = content.slice(content.indexOf("function chooseIfFits("), content.indexOf("/** The innermost element focus is on"));
  assert.match(fits, /if \(filling \|\| !cardBox \|\| !userActivated\(\)\) return;/);
  assert.match(fits, /if \(!chosenFieldSeen\(t\)\) return;\s*setCardFocus\(t\);/, "a field that cannot be seen is not chosen");
  assert.ok(!/cardFocus = t/.test(choose + fits), "a focus alone never sets it");
  assert.match(content, /return ua\?\.isActive === true;/, "no activation API, no choice");
  assert.match(content, /for \(const type of \["pointerdown", "touchstart", "mousedown", "click"\]\) document\.addEventListener\(type, notePress, \{ capture: true, passive: true \}\);/);
  assert.match(content, /setTimeout\(\(\) => \{\s*press\.sameTask = false;\s*\}, 0\);/, "the same task, and no longer");
  assert.match(content, /lastTab = \{ event: e, from: document\.activeElement, moves: focusMoves, at: performance\.now\(\) \};/);
  assert.match(content, /noteCardFocus\(t, e\);\s*maybeOpen\(t\);/, "every trusted focusin is looked at");
  assert.match(content, /try \{\s*chooseIfPersonPut\(t, focus\);\s*\} finally \{\s*if \(focus !== undefined\) focusMoves\+\+;\s*\}/, "and counted after it is looked at");
  // Owner decision 2026-11-14: the choice is let go only when ANOTHER element of this document takes focus; focus going
  // to the body (iOS's keyboard Done) or out of the window (the popup) keeps it, and so does nothing but its expiry.
  const left = content.slice(content.indexOf("function noteFocusLeft("), content.indexOf("/** [U12] a FRESH scan"));
  assert.match(left, /if \(filling \|\| cardFocus === null \|\| !document\.hasFocus\(\)\) return;/);
  assert.match(left, /if \(now === null \|\| now === cardFocus \|\| now === document\.body \|\| now === document\.documentElement\) return;\s*setCardFocus\(null\);/);
  assert.match(content, /if \(!cardFocus\.isConnected \|\| performance\.now\(\) - chosenAt > CHOICE_TTL_MS\) \{/, "the choice expires");
  assert.match(content, /const CHOICE_TTL_MS = 10 \* 60 \* 1000;/, "as the worker's does (cardrelease.ts)");
});

test("a card fill: only in a provider's card document, only the chosen form's fields, or a sibling's one form, that can be seen", () => {
  const fill = content.slice(content.indexOf("async function fillCardIntoForm("), content.indexOf("// ---- G2 save-card capture"));
  assert.match(fill, /if \(typeof sig !== "string" \|\| !cardBox\) return nothing\("no_form"\);/);
  assert.match(fill, /if \(chosen === true\) \{\s*\/\/[^\n]*\n\s*anchor = chosenField\(\);/);
  assert.match(fill, /if \(anchor === null\) return nothing\(cardFormsAllClosed\(\) \? "closed_form" : "no_focus"\);/);
  assert.match(fill, /const forms = freshCardForms\(\);\s*return forms\.length === 1 \? forms\[0\]! : null;/, "a sibling fills its one card form, never one of several");
  const sig = fill.indexOf('if (!form || cardSigOf(form) !== sig) return nothing("no_form");');
  const before = fill.indexOf('if (cardFieldsSeen(form, anchor) === null) return nothing("not_visible");');
  const reveal = fill.indexOf('await safeSend({ type: "revealCardForFill", itemId })');
  const sigAfter = fill.indexOf('if (!now || cardSigOf(now) !== sig) return nothing("no_form");');
  const after = fill.indexOf('if (seen === null) return nothing("not_visible");');
  const write = fill.indexOf("return applyCardFill(now, r.fields, seen);");
  assert.ok(sig > 0 && sig < before && before < reveal && reveal < sigAfter && sigAfter < after && after < write, "checked before the card is asked for and again before it is written");
  const seen = content.slice(content.indexOf("function cardFieldsSeen("), content.indexOf("/** Whether every card form this frame found"));
  assert.match(seen, /if \(anchor !== null && \(!live\.some\(\(f\) => f\.input === anchor\) \|\| !chosenFieldSeen\(anchor\)\)\) return null;/, "the chosen field, full rules");
  assert.match(seen, /visibilityOf\(probeVisibility\(f\.input, \{ onScreen: true, hitTest: true, fill: true, ignore: isOwnUiHost \}\), proxiedAtFill\(f\.input, f\.kind\), MIN_OPACITY\) === "ok"/, "every other field: on screen, hit-tested, full rules but the proxy's");
  const apply = content.slice(content.indexOf("function applyCardFill("), content.indexOf("/** Popup-granted card fill"));
  assert.match(apply, /if \(!seen\.has\(input\)\) \{\s*unseen\(kind\);\s*continue;/, "a field that cannot be seen is never written");
  assert.match(apply, /if \(splitRan && panBoxes\.some\(\(b\) => !seen\.has\(b\)\)\) \{\s*unseen\("cardnumber"\);/, "a split number goes in whole or not at all");
  // The chip shows only where a fill can go.
  assert.match(content, /if \(!cardBox\) return;\s*if \(!\(target instanceof HTMLInputElement \|\| target instanceof HTMLSelectElement\)\) return;/);
  // A form without a card number is a card form only in a provider's card document (a security code alone, one field of
  // a split form); everywhere else detection is as it was.
  assert.match(content, /findCardForms\(s, \{ numberless: cardBox \}\)/);
  assert.match(detect, /if \(!numberless && !fields\.some\(\(f\) => f\.cardKind === "cardnumber"\)\) return null;/);
  // The page-geometry rules the owner's decision replaced are gone, not left unused.
  for (const gone of ["framesAgainst", "cardFillAgainst", "framesUpChain", "frameChainSeen", "frameContentMapping", "providerCardFramesHere", "cardEntryHost", "styleDigest", "remeasureAfterBlur", "refusedChoice", "everyElement", "paymentProvider"]) {
    assert.ok(!content.includes(gone), `content.ts: ${gone}`);
  }
  for (const gone of ["canHostShadow", "extensionFrameSrc", "axisAligned", "boxesOverlap", "FRAME_TAGS", "contentPositionOf", "unionBox", "clipBox"]) {
    assert.ok(!detect.includes(gone), `detect.ts: ${gone}`);
  }
});

test("the worker: a card only to a provider's card document, by the origin the browser reports; grants per frame", () => {
  const info = background.slice(background.indexOf("async function cardFormInfo("), background.indexOf("function broadcastRescanCardForms("));
  assert.match(info, /const origin = frameOriginOf\(sender\);/, "the frame's identity is the browser's report");
  assert.match(info, /const anchor = typeof a === "number" && Number\.isInteger\(a\) && a >= 0 && a < msg\.forms\.length \? a : null;/, "an index out of range is no choice");
  assert.match(info, /msg\.choseNow === true \|\| was\?\.anchor !== anchor \|\| was\.anchorAt === undefined \? Date\.now\(\) : was\.anchorAt/, "L7: every choice is stamped");
  // The top frame's word about the provider frames it shows is a hint for the popup's line, kept apart from the records
  // a fill reads; the frames' ancestor origins are each frame's own report of what the browser lists for it.
  assert.match(info, /if \(frameId === 0\) \{\s*heard\.top = true;[\s\S]*?heard\.hints = /);
  assert.match(info, /reg\[frameId\] = \{ origin, forms: msg\.forms, anchor, \.\.\.\(anchorAt !== undefined \? \{ anchorAt \} : \{\}\), ancestors: ancestorsOf\(msg\.ancestors\) \};/);
  for (const [name, from, to] of [
    ["fillCardFromPopup", "async function fillCardFromPopup(", "async function revealCardForFill("],
    ["revealCardForFill", "async function revealCardForFill(", "// ---- capture → pending save → resolve ----"],
    ["cardChipOffer", "async function cardChipOffer(", "async function openPopupForCards("],
  ] as const) {
    const body = background.slice(background.indexOf(from), background.indexOf(to));
    assert.ok(!/\.hints\b/.test(body), `${name} never reads the page's hints`);
  }
  const chip = background.slice(background.indexOf("async function cardChipOffer("), background.indexOf("async function openPopupForCards("));
  assert.match(chip, /if \(!isCardProviderOrigin\(origin\)\) return no;/);
  assert.match(chip, /if \(rec\.origin !== origin \|\| !mayReceiveCard\(rec\)\) return no;/);
  const fill = background.slice(background.indexOf("async function fillCardFromPopup("), background.indexOf("async function revealCardForFill("));
  assert.match(fill, /const plan = cardFillPlan\(records\(\), chosen\);[\s\S]{0,200}?if \(!plan\.ok\) return \{ ok: false, code: "duplicate_fields",[\s\S]{0,120}?const targets = plan\.targets;/, "two frames taking one kind: no fill at all");
  assert.ok(fill.indexOf("if (!plan.ok)") < fill.indexOf("cardGrants.set("), "refused before any grant is minted");
  assert.match(fill, /if \(outcome\.filled === "nothing"\) return \{ ok: false, outcome,/, "a fill the chosen frame refuses fills no sibling");
  assert.match(fill, /\} finally \{\s*\/\/[^\n]*\n\s*cardGrants\.delete\(tabId\);/, "every grant not redeemed is voided when the round trip ends");
  assert.ok(!fill.includes("topOrigin("), "the shop's top origin decides nothing");
  const reveal = background.slice(background.indexOf("async function revealCardForFill("), background.indexOf("// ---- capture → pending save → resolve ----"));
  assert.match(reveal, /const grant = cardGrants\.get\(tabId\)\?\.get\(frameId\);\s*if \(!mayRedeem\(grant, msg\.itemId, sender, Date\.now\(\)\)\) return \{ ok: false, error: "no card grant" \};/, "each frame redeems its own grant");
  assert.match(reveal, /cardGrants\.get\(tabId\)\?\.delete\(frameId\); \/\/ one-shot/);
});

test("the Safari lane releases no card number or security code to an extension page", () => {
  const appLane = background.slice(background.indexOf('case "revealCardField": {'), background.indexOf('case "reveal":\n      return appVaultReveal(msg, sender);'));
  assert.match(appLane, /if \(msg\.field === "number" \|\| msg\.field === "cvv"\) return \{ ok: false, error: "not in this build" \}/);
  assert.ok(appLane.indexOf('msg.field === "number"') < appLane.indexOf("appVaultCard("), "refused before the app is asked");
});
