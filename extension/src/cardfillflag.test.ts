// node --test. In-page card fill is per build (owner decision 2026-11-14: the first App Store version ships without it).
// These prove, of the Safari worker as esbuild bundles it, that a build without card fill cannot release card data: the
// card path's handlers are not in the bundle at all, and every entry point answers its fixed refusal.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import * as esbuild from "esbuild";
import { CARD_FILL, CARD_FILL_OFF } from "./cardfillflag.ts";
import { CARD_FILL_FROM_APP, CARD_FILL_OFF_COPY, cardFillErrorCopy, cardFillOffLine } from "./errors.ts";

const read = (f: string): string => readFileSync(new URL(f, import.meta.url), "utf8");

/** The Safari worker as build.mjs bundles it for the App Store (release), with or without card fill. */
async function safariWorker(cardFill: boolean): Promise<string> {
  const out = await esbuild.build({
    entryPoints: [new URL("./background.ts", import.meta.url).pathname],
    bundle: true,
    format: "iife",
    target: "es2022",
    minify: true,
    write: false,
    logLevel: "silent",
    define: {
      __ANDVARI_TARGET__: JSON.stringify("safari"),
      __ANDVARI_UITEST_PROVIDER__: JSON.stringify(""),
      __ANDVARI_PROVIDER_TEST_HOSTS__: "false",
      __ANDVARI_CARDFILL__: JSON.stringify(cardFill),
    },
  });
  return out.outputFiles[0]!.text;
}

/** The Safari content script as build.mjs bundles it for the App Store (release), with or without card fill. */
async function safariContent(cardFill: boolean): Promise<string> {
  const out = await esbuild.build({
    entryPoints: [new URL("./content.ts", import.meta.url).pathname],
    bundle: true,
    format: "iife",
    target: "es2022",
    minify: true,
    write: false,
    logLevel: "silent",
    define: {
      __ANDVARI_TARGET__: JSON.stringify("safari"),
      __ANDVARI_UITEST_PROVIDER__: JSON.stringify(""),
      __ANDVARI_PROVIDER_TEST_HOSTS__: "false",
      __ANDVARI_CARDFILL__: JSON.stringify(cardFill),
    },
  });
  return out.outputFiles[0]!.text;
}

/** Strings only the content script's in-page card fill holds, by part: the report of a frame's card forms (with the
 *  choice it carries), the chip (its offer, its words, its popup), the choice of a field (the page's user activation, the
 *  frame's ancestors), and the fill (its redemption, its refusals). */
const CONTENT_CARD = {
  report: ["cardFormInfo", "choseNow"],
  chip: ["cardChipOffer", "Fill card with andvari", "openPopupForCards", "Open andvari from the toolbar to fill this card"],
  choice: ["userActivation", "ancestorOrigins"],
  fill: ["revealCardForFill", "closed_form"],
};

/** Strings only the card path's handlers hold: the grant's redemption and the fill's verdict (build.mjs checks the same). */
const CARD_PATH = ["no card grant", "card fill wrote nothing", "frame not reachable", "the payment form changed since andvari showed it", "no grant kinds"];

test("the Safari worker without card fill bundles no card path, and answers its fixed refusal", async () => {
  const worker = await safariWorker(false);
  for (const marker of CARD_PATH) assert.ok(!worker.includes(marker), `the card path is in the bundle: ${marker}`);
  assert.ok(worker.includes(CARD_FILL_OFF), "the entry points answer the fixed refusal");
});

test("the Safari worker with card fill (CARDFILL=1: UI tests, card preview) bundles the card path", async () => {
  const worker = await safariWorker(true);
  for (const marker of CARD_PATH) assert.ok(worker.includes(marker), `the card path is missing: ${marker}`);
});

test("the release Safari content script without card fill has no card chip, choice, report or fill code", async () => {
  const content = await safariContent(false);
  for (const [part, markers] of Object.entries(CONTENT_CARD)) {
    for (const marker of markers) assert.ok(!content.includes(marker), `the content script's card ${part} is in the bundle: ${marker}`);
  }
  // What stays: a card typed into a checkout is still offered for saving, and the login fill still keeps out of card fields.
  assert.ok(content.includes("captureCard"), "card capture is not in-page card fill");
  // 0.30.0 release check: the cards' code was most of what pushed content.js past the packaging cap.
  assert.ok(content.length < 60 * 1024, `content.js is ${content.length} bytes`);
});

test("with card fill (CARDFILL=1: UI tests, card preview) the content script has every part of it", async () => {
  const content = await safariContent(true);
  for (const [part, markers] of Object.entries(CONTENT_CARD)) {
    for (const marker of markers) assert.ok(content.includes(marker), `the content script's card ${part} is missing: ${marker}`);
  }
});

test("every entry point of the card path is gated on the build's define itself", () => {
  const bg = read("./background.ts");
  const gated: [string, RegExp][] = [
    ["cardFormInfo", /case "cardFormInfo":\s*return __ANDVARI_CARDFILL__ \? cardFormInfo\(msg, sender\) : \(\{ ok: false \}/],
    ["cardChipOffer", /case "cardChipOffer":[\s\S]{0,120}?return __ANDVARI_CARDFILL__ \? cardChipOffer\(sender\) : \(\{ fillable: false, locked: false \}/],
    ["openPopupForCards", /case "openPopupForCards":[\s\S]{0,120}?return __ANDVARI_CARDFILL__ \? openPopupForCards\(sender\) : \(\{ opened: false \}/],
    ["cardFillOffers", /case "cardFillOffers":\s*return __ANDVARI_CARDFILL__ \? cardFillOffers\(sender\) : \(\{ fillable: false, origin: null, frames: \[\], pageFormOnly: false, fillOff: true \}/],
    ["clearCardChoices", /case "clearCardChoices":\s*return __ANDVARI_CARDFILL__ \? clearCardChoices\(sender\) : \(\{ ok: false \}/],
    ["fillCardFromPopup", /case "fillCardFromPopup":\s*return __ANDVARI_CARDFILL__ \? fillCardFromPopup\(msg\.itemId, msg\.frames, sender\) : \(\{ ok: false, code: "fill_off", error: CARD_FILL_OFF \}/],
    ["revealCardForFill", /case "revealCardForFill":\s*return __ANDVARI_CARDFILL__ \? revealCardForFill\(msg, sender\) : \(\{ ok: false, error: CARD_FILL_OFF \}/],
  ];
  for (const [name, re] of gated) assert.match(bg, re, `${name} is not gated on __ANDVARI_CARDFILL__`);
  // Each handler is called from its gated case only, so a build without card fill drops it.
  for (const name of ["cardFormInfo(msg", "cardChipOffer(sender)", "openPopupForCards(sender)", "cardFillOffers(sender)", "clearCardChoices(sender)", "fillCardFromPopup(msg", "revealCardForFill(msg"]) {
    assert.equal(bg.split(name).length - 1, 1, `${name} is called somewhere else too`);
  }
});

test("without card fill the content script chooses nothing and reports nothing, and the popup copies with one line", () => {
  const content = read("./content.ts");
  assert.match(content, /const cardBox = __ANDVARI_CARDFILL__ && isCardEntryDocument\(location\.origin, location\.pathname\);/);
  assert.match(content, /function reportCardForm\(\): void \{[\s\S]{0,200}?if \(!__ANDVARI_CARDFILL__\) return;/);
  // Each entry of the content script's card fill is gated on the define itself, as the worker's are: a sync function
  // returns first, the async chip runs its body in a block (esbuild drops an async function's code after a folded
  // return only after bundling what it reaches), and the listeners and messages only it uses are registered under it.
  assert.match(content, /function noteCardFocus\(t: EventTarget \| null, focus\?: FocusEvent\): void \{\s*if \(!__ANDVARI_CARDFILL__\) return;/);
  assert.match(content, /function noteFocusLeft\(\): void \{\s*if \(!__ANDVARI_CARDFILL__ \|\| cardFocus === null \|\| filling\) return;/);
  assert.match(content, /function dismissCardChip\(\): void \{\s*if \(!__ANDVARI_CARDFILL__\) return;/);
  assert.match(content, /async function maybeCardChip\(target: EventTarget \| null, viaClick = false\): Promise<void> \{\s*(\/\/[^\n]*\n\s*)*if \(__ANDVARI_CARDFILL__\) \{/);
  assert.match(content, /if \(__ANDVARI_CARDFILL__ && msg\.type === "fillCard"\) \{/);
  assert.match(content, /if \(__ANDVARI_CARDFILL__\) \{\s*const notePress = /);
  assert.match(content, /if \(__ANDVARI_CARDFILL__\) \{\s*window\.addEventListener\("popstate", dismissCardChip\);/);
  assert.doesNotMatch(content, /\bCARD_FILL\b/, "the content script reads the define, never the unbundled flag");
  const popup = read("./popup.ts");
  assert.match(popup, /if \(!CARD_FILL\) \{\s*cardFill = \{ fillable: false, origin: null, frames: \[\], pageFormOnly: false, fillOff: true \};/);
  assert.match(popup, /if \(cardFill\.fillOff === true\) return cardFillOffLine\(safari\);/);
  assert.match(popup, /const why = cardCopyReason\(BUILD_TARGET === "safari"\);/, "the target decides the line");
  // Per target (0.30.0 release prep): only the Safari popup, which copies no card number or code, sends the person to
  // the app; a Chrome or Firefox build made with CARDFILL=0 copies every detail itself, and says so.
  assert.equal(CARD_FILL_FROM_APP, "andvari fills no cards here: copy a card's number and code in the andvari app.");
  assert.equal(CARD_FILL_OFF_COPY, "This build of andvari fills no cards into pages: copy a card's details with the buttons below.");
  assert.equal(cardFillOffLine(true), CARD_FILL_FROM_APP);
  assert.equal(cardFillOffLine(false), CARD_FILL_OFF_COPY);
  assert.ok(!CARD_FILL_OFF_COPY.includes("andvari app"), "a desktop build never sends the person to the app for a card");
  assert.equal(cardFillErrorCopy("fill_off", undefined, true), CARD_FILL_FROM_APP);
  assert.equal(cardFillErrorCopy("fill_off", undefined, false), CARD_FILL_OFF_COPY, "the fill's refusal says the same");
});

test("build.mjs: the Safari build has card fill only with CARDFILL=1, the desktop builds unless CARDFILL=0, and it checks the bundle", () => {
  const build = read("../build.mjs");
  assert.match(build, /const cardFill = target === "safari" \? process\.env\.CARDFILL === "1" : process\.env\.CARDFILL !== "0";/);
  assert.match(build, /__ANDVARI_CARDFILL__: JSON\.stringify\(cardFill\),/);
  assert.match(build, /if \(!cardFill && held\.length > 0\) throw new Error/);
  // Unbundled (this test, tsc) the flag reads on, so the card-fill rules stay tested.
  assert.equal(CARD_FILL, true);
});
