// node --test. In-page card fill is per build (owner decision 2026-11-14: the first App Store version ships without it).
// These prove, of the Safari worker as esbuild bundles it, that a build without card fill cannot release card data: the
// card path's handlers are not in the bundle at all, and every entry point answers its fixed refusal.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import * as esbuild from "esbuild";
import { CARD_FILL, CARD_FILL_OFF } from "./cardfillflag.ts";
import { CARD_FILL_FROM_APP } from "./errors.ts";

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
  assert.match(content, /const cardBox = CARD_FILL && isCardEntryDocument\(location\.origin, location\.pathname\);/);
  assert.match(content, /function reportCardForm\(\): void \{[\s\S]{0,200}?if \(!CARD_FILL\) return;/);
  const popup = read("./popup.ts");
  assert.match(popup, /if \(!CARD_FILL\) \{\s*cardFill = \{ fillable: false, origin: null, frames: \[\], pageFormOnly: false, fillOff: true \};/);
  assert.match(popup, /if \(cardFill\.fillOff === true\) return CARD_FILL_FROM_APP;/);
  assert.equal(CARD_FILL_FROM_APP, "andvari fills no cards here: copy a card's number and code in the andvari app.");
});

test("build.mjs: the Safari build has card fill only with CARDFILL=1, the desktop builds unless CARDFILL=0, and it checks the bundle", () => {
  const build = read("../build.mjs");
  assert.match(build, /const cardFill = target === "safari" \? process\.env\.CARDFILL === "1" : process\.env\.CARDFILL !== "0";/);
  assert.match(build, /__ANDVARI_CARDFILL__: JSON\.stringify\(cardFill\),/);
  assert.match(build, /if \(!cardFill && held\.length > 0\) throw new Error/);
  // Unbundled (this test, tsc) the flag reads on, so the card-fill rules stay tested.
  assert.equal(CARD_FILL, true);
});
