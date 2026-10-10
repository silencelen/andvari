// Security review 2026-10 (root cause E): TOTP enrolment comes ONLY from the extension's own UI.
//
// The content script used to take the first `a[href^="otpauth://"]` anywhere in the top document —
// hidden links deliberately included — and, on one click of a banner that named only the item,
// store that page-authored secret as the site login's second factor. Nothing could tell the site's
// enrolment link from one a forum post, comment or profile planted in the page, and the user never
// saw the secret they were consenting to. The page lane is gone: no DOM scrape, no page-side
// message that writes a TOTP, and the SW's one TOTP write is reachable only from the popup.
// Source-text pins (background.ts / content.ts are not node-importable — background.pins.test.ts).
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const src = (f: string) => readFileSync(new URL(`./${f}`, import.meta.url), "utf-8");
const bg = src("background.ts");
const ct = src("content.ts");
const cu = src("content-ui.ts");
const msgs = src("messages.ts");

test("content never reads an otpauth:// link out of the page DOM", () => {
  assert.doesNotMatch(ct, /otpauth:\/\/["'` ]*\s*i?\]/i, "no otpauth selector may scrape the page");
  assert.doesNotMatch(ct, /querySelector[^;]*otpauth/i);
  assert.ok(!ct.includes("maybeOfferTotp"), "the page-offer driver is gone, with its mutation and load-time calls");
  assert.ok(!cu.includes("showTotpOffer"), "no in-page banner offers to attach a code");
});

test("no page-side message can write or offer a TOTP", () => {
  for (const t of ["totpOffer", "addTotpFromPage"]) {
    assert.ok(!msgs.includes(`type: "${t}"`), `${t} must be gone from the message contract`);
    assert.ok(!bg.includes(`case "${t}"`), `${t} must have no SW handler`);
  }
  assert.ok(!bg.includes("function pageTotpTarget("), "no page-origin TOTP target derivation survives");
});

test("the SW's one TOTP write is the popup's, and it refuses every tab sender", () => {
  const writers = bg.match(/writeTotp\(/g) ?? [];
  assert.equal(writers.length, 2, "writeTotp: its declaration plus setTotp's call, nothing else");
  const setTotp = bg.slice(bg.indexOf("async function setTotp("), bg.indexOf("return writeTotp(target, msg.totp);"));
  assert.ok(setTotp.includes('if (sender.tab !== undefined) return { ok: false, code: "not_allowed"'), "setTotp stays popup-only");
});
