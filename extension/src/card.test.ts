// Runs under Node's built-in runner (node --test); type-stripped natively.
// Excluded from tsc (tsconfig `exclude`) — it imports node:test. `npm test` runs it.
//
// Pins the G2 [X2-N2] Luhn leaf (design 2026-07-23 §G2) — the content-side + SW-side save-card gate
// — against spec/test-vectors/card.json's `luhn` set (CardNormalize parity: the same vectors the web
// card.ts and core CardNormalize consume).
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { luhnValid } from "./card.ts";

const vectorsDir = fileURLToPath(new URL("../../spec/test-vectors/", import.meta.url));
const v = JSON.parse(readFileSync(vectorsDir + "card.json", "utf-8"));

test("luhnValid — [X2-N2] CardNormalize parity over the card.json luhn vectors", () => {
  for (const c of v.luhn) assert.equal(luhnValid(c.raw), c.valid, JSON.stringify(c.raw));
});

test("luhnValid — separators, the 12..19 ISO/IEC 7812 window, non-digit reject (hand edges)", () => {
  assert.equal(luhnValid("4242 4242 4242 4242"), true); // spaces accepted
  assert.equal(luhnValid("4111-1111-1111-1111"), true); // dashes accepted
  assert.equal(luhnValid("4111.1111.1111.1111"), true); // dots accepted
  assert.equal(luhnValid("4111111111111112"), false); // bad check digit
  assert.equal(luhnValid("411111111117"), true); // 12 digits — the floor
  assert.equal(luhnValid("41111111111"), false); // 11 digits — below the window (a phone can't look like a card)
  assert.equal(luhnValid("4111111111111111x"), false); // any other char fails
  assert.equal(luhnValid("４２４２４２４２４２４２４２４２"), false); // full-width digits rejected (ASCII-only arithmetic)
  assert.equal(luhnValid(""), false);
});
