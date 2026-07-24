// Runs under Node's built-in runner (node --test); type-stripped natively.
// Excluded from tsc (tsconfig `exclude`) — like detect.cards.test.ts. `npm test` runs it.
//
// The extension half of the cardfill.json lockstep (design 2026-07-23-card-autofill-tier1 §11):
// TABLES deep-equals the vector's normative copy ([T14] — drift on either side reds that side);
// `selectIndexShared` encodes options as single strings ([T8]: opt.value's attr-absent→text
// fallback makes value pass ≡ text pass on label-only options, so one string is lossless);
// `selectIndexDom` (value≠text pairs) is TS-only. The §4 text adapters run EVERY case including
// tsOnly (placeholder-signal) ones — core skips those, we ARE the TS engine. Hand edges cover
// what vectors can't: verifyLanded canonicalization ([T7]) and the deriveCardWrite wiring surface.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import {
  TABLES,
  cvvTextFor,
  deriveCardWrite,
  expiryTextFor,
  monthTextFor,
  nameTextFor,
  numberTextFor,
  selectIndexFor,
  typeTextFor,
  verifyLanded,
  yearTextFor,
} from "./cardfill.ts";
import type { CardFieldKind } from "./detect.ts";

const vectorsDir = fileURLToPath(new URL("../../spec/test-vectors/", import.meta.url));
const v = JSON.parse(readFileSync(vectorsDir + "cardfill.json", "utf-8"));

/** Vector kind names use the autocomplete-token spellings (engine-neutral, like cardform.json). */
const KIND: Record<string, CardFieldKind> = {
  "cc-exp-month": "cardexpmonth",
  "cc-exp-year": "cardexpyear",
  "cc-exp": "cardexpiry",
  "cc-type": "cardtype",
};

/** Vector case → CardFillValues: vector years are 4-digit; `brand` rides pre-derived exactly as
 *  the [T9]-gated wire would carry it (this engine's API takes the brand, never the number). */
const valuesOf = (c: { expMonth?: string; expYear?: string; brand?: string }) => ({
  expMonth: c.expMonth,
  expYear4: c.expYear,
  brand: c.brand,
});

test("tables — compiled-in TABLES deep-equal the normative vector copy ([T14])", () => {
  assert.deepEqual(TABLES, v.tables);
});

test("selectIndexShared — label-only options, pass-major ([T2]) incl. the [T3] month-name negatives", () => {
  for (const c of v.selectIndexShared) {
    const opts = c.options.map((s: string) => ({ value: s, text: s }));
    assert.equal(selectIndexFor(KIND[c.kind]!, opts, valuesOf(c)), c.expected, c.name);
  }
});

test("selectIndexDom — value≠text option pairs, value checked before text (TS engine only)", () => {
  for (const c of v.selectIndexDom) {
    assert.equal(selectIndexFor(KIND[c.kind]!, c.options, valuesOf(c)), c.expected, c.name);
  }
});

test("expiryText adapter — §4 maxLength table + [T16] anchored separator sniff", () => {
  for (const c of v.expiryText) {
    assert.equal(expiryTextFor(c.expMonth, c.expYear, c.maxLength, c.placeholder), c.expected, c.name);
  }
});

test("yearText adapter — declared 2/4 beats placeholder; default YYYY; fit-guard shrink", () => {
  for (const c of v.yearText) {
    assert.equal(yearTextFor(c.expYear, c.maxLength, c.placeholder), c.expected, c.name);
  }
});

test("monthText adapter — canonical MM, never pad-stripped", () => {
  for (const c of v.monthText) {
    assert.equal(monthTextFor(c.expMonth, c.maxLength), c.expected, c.name);
  }
});

test("number/cvv/name/type text — fit-guard skips, never truncates", () => {
  assert.equal(numberTextFor("4242 4242 4242 4242", null), "4242424242424242"); // digits-only write
  assert.equal(numberTextFor("4242424242424242", 16), "4242424242424242");
  assert.equal(numberTextFor("4242424242424242", 12), null); // longer than declared → skip
  assert.equal(numberTextFor("", null), null);
  assert.equal(cvvTextFor("123", 3), "123");
  assert.equal(cvvTextFor("1234", 3), null);
  assert.equal(cvvTextFor(undefined, null), null);
  assert.equal(nameTextFor("Ada Lovelace", null), "Ada Lovelace");
  assert.equal(nameTextFor("Ada Lovelace", 5), null);
  assert.equal(typeTextFor("visa", null), "Visa"); // the SW-derived brand's label, never a stored field
  assert.equal(typeTextFor("visa", 3), null);
  assert.equal(typeTextFor(null, null), null); // unknown IIN → no brand rode the wire → missed
});

test("verifyLanded — [T7] canonicalized read-back compare", () => {
  const t = (s: string) => ({ kind: "text", value: s }) as any;
  // masker auto-expansion / leading-zero strip = landed…
  assert.equal(verifyLanded("cardexpiry", t("07/27"), t("07/2027")), true);
  assert.equal(verifyLanded("cardexpiry", t("07/2027"), t("7/27")), true);
  assert.equal(verifyLanded("cardexpmonth", t("07"), t("7")), true);
  assert.equal(verifyLanded("cardexpyear", t("2027"), t("27")), true);
  // …truncation is NOT.
  assert.equal(verifyLanded("cardexpiry", t("07/2027"), t("07/20")), false);
  assert.equal(verifyLanded("cardexpyear", t("2027"), t("2026")), false);
  assert.equal(verifyLanded("cardexpmonth", t("07"), t("")), false);
  // number/cvv digitsOnly-equal: a re-spacing mask passes, a partial landing fails.
  assert.equal(verifyLanded("cardnumber", t("4242424242424242"), t("4242 4242 4242 4242")), true);
  assert.equal(verifyLanded("cardnumber", t("4242424242424242"), t("4242")), false);
  assert.equal(verifyLanded("cardcvv", t("123"), t("123")), true);
  // name/type: trimmed case-insensitive.
  assert.equal(verifyLanded("cardname", t("Ada Lovelace"), t(" ada lovelace ")), true);
  assert.equal(verifyLanded("cardtype", t("Visa"), t("VISA")), true);
  assert.equal(verifyLanded("cardname", t("Ada Lovelace"), t("Ada")), false);
  // selects: INDEX equality — a duplicate-value select landing a different index files missed.
  assert.equal(verifyLanded("cardexpmonth", { kind: "index", index: 2 }, { kind: "index", index: 2 }), true);
  assert.equal(verifyLanded("cardexpmonth", { kind: "index", index: 2 }, { kind: "index", index: 0 }), false);
  // shape mismatch (SPA swapped the control between write and read-back) is a miss.
  assert.equal(verifyLanded("cardexpmonth", t("07"), { kind: "index", index: 7 }), false);
});

test("deriveCardWrite — the wiring surface: kind + target metadata + values → one write or null", () => {
  const values = {
    number: "4242424242424242",
    name: "Ada Lovelace",
    cvv: "123",
    expMonth: "07",
    expYear2: "27",
    expYear4: "2027",
    expiry: "07/27",
    brand: "visa",
  };
  const input = (over: object = {}) => ({ tag: "input", type: "text", maxLength: null, placeholder: null, options: null, ...over }) as any;
  // text targets route through the §4 adapters…
  assert.deepEqual(deriveCardWrite("cardnumber", input({ maxLength: 19 }), values), { kind: "text", value: "4242424242424242" });
  assert.deepEqual(deriveCardWrite("cardexpiry", input({ maxLength: 5 }), values), { kind: "text", value: "07/27" });
  assert.deepEqual(deriveCardWrite("cardexpiry", input({ placeholder: "MM-YYYY" }), values), { kind: "text", value: "07-2027" });
  assert.deepEqual(deriveCardWrite("cardexpmonth", input(), values), { kind: "text", value: "07" });
  assert.deepEqual(deriveCardWrite("cardexpyear", input({ placeholder: "YY" }), values), { kind: "text", value: "27" });
  assert.deepEqual(deriveCardWrite("cardname", input(), values), { kind: "text", value: "Ada Lovelace" });
  assert.deepEqual(deriveCardWrite("cardtype", input(), values), { kind: "text", value: "Visa" });
  // …the 2-digit-half-only wire still fills (halves ride independently, yearTo4 pivots):
  assert.deepEqual(deriveCardWrite("cardexpyear", input(), { expYear2: "27" }), { kind: "text", value: "2027" });
  // fit-guard / absent value → null (skip + file missed), never truncate, never guess.
  assert.equal(deriveCardWrite("cardnumber", input({ maxLength: 12 }), values), null);
  assert.equal(deriveCardWrite("cardcvv", input(), { number: "4242424242424242" }), null);
  assert.equal(deriveCardWrite("cardexpiry", input(), { expMonth: "07" }), null); // combined needs BOTH halves
  // NOTE: an undeclared DOM maxLength reads -1 on HTMLInputElement — the WIRING maps -1 → null
  // before calling (this module never sees -1); null is asserted throughout as that mapping.
  const sel = (options: { value: string; text: string }[]) =>
    ({ tag: "select", type: "select-one", maxLength: null, placeholder: null, options }) as any;
  const monthOpts = [{ value: "", text: "Month" }].concat(
    ["01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12"].map((m) => ({ value: m, text: m })),
  );
  // select targets derive an INDEX write ([T8]: the executor writes selectedIndex, never .value)…
  assert.deepEqual(deriveCardWrite("cardexpmonth", sel(monthOpts), values), { kind: "index", index: 7 });
  assert.deepEqual(deriveCardWrite("cardtype", sel([{ value: "001", text: "Visa" }, { value: "002", text: "Mastercard" }]), values), {
    kind: "index",
    index: 0,
  });
  // …no matching option / select-impossible kind → null.
  assert.equal(deriveCardWrite("cardexpmonth", sel([{ value: "--", text: "--" }]), values), null);
  assert.equal(deriveCardWrite("cardnumber", sel(monthOpts), values), null); // §0: a select is never a PAN
});
