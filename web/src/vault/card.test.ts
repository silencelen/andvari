import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { ItemDoc } from "../api/types";
import {
  CARD_CREATE_ENABLED,
  brand,
  brandLabel,
  cardSubtitle,
  composeShortExpiry,
  digitsOnly,
  expiryLabel,
  groupNumber,
  isExpired,
  luhnValid,
  maskedLast4,
  padMonth,
  parseExpiry,
  yearTo2,
  yearTo4,
} from "./card";

// Consumes the SAME spec/test-vectors/card.json the Kotlin CardNormalizeVectorTest checks
// (JSON null ⇒ the function must return null — mirror that test's null-vs-value semantics).
const vectorsDir = fileURLToPath(new URL("../../../spec/test-vectors/", import.meta.url));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const v: any = JSON.parse(readFileSync(vectorsDir + "card.json", "utf-8"));

describe("card.json — CardNormalize parity", () => {
  it("digitsOnly", () => {
    for (const c of v.digitsOnly) expect(digitsOnly(c.raw), `digitsOnly ${c.raw}`).toBe(c.expected);
  });

  it("luhn", () => {
    for (const c of v.luhn) expect(luhnValid(c.raw), `luhn ${c.raw}`).toBe(c.valid);
  });

  it("brand", () => {
    for (const c of v.brand) expect(brand(c.raw), `brand ${c.raw}`).toBe(c.expected);
  });

  it("parseExpiry", () => {
    for (const c of v.parseExpiry) {
      const e = parseExpiry(c.raw);
      expect(e?.expMonth ?? null, `parseExpiry month ${c.raw}`).toBe(c.expMonth);
      expect(e?.expYear ?? null, `parseExpiry year ${c.raw}`).toBe(c.expYear);
    }
  });

  it("padMonth", () => {
    for (const c of v.padMonth) expect(padMonth(c.raw), `padMonth ${c.raw}`).toBe(c.expected);
  });

  it("yearTo4", () => {
    for (const c of v.yearTo4) expect(yearTo4(c.raw), `yearTo4 ${c.raw}`).toBe(c.expected);
  });

  it("yearTo2", () => {
    for (const c of v.yearTo2) expect(yearTo2(c.raw), `yearTo2 ${c.raw}`).toBe(c.expected);
  });

  it("composeShortExpiry", () => {
    for (const c of v.composeShortExpiry) {
      expect(composeShortExpiry(c.expMonth, c.expYear), `composeShortExpiry ${c.expMonth}/${c.expYear}`).toBe(c.expected);
    }
  });
});

describe("isExpired — expired strictly AFTER the last moment of the expiry month", () => {
  it("month boundaries", () => {
    // The very last moment of the expiry month — still valid…
    expect(isExpired("06", "2027", new Date(2027, 5, 30, 23, 59, 59, 999))).toBe(false);
    // …and the very first instant of the following month — expired.
    expect(isExpired("06", "2027", new Date(2027, 6, 1, 0, 0, 0, 0))).toBe(true);
    expect(isExpired("06", "2027", new Date(2027, 5, 1))).toBe(false);
    expect(isExpired("01", "2020", new Date(2027, 0, 1))).toBe(true);
    expect(isExpired("01", "2099", new Date(2027, 0, 1))).toBe(false);
  });

  it("December rolls over into the NEXT year", () => {
    expect(isExpired("12", "2027", new Date(2027, 11, 31, 23, 59, 59, 999))).toBe(false);
    expect(isExpired("12", "2027", new Date(2028, 0, 1, 0, 0, 0, 0))).toBe(true);
  });

  it("2-digit years pivot like yearTo4", () => {
    expect(isExpired("12", "27", new Date(2027, 11, 31))).toBe(false);
    expect(isExpired("12", "27", new Date(2028, 0, 1))).toBe(true);
  });

  it("missing/garbled fields never scare", () => {
    expect(isExpired(undefined, undefined, new Date(2099, 0, 1))).toBe(false);
    expect(isExpired("12", undefined, new Date(2099, 0, 1))).toBe(false);
    expect(isExpired(undefined, "2020", new Date(2099, 0, 1))).toBe(false);
    expect(isExpired("", "", new Date(2099, 0, 1))).toBe(false);
    expect(isExpired("13", "2020", new Date(2099, 0, 1))).toBe(false); // bad month
    expect(isExpired("12", "20x0", new Date(2099, 0, 1))).toBe(false); // bad year
    expect(isExpired("１２", "2020", new Date(2099, 0, 1))).toBe(false); // non-ASCII digits
  });
});

describe("display helpers", () => {
  const doc = (card?: ItemDoc["card"]): ItemDoc => ({ type: "card", name: "x", card });

  it("groupNumber — 4-4-4-4 generally, amex 4-6-5, partials group sanely", () => {
    expect(groupNumber("4242424242424242")).toBe("4242 4242 4242 4242");
    expect(groupNumber("378282246310005")).toBe("3782 822463 10005"); // amex
    expect(groupNumber("4917610000000000003")).toBe("4917 6100 0000 0000 003"); // 19-digit
    expect(groupNumber("42424")).toBe("4242 4");
    expect(groupNumber("3782822")).toBe("3782 822"); // partial amex
    expect(groupNumber("4111 1111-1111.1111")).toBe("4111 1111 1111 1111"); // raw editor text
    expect(groupNumber("")).toBe("");
  });

  it("maskedLast4 shows at most the last four digits", () => {
    expect(maskedLast4("4242424242424242")).toBe("••4242");
    expect(maskedLast4("005")).toBe("••005");
  });

  it("cardSubtitle falls back gracefully", () => {
    expect(cardSubtitle(doc({ number: "4242424242424242" }))).toBe("Visa ••4242");
    expect(cardSubtitle(doc({ number: "378282246310005" }))).toBe("Amex ••0005");
    expect(cardSubtitle(doc({ number: "9792111111111111" }))).toBe("Card ••1111"); // unknown IIN
    expect(cardSubtitle(doc({ cardholderName: "B" }))).toBe("card"); // no number
    expect(cardSubtitle(doc({}))).toBe("card");
    expect(cardSubtitle(doc(undefined))).toBe("card");
    // The STORED brand is display-only and never trusted — a stale value must not leak through.
    expect(cardSubtitle(doc({ number: "4242424242424242", brand: "discover" }))).toBe("Visa ••4242");
  });

  it("expiryLabel", () => {
    expect(expiryLabel({ expMonth: "12", expYear: "2027" })).toBe("12/2027");
    expect(expiryLabel({ expMonth: "12" })).toBe("12/—");
    expect(expiryLabel({ expYear: "2027" })).toBe("—/2027");
    expect(expiryLabel({})).toBe(null);
    expect(expiryLabel(undefined)).toBe(null);
  });

  it("brandLabel", () => {
    expect(brandLabel("visa")).toBe("Visa");
    expect(brandLabel("mastercard")).toBe("Mastercard");
    expect(brandLabel(null)).toBe(null);
    expect(brandLabel(undefined)).toBe(null);
    expect(brandLabel("somefutureco")).toBe(null);
  });
});

describe("rollout gate", () => {
  // The Option A dark gate (like the extension's fv pin): flipped DELIBERATELY at the
  // release that retires the 0.2.x MSI — never by accident. Editing this assertion is
  // the conscious act that enables card creation.
  it("pins CARD_CREATE_ENABLED === false", () => {
    expect(CARD_CREATE_ENABLED).toBe(false);
  });
});
