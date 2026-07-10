import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { brand, brandLabel, cardSubtitle, composeShortExpiry, digitsOnly, maskedLast4 } from "../../extension/src/card";
import { isCvvNameOrId } from "../../extension/src/detect";
import { LOGIN_FORMAT_VERSION, MAX_ITEM_FORMAT_VERSION } from "../../extension/src/format";
import type { ItemDoc } from "./api/types";
import {
  brand as webBrand,
  cardSubtitle as webCardSubtitle,
  composeShortExpiry as webCompose,
  digitsOnly as webDigitsOnly,
  maskedLast4 as webMaskedLast4,
} from "./vault/card";

/**
 * Cross-suite pins for the browser extension's cards slice (design 2026-07-09-cards-wallet.md).
 * The extension has no test harness of its own (build/typecheck/package only), so its
 * safety-critical values live in chrome-free modules (extension/src/{format,card,detect}.ts)
 * and are pinned HERE, from the web vitest suite — the same suite that already anchors the
 * extension's crypto parity (noble-extension-poc.test.ts). Editing a pinned value must break
 * this file first, deliberately.
 */

const extensionSrc = fileURLToPath(new URL("../../extension/src/", import.meta.url));
const vectorsDir = fileURLToPath(new URL("../../spec/test-vectors/", import.meta.url));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const v: any = JSON.parse(readFileSync(vectorsDir + "card.json", "utf-8"));

describe("formatVersion discipline (the safety-critical pins)", () => {
  it("read ceiling is 2 — the extension may read fv2 (cards) but must fail closed above", () => {
    expect(MAX_ITEM_FORMAT_VERSION).toBe(2);
  });

  it("new logins seal at fv 1 — the login doc floor; a gratuitous upgrade would strand the fleet's bit-compat", () => {
    expect(LOGIN_FORMAT_VERSION).toBe(1);
  });

  it("background.ts wires the consts and hardcodes no fv (tripwire over the write path)", () => {
    const src = readFileSync(extensionSrc + "background.ts", "utf-8");
    // POSITIVE structural anchors — usage shapes a comment or a bare import can't satisfy.
    // A rename/refactor of the write path must come back and edit this test deliberately.
    expect(src).toContain("formatVersion > MAX_ITEM_FORMAT_VERSION"); // the read gate, in code
    expect(src).toContain("Math.max(LOGIN_FORMAT_VERSION"); //           the monotonic reseal floor
    expect(src).toContain("adItem(vaultId, itemId, formatVersion)"); //  ONE fv feeds the AD…
    expect(src).toContain("item: { formatVersion,"); //                  …and the SAME fv the wire
    // Exactly two adItem call sites: the decrypt open (wire fv) + the putItem seal. A third
    // seal site would dodge the pins above — count the wire.
    expect(src.match(/adItem\(/g)).toHaveLength(2);
    // Broadened negatives: no literal-digit fv anywhere near a seal or a wire field, in any
    // spacing/naming shape (the pre-0.7.0 hardcodes and their trivial mutations).
    expect(src).not.toMatch(/adItem\([^)]*,\s*\d/);
    expect(src).not.toMatch(/formatVersion\s*:\s*\d/);
  });
});

describe("card display port ≡ web port ≡ card.json (IIN table + masking parity)", () => {
  const doc = (card?: ItemDoc["card"]): ItemDoc => ({ type: "card", name: "x", card });

  it("brand — every vector case, and bit-parity with the web port", () => {
    for (const c of v.brand) {
      expect(brand(c.raw), `brand ${c.raw}`).toBe(c.expected);
      expect(brand(c.raw), `brand parity ${c.raw}`).toBe(webBrand(c.raw));
    }
  });

  it("digitsOnly — every vector case, and parity", () => {
    for (const c of v.digitsOnly) {
      expect(digitsOnly(c.raw), `digitsOnly ${c.raw}`).toBe(c.expected);
      expect(digitsOnly(c.raw)).toBe(webDigitsOnly(c.raw));
    }
  });

  it("composeShortExpiry — every vector case, and parity", () => {
    for (const c of v.composeShortExpiry) {
      expect(composeShortExpiry(c.expMonth, c.expYear), `compose ${c.expMonth}/${c.expYear}`).toBe(c.expected);
      expect(composeShortExpiry(c.expMonth, c.expYear)).toBe(webCompose(c.expMonth, c.expYear));
    }
  });

  it("maskedLast4 + cardSubtitle track the web semantics exactly", () => {
    for (const c of v.brand) {
      expect(maskedLast4(c.raw)).toBe(webMaskedLast4(c.raw));
      expect(cardSubtitle(c.raw), `subtitle parity ${c.raw}`).toBe(webCardSubtitle(doc({ number: c.raw })));
    }
    expect(cardSubtitle("4242424242424242")).toBe("Visa ••4242");
    expect(cardSubtitle("378282246310005")).toBe("Amex ••0005");
    expect(cardSubtitle("9792111111111111")).toBe("Card ••1111"); // unknown IIN
    expect(cardSubtitle("")).toBe("card");
    expect(cardSubtitle(undefined)).toBe("card");
    expect(brandLabel("visa")).toBe("Visa");
    expect(brandLabel(null)).toBe(null);
  });
});

describe("CVV-negative rule — whole-token-run verdicts (never substring)", () => {
  it("suppresses the card security codes", () => {
    expect(isCvvNameOrId("cvv")).toBe(true);
    expect(isCvvNameOrId("cvv2")).toBe(true); // token run [cvv] + its own digit token
    expect(isCvvNameOrId("cvc2")).toBe(true);
    expect(isCvvNameOrId("csc")).toBe(true);
    expect(isCvvNameOrId("card-cvc")).toBe(true);
    expect(isCvvNameOrId("cardCvc")).toBe(true); // camelCase boundary (Stripe's field name)
  });

  it("never suppresses a real password (or anything by substring)", () => {
    expect(isCvvNameOrId("password")).toBe(false);
    expect(isCvvNameOrId("card_note")).toBe(false);
    expect(isCvvNameOrId("mycvv")).toBe(false); // substring guard — mirrors the classify vector
    expect(isCvvNameOrId("cv_code")).toBe(false); // a run may not end mid-token
    // Deliberately OUTSIDE the extension's set: the design scopes this rule to cvv/cvc/csc
    // (the core classifier's fuller CSC demotion — securitycode/cardverification — arrives
    // with the deferred in-page card-fill slice, not this suppression heuristic).
    expect(isCvvNameOrId("securityCode")).toBe(false);
    expect(isCvvNameOrId("")).toBe(false);
  });
});
