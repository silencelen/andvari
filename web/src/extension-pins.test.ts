import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { brand, brandLabel, cardSubtitle, composeShortExpiry, digitsOnly, maskedLast4, padMonth, yearTo4 } from "../../extension/src/card";
import { isCvvNameOrId } from "../../extension/src/detect";
import { LOGIN_FORMAT_VERSION, MAX_ITEM_FORMAT_VERSION } from "../../extension/src/format";
import type { ItemDoc } from "./api/types";
import {
  brand as webBrand,
  cardSubtitle as webCardSubtitle,
  composeShortExpiry as webCompose,
  digitsOnly as webDigitsOnly,
  maskedLast4 as webMaskedLast4,
  padMonth as webPadMonth,
  yearTo4 as webYearTo4,
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

  // Tier 1 (design 2026-07-23-card-autofill-tier1.md §6/§11): revealCardForFill composes the v2
  // expMonth/expYear2/expYear4 halves through these canonicalizers — a divergence from the web
  // twin would fill a checkout with a different value than the vault itself displays.
  it("padMonth — every vector case, and bit-parity with the web port", () => {
    for (const c of v.padMonth) {
      expect(padMonth(c.raw), `padMonth ${c.raw}`).toBe(c.expected);
      expect(padMonth(c.raw), `padMonth parity ${c.raw}`).toBe(webPadMonth(c.raw));
    }
  });

  it("yearTo4 — every vector case, and bit-parity with the web port", () => {
    for (const c of v.yearTo4) {
      expect(yearTo4(c.raw), `yearTo4 ${c.raw}`).toBe(c.expected);
      expect(yearTo4(c.raw), `yearTo4 parity ${c.raw}`).toBe(webYearTo4(c.raw));
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
    // [A7] S3 broadened the extension's set to FULL core CSC_DEMOTION parity (securitycode +
    // cardverification). This is the fix for the shipped 0.13.0 bug where a checkout
    // `securityCode` password slipped the save-suppression and could overwrite a stored merchant
    // password with a CVV. The pin below was written to break WHEN this arrived — flipped here.
    expect(isCvvNameOrId("securityCode")).toBe(true); // A7: flipped from false (was the deferred-slice sentinel)
    expect(isCvvNameOrId("cardVerificationValue")).toBe(true); // [card,verification,value] → "cardverification" run
  });

  it("never suppresses a real password (or anything by substring)", () => {
    expect(isCvvNameOrId("password")).toBe(false);
    expect(isCvvNameOrId("card_note")).toBe(false);
    expect(isCvvNameOrId("mycvv")).toBe(false); // substring guard — mirrors the classify vector
    expect(isCvvNameOrId("cv_code")).toBe(false); // a run may not end mid-token
    expect(isCvvNameOrId("securityCodes")).toBe(false); // plural — a run may not end mid-token
    expect(isCvvNameOrId("")).toBe(false);
  });
});

describe("S3 card-fill egress pins ([A9]) — the safety-critical background.ts lines", () => {
  const bg = readFileSync(extensionSrc + "background.ts", "utf-8");

  it("redemption binds the granted frameId (fail-closed)", () => {
    // The frame that detected the card form is the ONLY one that can redeem its grant.
    expect(bg).toContain("sender.frameId === grant.frameId");
  });

  it("redemption binds the granted origin (first-ever sender.origin reliance)", () => {
    expect(bg).toContain("sender.origin === grant.origin");
  });

  it("redemption re-fetches the live top-level origin and re-checks it", () => {
    // A nav between the popup click and the redemption voids the fill: the recheck reads tab.url…
    expect(bg).toContain("new URL(t.url).origin");
    // …and compares the grant's origin against that freshly-fetched top origin.
    expect(bg).toContain("grant.origin === top");
  });

  it("the card grant is ONE-SHOT (consumed on redemption) and a store SEPARATE from login grants", () => {
    expect(bg).toContain("cardGrants.delete(");
    // A distinct store — sharing single-slot `grants` would let card/login grants clobber + cross-redeem.
    expect(bg).toMatch(/const cardGrants = new Map</);
  });

  it("the new popup-only card messages refuse tab (page) senders", () => {
    // Both minting an offer and enumerating offers must be popup-only — a page can never invoke them.
    expect(bg).toMatch(/async function cardFillOffers[\s\S]*?sender\.tab !== undefined/);
    expect(bg).toMatch(/async function fillCardFromPopup[\s\S]*?sender\.tab !== undefined/);
  });
});

describe("Tier-1 card autofill pins ([T15]/[T9]/[T11]/§7) — structural anchors", () => {
  const bg = readFileSync(extensionSrc + "background.ts", "utf-8");
  const ct = readFileSync(extensionSrc + "content.ts", "utf-8");

  /** The card-path spans the [A6]/[A4] pins assert over. Both boundary anchors must exist and be
   *  ordered, or a refactor that moved a function would silently shrink the span to nothing and
   *  the negative assertions below would pass vacuously. */
  const spanOf = (src: string, from: string, to: string): string => {
    const a = src.indexOf(from);
    const b = src.indexOf(to);
    expect(a, `span start missing: ${from}`).toBeGreaterThan(-1);
    expect(b, `span end missing/out of order: ${to}`).toBeGreaterThan(a);
    return src.slice(a, b);
  };

  it("[A4] the card-clear onUpdated handler reads ONLY changeInfo.status and clears BOTH stores", () => {
    // Extract THE "loading" handler — its guard is its first statement, so the shipped
    // status==="complete" listener can never anchor the match start.
    const handler =
      bg.match(/onUpdated\.addListener\(\(tabId, changeInfo\) => \{\s*if \(changeInfo\.status !== "loading"\) return;[\s\S]*?\n\}\);/)?.[0] ?? "";
    expect(handler.length, "the status===loading card-clear handler must exist").toBeGreaterThan(0);
    // A top-level navigation must void the recorded forms AND any armed grant — leaving either
    // would offer (or redeem) against the previous document's record.
    expect(handler).toContain("cardGrants.delete(tabId)");
    expect(handler).toContain("delete st.cardForms");
    // Any `.url` read here (changeInfo.url / tab.url) is a `tabs`-permission bump outside the
    // popup-open activeTab window — the handler may consult NOTHING but changeInfo.status.
    expect(handler).not.toMatch(/\.url\b/);
  });

  it("§7 content anchors: NULL sig sentinel, attribute-reveal observer, rescan protocol", () => {
    // NULL (not "") sentinel — the first report after injection must ALWAYS send, even empty,
    // or a stale SW record survives the new document.
    expect(ct).toContain("lastCardSig: string | null = null");
    // CSS-toggle reveals (class/style/hidden flips on pre-rendered checkouts) must re-scan;
    // dropping the filter (or a key from it) makes those checkouts invisible until a DOM mutation.
    expect(ct).toContain('attributeFilter: ["class", "style", "hidden"]');
    // [T4]: the rescan handler resets the sig BEFORE reporting (bfcache restores this script's
    // JS state — an unreset sig swallows the rescan's own report for the document's life), then
    // acks so the SW's 250 ms re-read has something to read.
    expect(ct).toMatch(
      /msg\.type === "rescanCardForms"[\s\S]*?lastCardSig = null;[\s\S]*?reportCardForm\(\);[\s\S]*?sendResponse\(\{ ok: true \}\)/,
    );
    // The message rides the typed wire on all three hops (a rename on one side is a silent no-op).
    expect(readFileSync(extensionSrc + "messages.ts", "utf-8")).toContain('"rescanCardForms"');
    expect(bg).toContain('"rescanCardForms"');
  });

  it("[A6] the card fill path never feeds the capture engine (no snapshots, no save banner)", () => {
    // Scope: the card fill function bodies (cardTargetOf → applyCardFill → fillCardIntoForm), the
    // shared write helpers they drive (setValue/setSelectedIndex), and the pure leaf. The login
    // path's updateSnapshot calls (fillForm, generated-password capture) are LEGITIMATE and live
    // outside these spans — this pin must not widen to the whole file.
    const cardPath = spanOf(ct, "function cardTargetOf(", "function maybeOpen(");
    // The fill bodies must actually live inside the extracted span — a move must come back and
    // re-scope this pin deliberately, not drain it silently.
    expect(cardPath).toContain("function applyCardFill(");
    expect(cardPath).toContain("function fillCardIntoForm(");
    const writeHelpers = spanOf(ct, "const nativeValueSetter", "let filling = false");
    const leaf = readFileSync(extensionSrc + "cardfill.ts", "utf-8");
    for (const [name, span] of [
      ["content card path", cardPath],
      ["write helpers", writeHelpers],
      ["cardfill.ts", leaf],
    ] as const) {
      expect(span, `${name} calls updateSnapshot`).not.toContain("updateSnapshot(");
      expect(span, `${name} references the snapshot store`).not.toMatch(/\bsnapshots\b/);
    }
  });

  it("[T9] brand egress double-gate — the cardnumber check PRECEDES the one brand write", () => {
    // The zero-new-information argument (the same response already carries the PAN the brand
    // derives from) must never depend on a future registry shape: the gate is spelled in code,
    // cardnumber FIRST, and it is the gate of the write itself.
    expect(bg).toMatch(/declared\.has\("cardnumber"\) && declared\.has\("cardtype"\)[\s\S]{0,300}?fields\.brand = b/);
    // Derived from the number at reveal time — NEVER the stored display field (could be stale).
    expect(bg).toContain("brand(c.number");
    // Exactly ONE brand egress site — a second, ungated write would dodge the window above.
    expect(bg.match(/fields\.brand\s*=/g)).toHaveLength(1);
  });

  it('[T11] asCardFillOutcome accepts "partial" — a rejected partial reports unreachable AFTER fields landed', () => {
    expect(bg).toMatch(/function asCardFillOutcome[\s\S]*?f === "card" \|\| f === "partial" \|\| f === "nothing"/);
  });
});
