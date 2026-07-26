import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { brand, brandLabel, cardSubtitle, composeShortExpiry, digitsOnly, maskedLast4, padMonth, yearTo4 } from "../../extension/src/card";
import { isCvvNameOrId } from "../../extension/src/detect";
import type { CardFieldKind } from "../../extension/src/detect";
import { LOGIN_FORMAT_VERSION, MAX_ITEM_FORMAT_VERSION } from "../../extension/src/format";
import { chooseCardTarget } from "../../extension/src/messages";
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

/** messages.ts (imported above for the PURE chooseCardTarget export — §9 [U11]) types its send()
 *  helper against the chrome runtime, which the web program lacks (`types: ["node"]`). Type-only
 *  shim: nothing here ever CALLS send(), so no chrome value is evaluated at runtime. */
declare global {
  const chrome: { runtime: { sendMessage(req: unknown): Promise<unknown> } };
}

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

describe("Tier-2 card autofill pins (design 2026-07-23-…-tier2.md §9) — structural + behavioral anchors", () => {
  const bg = readFileSync(extensionSrc + "background.ts", "utf-8");
  const ct = readFileSync(extensionSrc + "content.ts", "utf-8");
  const pp = readFileSync(extensionSrc + "popup.ts", "utf-8");

  const spanOf = (src: string, from: string, to: string): string => {
    const a = src.indexOf(from);
    const b = src.indexOf(to);
    expect(a, `span start missing: ${from}`).toBeGreaterThan(-1);
    expect(b, `span end missing/out of order: ${to}`).toBeGreaterThan(a);
    return src.slice(a, b);
  };

  const F = (frameId: number, ...forms: CardFieldKind[][]): { frameId: number; forms: CardFieldKind[][] } => ({ frameId, forms });

  it("[U11] frame 0 wins with ANY eligible form — a same-origin sub-frame never out-bids the visible top checkout", () => {
    // The chooser is pure + exported from messages.ts (chrome-free at import) exactly so this
    // suite can pin the RULE, not just its source shape.
    expect(chooseCardTarget([F(3, ["cardnumber", "cardexpiry", "cardcvv", "cardname"]), F(0, ["cardnumber"])])).toEqual({ frameId: 0, kinds: ["cardnumber"] });
    // Frame 0 recorded but formless → it does NOT bid; the richest sub-frame wins…
    expect(chooseCardTarget([F(0), F(7, ["cardnumber"]), F(2, ["cardnumber", "cardcvv"])])).toEqual({ frameId: 2, kinds: ["cardnumber", "cardcvv"] });
    // …and a richness tie goes to the LOWEST frameId, regardless of input order.
    expect(chooseCardTarget([F(9, ["cardnumber", "cardcvv"]), F(4, ["cardexpiry", "cardname"])])).toEqual({ frameId: 4, kinds: ["cardexpiry", "cardname"] });
    // Richest FORM within the chosen frame: most DISTINCT kinds; a tie keeps document order.
    expect(chooseCardTarget([F(0, ["cardnumber"], ["cardnumber", "cardexpiry", "cardcvv"])])).toEqual({ frameId: 0, kinds: ["cardnumber", "cardexpiry", "cardcvv"] });
    expect(chooseCardTarget([F(0, ["cardnumber", "cardcvv"], ["cardexpiry", "cardname"])])).toEqual({ frameId: 0, kinds: ["cardnumber", "cardcvv"] });
    // Duplicate kinds must not inflate richness (twin expiry boxes ≠ a richer form).
    expect(chooseCardTarget([F(0, ["cardnumber", "cardnumber", "cardnumber"], ["cardnumber", "cardcvv"])])).toEqual({ frameId: 0, kinds: ["cardnumber", "cardcvv"] });
    expect(chooseCardTarget([])).toBe(null);
    // Source anchors: the frame-0 branch exists in the pure chooser, and the SW actually WIRES it
    // at grant mint (freezing the chosen form's kinds + sig — [U12]/[U15], not a live registry read).
    const ms = readFileSync(extensionSrc + "messages.ts", "utf-8");
    expect(ms).toContain("f.frameId === 0 && f.forms.length > 0");
    expect(bg).toContain("const target = chooseCardTarget(eligible)");
    expect(bg).toContain("kinds: target.kinds, sig,");
  });

  it("[U12] grant-sig targeting fails CLOSED — sig-match only, never an index fallback", () => {
    // Content side: redemption re-scans and takes the FIRST current-sig match; a non-string sig
    // (mid-update mixed-version SW) refuses rather than guesses.
    const bySig = spanOf(ct, "function cardFormBySig(", "function applyCardFill(");
    expect(bySig).toContain('.join(",") === sig');
    expect(bySig).toContain("?? null");
    // End the span at the G2 capture section (G2's own composedPath()[0] lives BELOW this, and is
    // not part of the fill-redemption path this pin guards) — not at maybeOpen far downstream.
    const fillEntry = spanOf(ct, "async function fillCardIntoForm(", "// ---- G2 save-card capture");
    expect(fillEntry).toContain('typeof sig === "string" ? cardFormBySig(sig) : null');
    expect(fillEntry).toContain('code: "no_form"');
    // The Tier-1 shape this replaced — any positional pick — must never come back on this path.
    for (const [name, span] of [["cardFormBySig", bySig], ["fillCardIntoForm", fillEntry]] as const) {
      expect(span, `${name} has an index fallback`).not.toMatch(/\[0\]|\.at\(|forms\[/);
    }
    // SW side ([U14]/[A3]): a malformed grant (missing kinds/sig) refuses before ANY compose.
    expect(bg).toMatch(/!Array\.isArray\(grant\.kinds\) \|\| typeof grant\.sig !== "string"/);
  });

  it("[U15] reveal composes against the GRANT's frozen kinds — never the live registry, never a frame union", () => {
    expect(bg).toContain("const declared = new Set(grant.kinds)");
    // Exactly ONE declared-set construction — a second (e.g. a registry-fed union) would widen
    // the [T9] brand gate across forms after a mint→redeem rescan.
    expect(bg.match(/const declared = new Set\(/g)).toHaveLength(1);
    expect(spanOf(bg, "async function revealCardForFill(", "const declared = new Set(grant.kinds)")).not.toContain(".cardForms");
  });

  it("[U13] the registry idempotence sig is JSON.stringify(forms) — join would alias [[a,b]] ≡ [[a],[b]]", () => {
    const report = spanOf(ct, "function reportCardForm(", "function cardTargetOf(");
    expect(report).toContain("const sig = JSON.stringify(forms)");
    expect(report).not.toContain(".join(");
    // The GRANT sig stays single-level kinds.join(",") (unambiguous over a flat list) — the two
    // sigs are different beasts and must not converge on one encoding by refactor.
    expect(bg).toContain('const sig = target.kinds.join(",")');
  });

  it("[U17] composedPath()[0] retargets the shadow-blind paths: focusin, input, keydown, click-reopen (+G2 capture keydown)", () => {
    // The Tier-2 four retarget sites, PLUS one added by G2's card-submit-capture keydown-Enter
    // path (design §G2 [X2-A3]) — a shadow-blind Enter in a card field must retarget the same way.
    // Five total; reverting any to e.target drops the count. The submit listener and the click
    // submit-control probe stay deliberate non-members (submit does not compose; the control probe
    // walks the WHOLE path). The `[=(]` prefix keeps the count over CODE shapes only.
    expect(ct.match(/[=(] ?e\.composedPath\(\)\[0\]/g)).toHaveLength(5);
    // [K15] RE-SCOPED (design 2026-07-26 §Gate+pins, deliberate): the C1 chip adds a SECOND
    // consumer to the focusin listener, and the design's binding resolution is
    // `const t = e.composedPath()[0] ?? null; maybeOpen(t); void maybeCardChip(t);` — ONE retarget
    // site feeding both surfaces, so the count above legitimately stays 5. The literal-argument
    // form `maybeOpen(e.composedPath()[0] ?? null)` is therefore RETIRED: keeping it would have
    // forced a second `composedPath()[0]` (count 6) purely to satisfy a pin — the tripwire firing
    // on a real shape change, not a weakening. The anchor still proves BOTH surfaces are wired to
    // the RETARGETED node (an `e.target` regression re-blinds shadow-DOM checkouts) and that the
    // login dropdown is still driven first.
    expect(ct).toMatch(/"focusin",[\s\S]{0,160}?maybeOpen\(t\)[\s\S]{0,80}?maybeCardChip\(t\)/);
    expect(ct).toMatch(/"input",[\s\S]{0,120}?e\.composedPath\(\)\[0\] \?\? e\.target/);
    expect(ct).toMatch(/"keydown",[\s\S]{0,120}?e\.composedPath\(\)\[0\] \?\? e\.target/);
    expect(ct).toMatch(/"click",[\s\S]{0,200}?e\.composedPath\(\)\[0\]/);
  });

  it("[U16] the shadow sweep skips our own closed-shadow UI host (no self-observation loop)", () => {
    // chrome.dom.openOrClosedShadowRoot PIERCES closed roots, so the sweep would otherwise
    // discover + observe our own dropdown/banner/toast root — and every UI render would re-enter
    // onMutations, self-sustaining a ~150 ms re-render loop in the multi-step auto-open window.
    // No runtime test can catch this (jsdom has no chrome.dom); the guard is the pin.
    const cu = readFileSync(extensionSrc + "content-ui.ts", "utf-8");
    expect(cu).toMatch(/export function isOwnUiHost\(/);
    // The sweep must consult it BEFORE probing an element's shadow root, and skip on a match.
    expect(ct).toMatch(/if \(isOwnUiHost\(n as Element\)\) continue;[\s\S]{0,120}?shadowRootOf\(/);
  });

  it("[U18] setValue: full event envelope in order, then ONE re-assert gated on an EMPTY read-back", () => {
    const sv = spanOf(ct, "function setValue(", "function setSelectedIndex(");
    // Order is the fidelity contract: focus → keydown → native write → input → keyup → change,
    // and the re-assert guard sits strictly AFTER the envelope.
    expect(sv).toMatch(
      /input\.focus\(\);[\s\S]*?new KeyboardEvent\("keydown"[\s\S]*?nativeValueSetter\.call\(input, value\);[\s\S]*?new InputEvent\("input"[\s\S]*?new KeyboardEvent\("keyup"[\s\S]*?new Event\("change"[\s\S]*?if \(input\.value === ""\)/,
    );
    // Exactly TWO writes: the envelope's + the guarded re-assert. A third (or an unguarded
    // second) is the blind re-assert [U18] forbids — a masker's reformat is SUCCESS, not a miss.
    expect(sv.match(/nativeValueSetter\.call\(input, value\)/g)).toHaveLength(2);
  });

  it("[U21] crossOriginFormsOnly: exact neutral copy, mutually-exclusive flags, Fill gated on fillable alone", () => {
    // Byte-exact design sentence — capability-framed, never vouching the page is a checkout.
    expect(pp).toContain("Andvari can't auto-fill payment forms embedded from another site. Use the copy buttons instead.");
    // The SW computes the two flags mutually exclusive in ONE return — an eligible frame can
    // never also raise the explainer, so gating Fill on `fillable` alone renders no Fill button
    // in the explainer state.
    expect(bg).toContain("return { fillable: eligible, origin: eligible ? top : null, crossOriginFormsOnly: recorded && !eligible };");
    expect(pp).toMatch(/if \(cardFill\.fillable\) \{\s*acts\.append\(\s*actBtn\("fill"/);
    expect(pp).toContain("cardsPspNote.hidden = items.length === 0 || !cardFill.crossOriginFormsOnly");
    // The popup's delayed re-query diffs the flag too (a late PSP-frame report must surface the
    // explainer), folding a missing field (mixed-version SW) to false.
    expect(pp).toContain("(o2.crossOriginFormsOnly === true) !== cardFill.crossOriginFormsOnly");
  });
});

describe("Tier-3 card autofill pins (design 2026-07-23-…-tier3.md §7) — V1–V4 structural anchors", () => {
  const bg = readFileSync(extensionSrc + "background.ts", "utf-8");
  const ct = readFileSync(extensionSrc + "content.ts", "utf-8");
  const dt = readFileSync(extensionSrc + "detect.ts", "utf-8");

  const spanOf = (src: string, from: string, to: string): string => {
    const a = src.indexOf(from);
    const b = src.indexOf(to);
    expect(a, `span start missing: ${from}`).toBeGreaterThan(-1);
    expect(b, `span end missing/out of order: ${to}`).toBeGreaterThan(a);
    return src.slice(a, b);
  };

  it("[W9] the radio card-type write commits via .checked and NEVER setValue/the native value setter", () => {
    // A radio's `.value` is its brand token, so a text write + a text verifyLanded would bless an
    // UNSELECTED group as "filled". setRadioChecked is the ONE card write that must stay off the
    // setValue path — select the winner by `.checked`, verify `.checked === true`.
    const radioWrite = spanOf(ct, "function setRadioChecked(", "let filling = false");
    expect(radioWrite).toContain(".checked = true");
    expect(radioWrite, "radio write must not call setValue").not.toContain("setValue(");
    expect(radioWrite, "radio write must not touch the native value setter").not.toContain("nativeValueSetter");
  });

  it("[W9] the radio fill branch routes through radioIndexFor + setRadioChecked, never deriveCardWrite/setValue", () => {
    // The radio arm picks with the pure radioIndexFor and commits with setRadioChecked — it must
    // never fall into the deriveCardWrite → setValue text arm (which would stamp a radio's brand
    // token into `.value` and falsely verify a filled group).
    const radioBranch = spanOf(ct, "for (const ref of form.fields.filter(isRadioRef))", "// §4 card path only");
    expect(radioBranch).toContain("radioIndexFor(");
    expect(radioBranch).toContain("setRadioChecked(");
    expect(radioBranch, "radio branch reaches deriveCardWrite").not.toContain("deriveCardWrite(");
    expect(radioBranch, "radio branch reaches setValue").not.toContain("setValue(");
    // Radios are held OUT of the text/select loop by ref shape (type==="radio") so one can never
    // reach the setValue/setSelectedIndex arm in the first place.
    expect(ct).toMatch(/const isRadioRef = \(f: CardFormFieldRef\): boolean =>[\s\S]{0,80}?\.type === "radio"/);
    expect(ct).toContain("const nonRadio = form.fields.filter((f) => !isRadioRef(f));");
  });

  it("[W11] the radio group fills LAST — after the whole text/select loop, before the closing blur", () => {
    // A synthetic radio click fires PAGE listeners (no isTrusted needed) and may submit/navigate,
    // detaching unfilled PAN/expiry inputs — so every text/select field is written first, and the
    // closing blur/focusout still lands on the last DATA field, not the radio.
    const textLoop = ct.indexOf("for (const { kind, input } of [...nonRadio");
    const radioLoop = ct.indexOf("for (const ref of form.fields.filter(isRadioRef))");
    const closingBlur = ct.indexOf('lastWritten.dispatchEvent(new FocusEvent("blur"');
    expect(textLoop, "text/select loop present").toBeGreaterThan(-1);
    expect(radioLoop, "radio loop present").toBeGreaterThan(-1);
    expect(radioLoop, "radio loop must run AFTER the text/select loop").toBeGreaterThan(textLoop);
    expect(closingBlur, "closing blur must run AFTER the radio loop").toBeGreaterThan(radioLoop);
  });

  it("[W7] formlessGroups' inert remainder is EXACTLY selects + cardtype radios (review-fold predicate)", () => {
    // [T1] re-scoped to "login-inert-control-blind": a cardtype RADIO is an input but login-inert
    // (excluded by its TYPE) and a select is input-inert — both ride the inert remainder or a
    // brand-radio/expiry-<select> row beside a password CVV would satisfy the early-stop a level too
    // low and split the PAN off the cluster. Review-fold: every OTHER card-classified input
    // (tel/number PANs, negative-name CVVs — kind "none"/!textLike but cardKind non-null) must STAY
    // in the pool via the cardKind clause, or the shipped password-CVV↔PAN clustering splits and
    // the [A7] save-suppression loses its anchor. The pin is the FULL predicate. G3 [X3-A3] adds
    // `cardpostal` to the inert set (login-inert, attaches post-formation) alongside radios.
    const fg = spanOf(dt, "export function formlessGroups(", "const remaining = new Set(inputs)");
    expect(fg).toContain(
      'f.input instanceof HTMLInputElement &&\n    (f.kind !== "none" || f.textLike || (f.cardKind !== null && f.cardKind !== "cardpostal" && f.input.type !== "radio"))',
    );
    expect(fg).toContain("const inputs = loose.filter(loginEligible);");
    expect(fg).toContain("const inert = loose.filter((f) => !loginEligible(f));");
  });

  it("[W4] the ASCII-fold lives at the cardKindFromTokens chokepoint, NEVER inside tokens()", () => {
    // tokens() also feeds isCvvNameOrId → buildLoginForm.suppressSave, a login-capture verdict that
    // MUST stay byte-identical; folding there would move a login verdict. The card path folds ONE
    // level up (tokens(fold(raw)) at cardKindFromTokens) so only card classification sees the folded
    // alphabet. Reverting to tokens(raw) — or sliding fold into tokens() — must red this pin.
    const cardKind = spanOf(dt, "function cardKindFromTokens(", "/** [U6] label-source bounds");
    expect(cardKind).toContain("tokens(fold(raw))");
    const toks = spanOf(dt, "function tokens(raw: string)", "function tokenMatch(");
    expect(toks, "tokens() must not fold — it feeds the login suppressSave verdict").not.toContain("fold(");
  });

  it("[V4] the discovery badge paints CARD_BADGE_TEXT only when a card form is eligible AND there is no login count", () => {
    // refreshTabBadge is the tab's SINGLE badge authority so the login count and the card dot never
    // clobber each other: login count takes precedence; the dot paints ONLY when loginCount === 0
    // and an eligible same-origin card frame exists.
    expect(bg).toContain('const CARD_BADGE_TEXT = "•"');
    // Review-fold: refreshTabBadge went SYNC — its origin now comes from the recorded top-frame
    // sender.origin (st.topOrigin), never a tab.url read; no await, no lock interleave.
    const badge = spanOf(bg, "function refreshTabBadge(", "/** Popup ONLY:");
    // The [A4] discipline extends to the badge: no tab.url / topOrigin(tabId) read in its body.
    expect(badge).not.toContain("await topOrigin(");
    expect(badge).not.toMatch(/tab\.url/);
    expect(badge).toContain("const loginCount = host !== \"\" ? matchesFor(host).length : 0;");
    expect(badge).toContain("loginCount > 0 ? String(loginCount) : top !== null && eligibleCardFrames(tabId, top).length > 0 ? CARD_BADGE_TEXT : \"\"");
    expect(badge).toContain("chrome.action.setBadgeText({ tabId, text })");
  });

  it("[V4] a top-level navigation clears the card dot in the [A4] loading handler, beside the cardForms delete", () => {
    // The dot must not outlive the form: the same loading handler that voids the card registry
    // clears the badge — but ONLY when the badge IS the dot (getBadgeText === CARD_BADGE_TEXT), so a
    // live login count is left for the destination's own pageInfo to repaint. No `.url` read (that
    // would be a `tabs`-permission bump — already pinned by [A4] above).
    const handler =
      bg.match(/onUpdated\.addListener\(\(tabId, changeInfo\) => \{\s*if \(changeInfo\.status !== "loading"\) return;[\s\S]*?\n\}\);/)?.[0] ?? "";
    expect(handler.length, "the status===loading card-clear handler must exist").toBeGreaterThan(0);
    expect(handler).toContain("getBadgeText({ tabId })");
    expect(handler).toContain('cur === CARD_BADGE_TEXT ? chrome.action.setBadgeText({ tabId, text: "" })');
    expect(handler).toContain("delete st.cardForms");
  });
});

describe("C1 in-page card chip pins (design 2026-07-26 §Gate + pins) — zero-data, [A4]/[A5] anchors", () => {
  const bg = readFileSync(extensionSrc + "background.ts", "utf-8");
  const cu = readFileSync(extensionSrc + "content-ui.ts", "utf-8");
  const ms = readFileSync(extensionSrc + "messages.ts", "utf-8");

  const spanOf = (src: string, from: string, to: string): string => {
    const a = src.indexOf(from);
    const b = src.indexOf(to);
    expect(a, `span start missing: ${from}`).toBeGreaterThan(-1);
    expect(b, `span end missing/out of order: ${to}`).toBeGreaterThan(a);
    return src.slice(a, b);
  };

  it("[S7] the two chip messages carry NO VALUES — exact request literals, boolean-only responses", () => {
    // [A2]: a page-controlled member (host/kinds/frameId) is the shape already struck once. The
    // request literals must stay MEMBERLESS, so adding one is a contract edit a reviewer sees.
    expect(ms).toContain('{ type: "cardChipOffer" }');
    expect(ms).toContain('{ type: "openPopupForCards" }');
    // The Res branches admit no `string` type — no origin echo, no item name, no masked identity.
    expect(ms).toMatch(/T extends "cardChipOffer"\s*\?\s*\{ fillable: boolean; locked: boolean \}/);
    expect(ms).toMatch(/T extends "openPopupForCards"\s*\?\s*\{ opened: boolean \}/);
    // [S4b] the repair nudge rides the typed wire (a rename on one side is a silent no-op).
    expect(ms).toContain('{ type: "reportPageInfo" }');
    expect(bg).toContain('{ type: "reportPageInfo" }');
  });

  it("[C2] cardChipOffer is PASSIVE (a focus loop must not defer the idle autolock); the click is NOT", () => {
    // [K13]: page script can fire *trusted* focus at frame rate, so the offer stream is page-driven
    // traffic, not user activity. `openPopupForCards` rides a real isTrusted click and stays out.
    const set = bg.match(/const PASSIVE_MSGS = new Set<Req\["type"\]>\(\[([^\]]*)\]\)/)?.[1] ?? "";
    expect(set.length, "PASSIVE_MSGS literal must exist").toBeGreaterThan(0);
    expect(set).toContain('"cardChipOffer"');
    expect(set).not.toContain("openPopupForCards");
  });

  it("[S4a] the pageInfo topOrigin write PERSISTS (regression pin for the shipped V4 badge bug)", () => {
    // Shipped defect: the write lived only in SW memory, so it died with the ~30 s MV3 idle-death —
    // and `pageInfo` fires ONCE at content init, so nothing rewrote it and the card discovery dot
    // silently stopped appearing. Every other TabState mutation persists; so must this one.
    const pageInfo = spanOf(bg, 'case "pageInfo": {', 'case "updateStatus":');
    const write = pageInfo.indexOf("st.topOrigin = sender.origin;");
    const persist = pageInfo.indexOf("persistTabs();");
    expect(write, "the pageInfo topOrigin write must exist").toBeGreaterThan(-1);
    expect(persist, "the topOrigin write must be followed by persistTabs()").toBeGreaterThan(write);
    // The badge repaint stays — the record and the paint are one unit.
    expect(pageInfo).toContain("void refreshTabBadge(tabId);");
  });

  it("[S2] a top-level nav marks the tab stale SYNCHRONOUSLY — before the async topOrigin erase", () => {
    // The erase can only run after `await ensureLoaded()`; between navigation-start and that
    // microtask the map still holds the PREVIOUS document's top origin, which is exactly what the
    // chip gate compares `sender.origin` against. The marker is added beside `cardGrants.delete`
    // (pre-await) and released in a `finally` so a failed hydrate can't blind the tab forever.
    expect(bg).toContain("const topOriginPendingClear = new Set<number>();");
    const handler =
      bg.match(/onUpdated\.addListener\(\(tabId, changeInfo\) => \{\s*if \(changeInfo\.status !== "loading"\) return;[\s\S]*?\n\}\);/)?.[0] ?? "";
    expect(handler.length, "the status===loading card-clear handler must exist").toBeGreaterThan(0);
    expect(handler).toMatch(/cardGrants\.delete\(tabId\);[\s\S]{0,400}?topOriginPendingClear\.add\(tabId\);[\s\S]*?await ensureLoaded\(\)/);
    expect(handler).toMatch(/finally \{[\s\S]{0,400}?topOriginPendingClear\.delete\(tabId\);/);
  });

  it("[S8]/[S1]/[S3] the cardChipOffer gate: no tab URL, no topOrigin() read, strict frame 0, no vault condition", () => {
    // PLACEMENT: the handler lives inside the refreshTabBadge → "Popup ONLY" span so the shipped
    // [V4] negatives cover it too; these are the gate's OWN pins (the [A4] pin is scoped to the
    // onUpdated handler and [V4] to refreshTabBadge — neither would catch a brand-new handler, and
    // a tab-URL read is the exact defect class the Tier-3 review-fold caught in the badge: it works
    // on broad-grant installs and silently fails on per-site grants).
    const gate = spanOf(bg, "async function cardChipOffer(", "/** C1 §C4");
    expect(gate).not.toMatch(/tab\.url/);
    expect(gate).not.toContain("topOrigin("); // `topOriginPendingClear` has no paren — the real read does
    // [S1] STRICTLY frameId 0. The shipped badge's `frameId === undefined || frameId === 0`
    // disjunct is a fail-OPEN admission — tolerable for a badge repaint, never for a per-frame
    // render decision. Reproducing it here must red this pin.
    expect(gate).toContain('typeof frameId !== "number" || frameId !== 0');
    expect(gate, "the gate must not inherit the badge's fail-open frameId disjunct").not.toContain("frameId === undefined ||");
    // The origin comparison is browser-set on BOTH sides.
    expect(gate).toContain("sender.origin !== top");
    // [S2] mid-nav tabs are refused.
    expect(gate).toContain("topOriginPendingClear.has(tabId)");
    // [S3] NO vault condition on `fillable` — a chip whose presence tracked "vault holds ≥1 card"
    // (or unlock state) would turn an elementFromPoint hit-test into a live vault-state monitor.
    // `locked` is reported separately as the copy selector, never as a presence gate.
    expect(gate, "fillable must carry no vault condition").not.toContain("session.items");
    expect(gate).toContain("const locked = session === null;");
    // [S-rate] + [S4b]: the gate is throttled, and a MISSING record repairs (never a refusal —
    // a hostile frame must not be able to retry a "no" into a "yes").
    expect(gate).toContain("CHIP_OFFER_MIN_GAP_MS");
    expect(gate).toMatch(/if \(top === undefined \|\| !hasForm\) \{[\s\S]{0,200}?repairPageRecords\(tabId, now\);/);
    // Re-scoped (review #7): the repair's rescan is now FRAME-0 SCOPED, not the tab-wide
    // broadcast. The wide form messaged every frame incl. cross-origin ones, each doing a full
    // document + shadow-root scan — a top frame that deletes its own registry entry could drive
    // that as a cross-origin CPU amplifier, and the chip only ever needs frame 0's record.
    expect(bg).toMatch(
      /function repairPageRecords\([\s\S]{0,900}?CHIP_REPAIR_MIN_GAP_MS[\s\S]{0,1200}?rescanCardForms[\s\S]{0,200}?\{ frameId: 0 \}/,
    );
    expect(bg, "the repair must not tab-broadcast the rescan").not.toMatch(
      /function repairPageRecords\([\s\S]{0,1400}?broadcastRescanCardForms\(/,
    );
    expect(bg).toContain('chrome.tabs.sendMessage(tabId, msg, { frameId: 0 })');
  });

  it("[C4] openPopupForCards ATTEMPTS the one API and answers honestly — never tabs.create, never a pre-mint", () => {
    const act = spanOf(bg, "async function openPopupForCards(", "/** Popup ONLY:");
    // FORBIDDEN: opening popup.html as a tab/window — the popup computes offers against the ACTIVE
    // tab and would see itself.
    expect(act).not.toMatch(/tabs\.create|windows\.create/);
    expect(act).toContain("openPopup");
    // [K14]: an honest `{opened}` needs the RESULT, so G4's fire-and-forget shape is not reusable.
    expect(act).toMatch(/return \{ opened: false \}/);
    expect(act).toMatch(/return \{ opened: true \}/);
    // [S9]: openPopup targets the FOCUSED window's active tab — a click from a tab that is no
    // longer that tab would open trusted chrome pointed at a different origin than the user clicked.
    expect(act).toContain("sender.tab?.active !== true");
    expect(act).toContain("chrome.tabs.query({ active: true, currentWindow: true })");
    // [A5]: the click mints nothing, pre-selects nothing, enumerates nothing — the card grant stays
    // a popup-only mint, and no tab URL is read ([A4]).
    expect(act, "the chip click must not touch the grant store").not.toContain("cardGrants");
    expect(act, "the chip click must not enumerate the vault").not.toContain("session.items");
    expect(act, "the chip click must not reach an item doc").not.toMatch(/\bdoc\b/);
    expect(act).not.toMatch(/tab\.url/);
  });

  it("[K6] exactly ONE attachShadow call site in content-ui.ts — isOwnUiHost is an IDENTITY test", () => {
    // The chip renders into ui()'s EXISTING closed root. A SECOND host would be pierced by
    // chrome.dom.openOrClosedShadowRoot, join `shadowRoots`, get an observer, and — since
    // OBSERVE_OPTS filters class/style/hidden — turn every re-anchor `style` write into an observed
    // mutation: the [U16] self-observation loop, worse. If a second host is ever required,
    // isOwnUiHost becomes a Set test IN THE SAME COMMIT and this pin moves with it.
    expect(cu.match(/attachShadow\(/g)).toHaveLength(1);
  });

  it("[S10] no andvari in-page surface may EVER contain a password input, in any state or path", () => {
    // The structural bound on every habituation argument: the chip may teach "in-page andvari UI
    // exists"; it must never be able to teach "andvari asks for the master password in-page".
    // Any quoting form (attribute or property literal); `type === "password"` comparisons are not
    // matched (no assignment/colon), so field-skipping logic stays legal.
    expect(cu, "content-ui.ts must contain no password input").not.toMatch(/type\s*[=:]\s*["'`]?password/i);
  });

  it("[C1] the chip surface is ZERO-DATA — one boolean in, string literals out", () => {
    // The chip's render input is `{ locked: boolean }` and NOTHING else: no card identity, no item
    // name, no count, no origin. The span is the whole surface (show → close).
    expect(cu).toMatch(/function showCardChip\([\s\S]{0,200}?state: \{ locked: boolean \}/);
    const chip = spanOf(cu, "function showCardChip(", "function closeCardChip(");
    for (const bad of ["MatchItem", "CardItem", "subtitle", "cvv", "expiry", "postal", "brand"]) {
      expect(chip, `chip surface references ${bad}`).not.toMatch(new RegExp(bad, "i"));
    }
    // `number` is BOTH a card field and a TS primitive: strip TYPE positions first so the pin fires
    // on `values.number` / `card.number` and never on the [K11] geometry's arithmetic signatures.
    const chipData = chip.replace(/:\s*number\b/g, ": <t>").replace(/\bas number\b/g, "as <t>").replace(/<number\b/g, "<t");
    expect(chipData, "chip surface references a card number").not.toMatch(/\bnumber\b/i);
    // …and it reads no state member other than `locked` (the copy selector).
    expect(chip.match(/state\.(\w+)/g) ?? [], "chip reads a state member other than locked").toEqual(
      (chip.match(/state\.(\w+)/g) ?? []).filter((m) => m === "state.locked"),
    );
    // Review #4: the labels must be STRING LITERALS. A template literal in this span is the one
    // shape that could interpolate a value into page-adjacent UI without tripping any pin above.
    expect(chip, "chip surface builds text with a template literal").not.toMatch(/`/);
  });

  it("[S3] the chip box is state-INDEPENDENT — a fixed width/height, no intrinsic sizing", () => {
    // Review #2: the fixed box IS the hit-test defence. `document.elementFromPoint` retargets to
    // our closed-shadow host, so a page can probe the chip's rect; if the locked and unlocked
    // copies produced different boxes, that rect would encode LIVE VAULT LOCK STATE — and a page
    // can force trusted focus at frame rate, turning it into a continuous monitor. Deleting the
    // `width` line alone would restore content-sizing (flex default) with every other pin green.
    const rule = spanOf(cu, ".chip {", ".chip:hover");
    expect(rule, "the .chip box must declare an explicit width").toMatch(/width:\s*\d+px/);
    expect(rule, "the .chip box must declare an explicit height (the locked copy wraps)").toMatch(/height:\s*\d+px/);
    expect(rule, "intrinsic sizing re-opens the locked/unlocked width oracle").not.toMatch(
      /(?:max|min|fit)-content|width:\s*auto/,
    );
  });

  it("[S6]/[K-label] the chip copy is verbatim: the locked line names the TOOLBAR, and neither reads as a submit", () => {
    // Review #3: the locked sentence teaches "unlocking happens in browser chrome, never in-page".
    // Reverting it to "Unlock to fill card" would invert that teaching silently — the page controls
    // the anchor position and could seat the REAL chip against a page-drawn master-password box.
    const chip = spanOf(cu, "function showCardChip(", "function closeCardChip(");
    expect(chip).toContain("andvari is locked — click the andvari toolbar icon");
    expect(chip).toContain("Fill card with andvari");
    // [K-label] neither label may match detect.ts's SUBMIT_TEXT_RX, or our own chip would read as
    // a submit control to the G2 capture gesture path.
    const submitRx = /sign.?in|log.?in|continue|next|submit|anmelden|einloggen/i;
    for (const label of ["Fill card with andvari", "andvari is locked — click the andvari toolbar icon"]) {
      expect(submitRx.test(label), `chip label "${label}" reads as a submit control`).toBe(false);
    }
  });

  it("[S3-lock] a lock retains ONLY page-known facts — never `pending` (plaintext password)", () => {
    // Review #1: a bare tabs.clear() made chip presence an EDGE-TRIGGER for "the vault just
    // locked" — the moment a fake in-page unlock prompt is most credible. The retention is an
    // ALLOW-LIST of fresh objects so a future TabState field is dropped by default.
    const lock = spanOf(bg, "[S3-lock] Retain ONLY", "grants.clear()");
    expect(lock).toMatch(/tabs\.set\(tabId, \{ topOrigin: st\.topOrigin, cardForms: st\.cardForms \}\)/);
    // Strip comment lines before the negative: the rationale comment must be free to NAME the
    // fields it forbids (that is the whole point of writing it down). The pin's subject is the
    // CODE — a retention that actually copies `pending`/`lastUsername` across a lock.
    const lockCode = lock
      .split("\n")
      .filter((l) => !l.trim().startsWith("//"))
      .join("\n");
    for (const secret of ["pending", "lastUsername", "password"]) {
      expect(lockCode, `the lock retention copies ${secret}`).not.toContain(secret);
    }
  });
});
