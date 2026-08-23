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
 * Cross-suite pins for the browser extension (originally its cards slice, design
 * 2026-07-09-cards-wallet.md; now its cross-cutting contracts generally).
 *
 * The extension DOES have a test harness of its own — `extension/ && npm test`, a node --test
 * suite of 20-odd files and 250+ tests over its chrome-free leaves (card, detect, savetarget,
 * quickunlock, urimatch, totp, the crypto vectors, …). That is where per-function behaviour
 * belongs, and the first place to look. (quality-tests--11: this header used to claim the
 * extension had "no test harness of its own (build/typecheck/package only)", which stopped being
 * true when that suite landed, and to point at noble-extension-poc.test.ts as the anchor of the
 * extension's crypto parity — that file is SKIPPED in every default run; crypto.vectors.test.ts
 * inside the extension is the live anchor.)
 *
 * What lives HERE is what that suite structurally cannot hold: values and code SHAPES that must
 * stay identical across the extension/web seam (chrome-free modules imported directly), plus
 * source-text pins over the chrome-bound modules — background.ts, content.ts, content-ui.ts,
 * popup.ts — which cannot be imported under node at all. Those are read as text and asserted on,
 * so editing a pinned line must break this file first, deliberately.
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

  it("[U17] composedPath()[0] retargets the shadow-blind paths: focusin, input, keydown, click-reopen, focusout (+G2 capture keydown)", () => {
    // The Tier-2 four retarget sites, PLUS one added by G2's card-submit-capture keydown-Enter
    // path (design §G2 [X2-A3]) — a shadow-blind Enter in a card field must retarget the same way.
    // PLUS one added 2026-08-22 by the signup reuse alert's `focusout` listener: a new-password
    // field inside a shadow root blurs shadow-blind exactly like it focuses, so it retargets the
    // same way or the warning silently never fires on those checkouts. SIX total; reverting any to
    // e.target drops the count. The submit listener and the click submit-control probe stay
    // deliberate non-members (submit does not compose; the control probe walks the WHOLE path).
    // The `[=(]` prefix keeps the count over CODE shapes only.
    expect(ct.match(/[=(] ?e\.composedPath\(\)\[0\]/g)).toHaveLength(6);
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
    expect(ct).toMatch(/"focusout",[\s\S]{0,160}?e\.composedPath\(\)\[0\]/);
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
    // F24 (2026-08-13 audit): lowercase brand. This was the ONE capitalized user-facing "andvari"
    // in the tree — and this pin was what protected the drift. If a sentence-initial capital is
    // ever wanted here, rephrase so the brand is not the first word.
    expect(pp).toContain("andvari can't auto-fill payment forms embedded from another site. Use the copy buttons instead.");
    expect(pp, "the brand is lowercase in running copy").not.toContain("Andvari can't auto-fill");
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
    // 2026-07-27 audit (bug-ext-gating--0): `matches` rides the SAME trusted focusin (the login
    // dropdown's open-query, one line above the chip's in the focusin listener) and `pendingSave`
    // fires on every top-frame load — both page-driven, so both must stay passive or a two-field
    // focus loop / an auto-refreshing tab holds the vault unlocked indefinitely.
    expect(set).toContain('"matches"');
    expect(set).toContain('"pendingSave"');
    expect(set).not.toContain("openPopupForCards");
    // 2026-08-13 audit (F01): `capturedCredential` was pinned OUT of this set on the reasoning
    // that "a submit is a real user activity" — and that reasoning was the defect. A submit is
    // page-DRIVEABLE (`form.requestSubmit()` fires one with isTrusted TRUE and no user gesture),
    // so a scripted loop in any frame re-armed the idle alarm forever, silently: a username-only
    // capture sends password:"" and the SW answers with no `pending`, so no banner is ever drawn.
    // Driveability is the whole test here, so it is passive; the user's save signal is the banner
    // click (`resolvePendingSave`), which stays out.
    expect(set, "capturedCredential is page-driveable (requestSubmit) ⇒ it must NOT re-arm the autolock").toContain('"capturedCredential"');
    // …while genuine user activity keeps re-arming: none of these may ever join the passive set
    // (each rides an isTrusted gesture in our closed-shadow UI, the popup, or a banner click).
    for (const active of ["reveal", "allItems", "resolvePendingSave", "generate", "linkUri"]) {
      expect(set, `${active} must re-arm the autolock (real user activity)`).not.toContain(`"${active}"`);
    }
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
    // 2026-07-27 audit (quality-secdrift--1): the nav must ALSO drop the [S-rate]/[S4b] throttle
    // caches — leaving them let the replay branch answer the NEW document with the PREVIOUS
    // document's cached `fillable`, skipping the [S2] check for up to 250 ms.
    expect(handler).toContain("chipOfferLast.delete(tabId)");
    expect(handler).toContain("chipRepairLast.delete(tabId)");
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
    // [S2] mid-nav tabs are refused — and (2026-07-27 audit, quality-secdrift--1) the stale check
    // PRECEDES the [S-rate] replay branch, so an [S2]-marked tab can never be served from cache
    // (belt to the loading handler's chipOfferLast delete — braces).
    expect(gate).toContain("topOriginPendingClear.has(tabId)");
    expect(gate.indexOf("topOriginPendingClear.has(tabId)")).toBeLessThan(gate.indexOf("CHIP_OFFER_MIN_GAP_MS"));
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
    // 2026-07-27 audit re-anchor: a bare ".chip {" start latched onto the shared
    // `.dropdown, .banner, .toast, .chip {` token block, so every match below could read ANOTHER
    // surface's declaration (the height check was passing off `.anv-sr`'s 1px). The newline
    // prefix pins the span to the .chip rule itself.
    const rule = spanOf(cu, "\n.chip {", ".chip:hover");
    expect(rule, "the .chip box must declare an explicit width").toMatch(/width:\s*\d+px/);
    expect(rule, "the .chip box must declare an explicit height (the locked copy wraps)").toMatch(/height:\s*\d+px/);
    expect(rule, "intrinsic sizing re-opens the locked/unlocked width oracle").not.toMatch(
      /(?:max|min|fit)-content|width:\s*auto/,
    );
    // 2026-07-27 audit (quality-secdrift--3): the fixed box must actually HOLD the two lines it
    // promises. border-box arithmetic over the rule's own declarations: height − vertical padding
    // − borders ≥ 2 × (font-size × line-height) — the shipped 46px left a 30px content box for
    // 35px of text, spilling the locked anti-phishing sentence outside the pill. And overflow
    // must clip: elementFromPoint retargets every shadow descendant to the host, so un-clipped
    // spill (a user minimum font size, a wide font fallback) makes the page-observable painted
    // region state-dependent again — the exact oracle [S3] closes.
    expect(rule, "the .chip box must clip its own text").toMatch(/overflow:\s*hidden/);
    expect(rule).toMatch(/border:\s*1px/); // the 2px border term below assumes a 1px border
    const h = Number(rule.match(/height:\s*(\d+(?:\.\d+)?)px/)![1]);
    const pad = Number(rule.match(/padding:\s*(\d+(?:\.\d+)?)px/)![1]); // first value = vertical
    const [, fs, lh] = rule.match(/font:\s*(\d+(?:\.\d+)?)px\/(\d+(?:\.\d+)?)/)!;
    expect(h - 2 * pad - 2, "two lines at the declared font must fit the border-box height").toBeGreaterThanOrEqual(
      2 * Number(fs) * Number(lh),
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

describe("2026-07-27 polish-release audit pins (extension lane) — checkout gating, frame gating, sign-out revoke", () => {
  const bg = readFileSync(extensionSrc + "background.ts", "utf-8");
  const ct = readFileSync(extensionSrc + "content.ts", "utf-8");

  const spanOf = (src: string, from: string, to: string): string => {
    const a = src.indexOf(from);
    const b = src.indexOf(to);
    expect(a, `span start missing: ${from}`).toBeGreaterThan(-1);
    expect(b, `span end missing/out of order: ${to}`).toBeGreaterThan(a);
    return src.slice(a, b);
  };

  it("bug-autofill-ux--0: maybeOpen cedes a suppressSave form's card fields (incl. the demoted CVV) — no login dropdown on a checkout card box", () => {
    // The owner-reported 2026-07-26 real-checkout failure: a hintless <input type=password
    // name=cvv> built a bogus login form ({password:<cvv>, username:<expiry/PAN/name>}) and a
    // dropdown pick filled vault credentials into the payment fields. The fix is FIELD-LOCAL at
    // the surface (core FieldClassifier CSC-demotion parity) — classify() itself stays byte-frozen
    // with web, so the gate must live in maybeOpen, never in the classifier.
    const open = spanOf(ct, "function maybeOpen(", "async function openFor(");
    expect(open).toContain("cardMisreadAsLogin(f) || (f.suppressSave && cardFormForInput(target) !== null)");
    // ANCHOR-LOCAL IS NOT ENOUGH (the shipped first cut): fillForm writes the FORM's slots, so a
    // dropdown opened on a cardholder-name field misread as the username — neither f.password nor
    // a card-form member — still wrote the vault password into the CVV box. The destination leg
    // must carry the gate; the anchor equality must not come back as the whole rule.
    expect(open, "the anchor-local password-equality leg cannot close the parity gap").not.toContain("f.password === target");
  });

  it("bug-autofill-ux--0: the checkout gate is DESTINATION-local — a genuine password beside card fields still fills", () => {
    // suppressSave is a UNION (detect.ts buildLoginForm): `isCardForm` ∨ lone-CVV, and [A7]
    // isCardForm fires for ANY form carrying a card-NUMBER field. A create-account-at-checkout
    // form is therefore suppressSave for SAVE reasons while its real password field is a
    // legitimate FILL target — so the gate keys on whether the form's password DESTINATION is
    // itself a card field, never on the blunt form-level flag.
    const fn = spanOf(ct, "function cardMisreadAsLogin(", "/** The FIELD-local half");
    expect(fn).toContain("if (!f.suppressSave) return false;"); //        not suppressSave ⇒ never blocked
    expect(fn).toContain("if (p === null) return true;"); //              password-less (username-step) on a card form stays blocked
    expect(fn).toContain("return isCardField(p);"); //                    …else the password DESTINATION decides
    // The two ways to BE a card field: card-form membership (which includes the demoted CVV ref),
    // or — on a lone-CVV form no card form claims (no PAN anchor ⇒ no card form exists) — the
    // field-local demotion rule itself, core FieldClassifier's CSC demotion. ONE resolver ([U12]):
    // the form-level gate and the per-slot gate below must never drift into two spellings of it.
    const field = spanOf(ct, "function isCardField(", "/** The card form a submit-like control");
    expect(field).toContain("cardFormForInput(el) !== null || demoteCsc(null, el.type, el.name, el.id) !== null");
    expect(ct.match(/demoteCsc\(null,/g), "the field-local demotion rule has exactly one call site").toHaveLength(1);
  });

  it("2026-07-27 residual: fillForm re-asks the destination question PER SLOT — an account email can never land in a card box", () => {
    // The shipped fix gated on the form's PASSWORD destination, which is the right question for
    // "may this form fill at all" and leaves the USERNAME slot unexamined. On a legitimate
    // create-account-at-checkout form (suppressSave for [A7] reasons, genuine password field),
    // detect.ts resolves the username by "nearest text field above the password" — routinely a PAN
    // or expiry input that classified as `none`. So the entry-point gate passed the form and
    // fillForm wrote the user's email into a card box. It is also the ONLY gate that survives
    // liveForm's re-resolve, which can hand back a DIFFERENT form than the one that was gated.
    const fill = spanOf(ct, "function fillForm(", "async function copyTotp(");
    expect(fill).toContain("const guard = live.suppressSave;"); // same cheap pre-check as the form gate
    expect(fill).toContain("live.username && s.username && !(guard && isCardField(live.username))");
    expect(fill).toContain("live.password && s.password && !(guard && isCardField(live.password))");
    // The FillOutcome union already carries a partial honestly, and must keep doing so: a skipped
    // username slot answers "password" (not "both"), and both slots skipped falls through to the
    // existing no_fields verdict — which is what makes `fillFromPopup`'s ok:true mean "something
    // really landed" rather than "the message was delivered" (Cut M) on a checkout too.
    expect(fill).toContain('if (!wroteUser && !wrotePass) return { filled: "nothing", code: "no_fields" };');
    expect(fill).toContain('return { filled: wroteUser && wrotePass ? "both" : wroteUser ? "username" : "password" };');
    // The TOTP side-copy still rides on a real write — a fill reduced to nothing must not leave a
    // 2FA code in the clipboard.
    expect(fill.indexOf("if (!wroteUser && !wrotePass)")).toBeLessThan(fill.indexOf("copyTotp(s.totpCode)"));
  });

  it("bug-autofill-ux--0: the chip's [K1] login precedence exempts suppressSave claims — the ceded fields get the chip, one surface per anchor", () => {
    const chip = spanOf(ct, "async function maybeCardChip(", "// ---- dropdown ----");
    expect(chip).toMatch(/lf !== null && !lf\.suppressSave/);
  });

  it("bug-autofill-ux--0: the popup-driven fill applies the SAME destination gate (both entry points agree)", () => {
    // The popup path used the blunt !x.suppressSave, which over-rejected the create-account-at-
    // checkout form the dropdown now fills — two entry points, one rule.
    expect(ct).toContain('all.find((x) => x.kind === "login" && !cardMisreadAsLogin(x)) ?? all.find((x) => !cardMisreadAsLogin(x))');
  });

  it("bug-autofill-ux--2: the focusout listener dismisses the dropdown too, behind the isOwnUiHost exemption", () => {
    // A script-driven focus move (section-expand autofocus, SPA hydration — no mousedown, no Tab)
    // must not leave a stale dropdown whose capture-phase arrow/Enter keys still act on the old
    // form, or co-render it with the chip. The isOwnUiHost exemption keeps the search-box focus
    // handoff into our closed root alive.
    expect(ct).toMatch(
      /addEventListener\(\s*"focusout",[\s\S]{0,900}?isOwnUiHost\(e\.relatedTarget\)[\s\S]{0,900}?dismissCardChip\(\);[\s\S]{0,700}?closeDropdown\(\);/,
    );
  });

  it("bug-ext-gating--2 / quality-secdrift--2: pending saves are FRAME-owned — read is top-frame, resolve is capturer-only", () => {
    // The capture side always defended its frame (background capturedCredential/captureCard);
    // these close the read/resolve half so a cross-origin sub-frame can neither read the top
    // frame's captured metadata nor commit / silently dismiss its pending — login and card twins
    // alike, matching the [S1]/revealCardForFill precedents. The popup (no tab) passes.
    const read = spanOf(bg, 'case "pendingSave": {', 'case "resolvePendingSave"');
    expect(read).toContain("sender.frameId !== undefined && sender.frameId !== 0");
    const login = spanOf(bg, "async function resolvePendingSave(", "// ---- G2 save-card capture");
    expect(login).toContain("sender.tab !== undefined && sender.frameId !== pending.frameId");
    const card = spanOf(bg, "async function resolvePendingCardSave(", "// ---- writes");
    expect(card).toContain("sender.tab !== undefined && sender.frameId !== rec.frameId");
    expect(card, "the card twin stays capturer-only — its banner never crosses frames").not.toContain("frameId !== 0");
    // …and all THREE offerPendingSave sends target frame 0: the metadata never rides into
    // sub-frames (the render was always isTop-gated content-side; the delivery now matches it).
    // Third sender since ext 0.20.1: commitApprovedSave's failure fallback (unlock-prompt design
    // 2026-08-12) re-offers the banner when an approved auto-commit could not land.
    expect(bg.match(/\{ type: "offerPendingSave"[\s\S]{0,300}?sendMessage\(tabId, (?:msg|m), \{ frameId: 0 \}\)/g) ?? []).toHaveLength(3);
  });

  it("bug-ext-gating--2 (regression half): the LOGIN resolve admits frame 0 — capture and offer live in different frames", () => {
    // Capturer-ONLY deadlocked every sub-frame login: content runs with allFrames, so a sub-frame
    // login records pending.frameId = N, but the re-offer surface is top-frame only
    // (offerPendingSave is sent { frameId: 0 }; the post-nav poll renders only when isTop). The
    // user's Save click therefore always arrives from frame 0 ≠ N → "nothing pending" forever, and
    // because capturedCredential refuses a cross-frame overwrite of a live pending, that stale
    // pending then SQUATS the tab's single slot for the tab's life (persisted through SW death),
    // silently dropping every later capture in the tab — top-frame ones included.
    const login = spanOf(bg, "async function resolvePendingSave(", "// ---- G2 save-card capture");
    // Sub-frame capture → resolved from frame 0 → passes the gate…
    expect(login).toContain("sender.frameId !== pending.frameId && sender.frameId !== 0");
    // …while a hostile non-zero, non-owning frame is still refused (the disjunction stays an AND
    // chain: any relaxation to `||` would admit every frame in the tab).
    expect(login, "the frame gate must stay a conjunction").not.toMatch(/sender\.frameId !== pending\.frameId \|\|/);
    // Dismiss must be reachable from frame 0 too, or the squat survives the user closing the
    // banner: the guard sits ABOVE the dismiss branch, so admitting frame 0 clears the slot.
    expect(login.indexOf("sender.frameId !== 0")).toBeLessThan(login.indexOf('if (action === "dismiss")'));
    // No new exposure: frame 0 could already READ any frame's pending (password stripped).
    const read = spanOf(bg, 'case "pendingSave": {', 'case "resolvePendingSave"');
    expect(read).toContain("sender.frameId !== undefined && sender.frameId !== 0");
  });

  it("bug-web--0 (extension half): doSignOut revokes the server session — bounded, best-effort, and NEVER from doLock", () => {
    // Android/desktop both AWAIT a bounded logout on sign-out; without it "Sign out" leaves the
    // refresh token valid server-side for ~30 days. The revoke fires BEFORE doLock nulls the
    // tokens; api.logout() never throws and the race caps the wait, so an offline sign-out still
    // wipes locally. doLock stays revoke-free: a lock KEEPS the session (quick-unlock re-arm).
    const so = spanOf(bg, "async function doSignOut(", "/** Re-arm the policy idle lock");
    expect(so).toMatch(/Promise\.race\(\[api\.logout\(\), delay\(5000\)\]\)/);
    const lock = spanOf(bg, "async function doLock(", "async function doSignOut(");
    expect(lock).not.toContain("logout(");
  });
});

describe("2026-07-27 polish-release audit pins (extension lane) — in-page a11y, chip dismissal, list order", () => {
  const bg = readFileSync(extensionSrc + "background.ts", "utf-8");
  const ct = readFileSync(extensionSrc + "content.ts", "utf-8");
  const cu = readFileSync(extensionSrc + "content-ui.ts", "utf-8");
  const pu = readFileSync(extensionSrc + "popup.ts", "utf-8");

  const spanOf = (src: string, from: string, to: string): string => {
    const a = src.indexOf(from);
    const b = src.indexOf(to);
    expect(a, `span start missing: ${from}`).toBeGreaterThan(-1);
    expect(b, `span end missing/out of order: ${to}`).toBeGreaterThan(a);
    return src.slice(a, b);
  };

  it("a11y-webext--1: dropdown rows activate on CLICK as well as mousedown — AT virtual-cursor picks work", () => {
    // NVDA/JAWS browse-mode Enter, VoiceOver VO+Space and touch double-tap all dispatch a trusted
    // CLICK, never a mousedown — so a mousedown-only row is announced as a listbox option that a
    // screen-reader user then cannot pick, on the extension's core fill surface. The chip fixed
    // this exact bug for itself (Review #4) and the rows were left out. ONE binder for both rows,
    // so they cannot drift apart again.
    const bind = spanOf(cu, "function bindRowActivation(", "function matchRow(");
    expect(bind).toContain('row.addEventListener("mousedown", activate)');
    expect(bind).toContain('row.addEventListener("click", activate)');
    expect(bind).toContain("if (!e.isTrusted) return;"); // anti-spoof: a page-synthesized event cannot fill
    expect(bind).toContain("e.preventDefault()"); //         focus stays on the page field, so it stays fillable
    for (const [fn, arg] of [["matchRow", "pick"], ["actionRow", "act"]] as const) {
      const at = cu.indexOf(`function ${fn}(`);
      expect(at, `${fn} missing`).toBeGreaterThan(-1);
      const body = cu.slice(at, cu.indexOf("\n}", at));
      expect(body, `${fn} must bind activation through the shared binder`).toContain(`bindRowActivation(row, ${arg});`);
      expect(body, `${fn} must not grow a second, drifting listener`).not.toContain("addEventListener");
    }
  });

  it("a11y-webext--12: the chip has a keyboard activation path, and it is announced", () => {
    // [K10] forbids a tabindex (real focus must stay in the page's card field), so a pure-keyboard
    // user could SEE the chip and had no way to trigger the one thing it does. The document-capture
    // handler already sees trusted keydowns while a chip is live; one low-collision chord there is
    // the only shape available. It must stay chip-scoped and dropdown-free ([K4]).
    const key = spanOf(cu, "a11y-webext--12: the chip's keyboard activation", "if (!dropdownEl) return; // a lone chip");
    expect(key).toContain("chipEl && !dropdownEl && e.altKey && e.key === \"ArrowDown\"");
    expect(key).toContain("dismissChipSurface()"); // [K9] the surface goes before the action
    // Strip comments before the negative: the rationale is free to NAME what it forbids.
    const keyCode = key
      .split("\n")
      .filter((l) => !l.trim().startsWith("//"))
      .join("\n");
    expect(keyCode, "[K4]: the chip must never touch the dropdown's reopen suppression").not.toContain("suppressOpenUntil");
    // Discoverability: an untabbable surface that does not say its key does not have one.
    const chip = spanOf(cu, "function showCardChip(", "function closeCardChip(");
    expect(chip).toContain("Press Alt plus Down Arrow to open andvari.");
    expect(chip, "the SPOKEN form must not alter the [S6] visible sentences").toContain('"Fill card with andvari"');
  });

  it("a11y-webext--0: the banners answer Escape, carry a labelled role, and never drop focus to <body>", () => {
    // The banner host is appended to documentElement, so its buttons sit at the very END of the
    // page's tab order — inside a 30 s idle close. Escape was the only realistic keyboard
    // dismissal and the keydown gate did not even consult bannerEl.
    const keys = spanOf(cu, "document.addEventListener(\n    \"keydown\"", "const reanchor =");
    expect(keys).toContain("!dropdownEl && !chipEl && !bannerEl");
    expect(keys).toContain("bannerDecline?.();");
    // …but NOT consumed, for Review #2's reason (a banner sits over the site's own modal).
    expect(keys.indexOf("bannerDecline?.()")).toBeLessThan(keys.indexOf("if (!dropdownEl) return;"));
    const shell = spanOf(cu, "function bannerShell(", "function closeBanner(");
    expect(shell).toContain('bar.setAttribute("role", "group")');
    expect(shell).toContain('bar.setAttribute("aria-label", "andvari")');
    expect(shell).toContain("bar.tabIndex = -1;"); // script-focusable only — never a new tab stop
    const offer = spanOf(cu, "function offerBanner(", "export function showSaveBanner(");
    // The verdict removes the focused button; focus must land somewhere real, not on <body>.
    expect(offer.indexOf("actions.remove()")).toBeLessThan(offer.indexOf("bar.focus()"));
    // Escape runs the GHOST path (close + onDismiss), and only while the offer is unanswered.
    expect(offer).toContain("bannerDecline = decline;");
    expect(offer).toContain("bannerDecline = null; // answered");
  });

  it("quality-deadcode--2: ONE banner builder — the three offers differ only by spec", () => {
    // They were ~95% identical, so every a11y contract had to be restated three times and
    // a11y-webext--0 is exactly the one that was not. The shared body must keep the pinned
    // ordering (announce the offer, then the verdict) and the isTrusted gates.
    const offer = spanOf(cu, "function offerBanner(", "export function showSaveBanner(");
    expect(offer.indexOf("announceLive(`andvari:")).toBeLessThan(offer.indexOf("announceLive(r.text)"));
    expect(offer.match(/if \(!e\.isTrusted\) return;/g), "both buttons stay isTrusted-gated").toHaveLength(2);
    // …and the three exports are thin: no second copy of the shell may reappear.
    expect(cu.match(/bannerShell\(\)/g), "bannerShell has exactly one caller").toHaveLength(2); // decl + call
    for (const fn of ["export function showSaveBanner(", "export function showCardSaveBanner(", "export function showLinkOffer("]) {
      const at = cu.indexOf(fn);
      expect(at, `${fn} missing`).toBeGreaterThan(-1);
      const wrap = cu.slice(at, cu.indexOf("\n}", at));
      expect(wrap, `${fn} must delegate to offerBanner`).toContain("offerBanner({");
      expect(wrap, `${fn} must not rebuild the shell itself`).not.toContain("bannerShell()");
    }
  });

  it("quality-secdrift--5: [K8] really IS one dismissal path — every content-ui close tells content.ts", () => {
    // content-ui closed the chip directly from four places content.ts cannot observe: the
    // outside-mousedown handler, the Escape branch and positionChip's two auto-closes. Each left
    // `chipAnchor` set and `chipGen` un-bumped, so an offer still in flight could repaint the chip
    // the user had just dismissed — reachable on any site whose widget preventDefault()s mousedown
    // (custom menus, date pickers): no blur, no focusout, nothing told content.ts.
    expect(cu).toContain("function dismissChipSurface(): void {");
    const dismiss = spanOf(cu, "function dismissChipSurface(", "function ui(): ShadowRoot");
    expect(dismiss).toContain("const onDismiss = chipDismissed;");
    expect(dismiss).toContain("closeCardChip();");
    expect(dismiss).toContain("onDismiss?.();");
    // closeCardChip stays the callback-FREE primitive, or content.ts's own dismissal recurses.
    const close = spanOf(cu, "export function closeCardChip(", "/** [K8] every close that ORIGINATES");
    expect(close).toContain("chipDismissed = null;");
    expect(close, "the primitive must not call back").not.toContain("onDismiss");
    // All four origin sites route through it, and content.ts supplies the handler.
    // The declaration + the FIVE origin sites: outside-mousedown, Escape, the a11y-webext--12
    // chord, and positionChip's disconnected/off-screen auto-closes.
    expect(cu.match(/dismissChipSurface\(\)/g) ?? []).toHaveLength(6);
    expect(ct).toContain("onDismiss: dismissCardChip");
  });

  it("quality-secdrift--4: the chip's SW-wake mitigation exists CONTENT-side, per the design's [K13]", () => {
    // What shipped was a per-tab SW-side throttle plus a per-INPUT content dedupe; neither reduces
    // wakes, because the SW's cache is consulted only after handle()'s await ensureLoaded(). A page
    // that focus-loops N distinct card fields therefore bought N wakes. The design asked for a
    // per-document cache — this is it, on the SW's own window so there is one number, not two.
    const chip = spanOf(ct, "async function maybeCardChip(", "// ---- dropdown ----");
    expect(chip).toContain("const cached = chipOffer !== null && now - chipOffer.t < CHIP_OFFER_CACHE_MS");
    expect(chip).toContain('const r = cached ?? (await safeSend({ type: "cardChipOffer" }));');
    // Every [K12]/[K5] re-check must still run on the replay path — the cache skips the MESSAGE,
    // never the gate.
    expect(chip.indexOf("const r = cached")).toBeLessThan(chip.indexOf("if (gen !== chipGen) return;"));
    expect(chip).toContain("if (filling) return;");
    // Invalidated where the registry it answers about changes.
    expect(spanOf(ct, "function reportCardForm(", "function cardTargetOf(")).toContain("chipOffer = null;");
    expect(ct).toContain("const CHIP_OFFER_CACHE_MS = 250;");
    expect(bg).toContain("CHIP_OFFER_MIN_GAP_MS = 250");
  });

  it("bug-ext-gating--1 / F01: the login submit capture needs a fresh GESTURE (isTrusted alone is not one), and the top frame outranks a sub-frame", () => {
    // requestSubmit() fires `submit` with isTrusted TRUE (it is a UA "fire an event"), so the
    // isTrusted gate costs the documented case nothing — while dispatchEvent(new SubmitEvent(...))
    // arrives FALSE and reached the handler, letting any frame forge a capture. It stays as the
    // cheap first refusal…
    const submit = spanOf(ct, "bug-ext-gating--1: this listener WAS ungated", 'document.addEventListener(\n    "click"');
    expect(submit).toContain("if (!e.isTrusted) return;");
    // …but 2026-08-13 audit F01: it is NOT the gate. The very case the comment above names —
    // requestSubmit() — needs no user gesture at all, so a 1 px form ticking `requestSubmit()`
    // captured on every tick (and, before capturedCredential became passive, re-armed the idle
    // autolock forever with nothing on screen). A fresh unconsumed click/Enter is now the gate,
    // the card lane's shape: form first, THEN consume, so a foreign submit cannot burn the
    // gesture the real login form is about to need.
    expect(submit).toContain("if (f && consumeLoginGesture()) captureNow(f);");
    // The gesture is recorded by the login lane's OWN trusted listeners — any click (a JS "Sign in"
    // element that calls requestSubmit() is an ordinary login shape) and Enter in a field.
    expect(ct).toMatch(/"click",\s*\(e\) => \{\s*if \(!e\.isTrusted\) return;\s*recordLoginGesture\(\);/);
    // …recorded BEFORE the dropdown's Enter check (a row pick is user activity too — the page
    // routinely auto-submits behind it), which also anchors this to the login keydown listener.
    expect(ct).toMatch(/e\.key !== "Enter"[\s\S]{0,600}?recordLoginGesture\(\);[\s\S]{0,600}?dropdownWillConsumeEnter\(\)/);
    // Its slot is PRIVATE to the login lane: recording into the card lane's one-shot would hand
    // the card capture the free 1 s window [X2-A3] forbids.
    const gesture = spanOf(ct, "function consumeLoginGesture(", "function captureNow(");
    expect(gesture).toContain("loginGesture.consumed = true;");
    expect(gesture, "the login gate must not reach into the card lane's slot").not.toContain("trustedGesture");
    // Slot ownership: a top-frame capture may EVICT a sub-frame's pending; every other pairing is
    // still refused, so the squat (which silently suppressed the real Save banner) is closed.
    const cap = spanOf(bg, "async function capturedCredential(", "const username = msg.username ||");
    expect(cap).toContain("st.pending.frameId !== frameId && frameId !== 0");
    // …and the sticky per-tab lastUsername is top-frame only (it steers saveTargetFor).
    expect(cap).toContain("if (msg.username && frameId === 0)");
  });

  it("F01 follow-up: the SW's own popup fill ARMS the login gesture, so an auto-submitting site still banners", () => {
    // The gesture gate closed a scripted-capture hole and opened a silent one: a popup fill IS a
    // real user click, but it lands in the popup's document, so a site that submits itself the
    // moment its fields change (fill → the page's change handler → requestSubmit()) found no
    // gesture in THIS document, captured nothing, and the Save banner simply never appeared.
    const branch = spanOf(ct, 'if (msg.type === "fillItem") {', 'if (msg.type === "fillCard")');
    expect(branch).toContain("recordLoginGesture();");
    // Armed BEFORE the fill: fillForm's input/change events can drive the page's requestSubmit()
    // synchronously, so an arm placed after the round-trip is an arm after the submit it exists for.
    expect(branch.indexOf("recordLoginGesture();")).toBeGreaterThan(-1);
    expect(branch.indexOf("void fillItem(")).toBeGreaterThan(-1);
    expect(branch.indexOf("recordLoginGesture();")).toBeLessThan(branch.indexOf("void fillItem("));
    // …and only when there IS a form to fill: the no_form early return must not leave a window armed
    // on a page we never touched.
    expect(branch.indexOf('code: "no_form"')).toBeLessThan(branch.indexOf("recordLoginGesture();"));

    // The recorders are an AUTHORITY LIST, not a gate — the opposite of senderHost, where a new
    // caller is the outcome the pin wants. Every recordLoginGesture() call site widens what counts
    // as the user's submit gesture, so exactly three, each argued in the source: the trusted click,
    // Enter in a field, and this SW-delivered fill. A fourth SHOULD red this pin.
    expect(ct.match(/recordLoginGesture\(\);/g) ?? [], "each recorder is a vetted user-gesture source").toHaveLength(3);
    // The property F01 bought is unchanged: nothing else admits a submit, so a scripted
    // requestSubmit() loop with no gesture anywhere still consumes nothing and captures nothing.
    const gate = spanOf(ct, "function consumeLoginGesture(", "function captureNow(");
    expect(gate).toContain("if (loginGesture && !loginGesture.consumed && Date.now() - loginGesture.t < LOGIN_GESTURE_MS)");
    // One-shot, and wide enough for a sign-in that round-trips before it submits (the reason the
    // login window is not the card lane's 1 s).
    expect(gate).toContain("loginGesture.consumed = true;");
    expect(ct).toContain("const LOGIN_GESTURE_MS = 10_000;");
  });

  it("ux-parity--2: extension lists sort by name, transliterating CORE's comparator", () => {
    // Web sorts (localeCompare) and core sorts (sortedBy name.lowercase); the extension listed in
    // server change-feed order, so the popup's hoard reshuffled as items were edited. Sorted at the
    // ONE projection every login surface reads through, and at the card twin.
    expect(bg).toContain("function loginItems(): DecryptedItem[] {\n  return session ? session.items.filter((i) => i.doc.type === \"login\").sort(byName) : [];");
    expect(bg).toContain('.filter((i) => i.doc.type === "card").sort(byName)');
    const cmp = spanOf(bg, "const byName = (a: DecryptedItem", "function loginItems(");
    expect(cmp).toContain("a.doc.name.toLowerCase()");
    expect(cmp, "a locale collator would be a THIRD order, not core's").not.toContain("localeCompare");
  });

  it("bug-ext-gating--4: the designed RP host-permission probe exists, and the popup hides what cannot work", () => {
    // A runtime-withheld host permission breaks the RP-ID claim with SecurityError, which the
    // engine maps to bio_cancelled → "Setup was cancelled — try again when you're ready.", forever.
    // The probe routes it to the honest bio_unsupported line (which names the PIN) instead.
    expect(bg).toContain("async function bioRpPermissionHeld(): Promise<boolean> {");
    expect(bg).toContain("const BIO_RP_ORIGIN_PATTERN = `${DEFAULT_SERVER_URL}/*`;");
    const enroll = spanOf(bg, "const biometricDep: QuBiometric = {", "async evalPrf(");
    expect(enroll).toContain("if (!(await bioRpPermissionHeld())) return { credentialId: \"\", prfEnabled: false, prfSalt };");
    // The popup's capability probe must ask the same question — a button that can only fail is the
    // bug, not the ceremony.
    const probe = spanOf(pu, "async function probeBioCapable(", "const label = bioLabel();");
    expect(probe).toContain("await bioRpPermissionHeld()");
    expect(probe).toContain("typeof navigator.credentials?.create === \"function\"");
    // One spelling of the RP origin, derived — connector.ts claims it, the SW probes it.
    const cx = readFileSync(extensionSrc + "connector.ts", "utf-8");
    expect(cx).toContain("const RP_ID = new URL(DEFAULT_SERVER_URL).hostname;");
    expect(cx, "the reference host must not be re-spelled as a literal").not.toContain('"andvari.monahanhosting.com"');
  });

  it("ux-parity--1 (extension half): sign-out is a two-step arm-confirm, disarmed on blur", () => {
    // Every other surface confirms; here one click on a footer button adjacent to "Lock" wiped the
    // quick-unlock enrollment (PIN/biometric re-setup required). The popup has no dialog surface,
    // so this is the options page's own inline idiom.
    const so = spanOf(pu, "let signOutArmed = false;", "/* ---- footer ---- */");
    expect(so).toContain("if (!signOutArmed) {");
    expect(so).toContain('signOutArmed = true;');
    expect(so.indexOf("signOutArmed = true;")).toBeLessThan(so.indexOf('ask({ type: "signOut" })'));
    expect(so).toContain('el("sign-out").addEventListener("blur", disarmSignOut)');
  });
});

describe("TOTP-add lane pins (design 2026-08-12) — add-only contract, sender gates, passive offer", () => {
  const bg = readFileSync(extensionSrc + "background.ts", "utf-8");
  const ct = readFileSync(extensionSrc + "content.ts", "utf-8");

  const spanOf = (src: string, from: string, to: string): string => {
    const a = src.indexOf(from);
    const b = src.indexOf(to);
    expect(a, `span start missing: ${from}`).toBeGreaterThan(-1);
    expect(b, `span end missing/out of order: ${to}`).toBeGreaterThan(a);
    return src.slice(a, b);
  };

  it("writeTotp is ADD-ONLY and SW-validated: the exists refusal and the parse gate both precede the put", () => {
    const w = spanOf(bg, "async function writeTotp(", "async function setTotp(");
    // The one contract line: an item that already carries a code refuses, whatever the surface.
    expect(w).toContain('code: "exists"');
    expect(w.indexOf('code: "exists"')).toBeLessThan(w.indexOf("putExisting("));
    // The SW normalizes + parse-gates ITSELF — a surface's validation is never the gate.
    expect(w).toContain("normalizeTotp(rawTotp)");
    expect(w).toContain("isValidTotp(totp)");
    expect(w.indexOf("isValidTotp(totp)")).toBeLessThan(w.indexOf("putExisting("));
  });

  it("setTotp is popup-only; the page derivation is origin-bound, exactly-one-match, code-less-only", () => {
    const s = spanOf(bg, "async function setTotp(", "function pageTotpTarget(");
    expect(s).toContain("if (sender.tab !== undefined) return"); // a page never reaches the pick-any-item write
    const p = spanOf(bg, "function pageTotpTarget(", "/** Offer gate for the in-page banner");
    // [A2] browser-set origin only (captureCard's guard shape) — no page-supplied host exists on this seam.
    expect(p).toContain('typeof sender.origin !== "string" || sender.origin === "" || sender.origin === "null"');
    // Ambiguity fails CLOSED to the popup path…
    expect(p).toContain("matches.length !== 1");
    // …and an item that already has a code is never a page target (add-only at the derivation too).
    expect(p).toContain('(it.doc.login?.totp ?? "") !== ""');
  });

  it("both page halves run the ONE derivation, and the offer answers a NAME only", () => {
    const o = spanOf(bg, "function totpOffer(", "/** Banner accept");
    expect(o).toContain("pageTotpTarget(sender)");
    expect(o, "the offer must never carry an itemId onto the page seam").not.toContain("itemId");
    const a = spanOf(bg, "async function addTotpFromPage(", "/** [X2-A6] card-aware re-seal");
    expect(a, "the accept must RE-DERIVE, never trust the offer round-trip").toContain("pageTotpTarget(sender)");
    expect(a).toContain("sender.frameId !== 0");
  });

  it("totpOffer is PASSIVE ([K13]); the accept and the popup write are NOT", () => {
    const m = /const PASSIVE_MSGS = new Set<Req\["type"\]>\(\[([^\]]*)\]\)/.exec(bg);
    expect(m).not.toBeNull();
    expect(m![1]).toContain('"totpOffer"');
    expect(m![1], "a real Add click is user activity — it must re-arm the idle lock").not.toContain('"addTotpFromPage"');
    expect(m![1]).not.toContain('"setTotp"');
  });

  it("content sends the href ONLY on the Add click — the offer ask is the bare literal", () => {
    const c = spanOf(ct, "async function maybeOfferTotp(", "// ---- wiring ----");
    expect(c).toContain('safeSend({ type: "totpOffer" })'); // no host, no href — [A2]
    expect(c).toContain('safeSend({ type: "addTotpFromPage", totp: href })');
    expect(c, "raw attribute, never the engine-normalized .href").toContain('getAttribute("href")');
    expect(c).toContain("if (!isTop) return");
  });
});

describe("2026-08-13 audit pins (extension lane) — F18 caller binding on the three unbound handlers", () => {
  const bg = readFileSync(extensionSrc + "background.ts", "utf-8");
  const ct = readFileSync(extensionSrc + "content.ts", "utf-8");
  const msgs = readFileSync(extensionSrc + "messages.ts", "utf-8");

  const spanOf = (src: string, from: string, to: string): string => {
    const a = src.indexOf(from);
    const b = src.indexOf(to);
    expect(a, `span start missing: ${from}`).toBeGreaterThan(-1);
    expect(b, `span end missing/out of order: ${to}`).toBeGreaterThan(a);
    return src.slice(a, b);
  };

  it("the dispatch hands `sender` to BOTH newly-bound handlers (a dropped argument is the whole defect)", () => {
    // `fillFromPopup(msg.itemId)` and `linkUri(msg.itemId, msg.host)` were the only two effectful
    // cases in the switch that never saw who was calling.
    expect(bg).toContain("return fillFromPopup(msg.itemId, sender);");
    expect(bg).toContain("return linkUri(msg, sender);");
  });

  it("fillFromPopup is POPUP ONLY, refused before anything else runs (its card twin's guard, verbatim)", () => {
    const f = spanOf(bg, "async function fillFromPopup(", "// ---- S3 in-page card fill");
    expect(f).toContain('if (sender.tab !== undefined) return { ok: false, code: "not_allowed", error: "not allowed from a page" };');
    // It mints a grant for whatever tab is ACTIVE — which need not be the sender's tab or origin —
    // so the refusal must precede the tab query, not merely exist somewhere in the body. (Both
    // indices are asserted present: a missing guard is -1, which would "pass" an ordering test.)
    expect(f.indexOf("sender.tab !== undefined")).toBeGreaterThan(-1);
    expect(f.indexOf("sender.tab !== undefined")).toBeLessThan(f.indexOf("chrome.tabs.query"));
    // The sibling that already did this must not regress alongside it.
    const c = spanOf(bg, "async function fillCardFromPopup(", "/** Content (S3 redemption)");
    expect(c).toContain("if (sender.tab !== undefined) return");
  });

  it("linkUri binds a TAB sender to ITS OWN host — a page cannot make an item match a site it never visited", () => {
    // linkUri closes the file, so this span runs to EOF rather than to the next section header.
    const l = bg.slice(bg.indexOf("async function linkUri("));
    expect(l.length, "linkUri must exist").toBeGreaterThan(0);
    expect(l).toContain("if (sender.tab !== undefined && senderHost(sender) !== webHost) return");
    // The refusal must sit ahead of the write: this handler persists to the server, so a late
    // check would still have appended the uri locally. (-1 must never satisfy the ordering.)
    expect(l.indexOf("senderHost(sender) !== webHost")).toBeGreaterThan(-1);
    expect(l.indexOf("senderHost(sender) !== webHost")).toBeLessThan(l.indexOf("putExisting("));
    // The popup keeps its freedom (its host comes from activeTabHost() under activeTab), which is
    // exactly what the `sender.tab !== undefined` conjunct buys.
    expect(l, "the guard must stay tab-scoped, not blanket").toContain("sender.tab !== undefined &&");
  });

  it("reveal's host gate reads the BROWSER-SET origin for tab senders, never the page-supplied msg.host", () => {
    const r = spanOf(bg, "function reveal(msg: Extract<", "/** Card copy egress");
    expect(r).toContain("const webHost = sender.tab !== undefined ? senderHost(sender) : normalizeHost(msg.host);");
    // The old unconditional read is the defect: a sandboxed frame has an opaque `sender.origin`
    // but a perfectly real `location.hostname`, so the two can disagree.
    expect(r, "msg.host must never be the tab sender's identity").not.toContain("const webHost = normalizeHost(msg.host);");
  });

  it("[A2]/[A3] senderHost is the ONE spelling of caller identity, and fails closed", () => {
    const s = spanOf(bg, "function senderHost(", "/** Contract reveal rules");
    expect(s).toContain('typeof sender.origin !== "string" || sender.origin === "" || sender.origin === "null"');
    expect(s).toContain("return hostOfUrl(sender.origin);");
    // ONE spelling means every gate reads it — reveal's host and linkUri's own-host rule are each
    // pinned to their own span above, which is what actually proves the seam is CONNECTED. This
    // count is only the floor: an exactly-2 pin would red the gate on a THIRD handler correctly
    // adopting the host gate, i.e. it would punish the outcome the pin exists to encourage.
    expect(
      (bg.match(/senderHost\(sender\)/g) ?? []).length,
      "the F18 host gates must route through the one spelling",
    ).toBeGreaterThanOrEqual(2);
  });

  it("reveal's `explicit` bypass is stated as deliberate, and stays narrow on the page side", () => {
    // `msg.explicit === true` short-circuits AHEAD of the host gate, so senderHost's fail-closed
    // property does not hold on that path. Deliberate — a search-all pick exists precisely to fill
    // an item this host does NOT match — but undocumented it reads as the same class of oversight
    // F18 fixed, so the contract now says so where the contract is stated.
    const c = spanOf(msgs, "/** Secret for a fill.", '| { type: "fillFromPopup"');
    expect(c).toContain("deliberate BYPASS");
    expect(c).toContain("`explicit` is checked AHEAD of the host gate");
    // The ordering the comment describes is the code's: no host is computed into the decision first.
    const r = spanOf(bg, "function reveal(msg: Extract<", "/** Card copy egress");
    expect(r).toContain("msg.explicit === true ||");
    // And the claim it rests on must stay true: the page side sets `explicit` at exactly ONE call
    // site, the closed-shadow search-all pick. Every other in-page fill goes through the host gate.
    expect(
      ct.match(/fill(?:Item|FromDropdown)\([^)]*, true\)/g) ?? [],
      "only the search-all pick may bypass the host gate",
    ).toHaveLength(1);
    expect(ct).toContain("const o = await fillFromDropdown(m.itemId, f, true);");
  });
});
