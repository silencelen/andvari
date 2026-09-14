// node --test (see version.test.ts). Pins the a11y contrast fixes (A1 7a/7b) by parsing the
// ACTUAL token values out of popup.css and computing WCAG 2.x contrast ratios — a green static
// gate on markup can lie about announcement, but a computed ratio is ground truth for contrast.
//
// The luminance helper is an INDEPENDENT ~20-line copy (parity with web/src/ui/contrast.test.ts
// by convention, not by import — there is no build path between the extension and web trees).
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

// --- WCAG relative luminance + contrast ratio (independent of the web copy) ---
function lin(c: number): number {
  const s = c / 255;
  return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
}
function luminance(hex: string): number {
  let h = hex.replace("#", "");
  if (h.length === 3) h = h.split("").map((x) => x + x).join("");
  const r = parseInt(h.slice(0, 2), 16);
  const g = parseInt(h.slice(2, 4), 16);
  const b = parseInt(h.slice(4, 6), 16);
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}
function ratio(fg: string, bg: string): number {
  const a = luminance(fg);
  const b = luminance(bg);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

/** Alpha-composite `fg` at `a` over opaque `bg` (sRGB, as a browser paints it). This is what
 *  `color-mix(in oklab, var(--tok) N%, transparent)` resolves to: mixing with `transparent`
 *  premultiplies, so the result is simply the token at N% alpha over whatever is behind it. */
function composite(fg: string, a: number, bg: string): string {
  const b = bg.replace("#", "");
  const f = fg.replace("#", "");
  return (
    "#" +
    [0, 2, 4]
      .map((i) => Math.round(parseInt(f.slice(i, i + 2), 16) * a + parseInt(b.slice(i, i + 2), 16) * (1 - a)))
      .map((c) => c.toString(16).padStart(2, "0"))
      .join("")
  );
}

const css = readFileSync(fileURLToPath(new URL("../popup.css", import.meta.url)), "utf-8");

/** Slice a `{ … }` block starting at the first `{` after `marker`, brace-matched. */
function block(source: string, marker: string): string {
  const i = source.indexOf(marker);
  assert.ok(i >= 0, `CSS marker not found: ${marker}`);
  const open = source.indexOf("{", i);
  let depth = 0;
  for (let j = open; j < source.length; j++) {
    if (source[j] === "{") depth++;
    else if (source[j] === "}" && --depth === 0) return source.slice(open, j);
  }
  throw new Error(`unbalanced braces after ${marker}`);
}
function token(blk: string, name: string): string {
  const m = new RegExp(`--${name}\\s*:\\s*(#[0-9a-fA-F]{3,6})`).exec(blk);
  assert.ok(m, `token --${name} not found in block`);
  return m[1];
}

// Dark tokens live in the first `:root {`; light tokens in the prefers-color-scheme:light @media.
const dark = block(css, ":root {");
const light = block(css, "@media (prefers-color-scheme: light)");
const AA = 4.5; // WCAG AA for normal-size text

for (const [theme, blk] of [
  ["dark", dark],
  ["light", light],
] as const) {
  const faint = token(blk, "ink-faint");
  const dim = token(blk, "ink-dim");
  const bg = token(blk, "bg");
  const bgRaised = token(blk, "bg-raised");
  const bgInput = token(blk, "bg-input");

  // 7a — faint helper text (labels, section labels, KDF caption, .link.dim, .muted) renders on
  // both --bg and --bg-raised surfaces; both must clear AA.
  test(`7a ${theme}: --ink-faint ${faint} clears AA on --bg and --bg-raised`, () => {
    const onBg = ratio(faint, bg);
    const onRaised = ratio(faint, bgRaised);
    assert.ok(onBg >= AA, `--ink-faint on --bg = ${onBg.toFixed(2)} (< ${AA})`);
    assert.ok(onRaised >= AA, `--ink-faint on --bg-raised = ${onRaised.toFixed(2)} (< ${AA})`);
  });

  // 7b — placeholders now use --ink-dim (was --ink-faint) on --bg-input.
  test(`7b ${theme}: placeholder --ink-dim ${dim} clears AA on --bg-input`, () => {
    const r = ratio(dim, bgInput);
    assert.ok(r >= AA, `--ink-dim on --bg-input = ${r.toFixed(2)} (< ${AA})`);
  });
}

// 7b — pin the actual rule: the ::placeholder colour must reference --ink-dim, not the faint token.
test("7b: input::placeholder uses var(--ink-dim)", () => {
  const m = /input::placeholder\s*\{\s*color:\s*var\(--([a-z-]+)\)/.exec(css);
  assert.ok(m, "input::placeholder color rule not found");
  assert.equal(m[1], "ink-dim", "placeholder should use --ink-dim for AA contrast");
});

// --- UI-audit Cut A: the classes the 7a/7b gates never covered — the ported --link token
// (web AM-1, finally adopted here), the focus indicator (light was ~2.1:1), gold-as-text,
// the button-gradient ink, and danger on its own tinted plate. Computed, not pinned prose. ---
const UI_MIN = 3; // WCAG 1.4.11 non-text minimum
for (const [theme, blk] of [
  ["dark", dark],
  ["light", light],
] as const) {
  const bg = token(blk, "bg");
  const bgRaised = token(blk, "bg-raised");
  const bgInput = token(blk, "bg-input");
  const link = token(blk, "link");
  const goldText = token(blk, "gold-text");
  const focus = token(blk, "focus");
  const hi = token(blk, "gold-hi");
  const lo = token(blk, "gold-lo");
  const btnInk = token(blk, "btn-ink");

  test(`CutA ${theme}: --link ${link} + --gold-text ${goldText} clear AA on --bg and --bg-raised`, () => {
    for (const [name, val] of [["--link", link], ["--gold-text", goldText]] as const) {
      assert.ok(ratio(val, bg) >= AA, `${name} on --bg = ${ratio(val, bg).toFixed(2)}`);
      assert.ok(ratio(val, bgRaised) >= AA, `${name} on --bg-raised = ${ratio(val, bgRaised).toFixed(2)}`);
    }
  });
  test(`CutA ${theme}: --focus ${focus} ≥ ${UI_MIN}:1 on every input/row surface`, () => {
    for (const [name, s] of [["--bg", bg], ["--bg-raised", bgRaised], ["--bg-input", bgInput]] as const) {
      assert.ok(ratio(focus, s) >= UI_MIN, `--focus on ${name} = ${ratio(focus, s).toFixed(2)}`);
    }
  });
  test(`CutA ${theme}: --btn-ink clears AA on BOTH gradient stops, and --gold-hi is the lighter stop`, () => {
    assert.ok(ratio(btnInk, hi) >= AA, `on --gold-hi = ${ratio(btnInk, hi).toFixed(2)}`);
    assert.ok(ratio(btnInk, lo) >= AA, `on --gold-lo = ${ratio(btnInk, lo).toFixed(2)}`);
    assert.ok(luminance(hi) > luminance(lo), "gradient must be lit from above (hi lighter than lo)");
  });
}

// --- H134 (audit 2026-09-13): the tinted PLATES. This block used to parse the ONE hardcoded rgba
// literal out of .msg.err and composite it — "hardcoded rgba literal" was in its own name, because
// the literal did not track --danger. That was the bug, not a quirk of the test: the literals were
// frozen copies of the DARK palette (the .err pair was still the pre-Cut-A #cf6b5a, retired when
// --danger was lifted to #d97f6f / light #b3402c), so light mode got a pink-salmon wash around
// brick-red text and the gold plates carried the dark gold. The rules now mix the plate from the
// same token the text uses, and this composites THAT — so the gate follows the palette instead of a
// snapshot of it, in both themes.
//
// What is and is not gated, honestly:
//  · dark, both surfaces: full AA. That is the gate this file has always had, extended to .info/.ok.
//  · light: the WASH invariant (below) plus the 3:1 non-text floor, NOT AA — because the light
//    palette is already at its own ceiling before any plate exists. Bare --ok on light --bg is
//    4.38:1 and bare --danger 4.97:1; a 12% wash of the text's own hue costs ~15% of any ratio, so
//    no plate percentage can make light --ok reach AA. That is a PALETTE matter, owned by the
//    five-way token lockstep in web/src/ui/token-lockstep.test.ts, and gating it here would be
//    gating someone else's file through this one.
// The wash invariant is what a tint plate must actually satisfy: tinting a surface with the text's
// own hue always drags the surface toward the text, so the plate may READ as coloured but may not
// cost more than a fifth of the bare surface's contrast. Every plate lands at ~83-90% today.
// R11: ALL EIGHT converted plates, not the four the first pass listed. The other four
// (.host-grant-cta, .update-banner, .qu-offer, .totp-chip) were converted in the same diff and
// mentioned by no test in the tree, so re-freezing any of them as an rgba() literal shipped with
// the whole suite green — which is precisely the regression this block exists to make impossible.
// `borderPct: null` means the rule's BORDER is a token (--edge / --edge-strong), not a mix, so the
// structural pin expects one declared mix rather than two.
const PLATES = [
  { rule: ".msg.err", text: "danger", tint: "danger", bgPct: 12, borderPct: 30 },
  { rule: ".msg.info", text: "gold-bright", tint: "gold", bgPct: 10, borderPct: 25 },
  { rule: ".msg.ok", text: "ok", tint: "ok", bgPct: 12, borderPct: 40 },
  { rule: ".must-change-strip", text: "danger", tint: "danger", bgPct: 12, borderPct: 30 },
  // Firefox first-run route strip: gold wash, --edge border.
  { rule: ".host-grant-cta", text: "gold-text", tint: "gold", bgPct: 12, borderPct: null },
  { rule: ".update-banner", text: "gold-bright", tint: "gold", bgPct: 10, borderPct: 25 },
  // The quick-unlock offer card paints its body text with --ink, not the tint's own hue.
  { rule: ".qu-offer", text: "ink", tint: "gold", bgPct: 10, borderPct: 32 },
  // Live TOTP chip: gold wash, --edge-strong border. The FULL selector, because a bare
  // `.totp-chip` matches the one-line `.detail .totp-chip { align-self }` rule 9 lines earlier
  // and would silently read an empty mix list — a pin that passes for the wrong reason.
  { rule: ".item .totp-chip, .detail .totp-chip", text: "gold-bright", tint: "gold", bgPct: 8, borderPct: null },
] as const;
const WASH_KEEP = 0.8; // the plate must keep ≥80% of the bare surface's contrast

/** The `color-mix(in oklab, var(--tok) N%, transparent)` percentages declared in one rule.
 *  Two hits per plate rule: the background wash first, then the border. */
function plateMixes(rule: string): Array<{ tok: string; pct: number }> {
  const esc = rule.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const m = new RegExp(`${esc}\\s*\\{([^}]*)\\}`).exec(css);
  assert.ok(m, `${rule} rule not found`);
  return [...m![1]!.matchAll(/color-mix\(in oklab,\s*var\(--([a-z-]+)\)\s*(\d+)%,\s*transparent\)/g)]
    .map((x) => ({ tok: x[1]!, pct: Number(x[2]!) }));
}

for (const plate of PLATES) {
  // Structural: the H134 pin. Re-freezing either wash as an rgba() literal fails here even if the
  // dark composite happens to land in the same place — which is exactly how the drift shipped.
  test(`H134: ${plate.rule} mixes its plate from var(--${plate.tint}), not a frozen literal`, () => {
    const mixes = plateMixes(plate.rule);
    const expected: Array<{ tok: string; pct: number }> = [{ tok: plate.tint, pct: plate.bgPct }];
    if (plate.borderPct !== null) expected.push({ tok: plate.tint, pct: plate.borderPct });
    assert.deepEqual(mixes, expected,
      `${plate.rule} must declare ${expected.length === 2 ? "background then border" : "its background"} as color-mix of --${plate.tint}`);
  });

  for (const [theme, blk] of [["dark", dark], ["light", light]] as const) {
    const text = token(blk, plate.text);
    const tint = token(blk, plate.tint);
    // Both grounds a plate can land on: the popup body (--bg, where #msg and the strip live) and a
    // raised card (--bg-raised, the options page's .section).
    for (const surface of ["bg", "bg-raised"] as const) {
      const base = token(blk, surface);
      const composited = composite(tint, plate.bgPct / 100, base);
      const bare = ratio(text, base);
      const got = ratio(text, composited);
      test(`H134 ${theme}: ${plate.rule} on --${surface} keeps ≥${WASH_KEEP * 100}% of the bare ${bare.toFixed(2)}:1`, () => {
        assert.ok(got / bare >= WASH_KEEP, `${got.toFixed(2)} / ${bare.toFixed(2)} = ${((got / bare) * 100).toFixed(1)}%`);
        assert.ok(got >= UI_MIN, `--${plate.text} on the plate = ${got.toFixed(2)} (< ${UI_MIN})`);
        if (theme === "dark") assert.ok(got >= AA, `--${plate.text} on the plate = ${got.toFixed(2)} (< ${AA})`);
      });
    }
  }
}

test("CutA: dark --danger is still the Cut A lifted value (web lockstep)", () => {
  assert.equal(token(dark, "danger"), "#d97f6f", "dark --danger pinned to the lifted value (web lockstep)");
});

// --- Overlay (content-script) tokens: a THIRD independent copy of the palette (content-ui.ts's
// UI_CSS), which the popup.css gate above never touched. Its --anv-ink-faint had drifted to the
// pre-AA value while web+popup were bumped; gate it here so the injected overlay's faint/dim text
// can't silently regress below AA (UI-audit 2026-07). --anv-bg is the RAISED tone; --anv-bg-deep
// the ground — faint text renders on both, both must clear AA. ---
const overlay = readFileSync(fileURLToPath(new URL("./content-ui.ts", import.meta.url)), "utf-8");
const OV_LIGHT_AT = overlay.indexOf("@media (prefers-color-scheme: light)");
const overlayDark = overlay.slice(0, OV_LIGHT_AT >= 0 ? OV_LIGHT_AT : overlay.length);
const overlayLight = block(overlay, "@media (prefers-color-scheme: light)");
function anv(blk: string, name: string): string {
  const m = new RegExp(`--anv-${name}\\s*:\\s*(#[0-9a-fA-F]{3,6})`).exec(blk);
  assert.ok(m, `overlay token --anv-${name} not found`);
  return m[1];
}
for (const [theme, blk] of [
  ["dark", overlayDark],
  ["light", overlayLight],
] as const) {
  const faint = anv(blk, "ink-faint");
  const dim = anv(blk, "ink-dim");
  const bg = anv(blk, "bg"); // overlay --anv-bg is the RAISED surface tone
  const bgDeep = anv(blk, "bg-deep");

  test(`overlay 7a ${theme}: --anv-ink-faint ${faint} clears AA on --anv-bg and --anv-bg-deep`, () => {
    const onBg = ratio(faint, bg);
    const onDeep = ratio(faint, bgDeep);
    assert.ok(onBg >= AA, `--anv-ink-faint on --anv-bg = ${onBg.toFixed(2)} (< ${AA})`);
    assert.ok(onDeep >= AA, `--anv-ink-faint on --anv-bg-deep = ${onDeep.toFixed(2)} (< ${AA})`);
  });
  test(`overlay ${theme}: --anv-ink-dim ${dim} clears AA on --anv-bg`, () => {
    const r = ratio(dim, bg);
    assert.ok(r >= AA, `--anv-ink-dim on --anv-bg = ${r.toFixed(2)} (< ${AA})`);
  });

  // Cut A: the overlay's action rows (.row.action) render gold TEXT — must ride the
  // darkened gold-text token, and its danger follows the web lift in lockstep.
  test(`overlay CutA ${theme}: --anv-gold-text clears AA on --anv-bg and --anv-bg-deep`, () => {
    const gt = anv(blk, "gold-text");
    assert.ok(ratio(gt, bg) >= AA, `--anv-gold-text on --anv-bg = ${ratio(gt, bg).toFixed(2)}`);
    assert.ok(ratio(gt, bgDeep) >= AA, `--anv-gold-text on --anv-bg-deep = ${ratio(gt, bgDeep).toFixed(2)}`);
  });
}

test("overlay CutA: .row.action uses --anv-gold-text and dark --anv-danger is the lifted value", () => {
  assert.match(overlay, /\.row\.action\s*\{[^}]*var\(--anv-gold-text\)/, ".row.action must use --anv-gold-text");
  assert.equal(anv(overlayDark, "danger"), "#d97f6f", "dark --anv-danger pinned (web lockstep)");
});
