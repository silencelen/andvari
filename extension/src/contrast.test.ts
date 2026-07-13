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
}
