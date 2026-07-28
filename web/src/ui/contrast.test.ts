import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * a11yweb-03 (P6): contrast is the one a11y property that is fully computable, so it is
 * pinned as a unit test rather than left to a screen-reader smoke. This parses the REAL
 * styles.css `:root` (dark) and `@media (prefers-color-scheme: light) :root` token maps
 * and asserts the WCAG relative-luminance ratio of each CHANGED token against BOTH card
 * surfaces (--bg and --bg-raised) clears AA body text (4.5:1). A regression of --ink-faint
 * or --link back toward the old faint values trips here.
 *
 * Parity note: the extension ships an independent copy of this helper against popup.css
 * (the two token files are kept in lockstep by convention, not by import).
 */
const css = readFileSync(fileURLToPath(new URL("./styles.css", import.meta.url)), "utf8");

/** Token map for the `:root { … }` block beginning at/after `from`. */
function tokenBlock(from: number): Record<string, string> {
  const open = css.indexOf("{", from);
  const close = css.indexOf("}", open);
  const body = css.slice(open + 1, close);
  const map: Record<string, string> = {};
  for (const m of body.matchAll(/(--[\w-]+):\s*(#[0-9a-fA-F]{3,8})\s*;/g)) map[m[1]!] = m[2]!;
  return map;
}

const dark = tokenBlock(css.indexOf(":root"));
const lightMedia = css.indexOf("prefers-color-scheme: light");
const light = tokenBlock(css.indexOf(":root", lightMedia));

function relLuminance(hex: string): number {
  let h = hex.replace("#", "");
  if (h.length === 3) h = h.split("").map((c) => c + c).join("");
  const chan = [0, 2, 4].map((i) => {
    const c = parseInt(h.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * chan[0]! + 0.7152 * chan[1]! + 0.0722 * chan[2]!;
}

function ratio(a: string, b: string): number {
  const la = relLuminance(a);
  const lb = relLuminance(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

const AA = 4.5;

describe("contrast tokens (parsed from styles.css) meet WCAG AA on both surfaces", () => {
  it("resolved the token blocks from the real stylesheet", () => {
    for (const map of [dark, light]) {
      for (const t of ["--bg", "--bg-raised", "--ink-faint", "--ink-dim", "--link"]) expect(map[t], t).toMatch(/^#[0-9a-fA-F]{3,8}$/);
    }
  });

  for (const [theme, map] of [["dark", dark], ["light", light]] as const) {
    // a11y-webext--3 added --ink-dim: the "pending sync" tag paints with it (it used to use a
    // hardcoded #8a7a5c behind an undeclared token, below AA in BOTH themes), so it now has to
    // clear the same floor as the other body-text tones.
    for (const token of ["--ink-faint", "--ink-dim", "--link"] as const) {
      it(`${theme} ${token} ≥ ${AA}:1 on --bg`, () => {
        expect(ratio(map[token]!, map["--bg"]!)).toBeGreaterThanOrEqual(AA);
      });
      it(`${theme} ${token} ≥ ${AA}:1 on --bg-raised`, () => {
        expect(ratio(map[token]!, map["--bg-raised"]!)).toBeGreaterThanOrEqual(AA);
      });
    }
  }

  it("pins the reviewed hex values (guards against a silent 'improvement' back below AA)", () => {
    expect(dark["--ink-faint"]).toBe("#8d8370");
    expect(light["--ink-faint"]).toBe("#786c50");
    expect(dark["--link"]).toBe("#d0a94a");
    expect(light["--link"]).toBe("#7d5e14");
  });
});

/**
 * UI-audit Cut A: the audit found whole token CLASSES the block above never covered —
 * focus indicators (light was ~2.1:1, invisible), gold-as-text, danger on its own tinted
 * plates, and the button-gradient ink. Each is now computed from the real stylesheet so
 * none of these classes can silently regress again.
 */
describe("Cut A tokens (focus / gold-text / danger-on-plate / button gradient)", () => {
  const UI_MIN = 3; // WCAG 1.4.11 non-text minimum (focus indicators)

  for (const [theme, map] of [["dark", dark], ["light", light]] as const) {
    it(`${theme} --focus ≥ ${UI_MIN}:1 on --bg, --bg-raised and --bg-input`, () => {
      for (const bg of ["--bg", "--bg-raised", "--bg-input"] as const) {
        expect(ratio(map["--focus"]!, map[bg]!), `--focus on ${bg}`).toBeGreaterThanOrEqual(UI_MIN);
      }
    });

    it(`${theme} --gold-text ≥ ${AA}:1 on --bg and --bg-raised`, () => {
      expect(ratio(map["--gold-text"]!, map["--bg"]!)).toBeGreaterThanOrEqual(AA);
      expect(ratio(map["--gold-text"]!, map["--bg-raised"]!)).toBeGreaterThanOrEqual(AA);
    });

    it(`${theme} --btn-ink ≥ ${AA}:1 on BOTH button-gradient stops`, () => {
      expect(ratio(map["--btn-ink"]!, map["--gold-hi"]!), "on --gold-hi").toBeGreaterThanOrEqual(AA);
      expect(ratio(map["--btn-ink"]!, map["--gold-lo"]!), "on --gold-lo").toBeGreaterThanOrEqual(AA);
    });

    it(`${theme} button gradient is lit from above (--gold-hi lighter than --gold-lo)`, () => {
      // The pre-fix light gradient had the DARKER stop on top — an inverted sheen vs dark.
      expect(relLuminance(map["--gold-hi"]!)).toBeGreaterThan(relLuminance(map["--gold-lo"]!));
    });
  }

  it("dark --danger ≥ 4.5:1 on the composited .msg.err plate", () => {
    // The plate is a HARDCODED literal in styles.css (rgba(207,107,90,0.12) over --bg-raised)
    // — it does not track --danger, so composite exactly what the rule ships.
    // Non-greedy scan: the FIRST rgba in the rule is the background plate (0.12); the
    // greedy form skips ahead and captures the border's 0.3.
    const m = /\.msg\.err\s*\{[^}]*?rgba\((\d+),\s*(\d+),\s*(\d+),\s*(0?\.\d+)\)/.exec(css);
    expect(m, ".msg.err plate rgba literal").toBeTruthy();
    const [r, g, b, a] = [Number(m![1]), Number(m![2]), Number(m![3]), Number(m![4])];
    const base = dark["--bg-raised"]!.replace("#", "");
    const bc = [0, 2, 4].map((i) => parseInt(base.slice(i, i + 2), 16));
    const plate = "#" + bc.map((c, i) => Math.round([r, g, b][i]! * a + c * (1 - a)).toString(16).padStart(2, "0")).join("");
    expect(ratio(dark["--danger"]!, plate)).toBeGreaterThanOrEqual(AA);
  });

  it("pins the Cut A hex values", () => {
    expect(dark["--danger"]).toBe("#d97f6f");
    expect(dark["--focus"]).toBe("#d0a94a");
    expect(light["--focus"]).toBe("#7d5e14");
    expect(light["--gold-hi"]).toBe("#8f6b16");
    expect(light["--gold-lo"]).toBe("#7d5e14");
  });

  it("focus rules reference var(--focus), not the old --gold-deep", () => {
    const inputFocus = /input:focus[^{]*\{[^}]*border-color:\s*var\(--([\w-]+)\)/.exec(css);
    expect(inputFocus?.[1]).toBe("focus");
    // a11y-webext--2: the row's focus style moved to :focus-within (the focusable thing is
    // now the in-cell button) — the token it paints with must not drift.
    const rowlink = /rowlink:focus-within\s*\{[^}]*outline:\s*2px solid var\(--([\w-]+)\)/.exec(css);
    expect(rowlink?.[1]).toBe("focus");
    // The global button/link focus ring must exist (buttons had NO indicator before Cut A).
    expect(css).toMatch(/button:focus-visible[^{]*\{[^}]*outline:\s*2px solid var\(--focus\)/);
  });
});

/**
 * a11y-webext--3 (polish audit 2026-07-27): the two describes above compute contrast from the
 * TOKENS — which made them structurally blind to the one place colour actually regressed: an
 * inline `style={{ color: "var(--muted-strong, #8a7a5c)" }}` in Vault.tsx naming a token declared
 * nowhere, so the hardcoded fallback shipped in BOTH themes at ~4:1 (Sharing.tsx had the same
 * shape with `--line`/#333). A fallback is only reachable when the token is missing, so the rule
 * that closes the hole is simply: every custom property an inline style references must exist in
 * styles.css. Then the ratio tests above actually cover it.
 */
describe("inline styles reference declared tokens only (no fallback literals)", () => {
  const declared = new Set([...css.matchAll(/(--[\w-]+)\s*:/g)].map((m) => m[1]!));
  const sources = readdirSync(fileURLToPath(new URL(".", import.meta.url)))
    .filter((f) => (f.endsWith(".tsx") || f.endsWith(".ts")) && !f.includes(".test."));

  it("resolved the stylesheet's declarations and the UI sources", () => {
    expect(declared.has("--ink-faint")).toBe(true);
    expect(sources).toContain("Vault.tsx");
    expect(sources).toContain("Sharing.tsx");
  });

  for (const file of sources) {
    it(`${file} names no undeclared custom property`, () => {
      const src = readFileSync(fileURLToPath(new URL(`./${file}`, import.meta.url)), "utf8");
      // Only real style values: `var(--x)` / `var(--x, fallback)` inside a quoted string.
      for (const m of src.matchAll(/["'`][^"'`]*var\((--[\w-]+)/g)) {
        expect(declared.has(m[1]!), `${file} uses ${m[1]} — declare it in styles.css or use an existing token`).toBe(true);
      }
    });
  }
});
