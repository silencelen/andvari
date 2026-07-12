import { readFileSync } from "node:fs";
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
      for (const t of ["--bg", "--bg-raised", "--ink-faint", "--link"]) expect(map[t], t).toMatch(/^#[0-9a-fA-F]{3,8}$/);
    }
  });

  for (const [theme, map] of [["dark", dark], ["light", light]] as const) {
    for (const token of ["--ink-faint", "--link"] as const) {
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
