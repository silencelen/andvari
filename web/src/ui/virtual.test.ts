import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { windowRange } from "./virtual";

// Geometry mirrors the vault list: 72px rows on an 8px gap → 80px stride.
const STRIDE = 80;

describe("windowRange", () => {
  it("at the top: starts at 0 and covers the viewport plus trailing overscan", () => {
    // ceil(800/80) = 10 visible rows, +3 overscan below.
    expect(windowRange(0, 800, STRIDE, 3, 1000)).toEqual({ start: 0, end: 13 });
  });

  it("clamps leading overscan at the top instead of going negative", () => {
    // first visible row = 1; 1 - 3 overscan clamps to 0.
    expect(windowRange(80, 800, STRIDE, 3, 1000)).toEqual({ start: 0, end: 14 });
  });

  it("mid-list: overscan widens both sides symmetrically", () => {
    // rows 100..110 visible; ±3 overscan.
    expect(windowRange(8000, 800, STRIDE, 3, 1000)).toEqual({ start: 97, end: 113 });
  });

  it("at the bottom: end clamps to count", () => {
    // scrolled to the very end of 1000 rows: last visible = 1000, +3 overscan clamps.
    expect(windowRange(1000 * STRIDE - 800, 800, STRIDE, 3, 1000)).toEqual({ start: 987, end: 1000 });
  });

  it("count smaller than one viewport renders everything", () => {
    expect(windowRange(0, 800, STRIDE, 3, 5)).toEqual({ start: 0, end: 5 });
  });

  it("includes rows only partially inside the viewport", () => {
    // viewport 100px cuts into row 1 → rows 0..1 render (end exclusive = 2).
    expect(windowRange(0, 100, STRIDE, 0, 10)).toEqual({ start: 0, end: 2 });
    // scrollTop 79 still shows row 0's tail; 81 is fully past row 0's stride.
    expect(windowRange(79, 100, STRIDE, 0, 10).start).toBe(0);
    expect(windowRange(81, 100, STRIDE, 0, 10).start).toBe(1);
  });

  it("empty list and non-positive stride collapse to the empty range", () => {
    expect(windowRange(0, 800, STRIDE, 3, 0)).toEqual({ start: 0, end: 0 });
    expect(windowRange(0, 800, 0, 3, 10)).toEqual({ start: 0, end: 0 });
  });

  it("treats a negative scrollTop (list header still below the fold) as 0", () => {
    expect(windowRange(-500, 800, STRIDE, 3, 1000)).toEqual(windowRange(0, 800, STRIDE, 3, 1000));
  });

  it("a scrollTop past the end (filter shrank the list) yields an empty in-bounds range", () => {
    const r = windowRange(79200, 800, STRIDE, 3, 10);
    expect(r.start).toBe(10);
    expect(r.end).toBe(10);
  });
});

/**
 * Audit F16: the 72px row height was pinned for BOTH render paths, because the windowed one needs
 * one fixed stride. Measured at 16px default fonts a row needs 68.75px of content (2px border +
 * 26px padding + a 24px `.name` + an 18.75px `.sub`) inside a 72px border-box — 1.25px of slack.
 * Raise the browser's default or MINIMUM font size to 18px (a standard low-vision setting in both
 * Chrome and Firefox) and both lines become 27px: 54px of content in a 44px content box, which
 * `overflow: hidden` clips — taking `.sub`, the row's ONLY distinguishing text (username or
 * website), i.e. exactly the disambiguation a password-manager list exists for. Full-page zoom
 * scales the px height and is unaffected; this is text-only scaling (WCAG 1.4.4 / 1.4.12).
 * So the fixed stride is scoped to the path that requires it and the plain ≤500-row branch —
 * which is most households — sizes to content.
 */
describe("F16 — the fixed row stride is scoped to the windowed path", () => {
  const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
  const css = readFileSync(here("./styles.css"), "utf8");
  const vaultTsx = readFileSync(here("./Vault.tsx"), "utf8");

  it("only the virtual list pins a height; the plain list uses min-height so text can grow", () => {
    expect(css).toContain(".vault-list--virtual .item { height: 72px; overflow: hidden; }");
    expect(css).toContain(".vault-list .item { min-height: 72px; }");
    expect(css, "the unscoped fixed height is the defect").not.toContain(".vault-list .item { height: 72px");
  });

  it("VirtualList is the only renderer that puts the class on, and ROW_H still matches it", () => {
    expect(vaultTsx).toContain('className="list vault-list vault-list--virtual"');
    // The plain branch keeps the plain class only.
    expect(vaultTsx).toContain('<div className="list vault-list">{filtered.map(renderRow)}</div>');
    expect(vaultTsx).toContain("const ROW_H = 72;");
    const rowH = Number(vaultTsx.match(/const ROW_H = (\d+);/)![1]);
    const cssH = Number(css.match(/\.vault-list--virtual \.item \{ height: (\d+)px/)![1]);
    expect(cssH, "the stride and the CSS height must move together (F56)").toBe(rowH);
  });
});
