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
