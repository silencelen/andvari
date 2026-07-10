/**
 * F56 (perf addendum 2026-07-09): pure windowing math for the vault-list
 * virtualizer. Rows sit on one fixed stride (pinned row height + list gap), so
 * the rendered slice is arithmetic — no per-row measurement, no dependency.
 */

export interface WindowRange {
  /** first rendered row (inclusive) */
  start: number;
  /** one past the last rendered row (slice-friendly) */
  end: number;
}

/**
 * The rows intersecting [scrollTop, scrollTop + viewport), widened by `overscan`
 * on each side and clamped to [0, count]. Over-inclusive at fractional offsets on
 * purpose — a partially visible row must render. Degenerate inputs (empty list,
 * non-positive stride) collapse to the empty range; a scrollTop past the end
 * (a filter just shrank the list under a deep scroll) clamps to {count, count}
 * until the browser corrects the scroll position.
 */
export function windowRange(scrollTop: number, viewport: number, stride: number, overscan: number, count: number): WindowRange {
  if (count <= 0 || stride <= 0) return { start: 0, end: 0 };
  const top = Math.max(0, scrollTop);
  const first = Math.floor(top / stride);
  const last = Math.ceil((top + Math.max(0, viewport)) / stride);
  return {
    start: Math.min(Math.max(0, first - overscan), count),
    end: Math.min(count, last + overscan),
  };
}
