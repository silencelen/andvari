import { describe, expect, it } from "vitest";
import { ago, fmtDay, fmtDayYear, inactivityNotice } from "./format";

describe("inactivityNotice (F26 unlock-card reason line)", () => {
  it("formats whole minutes with singular/plural", () => {
    expect(inactivityNotice(60)).toBe("Locked after 1 minute of inactivity.");
    expect(inactivityNotice(300)).toBe("Locked after 5 minutes of inactivity.");
    expect(inactivityNotice(900)).toBe("Locked after 15 minutes of inactivity.");
  });

  it("formats sub-minute windows in seconds", () => {
    expect(inactivityNotice(30)).toBe("Locked after 30 seconds of inactivity.");
    expect(inactivityNotice(1)).toBe("Locked after 1 second of inactivity.");
  });
});

/**
 * H131 (audit 2026-09-13): date and relative-time formatting had grown three helpers and one
 * inline `toLocaleDateString`, and two of the results were wrong rather than merely inconsistent —
 * `ago()` said "1 years ago" for anything 720–729 days old, and version history printed a bare
 * "July 14" for a save that can be years old. `ago` moved here from Staleness.tsx so the Health
 * tabs share one vocabulary and so both are pinned in the formatting home.
 */
describe("ago (relative day-resolution time)", () => {
  const DAY = 86_400_000;
  const now = Date.UTC(2026, 8, 13, 12, 0, 0);
  const daysAgo = (d: number) => now - d * DAY;

  it("the near buckets read as English, and an unknown time is the honest em dash", () => {
    expect(ago(undefined, now)).toBe("—");
    expect(ago(now, now)).toBe("today");
    expect(ago(daysAgo(1), now)).toBe("yesterday");
    expect(ago(daysAgo(2), now)).toBe("2 days ago");
    expect(ago(daysAgo(59), now)).toBe("59 days ago");
    expect(ago(daysAgo(60), now)).toBe("2 months ago");
  });

  it("the year branch is SINGULAR at one year — the '1 years ago' the audit found", () => {
    // 720 days: months (720/30) is exactly 24, which leaves the month branch, and 720/365 floors
    // to 1. This is the whole window the bug lived in, so pin both of its edges.
    expect(ago(daysAgo(719), now)).toBe("23 months ago");
    expect(ago(daysAgo(720), now)).toBe("1 year ago");
    expect(ago(daysAgo(729), now)).toBe("1 year ago");
    expect(ago(daysAgo(730), now)).toBe("2 years ago");
  });

  it("a future timestamp (a skewed peer's clock) reads as today, never as a negative age", () => {
    expect(ago(now + 5 * DAY, now)).toBe("today");
  });
});

describe("fmtDayYear (H131 — a date that can be arbitrarily old carries its year)", () => {
  const now = Date.UTC(2026, 8, 13);
  it("a date in the current year is the plain house day form", () => {
    const sameYear = Date.UTC(2026, 6, 14, 12);
    expect(fmtDayYear(sameYear, now)).toBe(fmtDay(sameYear));
    expect(fmtDayYear(sameYear, now)).not.toContain("2026");
  });

  it("an earlier year says so — the version-history case that read as 'this July'", () => {
    const lastYear = Date.UTC(2025, 6, 14, 12);
    expect(fmtDayYear(lastYear, now)).toContain("2025");
  });

  it("an absent time keeps fmtDay's 'soon' — the callers' shared placeholder", () => {
    expect(fmtDayYear(undefined, now)).toBe("soon");
    expect(fmtDayYear(0, now)).toBe("soon");
  });
});
