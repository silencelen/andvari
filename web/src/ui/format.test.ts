import { describe, expect, it } from "vitest";
import { inactivityNotice } from "./format";

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
