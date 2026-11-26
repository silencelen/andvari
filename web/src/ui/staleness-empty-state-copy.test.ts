import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * H123 (audit 2026-09-13): the G31 all-snoozed staleness empty state was written TWICE, in the
 * same remediation, with different sentences on web and on Android, although the Android change
 * cited "web's twin" as its source. A parity pin for UI copy was the structural answer, and this
 * file was that pin: it read the phone's sentence out of Android's HealthScreen.kt and required
 * web to say exactly that.
 *
 * The Android half is retired for now. The old Android health screen was deleted when the app
 * moved to the new design's screens, and those screens show visible placeholders until the
 * product's wording is approved. When the approved wording lands on Android, bring the Android
 * half back against the new screen (or better, against one shared sentence both clients read),
 * so a one-sided reword breaks here first again.
 *
 * Until then this pins web's side: the sentence both clients agreed on, stated once, naming the
 * control the reader must use. Text pins, not renders: the empty state is a branch inside a
 * closure and this suite has no DOM harness.
 */

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const stalenessTsx = readFileSync(here("./Staleness.tsx"), "utf8");

/** The sentence web and the phone agreed on (H123); the phone's wording was the source of truth. */
const AGREED = "Every login is snoozed right now — Show snoozed to see them or bring one back early.";

describe("H123 — the all-snoozed staleness empty state is ONE sentence", () => {
  it("web says the agreed sentence", () => {
    expect(stalenessTsx).toContain(`<p>${AGREED}</p>`);
  });

  it("the sentence names the control it asks the reader to use, and that control is really there", () => {
    expect(AGREED).toContain("Show snoozed");
    // Web's toggle label, in the same branch: a rename must break this pair.
    expect(stalenessTsx.match(/Show snoozed/g)!.length).toBeGreaterThan(1);
  });

  it("web's pre-fix wording is gone — no second sentence for the same state", () => {
    expect(stalenessTsx).not.toContain("Every login here is snoozed");
    expect(stalenessTsx.match(/Every login is snoozed/g), "stated once").toHaveLength(1);
  });

  it("the OTHER staleness empty state (no logins at all) keeps its sentence", () => {
    expect(stalenessTsx).toContain("No logins to rank yet — staleness needs saved logins.");
  });
});
