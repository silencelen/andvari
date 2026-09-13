import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * H123 (audit 2026-09-13): the G31 all-snoozed staleness empty state was written TWICE, in the
 * same remediation, with different sentences — web's "Every login here is snoozed — show them to
 * unsnooze one early." against Android's "Every login is snoozed right now — Show snoozed to see
 * them or bring one back early." — although the Android change cited "web's twin" as its source.
 * Two lanes fixing one finding from the feature description rather than from one pinned string is
 * precisely the drift the 2026-08-30 report named ("the Kotlin twin was written from the feature
 * description rather than the pinned web behavior"), and a behaviour-parity pin for UI copy was
 * the structural answer it proposed. This is that pin.
 *
 * The phone's sentence is the one both clients now say: it names the control the reader must
 * operate ("Show snoozed" — the literal label on the toggle directly below the sentence on both
 * clients) rather than the vaguer "show them", and it says "right now", which is true of a state
 * that expires on its own.
 *
 * Text pins, not renders: the empty state is a branch inside a closure on both clients, and this
 * suite has no DOM harness (nor a JVM). Reading both sources is the enroll-errors/token-lockstep
 * idiom — a one-sided reword breaks here first, deliberately.
 */

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const stalenessTsx = readFileSync(here("./Staleness.tsx"), "utf8");
const healthScreenKt = readFileSync(
  here("../../../app-android/src/main/kotlin/io/silencelen/andvari/app/HealthScreen.kt"),
  "utf8",
);

/** The sentence inside Android's all-snoozed `Empty(...)` — the twin, and the source of truth. */
const androidSentence = (): string => {
  const m = healthScreenKt.match(/Empty\("(Every login[^"]*)"\)/);
  expect(m, "HealthScreen's all-snoozed Empty moved — update the pin").not.toBeNull();
  return m![1]!;
};

describe("H123 — the all-snoozed staleness empty state is ONE sentence on web and Android", () => {
  it("web says exactly what the phone says", () => {
    expect(stalenessTsx).toContain(`<p>${androidSentence()}</p>`);
  });

  it("the sentence names the control it asks the reader to use, and that control is really there", () => {
    const s = androidSentence();
    expect(s).toContain("Show snoozed");
    // Web's toggle label, in the same branch — a rename on either side must break this pair.
    expect(stalenessTsx).toContain("Show snoozed");
    expect(healthScreenKt).toContain('"Show snoozed"');
  });

  it("web's pre-fix wording is gone — no second sentence for the same state", () => {
    expect(stalenessTsx).not.toContain("Every login here is snoozed");
    expect(stalenessTsx.match(/Every login is snoozed/g), "stated once").toHaveLength(1);
  });

  it("the OTHER staleness empty state (no logins at all) was already byte-equal — keep it that way", () => {
    const both = "No logins to rank yet — staleness needs saved logins.";
    expect(stalenessTsx).toContain(both);
    expect(healthScreenKt).toContain(both);
  });
});
