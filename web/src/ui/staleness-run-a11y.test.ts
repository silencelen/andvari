import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { runPositionSentence } from "./Staleness";

/**
 * H30 + H50 (audit 2026-09-13), pinned on the source the a11y-controls way — the run card is a
 * closure inside Staleness.tsx with no render seam in this node env.
 *
 * H30: the verification run advanced SILENTLY — the only sentence it ever fed a live region was
 * the finish, and focus stayed on the verdict button just pressed (or fell to <body> when the
 * start buttons unmounted), so a screen-reader user answered for logins they were never told
 * about. The fix is a dedicated persistent Announcer carrying name + position on every advance,
 * and a focus target on the run head that takes focus on start and on each advance.
 *
 * H50: the "Move to Deleted items" button carried className="danger", defined nowhere, and fell
 * through to the UA's grey system button beside a themed "Keep it".
 */
const src = readFileSync(fileURLToPath(new URL("./Staleness.tsx", import.meta.url)), "utf8");
const css = readFileSync(fileURLToPath(new URL("./styles.css", import.meta.url)), "utf8");

describe("runPositionSentence", () => {
  it("names the login AND its 1-based position out of the queue length", () => {
    expect(runPositionSentence("Netflix", 0, 12)).toBe("Now checking Netflix · 1 of 12");
    expect(runPositionSentence("Bank", 11, 12)).toBe("Now checking Bank · 12 of 12");
  });
});

describe("Staleness.tsx — the run announces and focuses every advance (H30)", () => {
  it("feeds a DEDICATED persistent Announcer with the run position, separate from the outcome region", () => {
    expect(src).toContain("const runNotice = current && currentRow && run ? runPositionSentence(currentRow.name, run.index, run.queue.length) : \"\";");
    expect(src).toContain("<Announcer text={runNotice} />");
    // Both regions are persistent siblings — the position never rides the outcome chain, where a
    // copy flash or the delete offer would mask it.
    expect(src.match(/<Announcer/g)?.length).toBe(2);
  });

  it("the run head is a focus target that takes focus on start and on every index change", () => {
    expect(src).toContain('<div className="run-head" ref={runHeadRef} tabIndex={-1}>');
    const eff = src.indexOf("useEffect(() => {\n    if (runKey !== null) runHeadRef.current?.focus();");
    expect(eff, "the focus effect moved or was dropped").toBeGreaterThan(-1);
    // Keyed on index + queue, so a single-item re-run of the same login still refocuses.
    expect(src).toContain("const runKey = run ? `${run.index}/${run.queue.join(\",\")}` : null;");
  });
});

describe("Staleness.tsx — the destructive confirm uses the house danger idiom (H50)", () => {
  it("'Move to Deleted items' is a ghost in the danger ink, like Vault's Confirm delete", () => {
    const start = src.indexOf("Move to Deleted items");
    const tag = src.slice(src.lastIndexOf("<button", start), start);
    expect(tag).toContain('className="ghost"');
    expect(tag).toContain('style={{ color: "var(--danger)" }}');
  });

  it("no view uses an undefined .danger button class", () => {
    expect(src).not.toContain('className="danger"');
    expect(css).not.toMatch(/\.danger\s*\{/); // the idiom is inline var(--danger) on a ghost; nothing to define
  });
});
