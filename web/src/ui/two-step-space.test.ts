import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * The two-step card's line under the setup link and code is two sentences: the clipboard line ({@link TWO_STEP_SECRET_CLEARS})
 * and "The values stay on this screen until you finish." JSX drops a line break between an expression and the text after
 * it, so they ran together as "…after 30 seconds.The values stay…". They are now on one line, a space between them.
 */
describe("the two-step card's setup line", () => {
  it("keeps a space between the clipboard sentence and the next one", () => {
    const settings = readFileSync(fileURLToPath(new URL("./Settings.tsx", import.meta.url)), "utf8");
    const at = settings.indexOf("{fill(TWO_STEP_SECRET_CLEARS, String(clipClear))}");
    expect(at).toBeGreaterThan(0);
    const after = settings.slice(at + "{fill(TWO_STEP_SECRET_CLEARS, String(clipClear))}".length, settings.indexOf("</p>", at));
    // What follows the expression on its own line is a JSX text whose leading space survives: " The values stay…".
    expect(after.startsWith(" The values stay on this screen until you finish.")).toBe(true);
  });
});
