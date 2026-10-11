import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { shortFormMatches } from "./escrow";
import { groupedShort, matchesShort, shortForm } from "./fingerprint";

/**
 * The 128-bit human short-form fingerprint matcher + display grouping (security review 2026-10, §7),
 * graded off the SAME spec/test-vectors/fingerprint.json the Kotlin engine consumes
 * (core/src/jvmTest/.../crypto/FingerprintTest.kt). Keep the two in lockstep.
 */
const vectorsDir = fileURLToPath(new URL("../../../spec/test-vectors/", import.meta.url));
const v = JSON.parse(readFileSync(vectorsDir + "fingerprint.json", "utf-8"));

describe("fingerprint.json — 128-bit short form", () => {
  it("shortForm + groupedShort match the vector", () => {
    expect(shortForm(v.full)).toBe(v.shortForm);
    expect(shortForm(v.full).length).toBe(32);
    expect(groupedShort(v.full)).toBe(v.groupedShort);
  });

  it("matchesShort grades every vector row (and Escrow.shortFormMatches is the same helper)", () => {
    for (const c of v.match) {
      expect(matchesShort(c.entry, v.full), `matchesShort(${JSON.stringify(c.entry)}): ${c.why}`).toBe(c.ok);
      expect(shortFormMatches(c.entry, v.full), `shortFormMatches parity: ${c.why}`).toBe(c.ok);
    }
  });

  it("machine values compare full-length; a short (prefix) match is human-only", () => {
    const m = v.machineFullCompare;
    // A human-typed prefix matches the 32-hex short form…
    expect(matchesShort(m.short, m.full)).toBe(m.shortMatchesHuman);
    // …but a machine compare is full 64 hex: the full value equals itself, the truncation does not.
    expect(m.full === m.full).toBe(m.fullEqualsFull);
    expect(m.short === m.full).toBe(m.shortEqualsFull);
    expect(m.short === m.full, "a 32-hex short form must NOT pass a full-length machine compare").toBe(false);
  });
});
