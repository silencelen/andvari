import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { classify, matches, parseSavedUri, type FieldKind } from "./urimatch";

// Consumes the SAME spec/test-vectors/urimatch.json the Kotlin UriMatchVectorTest checks.
const vectorsDir = fileURLToPath(new URL("../../../spec/test-vectors/", import.meta.url));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const v: any = JSON.parse(readFileSync(vectorsDir + "urimatch.json", "utf-8"));

describe("urimatch.json — matching", () => {
  it("matches per the label-boundary rule", () => {
    for (const c of v.match) {
      const saved = parseSavedUri(c.savedUri);
      const actual = saved !== null && matches(saved, { webHost: c.webHost ?? null, packageName: c.packageName });
      expect(actual, `${c.savedUri} @ ${c.webHost}/${c.packageName}`).toBe(c.expected);
    }
  });
});

describe("urimatch.json — classification", () => {
  it("classifies fields per priority", () => {
    for (const c of v.classify) {
      const actual: FieldKind = classify({
        hints: c.hints,
        inputTypeClass: c.inputTypeClass,
        inputTypeVariation: c.inputTypeVariation,
        htmlType: c.htmlType ?? null,
        htmlNameOrId: c.htmlNameOrId ?? null,
      });
      expect(actual, JSON.stringify(c)).toBe(c.expected);
    }
  });
});
