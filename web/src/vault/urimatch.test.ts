import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { pslResolve, PSL_SNAPSHOT_HASH } from "./psl";
import { PSL_RULES_JOINED } from "./pslData";
import { classify, matches, parseSavedUri, RESOLVE_UNKNOWN, type FieldKind } from "./urimatch";

// Consumes the SAME spec/test-vectors/urimatch.json the Kotlin UriMatchVectorTest checks.
const vectorsDir = fileURLToPath(new URL("../../../spec/test-vectors/", import.meta.url));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const v: any = JSON.parse(readFileSync(vectorsDir + "urimatch.json", "utf-8"));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const v2: any = JSON.parse(readFileSync(vectorsDir + "urimatch-etld1.json", "utf-8"));

describe("urimatch.json — matching (byte-frozen originals)", () => {
  it("matches per the label-boundary rule — with the REAL resolver (frozen outcomes must hold under eTLD+1)", () => {
    for (const c of v.match) {
      const saved = parseSavedUri(c.savedUri);
      const actual = saved !== null && matches(saved, { webHost: c.webHost ?? null, packageName: c.packageName }, pslResolve);
      expect(actual, `${c.savedUri} @ ${c.webHost}/${c.packageName}`).toBe(c.expected);
    }
  });

  it("matches per the label-boundary rule — with RESOLVE_UNKNOWN (pre-amendment semantics preserved)", () => {
    for (const c of v.match) {
      const saved = parseSavedUri(c.savedUri);
      const actual = saved !== null && matches(saved, { webHost: c.webHost ?? null, packageName: c.packageName }, RESOLVE_UNKNOWN);
      expect(actual, `${c.savedUri} @ ${c.webHost}/${c.packageName}`).toBe(c.expected);
    }
  });
});

describe("urimatch-etld1.json — eTLD+1 / PSL (design 2026-07-10 A1-A12)", () => {
  it("A6: the snapshot hash matches the RUNTIME rule string (not constant-vs-constant)", () => {
    expect(PSL_SNAPSHOT_HASH).toBe(v2.snapshotHash);
    const runtime = createHash("sha256").update(PSL_RULES_JOINED, "ascii").digest("hex");
    expect(runtime, "sha256 of the loaded joined rule string").toBe(v2.snapshotHash);
  });

  it("resolves registrable/public-suffix/unknown per the shared vectors", () => {
    for (const c of v2.registrable) {
      const r = pslResolve(c.host);
      expect(r.kind, `resolve(${c.host}).kind`).toBe(c.kind);
      if (c.kind === "registrable") {
        expect(r.kind === "registrable" && r.domain, `resolve(${c.host}).domain`).toBe(c.domain);
      }
    }
  });

  it("matches per the amended rules (R-SUFFIX-BARE, R-EQ, R-OLD)", () => {
    for (const c of v2.match) {
      const saved = parseSavedUri(c.savedUri);
      const actual = saved !== null && matches(saved, { webHost: c.webHost ?? null, packageName: c.packageName }, pslResolve);
      expect(actual, `${c.savedUri} @ ${c.webHost}`).toBe(c.expected);
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
