import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { type UsageMap, mergeUsage, parseUsage, pruneUsage, recordUse, serializeUsage } from "./usage";

/**
 * Consumes spec/test-vectors/usageledger.json — the SAME file core UsageLedgerVectorsTest and the
 * extension's usage.vectors.test.ts run — so the three ledger twins (spec 02 §8.2) parse, merge,
 * record, prune and serialize identically.
 *
 * Why a shared file when usage.test.ts already pins these rules: the three suites were
 * hand-mirrored, and by the 2026-09-13 audit (H92) the Kotlin parse had drifted from this one
 * while every suite stayed green — string-typed numbers accepted, one malformed nested field
 * emptying the WHOLE ledger instead of one entry. Combined with a flush that re-merges against
 * what it parsed, "read as empty" on one client is "overwrite the household's ledger with this
 * session's few entries". Only a corpus all three read catches a drift all three consider correct.
 */
const vectorsDir = fileURLToPath(new URL("../../../spec/test-vectors/", import.meta.url));
const v = JSON.parse(readFileSync(`${vectorsDir}usageledger.json`, "utf8")) as {
  parse: { name: string; inputUtf8: string; expected: UsageMap }[];
  merge: { name: string; a: UsageMap; b: UsageMap; expected: UsageMap }[];
  record: { name: string; map: UsageMap; itemId: string; now: number; expected: UsageMap }[];
  prune: { name: string; map: UsageMap; liveItemIds: string[]; expected: UsageMap }[];
  serialize: { name: string; map: UsageMap; expectedUtf8: string }[];
};

describe("usage ledger — the shared cross-implementation corpus (H92)", () => {
  it("parse matches core and the extension, case for case", () => {
    for (const c of v.parse) expect(parseUsage(c.inputUtf8), `parse ${c.name}`).toEqual(c.expected);
  });

  // The parse block must keep carrying the two drifts H92 found, or the loop above grades the
  // easy cases only: a string-typed number that must NOT parse, and a nested field that must cost
  // one entry while the good entry beside it survives.
  it("still covers the two drifts it was added for", () => {
    expect(v.parse.some((c) => c.inputUtf8.includes('"lastUsedAt":"'))).toBe(true);
    expect(v.parse.some((c) => c.inputUtf8.includes('"lastUsedAt":{') && Object.keys(c.expected).length > 0)).toBe(true);
  });

  it("merge matches", () => {
    for (const c of v.merge) expect(mergeUsage(c.a, c.b), `merge ${c.name}`).toEqual(c.expected);
  });

  it("record matches", () => {
    for (const c of v.record) expect(recordUse(c.map, c.itemId, c.now), `record ${c.name}`).toEqual(c.expected);
  });

  it("prune matches", () => {
    for (const c of v.prune) expect(pruneUsage(c.map, new Set(c.liveItemIds)), `prune ${c.name}`).toEqual(c.expected);
  });

  // Byte-exact: this is the wire the other two clients read.
  it("serialize matches byte for byte", () => {
    for (const c of v.serialize) expect(serializeUsage(c.map), `serialize ${c.name}`).toBe(c.expectedUtf8);
  });
});
