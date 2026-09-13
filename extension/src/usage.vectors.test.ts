// The extension's OWN run of spec/test-vectors/usageledger.json (node --test) — the same file core
// UsageLedgerVectorsTest and web usage.vectors.test.ts consume, so the three ledger twins
// (spec 02 §8.2) parse, merge, record, prune and serialize identically. usage.test.ts pins the
// rules from this side by hand; by the 2026-09-13 audit (H92) the Kotlin twin had drifted from this
// one while every hand-mirrored suite stayed green. Only a corpus all three read catches a drift
// all three consider correct.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { type UsageMap, mergeUsage, parseUsage, pruneUsage, recordUse, serializeUsage } from "./usage.ts";

const vectorsDir = fileURLToPath(new URL("../../spec/test-vectors/", import.meta.url));
const v = JSON.parse(readFileSync(vectorsDir + "usageledger.json", "utf-8")) as {
  parse: { name: string; inputUtf8: string; expected: UsageMap }[];
  merge: { name: string; a: UsageMap; b: UsageMap; expected: UsageMap }[];
  record: { name: string; map: UsageMap; itemId: string; now: number; expected: UsageMap }[];
  prune: { name: string; map: UsageMap; liveItemIds: string[]; expected: UsageMap }[];
  serialize: { name: string; map: UsageMap; expectedUtf8: string }[];
};

test("usageledger.json parse — case for case with core and web", () => {
  for (const c of v.parse) assert.deepEqual(parseUsage(c.inputUtf8), c.expected, `parse ${c.name}`);
  // The block must keep carrying the two drifts H92 found (a string-typed number that must NOT
  // parse; a nested field that costs one entry while the good one beside it survives).
  assert.ok(v.parse.some((c) => c.inputUtf8.includes('"lastUsedAt":"')));
  assert.ok(v.parse.some((c) => c.inputUtf8.includes('"lastUsedAt":{') && Object.keys(c.expected).length > 0));
});

test("usageledger.json merge / record / prune", () => {
  for (const c of v.merge) assert.deepEqual(mergeUsage(c.a, c.b), c.expected, `merge ${c.name}`);
  for (const c of v.record) assert.deepEqual(recordUse(c.map, c.itemId, c.now), c.expected, `record ${c.name}`);
  for (const c of v.prune) assert.deepEqual(pruneUsage(c.map, new Set(c.liveItemIds)), c.expected, `prune ${c.name}`);
});

test("usageledger.json serialize — byte for byte, the wire the other clients read", () => {
  for (const c of v.serialize) assert.equal(serializeUsage(c.map), c.expectedUtf8, `serialize ${c.name}`);
});
