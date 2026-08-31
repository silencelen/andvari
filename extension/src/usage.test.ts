import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import { adUsage, fromB64, toB64, usageKey } from "./crypto.ts";
import { mergeUsage, parseUsage, pruneUsage, recordUse, serializeUsage, type UsageMap } from "./usage.ts";

/**
 * Usage ledger (spec 02 §8.2) — the extension's twin of web/src/vault/usage.test.ts.
 *
 * These are convergence pins, not style pins. The two clients write the SAME server-side blob, so
 * if their merge rules ever diverge they stop converging and start clobbering each other's
 * entries — a bug that would show up as "my phone's usage keeps disappearing" long after the
 * change that caused it.
 */

const T = 1_755_000_000_000;
const vectorsDir = fileURLToPath(new URL("../../spec/test-vectors/", import.meta.url));
const v = JSON.parse(readFileSync(vectorsDir + "usagekey.json", "utf-8")) as {
  vkB64: string;
  usageKeyB64: string;
  adUtf8: string;
  adUserId: string;
};

describe("usage crypto twins (spec 02 §2/§8.2)", () => {
  // Checked against a vector computed by an INDEPENDENT third implementation, so this pins "the
  // extension is correct" rather than "the extension agrees with web" — which two mirrored-but-
  // equally-wrong impls would also satisfy.
  it("derives the vector's usageKey from the vector's VK", () => {
    assert.equal(toB64(usageKey(fromB64(v.vkB64))), v.usageKeyB64);
  });

  it("builds the vector's AD", () => {
    assert.equal(new TextDecoder().decode(adUsage(v.adUserId)), v.adUtf8);
  });

  it("refuses a userId carrying the separator", () => {
    assert.throws(() => adUsage("a|b"));
  });
});

describe("mergeUsage (must stay identical to the web twin)", () => {
  it("keeps the most recent use per item", () => {
    const a: UsageMap = { x: { lastUsedAt: T, useCount: 2 } };
    const b: UsageMap = { x: { lastUsedAt: T + 1000, useCount: 1 } };
    assert.deepEqual(mergeUsage(a, b).x, { lastUsedAt: T + 1000, useCount: 2 });
  });

  // Max and not sum: flushes re-merge against the server copy, so a sum would re-count the same
  // uses on every round trip and inflate without bound.
  it("is idempotent and order-independent, so clients converge", () => {
    const m: UsageMap = { x: { lastUsedAt: T, useCount: 5 } };
    assert.deepEqual(mergeUsage(m, m), m);
    const a: UsageMap = { x: { lastUsedAt: T + 5, useCount: 1 }, y: { lastUsedAt: T, useCount: 9 } };
    const b: UsageMap = { x: { lastUsedAt: T, useCount: 4 }, z: { lastUsedAt: T + 2, useCount: 1 } };
    assert.deepEqual(mergeUsage(a, b), mergeUsage(b, a));
  });

  it("keeps entries only one side has", () => {
    const out = mergeUsage({ a: { lastUsedAt: T, useCount: 1 } }, { b: { lastUsedAt: T, useCount: 1 } });
    assert.deepEqual(Object.keys(out).sort(), ["a", "b"]);
  });
});

describe("recordUse", () => {
  it("stamps and increments", () => {
    assert.deepEqual(recordUse({}, "x", T).x, { lastUsedAt: T, useCount: 1 });
    assert.deepEqual(recordUse({ x: { lastUsedAt: T, useCount: 1 } }, "x", T + 5).x, { lastUsedAt: T + 5, useCount: 2 });
  });

  it("never moves a stamp backwards", () => {
    assert.equal(recordUse({ x: { lastUsedAt: T, useCount: 1 } }, "x", T - 99_999).x!.lastUsedAt, T);
  });
});

// G04 (2026-08-30 audit): twin of web's pruneUsage pins. The SW flushes the prune ONLY at resync's
// post-full-snapshot point (background.ts), where the live set is provably complete; the debounce
// and lock-path flushes pass nothing, so a partial view can never drop an item's usage. These pin
// the pure half — that a complete set drops the gone item, and that an empty set drops EVERYTHING,
// which is exactly why a caller must never hand this a partial (mid-sync) set.
describe("pruneUsage (must stay identical to the web twin)", () => {
  it("drops entries whose item is gone so the blob cannot grow forever", () => {
    const m: UsageMap = { alive: { lastUsedAt: T, useCount: 1 }, deleted: { lastUsedAt: T, useCount: 1 } };
    assert.deepEqual(Object.keys(pruneUsage(m, new Set(["alive"]))), ["alive"]);
  });

  it("drops everything when handed an empty set — which is why callers must pass the FULL set", () => {
    assert.deepEqual(pruneUsage({ a: { lastUsedAt: T, useCount: 1 } }, new Set()), {});
  });
});

describe("parseUsage", () => {
  it("round-trips", () => {
    const m: UsageMap = { x: { lastUsedAt: T, useCount: 2 } };
    assert.deepEqual(parseUsage(serializeUsage(m)), m);
  });

  // A corrupt ledger must cost a health column, never a fill.
  it("reads garbage as empty instead of throwing", () => {
    for (const bad of ["", "not json", "null", "[]", "42"]) assert.deepEqual(parseUsage(bad), {});
  });

  it("skips malformed entries and defaults a missing count", () => {
    const parsed = parseUsage(JSON.stringify({ good: { lastUsedAt: T }, bad: { useCount: 4 }, nul: null }));
    assert.deepEqual(Object.keys(parsed), ["good"]);
    assert.deepEqual(parsed.good, { lastUsedAt: T, useCount: 1 });
  });
});
