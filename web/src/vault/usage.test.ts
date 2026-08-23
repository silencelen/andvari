import { describe, expect, it } from "vitest";
import { adUsage } from "../crypto/ad";
import { fromUtf8 } from "../crypto/bytes";
import { type UsageMap, mergeUsage, parseUsage, pruneUsage, recordUse, serializeUsage } from "./usage";

/**
 * Usage ledger pins (spec 02 §8.2, design 2026-08-22-login-health). The network half is a thin
 * wrapper; every rule that could silently corrupt a user's ranking lives in these pure functions.
 */

const T = 1_755_000_000_000;

describe("mergeUsage", () => {
  it("keeps the most recent use per item across devices", () => {
    const a: UsageMap = { x: { lastUsedAt: T, useCount: 2 } };
    const b: UsageMap = { x: { lastUsedAt: T + 1000, useCount: 1 } };
    expect(mergeUsage(a, b).x!).toEqual({ lastUsedAt: T + 1000, useCount: 2 });
  });

  it("keeps entries only one side has", () => {
    expect(Object.keys(mergeUsage({ a: { lastUsedAt: T, useCount: 1 } }, { b: { lastUsedAt: T, useCount: 1 } })).sort()).toEqual(["a", "b"]);
  });

  // THE reason useCount is max and not sum: every flush re-merges against the server copy, so a
  // sum would re-count the same uses on each round trip and inflate without bound.
  it("is IDEMPOTENT — re-merging the same ledger changes nothing", () => {
    const m: UsageMap = { x: { lastUsedAt: T, useCount: 5 } };
    expect(mergeUsage(m, m)).toEqual(m);
    expect(mergeUsage(mergeUsage(m, m), m)).toEqual(m);
  });

  it("is order-independent, so devices converge whatever sequence they flush in", () => {
    const a: UsageMap = { x: { lastUsedAt: T + 5, useCount: 1 }, y: { lastUsedAt: T, useCount: 9 } };
    const b: UsageMap = { x: { lastUsedAt: T, useCount: 4 }, z: { lastUsedAt: T + 2, useCount: 1 } };
    expect(mergeUsage(a, b)).toEqual(mergeUsage(b, a));
  });

  it("does not mutate its inputs", () => {
    const a: UsageMap = { x: { lastUsedAt: T, useCount: 1 } };
    const frozen = JSON.stringify(a);
    mergeUsage(a, { x: { lastUsedAt: T + 1, useCount: 3 } });
    expect(JSON.stringify(a)).toBe(frozen);
  });
});

describe("recordUse", () => {
  it("stamps the time and increments the count", () => {
    expect(recordUse({}, "x", T).x!).toEqual({ lastUsedAt: T, useCount: 1 });
    expect(recordUse({ x: { lastUsedAt: T, useCount: 1 } }, "x", T + 5).x!).toEqual({ lastUsedAt: T + 5, useCount: 2 });
  });

  // A device whose clock runs backwards must not walk an item's stamp back down.
  it("never moves a stamp backwards", () => {
    expect(recordUse({ x: { lastUsedAt: T, useCount: 1 } }, "x", T - 99_999).x!.lastUsedAt).toBe(T);
  });

  it("leaves other items alone", () => {
    const out = recordUse({ y: { lastUsedAt: T, useCount: 3 } }, "x", T);
    expect(out.y).toEqual({ lastUsedAt: T, useCount: 3 });
  });
});

describe("pruneUsage", () => {
  it("drops entries whose item is gone so the blob cannot grow forever", () => {
    const m: UsageMap = { alive: { lastUsedAt: T, useCount: 1 }, deleted: { lastUsedAt: T, useCount: 1 } };
    expect(Object.keys(pruneUsage(m, new Set(["alive"])))).toEqual(["alive"]);
  });

  // The hazard this function's contract exists for: handed a PARTIAL set it would discard usage
  // for items that are merely not loaded yet. Pinned so nobody wires it to a mid-sync snapshot.
  it("drops everything when handed an empty set — which is why callers must pass the FULL set", () => {
    expect(pruneUsage({ a: { lastUsedAt: T, useCount: 1 } }, new Set())).toEqual({});
  });
});

describe("parseUsage", () => {
  it("round-trips through serializeUsage", () => {
    const m: UsageMap = { x: { lastUsedAt: T, useCount: 2 } };
    expect(parseUsage(serializeUsage(m))).toEqual(m);
  });

  // A corrupt ledger must cost one health column, never an unlock or a sync.
  it("reads garbage as an EMPTY ledger instead of throwing", () => {
    for (const bad of ["", "not json", "null", "[]", "42", '"str"']) expect(parseUsage(bad)).toEqual({});
  });

  it("skips malformed entries but keeps the good ones", () => {
    const parsed = parseUsage(JSON.stringify({
      good: { lastUsedAt: T, useCount: 2 },
      noStamp: { useCount: 4 },
      nanStamp: { lastUsedAt: "soon" },
      nullEntry: null,
    }));
    expect(Object.keys(parsed)).toEqual(["good"]);
  });

  it("defaults a missing count rather than dropping a usable stamp", () => {
    expect(parseUsage(JSON.stringify({ x: { lastUsedAt: T } })).x!).toEqual({ lastUsedAt: T, useCount: 1 });
  });

  it("rejects a non-finite stamp", () => {
    // JSON has no Infinity literal; this is the shape a hand-edited or buggy writer produces.
    expect(parseUsage('{"x":{"lastUsedAt":1e999,"useCount":1}}')).toEqual({});
  });
});

/**
 * The AD twin (spec 02 §2). `adUsage` here and `Ad.usage` in :core are hand-mirrored one-liners
 * with no shared vector between them, and a silent divergence would be nasty in a specific way:
 * each client would still seal and open its OWN ledger perfectly while being unable to open the
 * other's — the failure would look like "the phone just never records anything". Both sides
 * therefore pin the exact byte string, so a drift breaks a test rather than a user's column.
 */
describe("adUsage (spec 02 §2 — twin of core Ad.usage)", () => {
  it("is exactly andvari/v1|usage|<userId>", () => {
    expect(fromUtf8(adUsage("u1"))).toBe("andvari/v1|usage|u1");
  });

  it("refuses a userId carrying the separator, so components cannot be forged across fields", () => {
    expect(() => adUsage("a|b")).toThrow();
  });
});
