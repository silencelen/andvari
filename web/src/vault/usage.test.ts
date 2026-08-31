import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import type { ApiClient } from "../api/client";
import { adUsage } from "../crypto/ad";
import { fromB64, fromUtf8, toB64, utf8 } from "../crypto/bytes";
import { initSodium } from "../crypto/sodium";
import { usageKey } from "../crypto/usagekey";
import type { Account } from "./account";
import { UsageTracker, type UsageMap, mergeUsage, parseUsage, pruneUsage, recordUse, serializeUsage } from "./usage";

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

// G04 (2026-08-30 audit): the flush prunes ONLY when it is handed a live set, and the only caller
// that passes one is the successful-full-sync completion point (Vault.tsx syncNow) — where the
// store's item list is provably complete. The pagehide/unmount/debounce flushes call bare flush()
// so a partial view can never silently drop an item's usage. These pin BOTH halves of that wiring.
describe("UsageTracker.flush pruning", () => {
  // Minimal duck-typed doubles: the tracker touches only these four methods, and the seal is made
  // an identity round-trip (openUsage(sealUsage(x)) === x) so the test reads back what was stored.
  function makeTracker() {
    let stored: string | null = null;
    const client = {
      getUsage: async () => ({ sealedUsage: stored, updatedAt: 0 }),
      putUsage: async (sealedUsage: string) => {
        stored = sealedUsage;
      },
    } as unknown as ApiClient;
    const account = {
      sealUsage: async (b: Uint8Array) => fromUtf8(b),
      openUsage: async (s: string) => utf8(s),
    } as unknown as Account;
    return { tracker: new UsageTracker(client, account), stored: () => (stored === null ? null : parseUsage(stored)) };
  }

  it("prunes a deleted item when flush is handed the complete live set (the post-sync point)", async () => {
    const { tracker, stored } = makeTracker();
    tracker.record("alive", T);
    tracker.record("deleted", T);
    await tracker.flush(new Set(["alive"]));
    expect(Object.keys(stored()!)).toEqual(["alive"]);
    tracker.dispose();
  });

  it("never prunes on a bare flush() — pagehide/unmount/debounce must keep every entry", async () => {
    const { tracker, stored } = makeTracker();
    tracker.record("alive", T);
    tracker.record("deleted", T);
    await tracker.flush();
    expect(Object.keys(stored()!).sort()).toEqual(["alive", "deleted"]);
    tracker.dispose();
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
 * The crypto twins (spec 02 §2/§8.2). `usageKey`/`adUsage` here and `UsageKey`/`Ad.usage` in
 * :core are hand-mirrored, and a silent divergence would fail in a specific and misleading way:
 * each client would seal and open its OWN ledger perfectly while being unable to open the
 * other's, so the symptom would read as "the phone just never records anything" rather than as a
 * crypto fault.
 *
 * Both sides are therefore checked against spec/test-vectors/usagekey.json, whose expected value
 * was computed by an INDEPENDENT third implementation — so this pins "web is correct", not merely
 * "web and core agree", which two mirrored-but-equally-wrong impls would also satisfy.
 */
describe("usage crypto (spec 02 §2/§8.2 — twins of core UsageKey/Ad.usage)", () => {
  // fromB64/toB64 go through libsodium, which the crypto vector tests init the same way.
  beforeAll(async () => {
    await initSodium();
  });

  const v = JSON.parse(
    readFileSync(fileURLToPath(new URL("../../../spec/test-vectors/usagekey.json", import.meta.url)), "utf8"),
  ) as { vkB64: string; usageKeyB64: string; adUtf8: string; adUserId: string };

  it("derives the vector's usageKey from the vector's VK", async () => {
    expect(toB64(await usageKey(fromB64(v.vkB64)))).toBe(v.usageKeyB64);
  });

  it("builds the vector's AD", () => {
    expect(fromUtf8(adUsage(v.adUserId))).toBe(v.adUtf8);
  });

  it("refuses a userId carrying the separator, so components cannot be forged across fields", () => {
    expect(() => adUsage("a|b")).toThrow();
  });
});
