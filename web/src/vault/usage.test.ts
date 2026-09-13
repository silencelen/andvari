import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import type { ApiClient } from "../api/client";
import { adUsage } from "../crypto/ad";
import { fromB64, fromUtf8, toB64, utf8 } from "../crypto/bytes";
import { initSodium } from "../crypto/sodium";
import { usageKey } from "../crypto/usagekey";
import type { Account } from "./account";
import { UsageTracker, type UsageMap, mergeUsage, parseUsage, planFlush, pruneUsage, recordUse, serializeUsage } from "./usage";

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

// planFlush (spec 02 §8.2 — audits H05 / H35). The SAME cases are pinned in extension/src/usage.test.ts
// and core's UsageLedgerTest, so the three flush engines cannot drift in WHEN they write.
describe("planFlush (must stay identical to the extension and core twins)", () => {
  const mine: UsageMap = { local: { lastUsedAt: T + 1000, useCount: 1 } };

  // THE H05 rule: a server copy this client could not fetch or open is never overwritten, buffered
  // uses or not. A PUT here would replace the household's ledger with one session's handful of
  // entries — the endpoint has no server-side merge to save it.
  it("never writes over an UNREADABLE server copy", () => {
    expect(planFlush({ kind: "unreadable" }, mine)).toBeNull();
    expect(planFlush({ kind: "unreadable" }, mine, new Set(["local"]))).toBeNull();
    expect(planFlush({ kind: "unreadable" }, {}, new Set(["x"]))).toBeNull();
  });

  // `sealedUsage: null` is the ONE case a merge-less write is a first write, not an overwrite.
  it("writes the buffer as a FIRST ledger when the server has none", () => {
    expect(planFlush({ kind: "absent" }, mine)).toEqual(mine);
    expect(planFlush({ kind: "absent" }, mine, new Set(["other"]))).toEqual(mine);
    expect(planFlush({ kind: "absent" }, {})).toBeNull();
    expect(planFlush({ kind: "absent" }, {}, new Set(["x"]))).toBeNull();
  });

  it("merges the buffer over a readable server copy", () => {
    const put = planFlush({ kind: "present", map: { "other-device-item": { lastUsedAt: T, useCount: 2 } } }, mine);
    expect(Object.keys(put!).sort()).toEqual(["local", "other-device-item"]);
  });

  // H35: a prune request with an EMPTY buffer must still drop a deleted item's entry — the
  // post-sync prune is the growth bound, and a sync almost never lands inside the debounce window.
  it("prunes with an EMPTY buffer", () => {
    const server: UsageMap = { alive: { lastUsedAt: T, useCount: 3 }, deleted: { lastUsedAt: T, useCount: 9 } };
    const put = planFlush({ kind: "present", map: server }, {}, new Set(["alive"]));
    expect(put).toEqual({ alive: { lastUsedAt: T, useCount: 3 } });
  });

  // Batched, never spurious (spec 03 §3): a quiet prune that drops nothing and has nothing buffered
  // must not write — no `updatedAt` bump on every poll.
  it("does not write when a prune changes nothing", () => {
    const server: UsageMap = { alive: { lastUsedAt: T, useCount: 1 } };
    expect(planFlush({ kind: "present", map: server }, {}, new Set(["alive"]))).toBeNull();
    expect(planFlush({ kind: "present", map: server }, {})).toBeNull();
  });

  it("keeps a buffered use the live-set snapshot does not know — under-prune, never drop a live entry", () => {
    const put = planFlush({ kind: "present", map: { alive: { lastUsedAt: T, useCount: 1 } } }, { fresh: { lastUsedAt: T + 1000, useCount: 1 } }, new Set(["alive"]));
    expect(Object.keys(put!).sort()).toEqual(["alive", "fresh"]);
  });
});

// G04 (2026-08-30 audit): the flush prunes ONLY when it is handed a live set, and the only caller
// that passes one is the successful-full-sync completion point (Vault.tsx syncNow) — where the
// store's item list is provably complete. The pagehide/unmount/debounce flushes call bare flush()
// so a partial view can never silently drop an item's usage. These pin BOTH halves of that wiring,
// plus the shell rules the 2026-09-13 audit added: H35 (the prune runs with an empty buffer), H05
// (an unreadable server copy is never overwritten), H34 (a rejected PUT re-arms) and H79 (a bare
// flush sends the BUFFER, not the display map).
describe("UsageTracker.flush", () => {
  // Minimal duck-typed doubles: the tracker touches only these four methods, and the seal is made
  // an identity round-trip (openUsage(sealUsage(x)) === x) so the test reads back what was stored.
  function makeTracker(seed: UsageMap | null = null) {
    let stored: string | null = seed === null ? null : serializeUsage(seed);
    const knobs = { failGet: false, failOpen: false, rejectPut: false, puts: 0, gets: 0 };
    const client = {
      getUsage: async () => {
        knobs.gets++;
        if (knobs.failGet) throw new Error("GET /usage failed");
        return { sealedUsage: stored, updatedAt: 0 };
      },
      putUsage: async (sealedUsage: string) => {
        // H34: putUsage REJECTS on a non-2xx (it rides text()); a refused write must throw here.
        if (knobs.rejectPut) throw new Error("400 bad_usage_blob");
        knobs.puts++;
        stored = sealedUsage;
      },
    } as unknown as ApiClient;
    const account = {
      sealUsage: async (b: Uint8Array) => fromUtf8(b),
      openUsage: async (s: string) => {
        if (knobs.failOpen) throw new Error("AEAD open failed");
        return utf8(s);
      },
    } as unknown as Account;
    return {
      tracker: new UsageTracker(client, account),
      knobs,
      stored: () => (stored === null ? null : parseUsage(stored)),
      /** Another device's write landing server-side between this tracker's calls. */
      setStored: (m: UsageMap) => {
        stored = serializeUsage(m);
      },
    };
  }

  // Seeded server-side, not recorded here: a use buffered in THIS session is inherently live (you
  // cannot copy a deleted item's secret) and survives the prune on every twin — the earlier shape
  // of this pin, which recorded "deleted" and expected it gone, pinned a web/core divergence.
  it("prunes a deleted item when flush is handed the complete live set (the post-sync point)", async () => {
    const { tracker, stored } = makeTracker({ deleted: { lastUsedAt: T, useCount: 1 } });
    tracker.record("alive", T);
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

  // H35: the sync-time state is "nothing buffered" (the debounce already flushed), and the prune
  // must still run then — it used to return at a dirty gate before ever reading the server.
  it("H35 — prunes a deleted item with NOTHING buffered", async () => {
    const { tracker, stored, knobs } = makeTracker({ alive: { lastUsedAt: T, useCount: 3 }, deleted: { lastUsedAt: T, useCount: 9 } });
    await tracker.flush(new Set(["alive"]));
    expect(knobs.gets).toBe(1);
    expect(stored()).toEqual({ alive: { lastUsedAt: T, useCount: 3 } });
    tracker.dispose();
  });

  it("H35 — a quiet post-sync flush with nothing to drop does not PUT (one GET, no updatedAt bump)", async () => {
    const { tracker, knobs } = makeTracker({ alive: { lastUsedAt: T, useCount: 1 } });
    await tracker.flush(new Set(["alive"]));
    expect(knobs.gets).toBe(1);
    expect(knobs.puts).toBe(0);
    tracker.dispose();
  });

  // H05: spec 02 §8.2 — a GET that fails is NOT an empty ledger to overwrite.
  it("H05 — a GET failure leaves the server ledger untouched and keeps the buffer for the next flush", async () => {
    const { tracker, stored, knobs } = makeTracker({ "other-device-item": { lastUsedAt: T, useCount: 2 } });
    tracker.record("local", T + 1000);
    knobs.failGet = true;
    await tracker.flush();
    expect(knobs.puts).toBe(0);
    expect(stored()).toEqual({ "other-device-item": { lastUsedAt: T, useCount: 2 } });
    // The next flush, once the server answers, lands the retained use merged over the copy.
    knobs.failGet = false;
    await tracker.flush();
    expect(Object.keys(stored()!).sort()).toEqual(["local", "other-device-item"]);
    tracker.dispose();
  });

  it("H05 — a blob that will not open is left untouched, and the buffer kept", async () => {
    const { tracker, stored, knobs } = makeTracker({ "other-device-item": { lastUsedAt: T, useCount: 2 } });
    tracker.record("local", T + 1000);
    knobs.failOpen = true;
    await tracker.flush(new Set(["local", "other-device-item"]));
    expect(knobs.puts).toBe(0);
    expect(stored()).toEqual({ "other-device-item": { lastUsedAt: T, useCount: 2 } });
    knobs.failOpen = false;
    await tracker.flush();
    expect(Object.keys(stored()!).sort()).toEqual(["local", "other-device-item"]);
    tracker.dispose();
  });

  it("H05 — a genuinely absent ledger is created from the buffer (the one merge-less write)", async () => {
    const { tracker, stored, knobs } = makeTracker(null);
    tracker.record("local", T + 1000);
    await tracker.flush();
    expect(knobs.puts).toBe(1);
    expect(stored()).toEqual({ local: { lastUsedAt: T + 1000, useCount: 1 } });
    tracker.dispose();
  });

  // H34: the re-arm catch is reachable for a server refusal only because putUsage now rejects.
  it("H34 — a rejected PUT leaves the tracker armed and the next flush re-sends the uses", async () => {
    const { tracker, stored, knobs } = makeTracker({});
    tracker.record("local", T + 1000);
    knobs.rejectPut = true;
    await tracker.flush();
    expect(stored()).toEqual({});
    knobs.rejectPut = false;
    await tracker.flush();
    expect(stored()).toEqual({ local: { lastUsedAt: T + 1000, useCount: 1 } });
    tracker.dispose();
  });

  // H79: the flush payload is the BUFFER. An entry another device pruned from the server copy
  // must not be resurrected by this tab's next bare flush just because its display map still
  // holds it from unlock time.
  it("H79 — a bare flush after another device pruned an entry does not re-add it", async () => {
    const { tracker, stored, setStored } = makeTracker({ "pruned-elsewhere": { lastUsedAt: T, useCount: 4 } });
    await tracker.load(); // the display map now holds the unlock-time copy
    expect(tracker.lastUsedAt("pruned-elsewhere")).toBe(T);
    setStored({}); // another device's post-sync prune removed it server-side
    tracker.record("local", T + 1000);
    await tracker.flush();
    expect(stored()).toEqual({ local: { lastUsedAt: T + 1000, useCount: 1 } });
    // …and the display follows what is stored, so the entry does not linger to be re-sent later.
    expect(tracker.lastUsedAt("pruned-elsewhere")).toBeUndefined();
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
