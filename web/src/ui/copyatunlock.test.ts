import { describe, expect, it } from "vitest";
import type { AccountKeysV2 } from "../api/wire";
import type { VaultCache } from "../vault/idbcache";
import { copyAtUnlock } from "./opensession";

/**
 * Spec 01 §7, item by item: every state in which this browser has nothing to compare a served wrap with, read at the
 * unlock of a held session. `none` is an ordinary sign-in's checks (onboardflow unlockSession); `unreadable` takes nothing.
 */
const KEYS = { kdfSalt: "s", kdfParams: { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 }, wrappedUvk: "w", genesis: "g" } as unknown as AccountKeysV2;
/** This browser has IndexedDB (the test environment itself has none: the last test reads the real feature test). */
const STORE = () => true;
const PENDING = [{ kdfSalt: "p", kdfParams: { v: 1, alg: "argon2id13", ops: 4, memBytes: 67_108_864 }, wrappedUvk: "pw" }];

function cache(over: Partial<Record<"durable" | "keys" | "row" | "throws", unknown>> = {}): { cache: VaultCache; closed: () => boolean } {
  let closed = false;
  const c = {
    durable: over.durable ?? true,
    accountKeysV2: async () => {
      if (over.throws) throw new Error("the read failed");
      return ("keys" in over ? over.keys : KEYS) as AccountKeysV2 | null;
    },
    hasAccountKeysV2Row: async () => (over.row ?? true) as boolean,
    pendingWraps: async () => PENDING,
    close: () => void (closed = true),
  } as unknown as VaultCache;
  return { cache: c, closed: () => closed };
}

describe("what this browser holds to compare the server's keys with at an unlock (spec 01 §7)", () => {
  it("the copy is off here for this account (never chosen, storage blocked or cleared, a private window): none, and the database is not opened", async () => {
    let opened = 0;
    expect(await copyAtUnlock("u", async () => ((opened++), cache().cache), () => false)).toEqual({ kind: "none" });
    expect(opened).toBe(0);
  });

  it("the copy is on, with no keys written yet (just chosen, or its database cleared under it): none", async () => {
    const c = cache({ keys: null, row: false });
    expect(await copyAtUnlock("u", async () => c.cache, () => true, STORE)).toEqual({ kind: "none" });
    expect(c.closed()).toBe(true);
  });

  it("the copy is on and its keys row is there but is not a usable key set: unreadable", async () => {
    expect(await copyAtUnlock("u", async () => cache({ keys: null, row: true }).cache, () => true, STORE)).toEqual({ kind: "unreadable" });
  });

  it("the copy is on and its database did not open (a NullCache in its place), the open threw, or the read threw: unreadable", async () => {
    expect(await copyAtUnlock("u", async () => cache({ durable: false }).cache, () => true, STORE)).toEqual({ kind: "unreadable" });
    expect(
      await copyAtUnlock("u", async () => {
        throw new Error("blocked");
      }, () => true, STORE),
    ).toEqual({ kind: "unreadable" });
    const c = cache({ throws: true });
    expect(await copyAtUnlock("u", async () => c.cache, () => true, STORE)).toEqual({ kind: "unreadable" });
    expect(c.closed()).toBe(true);
  });

  it("a usable copy: its keys and the wraps pending beside it", async () => {
    expect(await copyAtUnlock("u", async () => cache().cache, () => true, STORE)).toEqual({ kind: "copy", keys: KEYS, pending: PENDING });
  });

  it("a browser with no store at all (no IndexedDB) holds no copy: none, whatever its setting says, so the unlock is a sign-in's checks and not a trip to the sign-in form", async () => {
    let opened = 0;
    const open = async () => ((opened++), cache({ durable: false }).cache);
    expect(await copyAtUnlock("u", open, () => true, () => false)).toEqual({ kind: "none" });
    expect(opened).toBe(0);
    // The real feature test, as openVaultCache makes it: absent, and a getter that throws.
    const g = globalThis as { indexedDB?: unknown };
    const had = Object.getOwnPropertyDescriptor(globalThis, "indexedDB");
    try {
      delete g.indexedDB;
      expect(await copyAtUnlock("u", open, () => true)).toEqual({ kind: "none" });
      Object.defineProperty(globalThis, "indexedDB", { configurable: true, get: () => { throw new Error("storage is off"); } });
      expect(await copyAtUnlock("u", open, () => true)).toEqual({ kind: "none" });
      expect(opened).toBe(0);
      // With a store, a database that does not open stays what it was: a copy that cannot be read.
      Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: {} });
      expect(await copyAtUnlock("u", open, () => true)).toEqual({ kind: "unreadable" });
    } finally {
      if (had) Object.defineProperty(globalThis, "indexedDB", had);
      else delete g.indexedDB;
    }
  });
});
