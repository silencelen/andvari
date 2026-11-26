import { describe, expect, it } from "vitest";
import { decodeSync, type QuotaMeter, type QuotaUse, readQuota } from "../api/wire";
import { copySize, quotaRoom, type QuotaRoom, sealedBlobLength, type Shortfall, storedAttachmentSize } from "./quota";

/**
 * Spec 03 §14.4, the web twin of core QuotaCheckTest and QuotaWireTest: at each boundary the server's own check walks,
 * one below the limit and exactly on it are room and one over is short by 1; what cannot be four meters of whole,
 * non-negative numbers is unknown, never an error and never room.
 */
const m = (used: number, limit: number): QuotaMeter => ({ used, limit });
const use = (o: Partial<Record<"bytes" | "items" | "vaults" | "links", QuotaMeter>> = {}): QuotaUse => ({
  accountBytes: o.bytes ?? m(0, 1_000),
  items: o.items ?? m(0, 10),
  ownedSharedVaults: o.vaults ?? m(0, 2),
  openLinks: o.links ?? m(0, 20),
});
const short = (r: QuotaRoom): readonly Shortfall[] => {
  if (r.kind !== "short") throw new Error(`expected short, got ${r.kind}`);
  return r.limits;
};
const ROOM = { kind: "room" };
const TOP = Number.MAX_SAFE_INTEGER;

describe("the check before a large copy (spec 03 §14.4)", () => {
  it("accountBytes: one below and on the limit are room, one over is short by one", () => {
    const q = use({ bytes: m(900, 1_000) });
    expect(quotaRoom(q, copySize(99, 1))).toEqual(ROOM);
    expect(quotaRoom(q, copySize(100, 1))).toEqual(ROOM);
    expect(short(quotaRoom(q, copySize(101, 1)))).toEqual([{ quota: "accountBytes", used: 900, limit: 1_000, adds: 101, by: 1 }]);
    expect(short(quotaRoom(q, copySize(1_000_000, 1)))[0]!.by).toBe(1_000_000 - 100);
  });

  it("items: one below and on the limit are room, one over is short by one", () => {
    const q = use({ items: m(8, 10) });
    expect(quotaRoom(q, copySize(10, 1))).toEqual(ROOM);
    expect(quotaRoom(q, copySize(10, 2))).toEqual(ROOM);
    expect(short(quotaRoom(q, copySize(10, 3)))).toEqual([{ quota: "items", used: 8, limit: 10, adds: 3, by: 1 }]);
  });

  it("a new shared vault needs one vault of room and its meta must fit; B and M are not added, the larger counts", () => {
    expect(quotaRoom(use({ vaults: m(1, 2) }), copySize(0, 0, true, 10))).toEqual(ROOM);
    expect(short(quotaRoom(use({ vaults: m(2, 2) }), copySize(0, 0, true, 10)))).toEqual([{ quota: "ownedSharedVaults", used: 2, limit: 2, adds: 1, by: 1 }]);
    expect(quotaRoom(use({ vaults: m(5, 2) }), copySize(10, 1))).toEqual(ROOM); // no new vault: that meter is not grown
    const b = use({ bytes: m(900, 1_000) });
    expect(quotaRoom(b, copySize(0, 0, true, 99))).toEqual(ROOM);
    expect(quotaRoom(b, copySize(0, 0, true, 100))).toEqual(ROOM);
    expect(short(quotaRoom(b, copySize(0, 0, true, 101)))).toEqual([{ quota: "accountBytes", used: 900, limit: 1_000, adds: 101, by: 1 }]);
    expect(quotaRoom(b, copySize(100, 3, true, 60))).toEqual(ROOM);
    expect(short(quotaRoom(b, copySize(50, 3, true, 101)))[0]!.adds).toBe(101);
  });

  it("a limit lowered below use refuses every growth, in the meters' order, and nothing else", () => {
    const q = use({ bytes: m(1_200, 1_000), items: m(12, 10) });
    const s = short(quotaRoom(q, copySize(1, 1)));
    expect(s.map((x) => [x.quota, x.by])).toEqual([["accountBytes", 201], ["items", 3]]);
    expect(quotaRoom(q, copySize(0, 0))).toEqual(ROOM);
  });

  it("limits of zero are short on every meter the copy grows; first is the first of them", () => {
    const zero: QuotaUse = { accountBytes: m(0, 0), items: m(0, 0), ownedSharedVaults: m(0, 0), openLinks: m(0, 0) };
    const r = quotaRoom(zero, copySize(5, 1, true, 3));
    expect(short(r).map((x) => [x.quota, x.by])).toEqual([["accountBytes", 5], ["items", 1], ["ownedSharedVaults", 1]]);
    expect(r.kind === "short" && r.first.quota).toBe("accountBytes");
  });

  it("numbers at the edge never wrap round to room", () => {
    expect(short(quotaRoom(use({ bytes: m(TOP, TOP) }), copySize(1, 0)))[0]!.by).toBe(1);
    expect(short(quotaRoom(use({ bytes: m(1, TOP) }), copySize(TOP, 0)))[0]!.by).toBe(1);
    expect(short(quotaRoom(use({ bytes: m(TOP, 0) }), copySize(TOP, 0)))[0]!.by).toBe(TOP); // capped
    expect(quotaRoom(use({ bytes: m(0, TOP) }), copySize(TOP, 0))).toEqual(ROOM);
    expect(quotaRoom(use({ bytes: m(TOP - 1, TOP), items: m(TOP - 1, TOP), vaults: m(TOP - 1, TOP) }), copySize(1, 1, true, 1))).toEqual(ROOM);
  });

  it("no numbers is unknown, never room; a copy of negative size or a meta without a vault is the caller's mistake", () => {
    expect(quotaRoom(null, copySize(1, 1))).toEqual({ kind: "unknown" });
    expect(() => copySize(-1, 0)).toThrow(RangeError);
    expect(() => copySize(0, -1)).toThrow(RangeError);
    expect(() => copySize(0, 0, true, -1)).toThrow(RangeError);
    expect(() => copySize(0, 0, false, 5)).toThrow(RangeError);
    expect(() => copySize(0.5, 0)).toThrow(RangeError);
  });

  it("the sizes: an item's blob as sent, an attachment as stored", () => {
    expect(sealedBlobLength(0)).toBe(56);
    expect(sealedBlobLength(1)).toBe(58);
    expect(storedAttachmentSize(70_000)).toBe(70_000 + 34);
    expect(storedAttachmentSize(65_536)).toBe(65_536 + 17);
  });
});

describe("reading `quota` from a sync answer (spec 03 §14.4)", () => {
  const SPEC = { accountBytes: { used: 52_428_800, limit: 104_857_600 }, items: { used: 120, limit: 5_000 }, ownedSharedVaults: { used: 1, limit: 50 }, openLinks: { used: 0, limit: 20 } };

  it("reads the four meters, ignores a key it does not know, and reads an older server's none as unknown", () => {
    expect(readQuota(SPEC)).toEqual(SPEC);
    expect(readQuota({ ...SPEC, laterQuota: { used: 1, limit: 2 } })).toEqual(SPEC);
    expect(readQuota(undefined)).toBeNull();
  });

  it("every lie is unknown, never an error: missing, negative, fractional, too large to read exactly, a word, not an object", () => {
    const lies: unknown[] = [
      null, 7, "quota", [SPEC],
      { ...SPEC, items: undefined },
      { ...SPEC, items: { used: -1, limit: 10 } },
      { ...SPEC, items: { used: 0, limit: -1 } },
      { ...SPEC, accountBytes: { used: 1.5, limit: 10 } },
      { ...SPEC, accountBytes: { used: 0, limit: 2 ** 63 } },
      { ...SPEC, openLinks: { used: "0", limit: 20 } },
      { ...SPEC, openLinks: [0, 20] },
      { ...SPEC, ownedSharedVaults: { used: 0 } },
    ];
    for (const lie of lies) expect(readQuota(lie), JSON.stringify(lie)).toBeNull();
  });

  it("a sync answer with a lie still decodes, everything else as served, and its quota is unknown", () => {
    const body = { rev: 3, full: true, vaults: [], grants: [], items: [], removedGrants: [] };
    expect(decodeSync({ ...body, quota: SPEC } as never).value.quota).toEqual(SPEC);
    const lied = decodeSync({ ...body, quota: { ...SPEC, items: { used: -5, limit: 10 } } } as never);
    expect([lied.value.quota, lied.value.rev, lied.refused]).toEqual([null, 3, []]);
    expect(decodeSync(body as never).value.quota).toBeNull();
  });
});
