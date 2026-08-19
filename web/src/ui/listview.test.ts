import { describe, expect, it } from "vitest";
import type { ItemDoc } from "../api/types";
import type { VaultItem } from "../vault/store";
import { applyListView } from "./listview";

/**
 * Owner dev-note 2026-08-18: the vault list grew sort + facet controls. The transform is a pure
 * module precisely so this file can pin its contract: facets subset, "name" never re-orders
 * (store.list() already delivers alphabetical), "recent" orders by updatedAt desc with the
 * incoming order as the stable tiebreak.
 */

const item = (itemId: string, type: ItemDoc["type"], updatedAt: number, vaultId = "v1"): VaultItem => ({
  itemId,
  vaultId,
  rev: 1,
  updatedAt,
  formatVersion: 1,
  doc: type === "login" ? { type, name: itemId, login: { username: "u", password: "p" } } : { type, name: itemId, notes: "n" },
});

// Alphabetical by construction — the store's contract this module leans on.
const items: VaultItem[] = [
  item("alpha", "login", 300),
  item("bravo", "note", 100, "v2"),
  item("carol", "card", 300),
  item("delta", "login", 200, "v2"),
];

describe("applyListView — facets subset, sort orders", () => {
  it("passes everything through untouched in the default view (same array, no copy)", () => {
    expect(applyListView(items, "name", "all", "all")).toBe(items);
  });

  it("filters by type without disturbing the order", () => {
    expect(applyListView(items, "name", "login", "all").map((i) => i.itemId)).toEqual(["alpha", "delta"]);
  });

  it("filters by vault, and composes with the type facet", () => {
    expect(applyListView(items, "name", "all", "v2").map((i) => i.itemId)).toEqual(["bravo", "delta"]);
    expect(applyListView(items, "name", "login", "v2").map((i) => i.itemId)).toEqual(["delta"]);
  });

  it("recent = updatedAt desc, alphabetical (incoming order) as the stable tiebreak", () => {
    expect(applyListView(items, "recent", "all", "all").map((i) => i.itemId)).toEqual(["alpha", "carol", "delta", "bravo"]);
  });

  it("recent does not mutate the input array", () => {
    const before = items.map((i) => i.itemId);
    applyListView(items, "recent", "all", "all");
    expect(items.map((i) => i.itemId)).toEqual(before);
  });
});
