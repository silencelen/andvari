import type { VaultItem } from "../vault/store";

/** Owner dev-note 2026-08-18: sort + facet controls for the vault list. Pure and in its own
 *  module so the node-only test setup can pin the ordering/filtering directly (the
 *  format.ts/strength.ts idiom) — the Vault component only wires selects to these values.
 *
 *  Sort keys are limited by the client model on purpose: `updatedAt` is the only timestamp a
 *  decrypted row carries (wire `createdAt` is dropped at decrypt, store.ts), so "date added"
 *  is not offerable without a store change. `name` relies on store.list()'s existing
 *  alphabetical order — applyListView never re-sorts in that mode, so the two list paths
 *  (plain + virtualized) stay byte-identical with the pre-facet behavior. */
export type SortMode = "name" | "recent";
export type TypeFilter = "all" | "login" | "note" | "card";

export function applyListView(items: VaultItem[], sort: SortMode, type: TypeFilter, vaultId: string): VaultItem[] {
  let out = items;
  if (type !== "all") out = out.filter((it) => it.doc.type === type);
  if (vaultId !== "all") out = out.filter((it) => it.vaultId === vaultId);
  // Array.prototype.sort is stable, so equal timestamps keep the incoming alphabetical order.
  if (sort === "recent") out = [...out].sort((a, b) => b.updatedAt - a.updatedAt);
  return out;
}
