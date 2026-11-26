import type { VaultInfo, VaultStore } from "../vault/store";
import { fill, SAME_NAME_MADE, SAME_NAME_UNDATED } from "./copy";

/**
 * Two vaults of one name in one list (a move's fresh vault beside the one from an earlier try, two vaults a person named
 * alike): each is shown with when it was made, so that "the one from the earlier try" can be told apart and named. A
 * name no other vault in [all] shares is shown as it is.
 */
export function vaultLabel(v: Pick<VaultInfo, "vaultId" | "name" | "createdAt">, all: readonly Pick<VaultInfo, "vaultId" | "name">[]): string {
  if (!all.some((o) => o.vaultId !== v.vaultId && o.name === v.name)) return v.name;
  return fill(SAME_NAME_MADE, v.name, madeWhen(v.createdAt));
}

/** Every vault's label, by id ({@link vaultLabel}). */
export function vaultLabels(all: readonly Pick<VaultInfo, "vaultId" | "name" | "createdAt">[]): Map<string, string> {
  return new Map(all.map((v) => [v.vaultId, vaultLabel(v, all)] as const));
}

/** The label of [vaultId] among the store's vaults, or [name] when the store does not list it (a name the move kept). */
export function storeVaultLabel(store: Pick<VaultStore, "vaults">, vaultId: string | null, name: string): string {
  const all = store.vaults();
  const v = vaultId === null ? undefined : all.find((x) => x.vaultId === vaultId);
  return v === undefined ? name : vaultLabel({ ...v, name }, all);
}

/** "November 16, 9:31 PM": the day and the minute, since the vault from an earlier try is often made the same day. */
export function madeWhen(ms: number | undefined): string {
  if (!ms) return SAME_NAME_UNDATED;
  return new Date(ms).toLocaleString(undefined, { month: "long", day: "numeric", hour: "numeric", minute: "2-digit" });
}
