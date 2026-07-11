import type { VaultInfo } from "../vault/store";

/**
 * DN-1 (per-vault Settings layer): the two pure decisions behind Sharing's settings
 * flyout — which rows get the affordance, and what an open layer shows — extracted so
 * vitest can pin them without any DOM in the loop (house style: pure functions only).
 */

/** Which vault rows get a Settings button: SHARED vaults only, owner and member alike.
 *  Personal vaults have no lifecycle ops (rename/delete/leave/transfer are all
 *  shared-vault verbs) — an empty settings page is worse than no button. */
export function showSettingsButton(v: VaultInfo): boolean {
  return v.type === "shared";
}

/**
 * What the settings layer shows for `vaultId`, resolved against the CURRENT vaults list
 * (derived each render, invariant 4): "owner" → the vault's MemberPanel; "member" → the
 * read-only roster + LeaveControl; null → the id doesn't resolve to a shared vault
 * (vanished mid-view via revoke/delete on another device, or never valid) — the render
 * falls back to the vaults list and A2's effect actively clears the stale id.
 */
export function settingsContentFor(vaultId: string | null, vaults: VaultInfo[]): "owner" | "member" | null {
  if (!vaultId) return null;
  const v = vaults.find((x) => x.vaultId === vaultId);
  if (!v || v.type !== "shared") return null;
  return v.role === "owner" ? "owner" : "member";
}
