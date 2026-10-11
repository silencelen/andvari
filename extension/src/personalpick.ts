import { adVkPersonal, fromB64, open } from "./crypto.ts";

/**
 * The personal vault in the extension (security review 2026-10, root cause A §4 / §8.5; branch A5).
 * Core twins: `Account.applyPersonalWrap` and `PersonalVaultMigration.decide`; web: account.ts / personalvault.ts.
 *
 * 1. `AccountKeys.personalWrap` decides, when present: `Envelope(UVK, VK, adVkPersonal(vaultId, userId))`,
 *    which only this user's UVK can mint. Its VK is installed FIRST (precedence rule 1). If it is present
 *    and does not open, there is NO personal vault (an anomaly) and nothing falls back to a label.
 * 2. Only when the wrap is ABSENT (an account the full clients have not migrated yet) the §8.5 automatic
 *    rule applies, adopt-only (the extension never mints the wrap): exactly one held vault labelled
 *    `personal` whose key came from this account's own bare UVK wrap (no seal, owner row: not
 *    member-granted), and whose decrypted name is exactly "Personal". Anything else: no personal vault.
 */

export interface PersonalWrapWire {
  vaultId: string;
  wrappedVk: string;
}

export interface VaultRowWire {
  vaultId: string;
  type: string;
  metaBlob?: string;
}

export type PersonalPick = { vaultId: string; source: "wrap" | "migration" | "none" | "unreadable" };

const AD_VAULTMETA = (vaultId: string) => new TextEncoder().encode(`andvari/v1|vaultmeta|${vaultId}`);

function metaName(vk: Uint8Array, vaultId: string, metaBlob: string | undefined): string | null {
  if (!metaBlob) return null;
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(open(vk, fromB64(metaBlob), AD_VAULTMETA(vaultId))));
    const name = parsed && typeof parsed === "object" ? (parsed as { name?: unknown }).name : undefined;
    return typeof name === "string" ? name : null;
  } catch {
    return null;
  }
}

export function pickPersonal(
  wrap: PersonalWrapWire | null | undefined,
  uvk: Uint8Array,
  userId: string,
  vaultKeys: Map<string, Uint8Array>,
  vaults: VaultRowWire[],
  memberGranted: Set<string>,
): PersonalPick {
  if (wrap) {
    let vk: Uint8Array;
    try {
      vk = open(uvk, fromB64(wrap.wrappedVk), adVkPersonal(wrap.vaultId, userId));
    } catch {
      return { vaultId: "", source: "unreadable" };
    }
    if (vk.length !== 32) return { vaultId: "", source: "unreadable" };
    vaultKeys.set(wrap.vaultId, vk);
    return { vaultId: wrap.vaultId, source: "wrap" };
  }
  const eligible = vaults.filter((v) => v.type === "personal" && vaultKeys.has(v.vaultId) && !memberGranted.has(v.vaultId));
  if (eligible.length !== 1) return { vaultId: "", source: "none" };
  const only = eligible[0]!;
  return metaName(vaultKeys.get(only.vaultId)!, only.vaultId, only.metaBlob) === "Personal"
    ? { vaultId: only.vaultId, source: "migration" }
    : { vaultId: "", source: "none" };
}
