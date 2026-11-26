import { fromB64, open } from "./crypto.ts";
import { openSharedWrap, type WrapRecords } from "./wraps.ts";

/**
 * Shared-vault keys in the extension (design 2026-11-15-onboarding-trust §12.2 rule 1). LEAF module (no chrome), so
 * `node --test` grades the production code path.
 *
 * The extension takes UVK WRAPS ONLY: an owner wrap or a member self-wrap on the account's grant row, which a full
 * client minted after its own checks. Each opens under the genesis-bound AD (wraps.ts), with the genesis hash from the
 * account state's `vaults` record, and is tried only when the account state's `accepted[vaultId].decision` is
 * `accept` and the served account state is not below the extension's high-water mark (`records` null otherwise). It
 * NEVER opens a grant seal (`signedGrant`): a v2 grant must be verified against a pinned identity and the vault's log,
 * which the extension does not do. A row that carries a grant but no wrap, or a wrap the rule does not open, is
 * WAITING: the popup says so (errors.ts GRANTS_WAITING), and a full client verifies it and posts the self-wrap. After an MV3
 * eviction (no UVK in memory) nothing new is adopted at all.
 *
 * The personal vault's key comes from `AccountKeys.personalWrap` (wraps.ts personalVaultKey), never from a grant row.
 */

export interface GrantRow {
  vaultId: string;
  userId: string;
  role: string;
  wrappedVk: string;
  signedGrant?: string | null;
}

export interface VaultKeysFromWraps {
  vaultKeys: Map<string, Uint8Array>;
  vaultRoles: Map<string, string>;
  /** A wrap on the row, accepted, that does not open: the vault stays keyless (never a seal fallback). */
  keyUnreadable: Set<string>;
  /** Rows the extension will not open yet: no wrap (a grant only), or no `accept` decision / usable account state. */
  waiting: Set<string>;
}

/** The shared-vault keys of `grants` (the personal vault's row is skipped: its key is the personal wrap's). */
export function buildVaultKeys(grants: readonly GrantRow[], uvk: Uint8Array, userId: string, personalVaultId: string, records: WrapRecords | null): VaultKeysFromWraps {
  const vaultKeys = new Map<string, Uint8Array>();
  const vaultRoles = new Map<string, string>();
  const keyUnreadable = new Set<string>();
  const waiting = new Set<string>();
  for (const g of grants) {
    if (g.vaultId === personalVaultId) continue;
    if (!g.wrappedVk) {
      if (g.signedGrant) waiting.add(g.vaultId); // never opened here (§12.2 rule 1)
      continue;
    }
    const got = openSharedWrap(g.vaultId, g.wrappedVk, uvk, userId, records);
    if (!got.opened) {
      if (got.why === "unopenable") keyUnreadable.add(g.vaultId); // damaged or substituted wrap: NO seal fallback
      else waiting.add(g.vaultId);
      continue;
    }
    vaultKeys.set(g.vaultId, got.vk);
    // G21: the role beside the key — "reader" means the server denies every push to this vault.
    vaultRoles.set(g.vaultId, g.role);
  }
  return { vaultKeys, vaultRoles, keyUnreadable, waiting };
}

/** Rows still waiting for a full client, computed WITHOUT the UVK (a resync after an eviction can refresh it). */
export function waitingGrantCount(grants: readonly GrantRow[], held: ReadonlySet<string>, personalVaultId: string): number {
  let n = 0;
  for (const g of grants) if (g.vaultId !== personalVaultId && !held.has(g.vaultId) && (g.wrappedVk || g.signedGrant)) n++;
  return n;
}

/** A vault's display name from its meta blob under a HELD key (spec 02 §4: only a JSON string is a name). */
export function vaultNameFromMeta(vk: Uint8Array | undefined, vaultId: string, metaBlob: string | undefined): string | null {
  if (!vk || !metaBlob) return null;
  try {
    const plain = open(vk, fromB64(metaBlob), new TextEncoder().encode(`andvari/v1|vaultmeta|${vaultId}`));
    const obj = JSON.parse(new TextDecoder().decode(plain)) as { name?: unknown };
    return typeof obj?.name === "string" && obj.name.length > 0 ? obj.name : null;
  } catch {
    return null;
  }
}
