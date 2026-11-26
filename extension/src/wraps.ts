import { adVkPersonal, fromB64, open } from "./crypto.ts";
import type { AcceptedRecord, VaultRecord } from "./accountstate.ts";

/**
 * Vault keys in the extension (design 2026-11-15-onboarding-trust §12.2 rule 1, §2.3, §5.3): keys come ONLY
 * from UVK wraps a full client minted after its own checks.
 *
 * - The personal wrap (`AccountKeys.personalWrap`) is in force when it names the genesis's `personalVaultId`
 *   and opens under the UVK with the v1 personal AD `andvari/v1|vk-personal|{vaultId}|{userId}`.
 * - A shared-vault wrap (an owner wrap or a member self-wrap on the account's grant row) opens with
 *   `andvari/v2|vk-shared|{vaultId}|{userId}|{genesisHash}`, the genesis hash read from the account state's
 *   `vaults[vaultId].genesisHash`; it is tried only when `accepted[vaultId].decision` is `accept`, and only
 *   while the served account state is not below the extension's high-water mark (the caller passes null
 *   records then). A wrong or withheld genesis hash simply fails the AEAD and the vault stays closed.
 *
 * The extension opens no grant seal and verifies no vault log; it cannot check `addSeq`, membership or the
 * key commitment (R24). Graded by `wrapad.json` (`expect.extensionOpens`) and `accountgenesis.json`.
 * LEAF module: no chrome.
 */

/** `andvari/v2|vk-shared|{vaultId}|{userId}|{genesisHash}` (§2.3, T-B3). */
export function adVkShared(vaultId: string, userId: string, genesisHash: string): Uint8Array {
  for (const p of [vaultId, userId, genesisHash]) if (p.includes("|")) throw new Error("AD component must not contain '|'");
  return new TextEncoder().encode(`andvari/v2|vk-shared|${vaultId}|${userId}|${genesisHash}`);
}

function openKey(uvk: Uint8Array, wrappedVkB64: string, ad: Uint8Array): Uint8Array | null {
  try {
    const vk = open(uvk, fromB64(wrappedVkB64), ad);
    return vk.length === 32 ? vk : null;
  } catch {
    return null;
  }
}

/** The personal vault's key (§5.3), or null when the served wrap names another vault or does not open. */
export function personalVaultKey(wrappedVkB64: string, wrapVaultId: string, personalVaultId: string, uvk: Uint8Array, userId: string): Uint8Array | null {
  if (wrapVaultId !== personalVaultId) return null;
  return openKey(uvk, wrappedVkB64, adVkPersonal(wrapVaultId, userId));
}

/** The records a shared-vault wrap is opened under: from a served account state at or above the mark. */
export interface WrapRecords {
  readonly vaults: Readonly<Record<string, VaultRecord>>;
  readonly accepted: Readonly<Record<string, AcceptedRecord>>;
}

export type SharedWrapOutcome =
  | { opened: true; vk: Uint8Array }
  | { opened: false; why: "no_state" | "not_accepted" | "no_vault_record" | "unopenable" };

/** §12.2 rule 1 for one shared-vault wrap. `records` is null while no usable account state is held. */
export function openSharedWrap(vaultId: string, wrappedVkB64: string, uvk: Uint8Array, userId: string, records: WrapRecords | null): SharedWrapOutcome {
  if (records === null) return { opened: false, why: "no_state" };
  if (records.accepted[vaultId]?.decision !== "accept") return { opened: false, why: "not_accepted" };
  const genesisHash = records.vaults[vaultId]?.genesisHash;
  if (genesisHash === undefined) return { opened: false, why: "no_vault_record" };
  const vk = openKey(uvk, wrappedVkB64, adVkShared(vaultId, userId, genesisHash));
  return vk === null ? { opened: false, why: "unopenable" } : { opened: true, vk };
}
