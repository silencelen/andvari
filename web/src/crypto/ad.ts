import { utf8 } from "./bytes";
import { CryptoError } from "./sodium";

/** spec 02 §2 — associated-data construction; mirrors core Ad.kt. */
const NS = "andvari/v1";

function join(...parts: string[]): Uint8Array {
  for (const p of parts) {
    if (p.includes("|")) throw new CryptoError("AD component must not contain '|'");
  }
  return utf8(`${NS}|${parts.join("|")}`);
}

export const adItem = (vaultId: string, itemId: string, formatVersion: number) =>
  join("item", vaultId, itemId, String(formatVersion));
export const adUvk = (userId: string) => join("uvk", userId);
/** spec 04 §per-member (design 2026-07-12 §F.6) — the per-member self-service recovery envelope
 *  binding. Distinct from {@link adUvk} (`recovery-uvk` vs `uvk`) so a recovery blob and a
 *  password-wrapped UVK blob can never be cross-substituted between slots for the same user. */
export const adRecovery = (userId: string) => join("recovery-uvk", userId);
export const adIdkey = (userId: string) => join("idkey", userId);
export const adVk = (vaultId: string, userId: string) => join("vk", vaultId, userId);
export const adVaultMeta = (vaultId: string) => join("vaultmeta", vaultId);
/** Security review 2026-10, root cause A §4.1: the PERSONAL wrap (`AccountKeys.personalWrap`). A distinct
 *  purpose from {@link adVk}, so an owner wrap of a shared vault never opens as a personal wrap and the
 *  reverse. Twin of core `Ad.vkPersonal`. */
export const adVkPersonal = (vaultId: string, userId: string) => join("vk-personal", vaultId, userId);
/** Root cause A §4.2: the per-user account-state blob, sealed under the UVK. Twin of core `Ad.accountState`. */
export const adAccountState = (userId: string) => join("account-state", userId);
/** spec 02 §8.2 (design 2026-08-22) — the per-user usage ledger envelope. Bound to the userId so
 *  one member's ledger can never be served into another's slot on a shared endpoint. */
export const adUsage = (userId: string) => join("usage", userId);
/** spec 07 §2.4 — backup items envelope AD; `v` is the container header version. */
export const adExport = (v: number, fileId: string) => join("export", String(v), fileId);

// ---- andvari/v2 (design 2026-11-15 §2.3) ------------------------------------------------------------

function join2(...parts: string[]): Uint8Array {
  for (const p of parts) {
    if (p.includes("|")) throw new CryptoError("AD component must not contain '|'");
  }
  return utf8(`andvari/v2|${parts.join("|")}`);
}

/**
 * Design 2026-11-15 §2.3, §3.6 (d) (T-B3): the UVK wrap of a SHARED vault's key, for the owner wrap and
 * the member self-wrap alike: `andvari/v2|vk-shared|{vaultId}|{userId}|{genesisHash}`, where
 * `genesisHash = H(genesis frame)` of the vault's log (`VaultState.genesisHash`). A wrap opens only for
 * the log whose genesis the wrapping client verified. The personal wrap keeps {@link adVkPersonal}.
 * Twin of core `Ad.vkShared`; replaces {@link adVk} for shared vaults at the cut-over.
 */
export const adVkShared = (vaultId: string, userId: string, genesisHash: string) => join2("vk-shared", vaultId, userId, genesisHash);
