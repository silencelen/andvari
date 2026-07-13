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
/** spec 07 §2.4 — backup items envelope AD; `v` is the container header version. */
export const adExport = (v: number, fileId: string) => join("export", String(v), fileId);
