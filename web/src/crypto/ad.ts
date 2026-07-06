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
export const adIdkey = (userId: string) => join("idkey", userId);
export const adVk = (vaultId: string, userId: string) => join("vk", vaultId, userId);
export const adVaultMeta = (vaultId: string) => join("vaultmeta", vaultId);
