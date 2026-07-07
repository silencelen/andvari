import { ctEquals, fromB64, toB64, toHexLower, utf8 } from "./bytes";
import { hkdfSha256 } from "./hkdf";
import { hmacSha256, sha256 } from "./provider";

/**
 * Lifecycle proofs (spec 03 §11) — the TS mirror of core LifecycleProof.kt, byte-identical
 * (pinned by spec/test-vectors/lifecycleproof.json). Destructive shared-vault ops carry an
 * HMAC-SHA-256 under a key derived from the vault key VK (which the server never holds); a
 * 0.5.0 client verifies before treating a server's destructive claim as an owner action.
 * MACs, not signatures — they remove only the server from the forgery set.
 *
 * Domain strings: `|`-joined UTF-8; integers decimal; the accept proof embeds lowercase-hex
 * SHA-256 of the posted wrappedVk string's UTF-8 bytes. Proof values are base64url, unpadded.
 */
const LIFECYCLE_INFO = "andvari/v1|lifecycle";

/** lifecycleKey = HKDF-SHA-256(ikm = VK, salt = "", info = "andvari/v1|lifecycle", 32). */
export function lifecycleKey(vk: Uint8Array): Promise<Uint8Array> {
  return hkdfSha256(vk, new Uint8Array(0), utf8(LIFECYCLE_INFO), 32);
}

async function mac(key: Uint8Array, domain: string): Promise<string> {
  return toB64(await hmacSha256(key, utf8(domain)));
}

export const deleteProof = (key: Uint8Array, vaultId: string, deleteId: string): Promise<string> =>
  mac(key, `andvari/v1|lifecycle|delete|${vaultId}|${deleteId}`);

export const restoreProof = (key: Uint8Array, vaultId: string, deleteId: string): Promise<string> =>
  mac(key, `andvari/v1|lifecycle|restore|${vaultId}|${deleteId}`);

export const offerProof = (
  key: Uint8Array,
  vaultId: string,
  offerId: string,
  toUserId: string,
  expiresAt: number,
  seq: number,
): Promise<string> => mac(key, `andvari/v1|lifecycle|transfer|${vaultId}|${offerId}|${toUserId}|${expiresAt}|${seq}`);

export async function acceptProof(
  key: Uint8Array,
  vaultId: string,
  offerId: string,
  newOwnerUserId: string,
  seq: number,
  wrappedVk: string,
): Promise<string> {
  const wrapHash = toHexLower(await sha256(utf8(wrappedVk)));
  return mac(key, `andvari/v1|lifecycle|transfer-accept|${vaultId}|${offerId}|${newOwnerUserId}|${seq}|${wrapHash}`);
}

export const removeProof = (key: Uint8Array, vaultId: string, targetUserId: string, nonce: string): Promise<string> =>
  mac(key, `andvari/v1|lifecycle|remove|${vaultId}|${targetUserId}|${nonce}`);

/** Constant-time compare of a presented base64url proof against the expected value. */
export function verifyProof(expected: string, presented: string): boolean {
  try {
    return ctEquals(fromB64(expected), fromB64(presented));
  } catch {
    return false;
  }
}
