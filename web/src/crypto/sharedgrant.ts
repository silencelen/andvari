import { fromB64, fromUtf8, toB64, toHexLower, utf8 } from "./bytes";
import { sealOpen, sealTo, sha256 } from "./provider";
import { CryptoError } from "./sodium";

/** spec 01 §6 — sealed shared-vault grant; mirrors core SharedGrant.kt byte-for-byte. */
export interface SharedGrantPayload {
  v: number;
  vaultId: string;
  vk: string;
}

/** Canonical bytes — string template guarantees key order and no whitespace (matches Kotlin). */
export function canonicalGrantPayload(vaultId: string, vk: Uint8Array): Uint8Array {
  return utf8(`{"v":1,"vaultId":"${vaultId}","vk":"${toB64(vk)}"}`);
}

export function sealSharedGrant(memberIdentityPub: Uint8Array, vaultId: string, vk: Uint8Array): Uint8Array {
  return sealTo(memberIdentityPub, canonicalGrantPayload(vaultId, vk));
}

/**
 * Open a sealed grant → the 32-byte VK. The payload's vaultId MUST equal the grant row's
 * vaultId (binds the seal to the row it arrived on).
 */
export function openSharedGrant(
  memberIdentityPub: Uint8Array,
  memberIdentityPriv: Uint8Array,
  expectedVaultId: string,
  sealed: Uint8Array,
): Uint8Array {
  const raw = sealOpen(memberIdentityPub, memberIdentityPriv, sealed);
  let payload: SharedGrantPayload;
  try {
    payload = JSON.parse(fromUtf8(raw)) as SharedGrantPayload;
  } catch (e) {
    throw new CryptoError("shared grant payload is not JSON", { cause: e });
  }
  if (payload.v !== 1) throw new CryptoError(`unsupported shared-grant payload version ${payload.v}`);
  if (payload.vaultId !== expectedVaultId) throw new CryptoError("shared grant vaultId mismatch");
  const vk = fromB64(payload.vk);
  if (vk.length !== 32) throw new CryptoError("shared grant VK is not 32 bytes");
  return vk;
}

/**
 * spec 01 §5 — identity fingerprint = lowercase hex SHA-256 of the identity public key.
 * MUST be computed over the SEED-DERIVED pubkey, never the server-supplied identityPub.
 */
export async function identityFingerprint(identityPub: Uint8Array): Promise<string> {
  return toHexLower(await sha256(identityPub));
}

export async function shortIdentityFingerprint(identityPub: Uint8Array): Promise<string> {
  return (await identityFingerprint(identityPub)).slice(0, 16);
}
