import { ctEquals, fromB64, fromUtf8, toB64, toHexLower, utf8 } from "./bytes";
import { sealOpen, sealTo, sha256 } from "./provider";
import { CryptoError } from "./sodium";

/** spec 04 §3 — sealed escrow payloads; mirrors core Escrow.kt. */
export const KEY_TYPE_UVK = "uvk";
export const KEY_TYPE_CANARY = "canary";
export const CANARY_USER_ID = "00000000-0000-0000-0000-000000000000";
export const CANARY_KEY: Uint8Array = new Uint8Array(32).fill(0x5a);

export interface EscrowPayload {
  v: number;
  userId: string;
  keyType: string;
  key: string;
  sha256: string;
}

/** Canonical bytes — string template guarantees key order and no whitespace. */
export async function canonicalPayload(userId: string, keyType: string, keyBytes: Uint8Array): Promise<Uint8Array> {
  const keyB64 = toB64(keyBytes);
  const shaB64 = toB64(await sha256(keyBytes));
  return utf8(`{"v":1,"userId":"${userId}","keyType":"${keyType}","key":"${keyB64}","sha256":"${shaB64}"}`);
}

export async function sealUvk(recoveryPub: Uint8Array, userId: string, uvk: Uint8Array): Promise<Uint8Array> {
  return sealTo(recoveryPub, await canonicalPayload(userId, KEY_TYPE_UVK, uvk));
}

// quality-deadcode--3: `sealCanary` had ZERO callers here — only the org's recovery ceremony
// seals a canary, and that is Kotlin-side (core Escrow.sealCanary, live in recovery-cli and
// vector-gen). The web client only ever OPENS one: vectors.test.ts feeds a pre-sealed canary
// from spec/test-vectors through openEscrow below, which is the parity this engine has to hold.
// The three canary constants stay: they are spec 04 §3 values mirroring core Escrow.kt (and
// vectors.test.ts checks the opened canary's userId against CANARY_USER_ID), so they document
// the wire shape this engine has to agree on rather than being leftovers of the seal path.

/** Open + self-validate (sha256 of key must match; spec 04 §3). */
export async function openEscrow(
  recoveryPub: Uint8Array,
  recoveryPriv: Uint8Array,
  sealed: Uint8Array,
): Promise<EscrowPayload> {
  const raw = fromUtf8(sealOpen(recoveryPub, recoveryPriv, sealed));
  let payload: EscrowPayload;
  try {
    payload = JSON.parse(raw) as EscrowPayload;
  } catch (e) {
    throw new CryptoError("escrow payload is not JSON", { cause: e });
  }
  if (payload.v !== 1) throw new CryptoError(`unsupported escrow payload version ${payload.v}`);
  const keyBytes = fromB64(payload.key);
  const expected = toB64(await sha256(keyBytes));
  if (!ctEquals(utf8(expected), utf8(payload.sha256))) {
    throw new CryptoError("escrow payload self-check failed (sha256 mismatch)");
  }
  return payload;
}

/** spec 04 §1 — lowercase hex SHA-256 of the 32-byte public key. */
export async function fingerprint(publicKey: Uint8Array): Promise<string> {
  return toHexLower(await sha256(publicKey));
}

export async function shortFingerprint(publicKey: Uint8Array): Promise<string> {
  return (await fingerprint(publicKey)).slice(0, 16);
}

/**
 * spec 04 §2(3): at enrollment the user must TYPE the first 16 hex chars of the org
 * recovery fingerprint from the PRINTED sheet (the UI deliberately does not display
 * them first). Separators/whitespace are tolerated; exactly 16 hex chars required.
 */
export function shortFormMatches(entry: string, fullFingerprintHex: string): boolean {
  const norm = entry.toLowerCase().replace(/[^0-9a-f]/g, "");
  return norm.length === 16 && fullFingerprintHex.toLowerCase().slice(0, 16) === norm;
}
