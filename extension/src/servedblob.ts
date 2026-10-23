// Structure-first gate for an account-key blob the SERVER serves (security review 2026-10: R38 on the full unlock, A13
// q38 on the quick-unlock redeem), as a pure function so it is tested by behaviour (A13 review I5).
import { envelopeStructuralRefusal, fromB64 } from "./crypto.ts";

/**
 * Decode [b64] and check the envelope's PUBLIC header before any key is tried. `ok: false` means the blob is not
 * base64url, or not an envelope this build can read: a damaged or foreign account row (the server's doing, never the
 * device's key), which the caller reports as the terminal keys_damaged refusal instead of blaming a stale key. A blob
 * that passes can still fail to OPEN; that is the caller's other, key-dependent verdict.
 */
export function gateServedEnvelope(b64: string): { ok: true; envelope: Uint8Array } | { ok: false; why: string } {
  let envelope: Uint8Array;
  try {
    envelope = fromB64(b64);
  } catch {
    return { ok: false, why: "not valid base64url" };
  }
  const refusal = envelopeStructuralRefusal(envelope);
  return refusal === null ? { ok: true, envelope } : { ok: false, why: refusal };
}
