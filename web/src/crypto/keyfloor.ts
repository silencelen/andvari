/**
 * Spec 01 "Keys in memory and the lock", rule 4: an all-zero key is never a key. The web twin of core `KeyFloor` and
 * `KeysGoneException` (core/crypto/KeysGone.kt).
 *
 * No legitimate key is all zeros, so the crypto path refuses one before the platform's provider is called: an envelope
 * sealed or opened under it, an envelope whose plaintext is exactly 32 or 64 zero bytes (a wiped key being wrapped), an
 * HKDF input key of zeros, an Ed25519 signature whose secret's seed half is zeros, an escrow seal of a zero UVK, a file
 * encrypted or decrypted under a zero key. Data that would put zeros there is refused where it is read, as what it is:
 * a kit whose secret is zeros is a bad kit, and a zero key matches no vault-key commitment.
 */

/**
 * The keys an operation was given are not keys: all zeros, what a wipe leaves behind in an array something still holds.
 * The operation did nothing. Deliberately NOT a `CryptoError`: a `CryptoError` from an open reads as "wrong password",
 * "not ours" or "damaged" to its callers, and this is none of those.
 */
export class KeysGoneError extends Error {
  constructor(message = "the account's keys are gone: the vault locked or the session ended") {
    super(message);
    this.name = "KeysGoneError";
  }
}

/** True when [b] is non-empty and every byte is zero. Reads every byte (no early exit). */
export function allZero(b: Uint8Array): boolean {
  if (b.length === 0) return false;
  let acc = 0;
  for (let i = 0; i < b.length; i++) acc |= b[i]!;
  return acc === 0;
}

/** Refuses [key] (a symmetric key, an HKDF input key, an X25519 secret) when it is all zeros. */
export function requireKey(key: Uint8Array): void {
  if (allZero(key)) throw new KeysGoneError();
}

/** Refuses an Ed25519 secret (libsodium's 64 bytes: seed ‖ public) whose seed half is all zeros, or a seed of zeros. */
export function requireSigningKey(secret: Uint8Array): void {
  if (allZero(secret) || (secret.length === 64 && allZero(secret.subarray(0, 32)))) throw new KeysGoneError();
}

/**
 * Refuses a plaintext that is a wiped key: exactly 32 or 64 bytes, all zero (a UVK, a vault key, a seed or a signing
 * secret after a wipe). No item, document or record this app seals is 32 or 64 zero bytes.
 */
export function requireNotWipedKey(plaintext: Uint8Array): void {
  if ((plaintext.length === 32 || plaintext.length === 64) && allZero(plaintext)) throw new KeysGoneError();
}
