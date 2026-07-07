import { beforeAll, describe, expect, it } from "vitest";
import type { AccountKeys } from "../api/types";
import { toB64 } from "../crypto/bytes";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { CryptoError, initSodium } from "../crypto/sodium";
import { Account, IdentityMismatchError } from "./account";

/**
 * F31 (spec 01 §5 MUST, core Account.unlock parity): after deriving the identity
 * keypair from the UVK-sealed seed — which the server cannot forge — the server-sent
 * `identityPub` must EQUAL the derived public key. A substituted key is a tampering
 * signal thrown as a DISTINCT type, so the auth surfaces can never soften it into
 * "wrong master password".
 */

// Minimum-cost argon2id — these tests exercise the cross-check, not the KDF.
const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };
const PASSWORD = "correct horse battery";

/** Enroll for real and reshape the register request into the server's AccountKeys. */
async function enrolledKeys(): Promise<{ userId: string; keys: AccountKeys }> {
  const recovery = boxKeypairFromSeed(randomBytes(32));
  const { request } = await Account.enroll({
    inviteToken: "test-invite",
    email: "u@example.com",
    displayName: "u",
    password: PASSWORD,
    kdfParams: KDF,
    recoveryPublicKey: recovery.publicKey,
    recoveryFingerprint: await fingerprint(recovery.publicKey),
  });
  return {
    userId: request.userId,
    keys: {
      kdfSalt: request.kdfSalt,
      kdfParams: request.kdfParams,
      wrappedUvk: request.wrappedUvk,
      encryptedIdentitySeed: request.encryptedIdentitySeed,
      identityPub: request.identityPub,
      escrowFingerprint: request.escrow.fingerprint,
    },
  };
}

describe("Account.unlock identityPub cross-check (F31 / spec 01 §5)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("unlocks when the server-sent identityPub matches the seed-derived key", async () => {
    const { userId, keys } = await enrolledKeys();
    const account = await Account.unlock(userId, PASSWORD, keys);
    expect(toB64(account.identityPub)).toBe(keys.identityPub);
  });

  it("throws the distinct IdentityMismatchError on a substituted identityPub", async () => {
    const { userId, keys } = await enrolledKeys();
    // A malicious/compromised server swaps in a key IT controls — a valid 32-byte
    // curve25519 public key, so only the cross-check can catch it.
    const tampered: AccountKeys = { ...keys, identityPub: toB64(boxKeypairFromSeed(randomBytes(32)).publicKey) };
    const err = await Account.unlock(userId, PASSWORD, tampered).catch((e) => e);
    expect(err).toBeInstanceOf(IdentityMismatchError);
    expect((err as Error).message).toMatch(/identity key mismatch — possible tampering/i);
    // NEVER presentable as a wrong password (Welcome branches on the type).
    expect(err).not.toBeInstanceOf(CryptoError);
    expect((err as Error).message).not.toMatch(/password/i);
  });

  it("an empty/garbled identityPub also fails the cross-check (no silent skip)", async () => {
    const { userId, keys } = await enrolledKeys();
    const err = await Account.unlock(userId, PASSWORD, { ...keys, identityPub: "" }).catch((e) => e);
    expect(err).toBeInstanceOf(IdentityMismatchError);
  });

  it("a plain wrong password still reads as CryptoError, not tampering", async () => {
    const { userId, keys } = await enrolledKeys();
    const err = await Account.unlock(userId, "not the password", keys).catch((e) => e);
    expect(err).toBeInstanceOf(CryptoError);
    expect(err).not.toBeInstanceOf(IdentityMismatchError);
    expect((err as Error).message).toMatch(/wrong master password/);
  });
});
